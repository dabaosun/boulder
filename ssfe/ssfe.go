package ssfe

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/ratelimits"

	// 'grpc/noncebalancer' is imported for its init function.
	_ "github.com/letsencrypt/boulder/grpc/noncebalancer"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics/measured_http"
	"github.com/letsencrypt/boulder/probs"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/web"
)

// Paths are the ACME-spec identified URL path-segments for various methods.
// NOTE: In metrics/measured_http we make the assumption that these are all
// lowercase plus hyphens. If you violate that assumption you should update
// measured_http.
const (
	unpausePath = "/unpause"
	buildIDPath = "/build"
)

const (
	headerRetryAfter = "Retry-After"
)

var errIncompleteGRPCResponse = errors.New("incomplete gRPC response message")

// SelfServiceFrontEndImpl provides all the logic for Boulder's selfservice
// frontend web-facing interface, i.e., a portal where a subscriber can unpause
// their account. Its methods are primarily handlers for HTTPS requests for the
// various non-ACME functions.
type SelfServiceFrontEndImpl struct {
	ra rapb.RegistrationAuthorityClient
	sa sapb.StorageAuthorityReadOnlyClient

	log blog.Logger
	clk clock.Clock

	// requestTimeout is the per-request overall timeout.
	requestTimeout time.Duration

	// CORS settings
	AllowOrigins []string

	limiter    *ratelimits.Limiter
	txnBuilder *ratelimits.TransactionBuilder
}

// NewSelfServiceFrontEndImpl constructs a web service for Boulder
func NewSelfServiceFrontEndImpl(
	stats prometheus.Registerer,
	clk clock.Clock,
	logger blog.Logger,
	requestTimeout time.Duration,
	rac rapb.RegistrationAuthorityClient,
	sac sapb.StorageAuthorityReadOnlyClient,
	limiter *ratelimits.Limiter,
	txnBuilder *ratelimits.TransactionBuilder,
) (SelfServiceFrontEndImpl, error) {

	ssfe := SelfServiceFrontEndImpl{
		log:            logger,
		clk:            clk,
		requestTimeout: requestTimeout,
		ra:             rac,
		sa:             sac,
		limiter:        limiter,
		txnBuilder:     txnBuilder,
	}

	return ssfe, nil
}

// HandleFunc registers a handler at the given path. It's
// http.HandleFunc(), but with a wrapper around the handler that
// provides some generic per-request functionality:
//
// * Set a Replay-Nonce header.
//
// * Respond to OPTIONS requests, including CORS preflight requests.
//
// * Set a no cache header
//
// * Respond http.StatusMethodNotAllowed for HTTP methods other than
// those listed.
//
// * Set CORS headers when responding to CORS "actual" requests.
//
// * Never send a body in response to a HEAD request. Anything
// written by the handler will be discarded if the method is HEAD.
// Also, all handlers that accept GET automatically accept HEAD.
func (ssfe *SelfServiceFrontEndImpl) HandleFunc(mux *http.ServeMux, pattern string, h web.FrontEndHandlerFunc, methods ...string) {
	methodsMap := make(map[string]bool)
	for _, m := range methods {
		methodsMap[m] = true
	}
	if methodsMap["GET"] && !methodsMap["HEAD"] {
		// Allow HEAD for any resource that allows GET
		methods = append(methods, "HEAD")
		methodsMap["HEAD"] = true
	}
	methodsStr := strings.Join(methods, ", ")
	handler := http.StripPrefix(pattern, web.NewTopHandler(ssfe.log,
		web.FrontEndHandlerFunc(func(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
			span := trace.SpanFromContext(ctx)
			span.SetName(pattern)

			logEvent.Endpoint = pattern
			if request.URL != nil {
				logEvent.Slug = request.URL.Path
			}
			tls := request.Header.Get("TLS-Version")
			if tls == "TLSv1" || tls == "TLSv1.1" {
				ssfe.sendError(response, logEvent, probs.Malformed("upgrade your ACME client to support TLSv1.2 or better"), nil)
				return
			}

			switch request.Method {
			case "HEAD":
				// Go's net/http (and httptest) servers will strip out the body
				// of responses for us. This keeps the Content-Length for HEAD
				// requests as the same as GET requests per the spec.
			case "OPTIONS":
				ssfe.Options(response, request, methodsStr, methodsMap)
				return
			}

			if !methodsMap[request.Method] {
				response.Header().Set("Allow", methodsStr)
				ssfe.sendError(response, logEvent, probs.MethodNotAllowed(), nil)
				return
			}

			ssfe.setCORSHeaders(response, request, "")

			timeout := ssfe.requestTimeout
			if timeout == 0 {
				timeout = 5 * time.Minute
			}
			ctx, cancel := context.WithTimeout(ctx, timeout)

			// Call the wrapped handler.
			h(ctx, logEvent, response, request)
			cancel()
		}),
	))
	mux.Handle(pattern, handler)
}

// Handler returns an http.Handler that uses various functions for
// various ACME-specified paths.
func (ssfe *SelfServiceFrontEndImpl) Handler(stats prometheus.Registerer, oTelHTTPOptions ...otelhttp.Option) http.Handler {
	m := http.NewServeMux()

	// Serve our static files
	fs := http.FileServer(http.Dir("./static"))
	m.Handle("/static/", http.StripPrefix("/static/", fs))

	ssfe.HandleFunc(m, buildIDPath, ssfe.BuildID, "GET")
	ssfe.HandleFunc(m, unpausePath, ssfe.Unpause, "GET", "POST")

	// We don't use our special HandleFunc for "/" because it matches everything,
	// meaning we can wind up returning 405 when we mean to return 404. See
	// https://github.com/letsencrypt/boulder/issues/717
	m.Handle("/", web.NewTopHandler(ssfe.log, web.FrontEndHandlerFunc(ssfe.Index)))
	return measured_http.New(m, ssfe.clk, stats, oTelHTTPOptions...)
}

// Method implementations

// Index serves a simple identification page. It is not part of the ACME spec.
func (ssfe *SelfServiceFrontEndImpl) Index(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	// All requests that are not handled by our ACME endpoints ends up
	// here. Set the our logEvent endpoint to "/" and the slug to the path
	// minus "/" to make sure that we properly set log information about
	// the request, even in the case of a 404
	logEvent.Endpoint = "/"
	logEvent.Slug = request.URL.Path[1:]

	// http://golang.org/pkg/net/http/#example_ServeMux_Handle
	// The "/" pattern matches everything, so we need to check
	// that we're at the root here.
	if request.URL.Path != "/" {
		logEvent.AddError("Resource not found")
		http.NotFound(response, request)
		response.Header().Set("Content-Type", "application/problem+json")
		return
	}

	if request.Method != "GET" {
		response.Header().Set("Allow", "GET")
		ssfe.sendError(response, logEvent, probs.MethodNotAllowed(), errors.New("Bad method"))
		return
	}

	styleTemplate := filepath.Join("templates", "layout.tmpl")
	slugTemplate := filepath.Join("templates", filepath.Clean(request.URL.Path))
	renderedTemplate, err := template.ParseFiles(styleTemplate, slugTemplate)
	if err != nil {
		ssfe.log.Errf("%s\n", err)
	}
	renderedTemplate.ExecuteTemplate(response, "index", nil)

	/*
		fmt.Fprintln(response, `<html>
			<head>
				<title>Self-service Front End</title>
			</head>
			<body>
				<p>
					This is an <a href="https://tools.ietf.org/html/rfc8555">ACME</a>
					Certificate Authority running <a href="https://github.com/letsencrypt/boulder">Boulder</a>.
					However, this is not an <a href="https://tools.ietf.org/html/rfc8555">ACME</a> endpoint.
				</p>
				<p>
					The <a href="https://letsencrypt.org/getting-started/">directory</a> is in another castle!
				</p>
			</body>
		</html>
		`)
	*/
}

// sendError wraps web.SendError
func (ssfe *SelfServiceFrontEndImpl) sendError(response http.ResponseWriter, logEvent *web.RequestEvent, prob *probs.ProblemDetails, ierr error) {
	var bErr *berrors.BoulderError
	if errors.As(ierr, &bErr) {
		retryAfterSeconds := int(bErr.RetryAfter.Round(time.Second).Seconds())
		if retryAfterSeconds > 0 {
			response.Header().Add(headerRetryAfter, strconv.Itoa(retryAfterSeconds))
			if bErr.Type == berrors.RateLimit {
				response.Header().Add("Link", link("https://letsencrypt.org/docs/rate-limits", "help"))
			}
		}
	}
	//ssfe.stats.httpErrorCount.With(prometheus.Labels{"type": string(prob.Type)}).Inc()
	web.SendError(ssfe.log, response, logEvent, prob, ierr)
}

func link(url, relation string) string {
	return fmt.Sprintf("<%s>;rel=\"%s\"", url, relation)
}

// BuildID tells the requester what build we're running.
func (ssfe *SelfServiceFrontEndImpl) BuildID(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "text/plain")
	response.WriteHeader(http.StatusOK)
	detailsString := fmt.Sprintf("Boulder=(%s %s)", core.GetBuildID(), core.GetBuildTime())
	if _, err := fmt.Fprintln(response, detailsString); err != nil {
		ssfe.log.Warningf("Could not write response: %s", err)
	}
}

// Unpause allows a requester to unpause their account.
func (ssfe *SelfServiceFrontEndImpl) Unpause(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "text/plain")
	response.WriteHeader(http.StatusOK)
	detailsString := fmt.Sprintln("Unpause is not yet implemented, apparently.")
	if _, err := fmt.Fprintln(response, detailsString); err != nil {
		ssfe.log.Warningf("Could not write response: %s", err)
	}
}

// Options responds to an HTTP OPTIONS request.
func (ssfe *SelfServiceFrontEndImpl) Options(response http.ResponseWriter, request *http.Request, methodsStr string, methodsMap map[string]bool) {
	// Every OPTIONS request gets an Allow header with a list of supported methods.
	response.Header().Set("Allow", methodsStr)

	// CORS preflight requests get additional headers. See
	// http://www.w3.org/TR/cors/#resource-preflight-requests
	reqMethod := request.Header.Get("Access-Control-Request-Method")
	if reqMethod == "" {
		reqMethod = "GET"
	}
	if methodsMap[reqMethod] {
		ssfe.setCORSHeaders(response, request, methodsStr)
	}
}

// setCORSHeaders() tells the client that CORS is acceptable for this
// request. If allowMethods == "" the request is assumed to be a CORS
// actual request and no Access-Control-Allow-Methods header will be
// sent.
func (ssfe *SelfServiceFrontEndImpl) setCORSHeaders(response http.ResponseWriter, request *http.Request, allowMethods string) {
	reqOrigin := request.Header.Get("Origin")
	if reqOrigin == "" {
		// This is not a CORS request.
		return
	}

	// Allow CORS if the current origin (or "*") is listed as an
	// allowed origin in config. Otherwise, disallow by returning
	// without setting any CORS headers.
	allow := false
	for _, ao := range ssfe.AllowOrigins {
		if ao == "*" {
			response.Header().Set("Access-Control-Allow-Origin", "*")
			allow = true
			break
		} else if ao == reqOrigin {
			response.Header().Set("Vary", "Origin")
			response.Header().Set("Access-Control-Allow-Origin", ao)
			allow = true
			break
		}
	}
	if !allow {
		return
	}

	if allowMethods != "" {
		// For an OPTIONS request: allow all methods handled at this URL.
		response.Header().Set("Access-Control-Allow-Methods", allowMethods)
	}
	// NOTE(@cpu): "Content-Type" is considered a 'simple header' that doesn't
	// need to be explicitly allowed in 'access-control-allow-headers', but only
	// when the value is one of: `application/x-www-form-urlencoded`,
	// `multipart/form-data`, or `text/plain`. Since `application/jose+json` is
	// not one of these values we must be explicit in saying that `Content-Type`
	// is an allowed header. See MDN for more details:
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers
	response.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	response.Header().Set("Access-Control-Expose-Headers", "Link, Replay-Nonce, Location")
	response.Header().Set("Access-Control-Max-Age", "86400")
}
