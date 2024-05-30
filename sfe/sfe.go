package sfe

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"text/template"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/ratelimits"

	// 'grpc/noncebalancer' is imported for its init function.
	_ "github.com/letsencrypt/boulder/grpc/noncebalancer"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics/measured_http"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

var (
	//go:embed all:static
	staticFS embed.FS

	//go:embed all:templates all:pages
	dynamicFS embed.FS
)

// HTML pages to-be-served by the SFE
var tmplIndex, tmplUnpausePost, tmplUnpauseParams, tmplUnpauseNoParams *template.Template

// Parse the files once at startup to avoid each request causing the server to
// JIT parse. The pages are stored in an in-memory embed.FS to prevent
// unnecessary filesystem I/O on a physical HDD.
func init() {
	tmplIndex = template.Must(template.New("index").ParseFS(dynamicFS, "templates/layout.html", "pages/index.html"))
	tmplUnpausePost = template.Must(template.New("unpause").ParseFS(dynamicFS, "templates/layout.html", "pages/unpause-post.html"))
	tmplUnpauseParams = template.Must(template.New("unpause").ParseFS(dynamicFS, "templates/layout.html", "pages/unpause-params.html"))
	tmplUnpauseNoParams = template.Must(template.New("unpause").ParseFS(dynamicFS, "templates/layout.html", "pages/unpause-noParams.html"))

}

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

	// unpauseKey is an HMAC-SHA256 key used for verifying the HMAC included in
	// each unpause request.
	unpauseKey string
}

// NewSelfServiceFrontEndImpl constructs a web service for Boulder
func NewSelfServiceFrontEndImpl(
	stats prometheus.Registerer,
	clk clock.Clock,
	logger blog.Logger,
	requestTimeout time.Duration,
	rac rapb.RegistrationAuthorityClient,
	sac sapb.StorageAuthorityReadOnlyClient,
	unpauseKey string,
	limiter *ratelimits.Limiter,
	txnBuilder *ratelimits.TransactionBuilder,
) (SelfServiceFrontEndImpl, error) {

	sfe := SelfServiceFrontEndImpl{
		log:            logger,
		clk:            clk,
		requestTimeout: requestTimeout,
		ra:             rac,
		sa:             sac,
		limiter:        limiter,
		txnBuilder:     txnBuilder,
		unpauseKey:     unpauseKey,
	}

	return sfe, nil
}

/*
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
func (sfe *SelfServiceFrontEndImpl) HandleFunc(mux *http.ServeMux, pattern string, h web.FrontEndHandlerFunc, methods ...string) {
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
	handler := http.StripPrefix(pattern, web.NewTopHandler(sfe.log,
		web.FrontEndHandlerFunc(func(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
			span := trace.SpanFromContext(ctx)
			span.SetName(pattern)

			logEvent.Endpoint = pattern
			if request.URL != nil {
				logEvent.Slug = request.URL.Path
			}
			tls := request.Header.Get("TLS-Version")
			if tls == "TLSv1" || tls == "TLSv1.1" {
				sfe.sendError(response, logEvent, probs.Malformed("upgrade your ACME client to support TLSv1.2 or better"), nil)
				return
			}

			switch request.Method {
			case "HEAD":
				// Go's net/http (and httptest) servers will strip out the body
				// of responses for us. This keeps the Content-Length for HEAD
				// requests as the same as GET requests per the spec.
			case "OPTIONS":
				sfe.Options(response, request, methodsStr, methodsMap)
				return
			}

			if !methodsMap[request.Method] {
				response.Header().Set("Allow", methodsStr)
				sfe.sendError(response, logEvent, probs.MethodNotAllowed(), nil)
				return
			}

			sfe.setCORSHeaders(response, request, "")

			timeout := sfe.requestTimeout
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
*/

// Handler returns an http.Handler that uses various functions for various
// non-ACME-specified paths. Each endpoint should have a corresponding HTML
// page that shares the same name as the endpoint.
func (sfe *SelfServiceFrontEndImpl) Handler(stats prometheus.Registerer, oTelHTTPOptions ...otelhttp.Option) http.Handler {
	m := http.NewServeMux()

	sfs, _ := fs.Sub(staticFS, "static")
	staticAssetsHandler := http.StripPrefix("/static/", http.FileServerFS(sfs))

	m.Handle("GET /static/", staticAssetsHandler)
	m.HandleFunc("/", sfe.Index)
	m.HandleFunc("/unpause", sfe.Unpause)
	m.HandleFunc("GET /build", sfe.BuildID)

	return measured_http.New(m, sfe.clk, stats, oTelHTTPOptions...)
}

// renderTemplate takes an HTML template instantiated by the SFE init() and an
// optional dynamicData which are rendered and served back to the client via the
// response writer.
func renderTemplate(w http.ResponseWriter, tmpl *template.Template, dynamicData []string) {
	if tmpl == nil {
		http.Error(w, "Template does not exist", http.StatusInternalServerError)
		return
	}

	err := tmpl.ExecuteTemplate(w, "layout", dynamicData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Index is the homepage of the SFE
func (sfe *SelfServiceFrontEndImpl) Index(response http.ResponseWriter, request *http.Request) {
	if request.Method != "GET" && request.Method != "HEAD" {
		response.Header().Set("Access-Control-Allow-Methods", "GET, HEAD")
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	renderTemplate(response, tmplIndex, nil)
}

// BuildID tells the requester what boulder build version is running.
func (sfe *SelfServiceFrontEndImpl) BuildID(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "text/plain")
	response.WriteHeader(http.StatusOK)
	detailsString := fmt.Sprintf("Boulder=(%s %s)", core.GetBuildID(), core.GetBuildTime())
	if _, err := fmt.Fprintln(response, detailsString); err != nil {
		sfe.log.Warningf("Could not write response: %s", err)
	}
}

// Unpause allows a requester to unpause their account via a form present on the
// page.
func (sfe *SelfServiceFrontEndImpl) Unpause(response http.ResponseWriter, request *http.Request) {
	sfe.log.AuditInfof("Got here via %s", request.Method)

	if request.Method != "GET" && request.Method != "HEAD" && request.Method != "POST" {
		response.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, POST")
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if request.Method == "GET" && len(request.URL.Query()) <= 0 {
		// For relying parties who stumble across this page. Doesn't allow
		// unpausing.
		renderTemplate(response, tmplUnpauseNoParams, nil)
	} else if request.Method == "GET" {
		// Serve the actual unpause page given to a Subscriber. Allows
		// unpausing.
		renderTemplate(response, tmplUnpauseParams, nil)
	} else if request.Method == "POST" {
		// After clicking unpause, serve another page indicating that the
		// Subscriber should re-attempt issuance.
		renderTemplate(response, tmplUnpausePost, nil)
	}
}

// stillFresh verifies a given timestamp's "freshness", ensuring it is within a
// predefined window to prevent replay attacks.
func stillFresh(ts time.Time) error {

	return nil
}

// verifyHMAC takes a registrationID, timestamp, and a base64url encoded
// HMAC-SHA256 hash and attempts to match the given HMAC by computing a new HMAC
// with the SFE's UnpauseKey, regID, and timestamp. If a match is found, the
// Subscriber's account can be unpaused, otherwise an error is returned.
func (sfe *SelfServiceFrontEndImpl) verifyHMAC(regID string, ts time.Time, hash string) error {

	return nil
}
