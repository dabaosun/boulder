package sfe

import (
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
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

	// HTML pages to-be-served by the SFE
	tmplIndex           *template.Template
	tmplUnpausePost     *template.Template
	tmplUnpauseParams   *template.Template
	tmplUnpauseNoParams *template.Template
	tmplUnpauseExpired  *template.Template
)

// Parse the files once at startup to avoid each request causing the server to
// JIT parse. The pages are stored in an in-memory embed.FS to prevent
// unnecessary filesystem I/O on a physical HDD.
func init() {
	tmplIndex = template.Must(template.New("index").ParseFS(dynamicFS, "templates/layout.html", "pages/index.html"))
	tmplUnpausePost = template.Must(template.New("unpause").ParseFS(dynamicFS, "templates/layout.html", "pages/unpause-post.html"))
	tmplUnpauseParams = template.Must(template.New("unpause").ParseFS(dynamicFS, "templates/layout.html", "pages/unpause-params.html"))
	tmplUnpauseNoParams = template.Must(template.New("unpause").ParseFS(dynamicFS, "templates/layout.html", "pages/unpause-noParams.html"))
	tmplUnpauseExpired = template.Must(template.New("unpause").ParseFS(dynamicFS, "templates/layout.html", "pages/unpause-expired.html"))
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

	// unpauseStaleWindow is the amount of time an unpause URL is considered
	// "fresh" before returning an error to a client.
	unpauseStaleWindow time.Duration
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
	unpauseStaleWindow time.Duration,
	limiter *ratelimits.Limiter,
	txnBuilder *ratelimits.TransactionBuilder,
) (SelfServiceFrontEndImpl, error) {

	sfe := SelfServiceFrontEndImpl{
		log:                logger,
		clk:                clk,
		requestTimeout:     requestTimeout,
		ra:                 rac,
		sa:                 sac,
		limiter:            limiter,
		txnBuilder:         txnBuilder,
		unpauseKey:         unpauseKey,
		unpauseStaleWindow: unpauseStaleWindow,
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

const (
	// The API version should be checked when parsing paramters to quickly deny
	// a client request. Can be used to mass-invalidate URLs.
	unpausePath = "/sfe/v1/unpause"
)

// Handler returns an http.Handler that uses various functions for various
// non-ACME-specified paths. Each endpoint should have a corresponding HTML
// page that shares the same name as the endpoint.
func (sfe *SelfServiceFrontEndImpl) Handler(stats prometheus.Registerer, oTelHTTPOptions ...otelhttp.Option) http.Handler {
	m := http.NewServeMux()

	sfs, _ := fs.Sub(staticFS, "static")
	staticAssetsHandler := http.StripPrefix("/static/", http.FileServerFS(sfs))

	m.Handle("GET /static/", staticAssetsHandler)
	m.HandleFunc("/", sfe.Index)

	// A "version" parameter is also sent by the WFE and used as a quick
	// bail-out if it doesn't match the path.
	m.HandleFunc(unpausePath, sfe.Unpause)

	m.HandleFunc("GET /build", sfe.BuildID)

	return measured_http.New(m, sfe.clk, stats, oTelHTTPOptions...)
}

// renderTemplate takes an HTML template instantiated by the SFE init() and an
// optional dynamicData which are rendered and served back to the client via the
// response writer.
func renderTemplate(w http.ResponseWriter, tmpl *template.Template, dynamicData map[string]string) {
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
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
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

	if request.Method != http.MethodGet && request.Method != http.MethodHead && request.Method != http.MethodPost {
		response.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, POST")
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if request.Method == http.MethodGet && len(request.URL.Query()) <= 0 {
		// For relying parties who stumble across this page. Doesn't allow
		// unpausing.
		renderTemplate(response, tmplUnpauseNoParams, nil)
	} else if request.Method == http.MethodGet && len(request.URL.Query()) == 2 {
		params, err := sfe.parseAndValidateUnpauseParams(request)

		ok := sfe.stillFresh(params.ts)
		if !ok {
			renderTemplate(response, tmplUnpauseExpired, nil)
		}

		// Serve the actual unpause page given to a Subscriber. Allows
		// unpausing.
		renderTemplate(response, tmplUnpauseParams, nil)
	} else if request.Method == http.MethodGet {
		//
	} else if request.Method == http.MethodPost {
		// After clicking unpause, serve another page indicating that the
		// Subscriber should re-attempt issuance.
		renderTemplate(response, tmplUnpausePost, nil)
	}
}

type unpauseParams struct {
	// Unpause API version
	version string

	// Registration ID of the eventually to-be-unpaused account
	regID int64

	// Timestamp supplied by the WFE when it generated the unpause URL
	ts time.Time
}

// parseAndValidateUnpauseParams takes a base64 url-encoded string, decodes it,
// and parses out parameters from it. It returns the parameters or an error if
// any validation checks on the parameters fail.
//
// Validation checks include:
//  1. Check that the base64 decoded string contains 3 parameters in the form of
//     <version>.<registrationID>.<RFC3339 Timestamp>
//  2. If any parameter is missing or empty, exit
//  3. Check that the <version> matches the API endpoint version
func (sfe *SelfServiceFrontEndImpl) parseAndValidateUnpauseParams(input string) (*unpauseParams, error) {
	b64DecodedParams, err := base64.RawURLEncoding.DecodeString(input)
	if err != nil {
		return nil, fmt.Errorf("Parameters were not base64url-encoded or contained padding: %s", err)
	}

	parts := strings.Split(string(b64DecodedParams), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("Expected 3 parameters, received %d", len(parts))
	}

	version := parts[0]
	if version == "" {
		// This shouldn't happen because of the split check above.
		return nil, errors.New("Expected version, but received empty string")
	}

	versionSlug := strings.Split(unpausePath, "/")
	if len(versionSlug) != 4 {
		// This shouldn't happen because we control the unpausePath. If it does,
		// then it's an internal server error.
		return nil, errors.New("I can't believe we've done this.")
	}
	if version != versionSlug[2] {
		return nil, fmt.Errorf("Client sent a %s request to a %s endpoint", version, versionSlug[1])
	}

	parsedRegID := parts[1]
	regID, err := strconv.ParseInt(parsedRegID, 10, 64)
	if err != nil {
		return nil, err
	}

	parsedTimestamp := parts[2]
	timestamp, err := time.Parse(time.RFC3339, parsedTimestamp)
	if err != nil {
		return nil, fmt.Errorf("Error parsing timestamp: %w", err)
	}

	return &unpauseParams{
		version: version,
		regID:   regID,
		ts:      timestamp,
	}, nil
}

// stillFresh checks a timestamp for "freshness", ensuring it falls within a
// predefined window to prevent replay attacks.
func (sfe *SelfServiceFrontEndImpl) stillFresh(timestamp time.Time) bool {
	return sfe.clk.Since(timestamp) > sfe.unpauseStaleWindow
}

// verifyHMAC takes a registrationID, timestamp, and a base64url encoded
// HMAC-SHA256 hash and attempts to match the given HMAC by computing a new HMAC
// with the SFE's UnpauseKey, regID, and timestamp. If a match is found, the
// Subscriber's account can be unpaused, otherwise an error is returned.
func (sfe *SelfServiceFrontEndImpl) verifyHMAC(regID string, ts time.Time, hash string) error {

	return nil
}
