package sfe

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"text/template"
	"time"

	//jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/letsencrypt/boulder/core"

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
)

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

	// unpauseKey should contain 256 bits (32 bytes) of random data to be
	// suitable as an HMAC-SHA256 key (e.g. the output of `openssl rand -hex
	// 32`)
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
) (SelfServiceFrontEndImpl, error) {
	// The SFE will be validating JWTs produced by the WFE which uses the HS256
	// signing algorithm and must have at least as many bytes as the hash output
	// of that algorithm.
	if len(unpauseKey) < 32 {
		return SelfServiceFrontEndImpl{}, errors.New("unpauseKey invalid size, should be at least 32 hexadecimal characters")
	}

	sfe := SelfServiceFrontEndImpl{
		log:            logger,
		clk:            clk,
		requestTimeout: requestTimeout,
		ra:             rac,
		sa:             sac,
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
func renderTemplate(w http.ResponseWriter, tmpl *template.Template, dynamicData any) {
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

// unpauseJWT is generated by a WFE and is used to round-trip back to the WFE to
// unpause the requester's account.
type unpauseJWT string

func (sfe *SelfServiceFrontEndImpl) getHelper(response http.ResponseWriter, incomingJWT unpauseJWT) {
	if incomingJWT != "" {
		data := struct {
			UnpausePath string
			JWT         string
		}{
			UnpausePath: unpausePath,
			JWT:         string(incomingJWT),
		}

		// Serve the actual unpause page given to a Subscriber. Populates the
		// unpause form with the JWT from the URL. That JWT itself may be
		// invalid or expired, but that validation will be performed only after
		// submitting the form.
		renderTemplate(response, tmplUnpauseParams, data)
	} else {
		// We only want to accept requests containing the JWT param.
		renderTemplate(response, tmplUnpauseNoParams, nil)
	}
}

func (sfe *SelfServiceFrontEndImpl) postHelper(response http.ResponseWriter, incomingJWT unpauseJWT) {
	if incomingJWT != "" {
		data := struct {
			ShouldUnpause bool
		}{
			ShouldUnpause: false,
		}

		// After clicking unpause, serve a page indicating if the unpause
		// succeeded or failed.
		err := sfe.validateJWTforAccount(incomingJWT)
		if err == nil {
			data.ShouldUnpause = true
		}

		renderTemplate(response, tmplUnpausePost, data)
	} else {
		renderTemplate(response, tmplUnpauseNoParams, nil)
	}
}

// Unpause allows a requester to unpause their account via a form present on the
// page.
func (sfe *SelfServiceFrontEndImpl) Unpause(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodHead:
		return
	case http.MethodGet:
		sfe.getHelper(response, unpauseJWT(request.URL.Query().Get("jwt")))
	case http.MethodPost:
		request.ParseForm()
		sfe.postHelper(response, unpauseJWT(request.PostForm.Get("jwt")))
	default:
		response.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, POST")
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

// validateJWT uses a shared symmetric between the SFE and WFE to validate the
// signature and contents of an unpauseJWT and verify that the its claims match
// a set of expected claims. Passing validations allows the Subscriber to
// unpause their account, otherwise an error is returned.
func (sfe *SelfServiceFrontEndImpl) validateJWTforAccount(incomingJWT unpauseJWT) error {
	token, err := jwt.ParseSigned(string(incomingJWT), []jose.SignatureAlgorithm{jose.HS256})
	if err != nil {
		return fmt.Errorf("parsing JWT: %s", err)
	}

	incomingClaims := jwt.Claims{}
	err = token.Claims([]byte(sfe.unpauseKey), &incomingClaims)
	if err != nil {
		return err
	}

	expectedClaims := jwt.Expected{
		Issuer:      "WFE",
		AnyAudience: jwt.Audience{"SFE Unpause"},
		// Time is passed into the jwt package for tests to manipulate time.
		Time: sfe.clk.Now(),
	}

	err = incomingClaims.Validate(expectedClaims)
	if err != nil {
		return err
	}

	if len(incomingClaims.Subject) == 0 {
		return errors.New("Registration ID required for account unpausing")
	}

	return nil
}
