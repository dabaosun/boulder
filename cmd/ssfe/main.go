package notmain

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/ratelimits"
	bredis "github.com/letsencrypt/boulder/redis"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/ssfe"
)

type Config struct {
	SSFE struct {
		DebugAddr string `validate:"omitempty,hostname_port"`

		// ListenAddress is the address:port on which to listen for incoming
		// HTTP requests. Defaults to ":80".
		ListenAddress string `validate:"omitempty,hostname_port"`

		// TLSListenAddress is the address:port on which to listen for incoming
		// HTTPS requests. If none is provided the SSFE will not listen for HTTPS
		// requests.
		TLSListenAddress string `validate:"omitempty,hostname_port"`

		// Timeout is the per-request overall timeout. This should be slightly
		// lower than the upstream's timeout when making request to the SSFE.
		Timeout config.Duration `validate:"-"`

		// ShutdownStopTimeout is the duration that the SSFE will wait before
		// shutting down any listening servers.
		ShutdownStopTimeout config.Duration

		// AllowOrigins is for setting CORS on OPTIONS requests
		AllowOrigins []string

		ServerCertificatePath string `validate:"required_with=TLSListenAddress"`
		ServerKeyPath         string `validate:"required_with=TLSListenAddress"`

		TLS cmd.TLSConfig

		RAService *cmd.GRPCClientConfig
		SAService *cmd.GRPCClientConfig

		Features features.Config

		Limiter struct {
			// Redis contains the configuration necessary to connect to Redis
			// for rate limiting. This field is required to enable rate
			// limiting.
			Redis *bredis.Config `validate:"required_with=Defaults"`

			// Defaults is a path to a YAML file containing default rate limits.
			// See: ratelimits/README.md for details. This field is required to
			// enable rate limiting. If any individual rate limit is not set,
			// that limit will be disabled. Failed Authorizations limits passed
			// in this file must be identical to those in the RA.
			Defaults string `validate:"required_with=Redis"`

			// Overrides is a path to a YAML file containing overrides for the
			// default rate limits. See: ratelimits/README.md for details. If
			// this field is not set, all requesters will be subject to the
			// default rate limits. Overrides for the Failed Authorizations
			// overrides passed in this file must be identical to those in the
			// RA.
			Overrides string
		}
	}

	Syslog        cmd.SyslogConfig
	OpenTelemetry cmd.OpenTelemetryConfig

	// OpenTelemetryHTTPConfig configures tracing on incoming HTTP requests
	OpenTelemetryHTTPConfig cmd.OpenTelemetryHTTPConfig
}

type CacheConfig struct {
	Size int
	TTL  config.Duration
}

func setupSSFE(c Config, scope prometheus.Registerer, clk clock.Clock) (rapb.RegistrationAuthorityClient, sapb.StorageAuthorityReadOnlyClient) {
	tlsConfig, err := c.SSFE.TLS.Load(scope)
	cmd.FailOnError(err, "TLS config")

	raConn, err := bgrpc.ClientSetup(c.SSFE.RAService, tlsConfig, scope, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to RA")
	rac := rapb.NewRegistrationAuthorityClient(raConn)

	saConn, err := bgrpc.ClientSetup(c.SSFE.SAService, tlsConfig, scope, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sac := sapb.NewStorageAuthorityReadOnlyClient(saConn)

	return rac, sac
}

type errorWriter struct {
	blog.Logger
}

func (ew errorWriter) Write(p []byte) (n int, err error) {
	// log.Logger will append a newline to all messages before calling
	// Write. Our log checksum checker doesn't like newlines, because
	// syslog will strip them out so the calculated checksums will
	// differ. So that we don't hit this corner case for every line
	// logged from inside net/http.Server we strip the newline before
	// we get to the checksum generator.
	p = bytes.TrimRight(p, "\n")
	ew.Logger.Err(fmt.Sprintf("net/http.Server: %s", string(p)))
	return
}

func main() {
	listenAddr := flag.String("addr", "", "HTTP listen address override")
	tlsAddr := flag.String("tls-addr", "", "HTTPS listen address override")
	debugAddr := flag.String("debug-addr", "", "Debug server address override")
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c Config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	features.Set(c.SSFE.Features)

	if *listenAddr != "" {
		c.SSFE.ListenAddress = *listenAddr
	}
	if c.SSFE.ListenAddress == "" {
		cmd.Fail("HTTP listen address is not configured")
	}
	if *tlsAddr != "" {
		c.SSFE.TLSListenAddress = *tlsAddr
	}
	if *debugAddr != "" {
		c.SSFE.DebugAddr = *debugAddr
	}

	stats, logger, oTelShutdown := cmd.StatsAndLogging(c.Syslog, c.OpenTelemetry, c.SSFE.DebugAddr)
	logger.Info(cmd.VersionString())

	clk := cmd.Clock()

	rac, sac := setupSSFE(c, stats, clk)

	var limiter *ratelimits.Limiter
	var txnBuilder *ratelimits.TransactionBuilder
	var limiterRedis *bredis.Ring
	if c.SSFE.Limiter.Defaults != "" {
		// Setup rate limiting.
		limiterRedis, err = bredis.NewRingFromConfig(*c.SSFE.Limiter.Redis, stats, logger)
		cmd.FailOnError(err, "Failed to create Redis ring")

		source := ratelimits.NewRedisSource(limiterRedis.Ring, clk, stats)
		limiter, err = ratelimits.NewLimiter(clk, source, stats)
		cmd.FailOnError(err, "Failed to create rate limiter")
		txnBuilder, err = ratelimits.NewTransactionBuilder(c.SSFE.Limiter.Defaults, c.SSFE.Limiter.Overrides)
		cmd.FailOnError(err, "Failed to create rate limits transaction builder")
	}

	ssfei, err := ssfe.NewSelfServiceFrontEndImpl(
		stats,
		clk,
		logger,
		c.SSFE.Timeout.Duration,
		rac,
		sac,
		limiter,
		txnBuilder,
	)
	cmd.FailOnError(err, "Unable to create SSFE")
	ssfei.AllowOrigins = c.SSFE.AllowOrigins

	logger.Infof("Server running, listening on %s....", c.SSFE.ListenAddress)
	handler := ssfei.Handler(stats, c.OpenTelemetryHTTPConfig.Options()...)

	srv := http.Server{
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
		Addr:         c.SSFE.ListenAddress,
		ErrorLog:     log.New(errorWriter{logger}, "", 0),
		Handler:      handler,
	}

	go func() {
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			cmd.FailOnError(err, "Running HTTP server")
		}
	}()

	tlsSrv := http.Server{
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
		Addr:         c.SSFE.TLSListenAddress,
		ErrorLog:     log.New(errorWriter{logger}, "", 0),
		Handler:      handler,
	}
	if tlsSrv.Addr != "" {
		go func() {
			logger.Infof("TLS server listening on %s", tlsSrv.Addr)
			err := tlsSrv.ListenAndServeTLS(c.SSFE.ServerCertificatePath, c.SSFE.ServerKeyPath)
			if err != nil && err != http.ErrServerClosed {
				cmd.FailOnError(err, "Running TLS server")
			}
		}()
	}

	// When main is ready to exit (because it has received a shutdown signal),
	// gracefully shutdown the servers. Calling these shutdown functions causes
	// ListenAndServe() and ListenAndServeTLS() to immediately return, then waits
	// for any lingering connection-handling goroutines to finish their work.
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), c.SSFE.ShutdownStopTimeout.Duration)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = tlsSrv.Shutdown(ctx)
		limiterRedis.StopLookups()
		oTelShutdown(ctx)
	}()

	cmd.WaitForSignal()
}

func init() {
	cmd.RegisterCommand("ssfe", main, &cmd.ConfigValidator{Config: &Config{}})
}
