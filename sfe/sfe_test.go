package sfe

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/ratelimits"
	bredis "github.com/letsencrypt/boulder/redis"
	"github.com/letsencrypt/boulder/revocation"
	"github.com/letsencrypt/boulder/test"

	capb "github.com/letsencrypt/boulder/ca/proto"
	corepb "github.com/letsencrypt/boulder/core/proto"
	rapb "github.com/letsencrypt/boulder/ra/proto"
)

var ctx = context.Background()

type MockRegistrationAuthority struct {
	lastRevocationReason revocation.Reason
}

func (ra *MockRegistrationAuthority) NewRegistration(ctx context.Context, in *corepb.Registration, _ ...grpc.CallOption) (*corepb.Registration, error) {
	in.Id = 1
	created := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	in.CreatedAt = timestamppb.New(created)
	return in, nil
}

func (ra *MockRegistrationAuthority) UpdateRegistration(ctx context.Context, in *rapb.UpdateRegistrationRequest, _ ...grpc.CallOption) (*corepb.Registration, error) {
	if !bytes.Equal(in.Base.Key, in.Update.Key) {
		in.Base.Key = in.Update.Key
	}
	return in.Base, nil
}

func (ra *MockRegistrationAuthority) PerformValidation(context.Context, *rapb.PerformValidationRequest, ...grpc.CallOption) (*corepb.Authorization, error) {
	return &corepb.Authorization{}, nil
}

func (ra *MockRegistrationAuthority) RevokeCertByApplicant(ctx context.Context, in *rapb.RevokeCertByApplicantRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	ra.lastRevocationReason = revocation.Reason(in.Code)
	return &emptypb.Empty{}, nil
}

func (ra *MockRegistrationAuthority) RevokeCertByKey(ctx context.Context, in *rapb.RevokeCertByKeyRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	ra.lastRevocationReason = revocation.Reason(ocsp.KeyCompromise)
	return &emptypb.Empty{}, nil
}

func (ra *MockRegistrationAuthority) GenerateOCSP(ctx context.Context, req *rapb.GenerateOCSPRequest, _ ...grpc.CallOption) (*capb.OCSPResponse, error) {
	return nil, nil
}

func (ra *MockRegistrationAuthority) AdministrativelyRevokeCertificate(context.Context, *rapb.AdministrativelyRevokeCertificateRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (ra *MockRegistrationAuthority) OnValidationUpdate(context.Context, core.Authorization, ...grpc.CallOption) error {
	return nil
}

func (ra *MockRegistrationAuthority) DeactivateAuthorization(context.Context, *corepb.Authorization, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (ra *MockRegistrationAuthority) DeactivateRegistration(context.Context, *corepb.Registration, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (ra *MockRegistrationAuthority) NewOrder(ctx context.Context, in *rapb.NewOrderRequest, _ ...grpc.CallOption) (*corepb.Order, error) {
	created := time.Date(2021, 1, 1, 1, 1, 1, 0, time.UTC)
	expires := time.Date(2021, 2, 1, 1, 1, 1, 0, time.UTC)

	return &corepb.Order{
		Id:               1,
		RegistrationID:   in.RegistrationID,
		Created:          timestamppb.New(created),
		Expires:          timestamppb.New(expires),
		Names:            in.Names,
		Status:           string(core.StatusPending),
		V2Authorizations: []int64{1},
	}, nil
}

func (ra *MockRegistrationAuthority) FinalizeOrder(ctx context.Context, in *rapb.FinalizeOrderRequest, _ ...grpc.CallOption) (*corepb.Order, error) {
	in.Order.Status = string(core.StatusProcessing)
	return in.Order, nil
}

func setupSFE(t *testing.T) (SelfServiceFrontEndImpl, clock.FakeClock) {
	features.Reset()

	fc := clock.NewFake()
	stats := metrics.NoopRegisterer

	mockSA := mocks.NewStorageAuthorityReadOnly(fc)

	log := blog.NewMock()

	// Setup rate limiting.
	rc := bredis.Config{
		Username: "unittest-rw",
		TLS: cmd.TLSConfig{
			CACertFile: "../test/certs/ipki/minica.pem",
			CertFile:   "../test/certs/ipki/localhost/cert.pem",
			KeyFile:    "../test/certs/ipki/localhost/key.pem",
		},
		Lookups: []cmd.ServiceDomain{
			{
				Service: "redisratelimits",
				Domain:  "service.consul",
			},
		},
		LookupDNSAuthority: "consul.service.consul",
	}
	rc.PasswordConfig = cmd.PasswordConfig{
		PasswordFile: "../test/secrets/ratelimits_redis_password",
	}
	ring, err := bredis.NewRingFromConfig(rc, stats, log)
	test.AssertNotError(t, err, "making redis ring client")
	source := ratelimits.NewRedisSource(ring.Ring, fc, stats)
	test.AssertNotNil(t, source, "source should not be nil")
	limiter, err := ratelimits.NewLimiter(fc, source, stats)
	test.AssertNotError(t, err, "making limiter")
	txnBuilder, err := ratelimits.NewTransactionBuilder("../test/config-next/wfe2-ratelimit-defaults.yml", "")
	test.AssertNotError(t, err, "making transaction composer")

	sfe, err := NewSelfServiceFrontEndImpl(
		stats,
		fc,
		blog.NewMock(),
		10*time.Second,
		&MockRegistrationAuthority{},
		mockSA,
		"pleaseLetMeBackIn",
		3*24*time.Hour,
		limiter,
		txnBuilder,
	)
	test.AssertNotError(t, err, "Unable to create WFE")

	return sfe, fc
}

func TestIndex(t *testing.T) {
	sfe, _ := setupSFE(t)
	responseWriter := httptest.NewRecorder()
	url, _ := url.Parse("/")
	sfe.Index(responseWriter, &http.Request{
		Method: "GET",
		URL:    url,
	})

	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertNotEquals(t, responseWriter.Body.String(), "404 page not found\n")

	/*
			test.Assert(t, strings.Contains(responseWriter.Body.String(), directoryPath),
				"directory path not found")
		test.AssertEquals(t, responseWriter.Header().Get("Cache-Control"), "public, max-age=0, no-cache")

		responseWriter.Body.Reset()
		responseWriter.Header().Del("Cache-Control")
		url, _ = url.Parse("/foo")
		wfe.Index(ctx, newRequestEvent(), responseWriter, &http.Request{
			URL: url,
		})
		test.AssertEquals(t, responseWriter.Body.String(), "404 page not found\n")
		test.AssertEquals(t, responseWriter.Header().Get("Cache-Control"), "")
	*/
}

func TestParseAndValidateUnpauseParams(t *testing.T) {
	sfe, _ := setupSFE(t)

	ts := time.Now().AddDate(0, 0, -1).Format(time.RFC3339)
	createdAt, err := time.Parse(time.RFC3339, ts)
	fmt.Printf("createdAt: %v\n", createdAt)
	test.AssertNotError(t, err, "Could not create timestamp")
	version := "v1"
	regID := int64(1)

	ogParams := &unpauseParams{
		version:   version,
		regID:     regID,
		timestamp: createdAt,
	}

	// The WFE generates this string and provides it to the Subscriber via a URL
	// parameter.
	unpauseRequest := base64.RawURLEncoding.EncodeToString([]byte(version + "." + fmt.Sprint(regID) + "." + createdAt.String()))

	parsedParams, err := sfe.parseAndValidateUnpauseParams(unpauseRequest)
	test.AssertNotError(t, err, "Could not parse and validate unpause params from input string")
	test.AssertNotNil(t, parsedParams, "unpauseParam was nil")

	test.AssertDeepEquals(t, ogParams, parsedParams)
}

func TestVerifyHMAC(t *testing.T) {
	sfe, _ := setupSFE(t)

	createdAt := time.Now().AddDate(0, 0, -1).Unix()
	version := "v1"
	regID := int64(1)

	// The SFE and WFE share an unpause key
	hash := hmac.New(sha256.New, []byte(sfe.unpauseKey))
	hash.Write([]byte(version + "." + fmt.Sprint(regID) + "." + fmt.Sprint(createdAt)))
	wfeHMAC := hash.Sum(nil)

	testCases := []struct {
		name        string
		params      *unpauseParams
		expectError bool
	}{
		{
			name:   "hmac matches",
			params: &unpauseParams{version: version, regID: regID, timestamp: createdAt},
		},
		{
			name:        "hmac doesnt match",
			params:      &unpauseParams{version: "v2", regID: regID, timestamp: createdAt},
			expectError: true,
		},
		{
			name:        "unpauseParams are nil",
			params:      nil,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ok := sfe.verifyHMAC(tc.params, wfeHMAC)
			if tc.expectError {
				test.Assert(t, !ok, "HMAC should not have matched, but did")
			} else {
				test.Assert(t, ok, "HMAC should have matched, but did not")
			}
		})
	}
}
