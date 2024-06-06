package sfe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jmhodges/clock"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/mocks"
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

// openssl rand -hex 32
const unpauseKey = "98aa2cf2d463f3a5cdf8073435cb73de494b03592cc695c775a969b329f42729"

func setupSFE(t *testing.T) (SelfServiceFrontEndImpl, clock.FakeClock) {
	features.Reset()

	fc := clock.NewFake()
	// Set to some non-zero time.
	fc.Set(time.Date(2020, 10, 10, 0, 0, 0, 0, time.UTC))

	stats := metrics.NoopRegisterer

	mockSA := mocks.NewStorageAuthorityReadOnly(fc)

	sfe, err := NewSelfServiceFrontEndImpl(
		stats,
		fc,
		blog.NewMock(),
		10*time.Second,
		&MockRegistrationAuthority{},
		mockSA,
		unpauseKey,
		24*time.Hour,
	)
	test.AssertNotError(t, err, "Unable to create WFE")

	return sfe, fc
}

func TestIndex(t *testing.T) {
	t.Parallel()
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

// makeJWTForAccount is a standin for a WFE method that returns an unpauseJWT or
// an error. The JWT contains a set of claims which should be validated by the
// caller.
func makeJWTForAccount(notBefore time.Time, issuedAt time.Time, expiresAt time.Time, key []byte, regID int64) (unpauseJWT, error) {
	if key == nil {
		return "", errors.New("unable to create JWT")
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", fmt.Errorf("making signer: %s", err)
	}

	wfeClaims := jwt.Claims{
		Issuer:    "WFE",
		Subject:   fmt.Sprint(regID),
		Audience:  jwt.Audience{"SFE Unpause"},
		NotBefore: jwt.NewNumericDate(notBefore),
		IssuedAt:  jwt.NewNumericDate(issuedAt),
		Expiry:    jwt.NewNumericDate(expiresAt),
	}

	signedJWT, err := jwt.Signed(signer).Claims(&wfeClaims).Serialize()
	if err != nil {
		return "", fmt.Errorf("signing JWT: %s", err)
	}

	return unpauseJWT(signedJWT), nil
}

func TestValidateJWT(t *testing.T) {
	t.Parallel()
	sfe, fc := setupSFE(t)

	originalClock := fc
	testCases := []struct {
		Name                   string
		IssuedAt               time.Time
		NotBefore              time.Time
		ExpiresAt              time.Time
		UnpauseKey             string
		RegID                  int64
		MakeJWTShouldError     bool
		ValidateJWTShouldError bool
	}{
		{
			Name:       "valid",
			IssuedAt:   fc.Now(),
			NotBefore:  fc.Now().Add(5 * time.Minute),
			ExpiresAt:  fc.Now().Add(30 * time.Minute),
			UnpauseKey: unpauseKey,
			RegID:      1,
		},
		{
			Name:                   "validating expired JWT fails",
			IssuedAt:               fc.Now(),
			NotBefore:              fc.Now().Add(5 * time.Minute),
			ExpiresAt:              fc.Now().Add(-30 * time.Minute),
			UnpauseKey:             unpauseKey,
			RegID:                  1,
			ValidateJWTShouldError: true,
		},
		{
			Name:                   "validating wrong account ID fails",
			IssuedAt:               fc.Now(),
			NotBefore:              fc.Now().Add(5 * time.Minute),
			ExpiresAt:              fc.Now().Add(30 * time.Minute),
			UnpauseKey:             unpauseKey,
			RegID:                  2,
			ValidateJWTShouldError: true,
		},
		{
			Name:                   "validating JWT with different key fails",
			IssuedAt:               fc.Now(),
			NotBefore:              fc.Now().Add(5 * time.Minute),
			ExpiresAt:              fc.Now().Add(30 * time.Minute),
			UnpauseKey:             "xxxxxxxxxxyyyyyyyyyyzzzzzzzzzz12",
			RegID:                  1,
			ValidateJWTShouldError: true,
		},
		{
			Name:                   "creating JWT with empty key fails",
			IssuedAt:               fc.Now(),
			NotBefore:              fc.Now().Add(5 * time.Minute),
			ExpiresAt:              fc.Now().Add(30 * time.Minute),
			UnpauseKey:             "",
			RegID:                  1,
			MakeJWTShouldError:     true,
			ValidateJWTShouldError: true,
		},
		{
			Name:                   "creating JWT with invalid key size fails",
			IssuedAt:               fc.Now(),
			NotBefore:              fc.Now().Add(5 * time.Minute),
			ExpiresAt:              fc.Now().Add(30 * time.Minute),
			UnpauseKey:             "xxxxxxxxxx",
			RegID:                  1,
			MakeJWTShouldError:     true,
			ValidateJWTShouldError: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			fc = originalClock
			newJWT, err := makeJWTForAccount(tc.NotBefore, tc.IssuedAt, tc.ExpiresAt, []byte(tc.UnpauseKey), int64(1))
			if tc.MakeJWTShouldError || string(newJWT) == "" {
				test.AssertError(t, err, "JWT was created but should not have been")
			} else {
				test.AssertNotError(t, err, "Should have been able to create a JWT")
			}

			fc.Add(10 * time.Minute)
			err = sfe.validateJWTforAccount(newJWT, tc.RegID)
			if tc.ValidateJWTShouldError || string(newJWT) == "" {
				test.AssertError(t, err, "Error expected, but received none")
			} else {
				test.AssertNotError(t, err, "Unable to validate JWT")
			}
		})
	}
}
