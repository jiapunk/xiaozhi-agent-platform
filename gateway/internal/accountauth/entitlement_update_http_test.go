package accountauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type entitlementUpdateLedgerFunc func(context.Context,
	ServiceEntitlementUpdate) (ServiceEntitlement, bool, error)

func (function entitlementUpdateLedgerFunc) ApplyServiceEntitlement(
	ctx context.Context, update ServiceEntitlementUpdate) (
	ServiceEntitlement, bool, error) {
	return function(ctx, update)
}

func (entitlementUpdateLedgerFunc) AuthorizeService(context.Context,
	Principal, ProductService) (ServiceEntitlementGrant, bool, error) {
	return ServiceEntitlementGrant{}, false, nil
}

func signedEntitlementUpdateRequest(t *testing.T,
	input serviceEntitlementUpdateRequest, privateKey ed25519.PrivateKey) *http.Request {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost,
		ServiceEntitlementUpdatePath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set(EntitlementUpdateContractHeader,
		ServiceEntitlementUpdateContract)
	request.Header.Set(EntitlementUpdateKeyIDHeader, "billing-adapter-1")
	request.Header.Set(EntitlementUpdateSignatureHeader,
		base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey,
			serviceEntitlementUpdateSigningMessage(body))))
	certificate := &x509.Certificate{}
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}}}
	return request
}

func validEntitlementUpdateRequest(now time.Time) serviceEntitlementUpdateRequest {
	return serviceEntitlementUpdateRequest{
		Version: 1, SourceEventID: "billing-event-1",
		TenantID: "tenant-1", Subject: "owner-1",
		PreviousRevision: 0, Revision: 1, PlanID: "agent-pro",
		State: EntitlementActive, VoiceEnabled: true, AgentEnabled: true,
		AccessUntil:            now.Add(30 * 24 * time.Hour).Unix(),
		AuthorizedAt:           now.Unix(),
		AuthorizationExpiresAt: now.Add(5 * time.Minute).Unix(),
	}
}

func TestServiceEntitlementUpdateHandlerAppliesAndReplaysCanonicalEvent(
	t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	keyring, privateKey := entitlementUpdateKeyringFixture(t, now)
	store, err := NewStore(32)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	if _, err := store.BeginAuthenticatedSession(context.Background(),
		Principal{TenantID: "tenant-1", Subject: "owner-1"}); err != nil {
		t.Fatal(err)
	}
	handler, err := NewServiceEntitlementUpdateHandler(
		store, keyring, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	handler.now = func() time.Time { return now }
	input := validEntitlementUpdateRequest(now)
	for index, expected := range []string{"applied", "replayed"} {
		if index == 1 {
			// Transport authorization timestamps are deliberately excluded from
			// the business-event digest, so an adapter may safely re-sign a
			// timed-out delivery without creating a second commercial event.
			input.AuthorizedAt = now.Add(10 * time.Second).Unix()
			input.AuthorizationExpiresAt = now.Add(5 * time.Minute).Unix()
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response,
			signedEntitlementUpdateRequest(t, input, privateKey))
		if response.Code != http.StatusOK ||
			response.Header().Get("Cache-Control") != "no-store" ||
			response.Header().Get(EntitlementUpdateContractHeader) !=
				ServiceEntitlementUpdateContract {
			t.Fatalf("attempt=%d code=%d headers=%v body=%s", index,
				response.Code, response.Header(), response.Body.String())
		}
		var output serviceEntitlementUpdateResponse
		if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil ||
			output.Status != expected || output.SourceEventID !=
			input.SourceEventID || output.Revision != input.Revision {
			t.Fatalf("attempt=%d output=%#v err=%v", index, output, err)
		}
		canonical, err := json.Marshal(output)
		if err != nil || !bytes.Equal(canonical, response.Body.Bytes()) {
			t.Fatalf("attempt=%d response is not canonical", index)
		}
	}
}

func TestServiceEntitlementUpdateHandlerRejectsUntrustedOrExpiredRequest(
	t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	keyring, privateKey := entitlementUpdateKeyringFixture(t, now)
	ledger := entitlementUpdateLedgerFunc(func(context.Context,
		ServiceEntitlementUpdate) (ServiceEntitlement, bool, error) {
		t.Fatal("untrusted request reached the ledger")
		return ServiceEntitlement{}, false, nil
	})
	handler, err := NewServiceEntitlementUpdateHandler(
		ledger, keyring, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	handler.now = func() time.Time { return now }

	badSignature := signedEntitlementUpdateRequest(t,
		validEntitlementUpdateRequest(now), privateKey)
	badSignature.Header.Set(EntitlementUpdateSignatureHeader,
		base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, badSignature)
	if response.Code != http.StatusUnauthorized || response.Body.Len() != 0 {
		t.Fatalf("bad signature code=%d body=%q", response.Code,
			response.Body.String())
	}

	expired := validEntitlementUpdateRequest(now.Add(-10 * time.Minute))
	expired.AccessUntil = now.Add(time.Hour).Unix()
	response = httptest.NewRecorder()
	handler.ServeHTTP(response,
		signedEntitlementUpdateRequest(t, expired, privateKey))
	if response.Code != http.StatusUnauthorized || response.Body.Len() != 0 {
		t.Fatalf("expired code=%d body=%q", response.Code,
			response.Body.String())
	}

	unverifiedTLS := signedEntitlementUpdateRequest(t,
		validEntitlementUpdateRequest(now), privateKey)
	unverifiedTLS.TLS = nil
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, unverifiedTLS)
	if response.Code != http.StatusBadRequest || response.Body.Len() != 0 {
		t.Fatalf("unverified TLS code=%d body=%q", response.Code,
			response.Body.String())
	}
}

func TestServiceEntitlementUpdateHandlerUsesExactFailureSemantics(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	keyring, privateKey := entitlementUpdateKeyringFixture(t, now)
	for name, testCase := range map[string]struct {
		err      error
		expected int
	}{
		"account not found": {ErrNotFound, http.StatusNotFound},
		"stale revision":    {ErrStaleEntitlement, http.StatusConflict},
		"event conflict":    {ErrConflict, http.StatusConflict},
		"database unavailable": {ErrUnavailable,
			http.StatusServiceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			ledger := entitlementUpdateLedgerFunc(func(_ context.Context,
				update ServiceEntitlementUpdate) (ServiceEntitlement, bool, error) {
				return ServiceEntitlement{}, false, testCase.err
			})
			handler, err := NewServiceEntitlementUpdateHandler(
				ledger, keyring, 5*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			handler.now = func() time.Time { return now }
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, signedEntitlementUpdateRequest(t,
				validEntitlementUpdateRequest(now), privateKey))
			if response.Code != testCase.expected || response.Body.Len() != 0 {
				t.Fatalf("code=%d body=%q", response.Code,
					response.Body.String())
			}
			if errors.Is(testCase.err, ErrUnavailable) &&
				response.Header().Get("Retry-After") != "1" {
				t.Fatal("unavailable response omitted retry guidance")
			}
		})
	}
}

func TestServiceEntitlementUpdateHandlerRejectsProviderPayloadFields(
	t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	keyring, privateKey := entitlementUpdateKeyringFixture(t, now)
	ledger := entitlementUpdateLedgerFunc(func(context.Context,
		ServiceEntitlementUpdate) (ServiceEntitlement, bool, error) {
		t.Fatal("provider payload reached the ledger")
		return ServiceEntitlement{}, false, nil
	})
	handler, _ := NewServiceEntitlementUpdateHandler(
		ledger, keyring, 5*time.Minute)
	handler.now = func() time.Time { return now }
	input := validEntitlementUpdateRequest(now)
	body, _ := json.Marshal(input)
	body = append(body[:len(body)-1], []byte(`,"provider_customer_id":"cus_123"}`)...)
	request := signedEntitlementUpdateRequest(t, input, privateKey)
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	request.Header.Set(EntitlementUpdateSignatureHeader,
		base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey,
			serviceEntitlementUpdateSigningMessage(body))))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || response.Body.Len() != 0 {
		t.Fatalf("code=%d body=%q", response.Code, response.Body.String())
	}
}
