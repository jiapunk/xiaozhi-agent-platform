package accountauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

func activeHandlerFixture(t *testing.T) (*Store, *Service,
	*IntrospectionHandler, Session, IssuedToken) {
	t.Helper()
	store, service, principal := accountFixture(t)
	session, err := service.BeginAuthenticatedSession(
		context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := service.Issue(context.Background(), session,
		PurposeActionConsent, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewIntrospectionHandler(store)
	if err != nil {
		t.Fatal(err)
	}
	return store, service, handler, session, issued
}

func canonicalRequest(t *testing.T, claims auth.Claims) *http.Request {
	t.Helper()
	body, err := json.Marshal(auth.CompanionIntrospectionRequest{
		Version: 1, TokenID: claims.TokenID, Subject: claims.Subject,
		TenantID: claims.TenantID, Action: claims.Action,
		DeviceID: claims.DeviceID, IssuedAt: claims.IssuedAt,
		ExpiresAt: claims.Expires,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost,
		"https://accounts.example"+auth.CompanionIntrospectionPath,
		bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("X-Xiaozhi-Companion-Authorization",
		auth.CompanionAuthorizationContract)
	certificate := &x509.Certificate{}
	request.TLS = &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	}
	return request
}

func TestIntrospectionHandlerReturnsCanonicalActiveResponse(t *testing.T) {
	_, _, handler, _, issued := activeHandlerFixture(t)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, canonicalRequest(t, issued.Claims))
	if response.Code != http.StatusOK ||
		response.Header().Get("Content-Type") != "application/json" ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Xiaozhi-Companion-Authorization") !=
			auth.CompanionAuthorizationContract {
		t.Fatalf("active response: code=%d headers=%v body=%s",
			response.Code, response.Header(), response.Body.String())
	}
	expected, err := json.Marshal(auth.CompanionIntrospectionResponse{
		Version: 1, Status: "active", TokenID: issued.Claims.TokenID,
		Subject: issued.Claims.Subject, TenantID: issued.Claims.TenantID,
		Action: issued.Claims.Action, DeviceID: issued.Claims.DeviceID,
		AccountRevision: 1, ValidUntil: issued.Claims.Expires,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response.Body.Bytes(), expected) {
		t.Fatalf("non-canonical response:\n got %s\nwant %s",
			response.Body.Bytes(), expected)
	}
}

func TestIntrospectionHandlerReturnsExactNoBodyInactive(t *testing.T) {
	_, service, handler, session, issued := activeHandlerFixture(t)
	if _, err := service.Logout(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, canonicalRequest(t, issued.Claims))
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 ||
		response.Header().Get("Content-Type") != "" {
		t.Fatalf("inactive response: code=%d headers=%v body=%q",
			response.Code, response.Header(), response.Body.String())
	}
}

func TestIntrospectionHandlerRejectsNonCanonicalOrUntrustedRequests(t *testing.T) {
	_, _, handler, _, issued := activeHandlerFixture(t)
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "no verified TLS", mutate: func(request *http.Request) {
			request.TLS = nil
		}},
		{name: "TLS without client", mutate: func(request *http.Request) {
			request.TLS.PeerCertificates = nil
		}},
		{name: "query", mutate: func(request *http.Request) {
			request.URL.RawQuery = "debug=1"
		}},
		{name: "wrong contract", mutate: func(request *http.Request) {
			request.Header.Set("X-Xiaozhi-Companion-Authorization", "other")
		}},
		{name: "duplicate header", mutate: func(request *http.Request) {
			request.Header.Add("Accept", "application/json")
		}},
		{name: "transfer encoding", mutate: func(request *http.Request) {
			request.TransferEncoding = []string{"chunked"}
		}},
		{name: "wrong length", mutate: func(request *http.Request) {
			request.ContentLength++
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			request := canonicalRequest(t, issued.Claims)
			testCase.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || response.Body.Len() != 0 {
				t.Fatalf("code=%d body=%q", response.Code,
					response.Body.String())
			}
		})
	}

	request := canonicalRequest(t, issued.Claims)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	nonCanonical := append([]byte{' ', '\n'}, body...)
	request.Body = io.NopCloser(bytes.NewReader(nonCanonical))
	request.ContentLength = int64(len(nonCanonical))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("non-canonical JSON code=%d", response.Code)
	}
}

type unavailableLedger struct {
	Ledger
}

func (unavailableLedger) Introspect(context.Context,
	TokenBinding) (Authorization, bool, error) {
	return Authorization{}, false, ErrUnavailable
}

func TestIntrospectionHandlerFailsClosedWhenLedgerUnavailable(t *testing.T) {
	store, _, _, _, issued := activeHandlerFixture(t)
	handler, err := NewIntrospectionHandler(unavailableLedger{Ledger: store})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, canonicalRequest(t, issued.Claims))
	if response.Code != http.StatusServiceUnavailable ||
		response.Header().Get("Retry-After") != "1" || response.Body.Len() != 0 {
		t.Fatalf("unavailable response: code=%d headers=%v body=%q",
			response.Code, response.Header(), response.Body.String())
	}
}

type handlerRoundTripper struct {
	handler http.Handler
}

func (transport handlerRoundTripper) RoundTrip(
	request *http.Request) (*http.Response, error) {
	certificate := &x509.Certificate{}
	request.TLS = &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	}
	response := httptest.NewRecorder()
	transport.handler.ServeHTTP(response, request)
	result := response.Result()
	result.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	result.ContentLength = int64(response.Body.Len())
	return result, nil
}

func TestControlPlaneIntrospectorEndToEndWithAccountLedger(t *testing.T) {
	_, service, handler, session, issued := activeHandlerFixture(t)
	client := &http.Client{Transport: handlerRoundTripper{handler: handler},
		Timeout: time.Second}
	introspector, err := auth.NewCompanionTokenIntrospector(
		"https://accounts.example"+auth.CompanionIntrospectionPath, client)
	if err != nil {
		t.Fatal(err)
	}
	if err := introspector.Authorize(context.Background(), issued.Claims,
		time.Now().UTC()); err != nil {
		t.Fatalf("active end-to-end authorization: %v", err)
	}
	if _, err := service.Logout(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	if err := introspector.Authorize(context.Background(), issued.Claims,
		time.Now().UTC()); !errors.Is(err, auth.ErrCompanionInactive) {
		t.Fatalf("logged-out end-to-end authorization: %v", err)
	}
}
