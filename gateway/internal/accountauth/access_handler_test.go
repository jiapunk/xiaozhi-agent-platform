package accountauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

type accessAuthenticatorFixture struct {
	session       Session
	err           error
	calls         int
	deviceID      string
	ownerRevision uint64
}

func (fixture *accessAuthenticatorFixture) AuthenticateActionConsentAccess(
	request *http.Request, deviceID string, ownerRevision uint64) (Session, error) {
	fixture.calls++
	fixture.deviceID = deviceID
	fixture.ownerRevision = ownerRevision
	if request.Header.Get("Authorization") != "Bearer product-login-session" {
		return Session{}, ErrAppSessionUnauthorized
	}
	return fixture.session, fixture.err
}

func accessRequest(t *testing.T, ownerRevision uint64) *http.Request {
	t.Helper()
	body, err := json.Marshal(actionConsentAccessRequest{
		Version: 1, DeviceID: "device-1", OwnerRevision: ownerRevision,
		Purpose: string(PurposeActionConsent),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost,
		"https://accounts.example"+ActionConsentAccessPath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("Authorization", "Bearer product-login-session")
	request.Header.Set("X-Xiaozhi-Companion-Access",
		ActionConsentAccessContract)
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	return request
}

func TestActionConsentAccessHandlerIssuesCanonicalDeviceBoundToken(t *testing.T) {
	store, service, principal := accountFixture(t)
	session, err := service.BeginAuthenticatedSession(context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	authenticator := &accessAuthenticatorFixture{session: session}
	handler, err := NewActionConsentAccessHandler(service, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, accessRequest(t, 42))
	if response.Code != http.StatusOK ||
		response.Header().Get("Content-Type") != "application/json" ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Xiaozhi-Companion-Access") !=
			ActionConsentAccessContract || authenticator.calls != 1 ||
		authenticator.deviceID != "device-1" || authenticator.ownerRevision != 42 {
		t.Fatalf("access response: code=%d headers=%v auth=%#v body=%s",
			response.Code, response.Header(), authenticator, response.Body.String())
	}
	var output actionConsentAccessResponse
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil ||
		output.Version != 1 || output.DeviceID != "device-1" ||
		output.OwnerRevision != 42 || output.AccessToken == "" {
		t.Fatalf("access response body: %#v %v", output, err)
	}
	canonical, err := json.Marshal(output)
	if err != nil || !bytes.Equal(canonical, response.Body.Bytes()) {
		t.Fatalf("non-canonical access response: %v", err)
	}
	seed := sha256.Sum256([]byte("account-authorization-test-key"))
	verifier, err := auth.NewCompanionJWTVerifier(
		map[string]ed25519.PublicKey{
			"account-key-1": ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey),
		},
		"https://accounts.example/product", 5*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifier.Verify(output.AccessToken)
	if err != nil || claims.Action != auth.CompanionConsentAction ||
		claims.DeviceID != "device-1" || claims.Expires != output.ExpiresAtUnix ||
		claims.Expires-claims.IssuedAt > 300 {
		t.Fatalf("issued claims: %#v %v", claims, err)
	}
	binding, _ := BindingFromClaims(claims)
	if _, active, err := store.Introspect(context.Background(), binding); err != nil || !active {
		t.Fatalf("issued token not durably active: active=%t err=%v", active, err)
	}
}

func TestActionConsentAccessHandlerRejectsNonCanonicalOrUnsafeRequest(t *testing.T) {
	_, service, principal := accountFixture(t)
	session, _ := service.BeginAuthenticatedSession(context.Background(), principal)
	authenticator := &accessAuthenticatorFixture{session: session}
	handler, _ := NewActionConsentAccessHandler(service, authenticator)
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "no TLS", mutate: func(request *http.Request) { request.TLS = nil }},
		{name: "query", mutate: func(request *http.Request) { request.URL.RawQuery = "x=1" }},
		{name: "duplicate authorization", mutate: func(request *http.Request) {
			request.Header.Add("Authorization", "Bearer second")
		}},
		{name: "wrong contract", mutate: func(request *http.Request) {
			request.Header.Set("X-Xiaozhi-Companion-Access", "other")
		}},
		{name: "transfer encoding", mutate: func(request *http.Request) {
			request.TransferEncoding = []string{"chunked"}
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			request := accessRequest(t, 42)
			testCase.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || response.Body.Len() != 0 {
				t.Fatalf("code=%d body=%q", response.Code, response.Body.String())
			}
		})
	}
	request := accessRequest(t, 42)
	body, _ := io.ReadAll(request.Body)
	body = append([]byte("\n"), body...)
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("non-canonical code=%d", response.Code)
	}
}

func TestActionConsentAccessHandlerSeparatesAuthorizationFailures(t *testing.T) {
	_, service, principal := accountFixture(t)
	session, _ := service.BeginAuthenticatedSession(context.Background(), principal)
	for _, testCase := range []struct {
		err  error
		code int
	}{
		{ErrAppSessionUnauthorized, http.StatusUnauthorized},
		{ErrAppOwnershipChanged, http.StatusConflict},
		{ErrAppSessionUnavailable, http.StatusServiceUnavailable},
	} {
		authenticator := &accessAuthenticatorFixture{session: session,
			err: testCase.err}
		handler, _ := NewActionConsentAccessHandler(service, authenticator)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, accessRequest(t, 42))
		if response.Code != testCase.code || response.Body.Len() != 0 {
			t.Fatalf("error=%v code=%d body=%q", testCase.err,
				response.Code, response.Body.String())
		}
	}
}

func TestActionConsentAccessHandlerRejectsStaleSessionAndLongTTL(t *testing.T) {
	_, service, principal := accountFixture(t)
	session, _ := service.BeginAuthenticatedSession(context.Background(), principal)
	if _, err := service.Logout(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	handler, _ := NewActionConsentAccessHandler(service,
		&accessAuthenticatorFixture{session: session})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, accessRequest(t, 42))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("stale session code=%d", response.Code)
	}

	store, _ := NewStore(16)
	seed := sha256.Sum256([]byte("long-action-token-key"))
	issuer, _ := auth.NewCompanionJWTIssuer(
		ed25519.NewKeyFromSeed(seed[:]), "account-key-1",
		"https://accounts.example/product", 6*time.Minute)
	longService, _ := NewService(issuer, store)
	longSession, _ := longService.BeginAuthenticatedSession(
		context.Background(), principal)
	issued, err := longService.Issue(context.Background(), longSession,
		PurposeActionConsent, "device-1")
	if !errors.Is(err, ErrInvalid) || issued != (IssuedToken{}) ||
		len(store.tokens) != 0 {
		t.Fatalf("long-lived token escaped: %#v err=%v tokens=%d",
			issued, err, len(store.tokens))
	}
}
