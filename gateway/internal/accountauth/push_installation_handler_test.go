package accountauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type pushAuthenticatorStub struct {
	session Session
	err     error
	calls   int
}

func (stub *pushAuthenticatorStub) AuthenticatePushInstallation(
	*http.Request) (Session, error) {
	stub.calls++
	return stub.session, stub.err
}

func pushHandlerFixture(t *testing.T) (*PushInstallationHandler, *Store,
	*pushAuthenticatorStub, string) {
	t.Helper()
	store, _, session, _ := pushInstallationFixture(t)
	protector, _ := pushProtectorFixture(t)
	authenticator := &pushAuthenticatorStub{session: session}
	handler, err := NewPushInstallationHandler(store, protector, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	return handler, store, authenticator, pushInstallationID(1)
}

func pushRequest(method, installationID, body string) *http.Request {
	request := httptest.NewRequest(method,
		"https://accounts.example"+PushInstallationPathPrefix+installationID,
		bytes.NewBufferString(body))
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("X-Xiaozhi-Companion-Push", PushInstallationContract)
	request.Header.Set("Authorization", "Bearer fresh-app-session")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

func TestPushInstallationHandlerSealsRegistersAndRemoves(t *testing.T) {
	handler, store, authenticator, installationID := pushHandlerFixture(t)
	raw := "fcm-token:abcdefghijklmnopqrstuvwxyz_0123456789"
	body := fmt.Sprintf(`{"version":1,"platform":"fcm","token":%q}`, raw)
	request := pushRequest(http.MethodPut, installationID, body)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 ||
		authenticator.calls != 1 {
		t.Fatalf("register status=%d body=%q calls=%d", response.Code,
			response.Body.String(), authenticator.calls)
	}
	active, err := store.ActivePushInstallations(context.Background(),
		authenticator.session.Principal)
	if err != nil || len(active) != 1 ||
		bytes.Contains(active[0].Token.Ciphertext, []byte(raw)) {
		t.Fatalf("protected installation: %#v %v", active, err)
	}

	request = pushRequest(http.MethodDelete, installationID, "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("delete status=%d body=%q", response.Code, response.Body.String())
	}
	active, _ = store.ActivePushInstallations(context.Background(),
		authenticator.session.Principal)
	if len(active) != 0 {
		t.Fatalf("deleted installation active: %#v", active)
	}
}

func TestPushInstallationHandlerRejectsBeforeStorage(t *testing.T) {
	handler, store, authenticator, installationID := pushHandlerFixture(t)
	raw := "fcm-token:abcdefghijklmnopqrstuvwxyz_0123456789"
	canonical := fmt.Sprintf(`{"version":1,"platform":"fcm","token":%q}`, raw)
	tests := []struct {
		name   string
		mutate func(*http.Request)
		body   string
	}{
		{"noncanonical", func(*http.Request) {}, canonical + "\n"},
		{"unknown-field", func(*http.Request) {},
			fmt.Sprintf(`{"version":1,"platform":"fcm","token":%q,"device_id":"x"}`, raw)},
		{"no-tls", func(request *http.Request) { request.TLS = nil }, canonical},
		{"query", func(request *http.Request) { request.URL.RawQuery = "x=1" }, canonical},
		{"duplicate-auth", func(request *http.Request) {
			request.Header.Add("Authorization", "Bearer second")
		}, canonical},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			before := authenticator.calls
			request := pushRequest(http.MethodPut, installationID, testCase.body)
			testCase.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || response.Body.Len() != 0 {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			if testCase.name != "noncanonical" && testCase.name != "unknown-field" &&
				authenticator.calls != before {
				t.Fatal("transport-invalid request reached authenticator")
			}
		})
	}
	active, err := store.ActivePushInstallations(context.Background(),
		authenticator.session.Principal)
	if err != nil || len(active) != 0 {
		t.Fatalf("rejected request changed storage: %#v %v", active, err)
	}
}

func TestPushInstallationHandlerNeverMountsPrivateReader(t *testing.T) {
	handler, _, authenticator, installationID := pushHandlerFixture(t)
	authenticator.err = ErrAppSessionUnauthorized
	raw := "fcm-token:abcdefghijklmnopqrstuvwxyz_0123456789"
	body := fmt.Sprintf(`{"version":1,"platform":"fcm","token":%q}`, raw)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, pushRequest(http.MethodPut, installationID, body))
	if response.Code != http.StatusUnauthorized || response.Body.Len() != 0 {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}
