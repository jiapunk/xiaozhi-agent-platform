package accountauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type probeVerifier struct {
	err error
}

func (verifier probeVerifier) VerifySchema() error {
	return verifier.err
}

func TestProbeHandlerSeparatesHealthAndReadiness(t *testing.T) {
	handler, err := NewProbeHandler(probeVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNoContent || response.Body.Len() != 0 ||
			response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s returned %d headers=%v body=%q", path,
				response.Code, response.Header(), response.Body.String())
		}
	}

	unavailable, err := NewProbeHandler(probeVerifier{err: ErrUnavailable})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	unavailable.ServeHTTP(response,
		httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusServiceUnavailable ||
		response.Header().Get("Retry-After") != "1" || response.Body.Len() != 0 {
		t.Fatalf("unavailable readiness returned %d headers=%v body=%q",
			response.Code, response.Header(), response.Body.String())
	}
}

func TestProbeHandlerExposesNoOtherSurface(t *testing.T) {
	if _, err := NewProbeHandler(nil); err == nil {
		t.Fatal("nil schema verifier accepted")
	}
	handler, err := NewProbeHandler(probeVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/healthz", nil),
		httptest.NewRequest(http.MethodGet, "/readyz?detail=1", nil),
		httptest.NewRequest(http.MethodGet, "/metrics", nil),
		httptest.NewRequest(http.MethodGet, "/v1/companion-tokens/introspect", nil),
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound || response.Body.Len() != 0 {
			t.Fatalf("%s %s returned %d body=%q", request.Method,
				request.URL.String(), response.Code, response.Body.String())
		}
	}
}
