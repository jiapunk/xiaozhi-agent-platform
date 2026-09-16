package factorytime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type probeDatabase struct{ err error }

func (database probeDatabase) VerifySchema() error { return database.err }

type probeSigner struct{ err error }

func (signer probeSigner) Ready(context.Context) error { return signer.err }

func TestFactoryTimeProbeSeparatesLivenessAndReadiness(t *testing.T) {
	handler, err := NewProbeHandler(probeDatabase{}, probeSigner{})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response,
			httptest.NewRequest(http.MethodGet, "http://probe"+path, nil))
		if response.Code != http.StatusNoContent || response.Body.Len() != 0 ||
			response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s code=%d headers=%v body=%q", path, response.Code,
				response.Header(), response.Body.String())
		}
	}
}

func TestFactoryTimeReadinessFailsClosedForEitherDependency(t *testing.T) {
	for _, fixture := range []struct {
		name     string
		database error
		signer   error
	}{
		{"database", ErrUnavailable, nil},
		{"signer", nil, ErrUnavailable},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			handler, _ := NewProbeHandler(probeDatabase{fixture.database},
				probeSigner{fixture.signer})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response,
				httptest.NewRequest(http.MethodGet, "http://probe/readyz", nil))
			if response.Code != http.StatusServiceUnavailable ||
				response.Header().Get("Retry-After") != "1" ||
				response.Body.Len() != 0 {
				t.Fatalf("code=%d headers=%v body=%q", response.Code,
					response.Header(), response.Body.String())
			}
		})
	}
	handler, _ := NewProbeHandler(probeDatabase{}, probeSigner{})
	request := httptest.NewRequest(http.MethodPost, "http://probe/readyz", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unsafe probe request code=%d", response.Code)
	}
}

func TestFactoryTimeProbeRejectsMissingDependencies(t *testing.T) {
	if _, err := NewProbeHandler(nil, probeSigner{}); err == nil {
		t.Fatal("nil database accepted")
	}
	if _, err := NewProbeHandler(probeDatabase{}, nil); err == nil {
		t.Fatal("nil signer accepted")
	}
}
