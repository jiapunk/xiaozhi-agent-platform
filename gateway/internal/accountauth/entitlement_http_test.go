package accountauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

type entitlementAuthorizerFunc func(context.Context, Principal,
	ProductService) (ServiceEntitlementGrant, bool, error)

func (function entitlementAuthorizerFunc) AuthorizeService(ctx context.Context,
	principal Principal, service ProductService) (
	ServiceEntitlementGrant, bool, error) {
	return function(ctx, principal, service)
}

func entitlementHTTPRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost,
		ServiceEntitlementAuthorizationPath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("X-Xiaozhi-Service-Entitlement",
		ServiceEntitlementContract)
	certificate := &x509.Certificate{}
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}}}
	return request
}

func TestServiceEntitlementAuthorizationHandlerAllowsAndDeniesContentFree(t *testing.T) {
	validUntil := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	handler, err := NewServiceEntitlementAuthorizationHandler(
		entitlementAuthorizerFunc(func(_ context.Context, principal Principal,
			service ProductService) (ServiceEntitlementGrant, bool, error) {
			if principal != (Principal{TenantID: "tenant-1", Subject: "owner-1"}) ||
				service != ProductServiceVoice {
				return ServiceEntitlementGrant{}, false, nil
			}
			return ServiceEntitlementGrant{Revision: 7,
				State: EntitlementGrace, ValidUntil: validUntil}, true, nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(serviceEntitlementAuthorizationRequest{
		Version: 1, TenantID: "tenant-1", Subject: "owner-1",
		Service: ProductServiceVoice,
	})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, entitlementHTTPRequest(t, body))
	if recorder.Code != http.StatusOK ||
		recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response serviceEntitlementAuthorizationResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil ||
		response.Revision != 7 || response.Status != EntitlementGrace ||
		response.ValidUntil != validUntil.Unix() {
		t.Fatalf("response=%#v err=%v", response, err)
	}

	deniedBody, _ := json.Marshal(serviceEntitlementAuthorizationRequest{
		Version: 1, TenantID: "tenant-1", Subject: "owner-1",
		Service: ProductServiceAgent,
	})
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, entitlementHTTPRequest(t, deniedBody))
	if recorder.Code != http.StatusNoContent || recorder.Body.Len() != 0 ||
		recorder.Header().Get("Content-Type") != "" {
		t.Fatalf("denial status=%d body=%q", recorder.Code,
			recorder.Body.String())
	}
}

func TestServiceEntitlementAuthorizationHandlerFailsClosed(t *testing.T) {
	handler, _ := NewServiceEntitlementAuthorizationHandler(
		entitlementAuthorizerFunc(func(context.Context, Principal,
			ProductService) (ServiceEntitlementGrant, bool, error) {
			return ServiceEntitlementGrant{}, false, ErrUnavailable
		}))
	body := []byte(`{"version":1,"tenant_id":"tenant-1","subject":"owner-1","service":"voice"}`)
	request := entitlementHTTPRequest(t, body)
	request.TLS = nil
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unverified TLS status=%d", recorder.Code)
	}
	request = entitlementHTTPRequest(t, body)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable ||
		recorder.Header().Get("Retry-After") != "1" {
		t.Fatalf("unavailable status=%d", recorder.Code)
	}
}

func TestHTTPServiceEntitlementAuthorizerStrictRoundTrip(t *testing.T) {
	validUntil := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter,
		request *http.Request) {
		if request.URL.Path != ServiceEntitlementAuthorizationPath ||
			request.Header.Get("X-Xiaozhi-Service-Entitlement") !=
				ServiceEntitlementContract {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		response, _ := json.Marshal(serviceEntitlementAuthorizationResponse{
			Version: 1, Status: EntitlementActive,
			Revision: 3, ValidUntil: validUntil.Unix(),
		})
		setServiceEntitlementHeaders(writer.Header())
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Content-Length", strconv.Itoa(len(response)))
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(response)
	}))
	defer server.Close()
	authorizer, err := NewHTTPServiceEntitlementAuthorizer(
		server.URL+ServiceEntitlementAuthorizationPath, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	grant, allowed, err := authorizer.AuthorizeService(context.Background(),
		Principal{TenantID: "tenant-1", Subject: "owner-1"},
		ProductServiceAgent)
	if err != nil || !allowed || grant.Revision != 3 ||
		grant.ValidUntil != validUntil {
		t.Fatalf("grant=%#v allowed=%t err=%v", grant, allowed, err)
	}
}

func TestHTTPServiceEntitlementAuthorizerRejectsInvalidURLs(t *testing.T) {
	for _, endpoint := range []string{
		"http://account.example" + ServiceEntitlementAuthorizationPath,
		"https://account.example/v1/other",
		"https://user@account.example" + ServiceEntitlementAuthorizationPath,
		"https://account.example" + ServiceEntitlementAuthorizationPath + "?x=1",
	} {
		if _, err := NewHTTPServiceEntitlementAuthorizer(endpoint,
			http.DefaultClient); err == nil {
			t.Fatalf("invalid endpoint accepted: %s", endpoint)
		}
	}
}
