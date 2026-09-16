package pushdelivery

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
	"strings"
	"testing"
	"time"
)

type bearerStub struct {
	token string
	err   error
}

func (stub bearerStub) BearerToken(context.Context) (string, error) {
	return stub.token, stub.err
}

func http2TestServer(t *testing.T,
	handler http.HandlerFunc) (*httptest.Server, *http.Client) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	client := trustedTestClient(server, false)
	return server, client
}

func trustedTestClient(server *httptest.Server,
	withClientCertificate bool) *http.Client {
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	tlsConfiguration := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	if withClientCertificate {
		tlsConfiguration.MinVersion = tls.VersionTLS13
		tlsConfiguration.Certificates = []tls.Certificate{{
			Certificate: [][]byte{{1}},
		}}
	}
	return &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		Proxy: nil, TLSClientConfig: tlsConfiguration, ForceAttemptHTTP2: true,
	}}
}

func TestAPNsProviderSendsFixedBackgroundEnvelopeOverHTTP2(t *testing.T) {
	deviceToken := strings.Repeat("ab", 32)
	server, client := http2TestServer(t, func(writer http.ResponseWriter,
		request *http.Request) {
		if request.ProtoMajor != 2 || request.Method != http.MethodPost ||
			request.URL.Path != "/3/device/"+deviceToken ||
			request.Header.Get("Authorization") != "bearer apns-provider-token" ||
			request.Header.Get("apns-topic") != "com.example.product" ||
			request.Header.Get("apns-push-type") != "background" ||
			request.Header.Get("apns-priority") != "5" ||
			request.Header.Get("apns-expiration") != "0" {
			t.Errorf("unexpected APNs request: %#v", request)
		}
		body, _ := io.ReadAll(request.Body)
		if string(body) != apnsWakeBody || bytes.Contains(body, []byte(deviceToken)) {
			t.Errorf("unexpected APNs body %q", body)
		}
		writer.WriteHeader(http.StatusOK)
	})
	provider, err := NewAPNsProvider(client,
		bearerStub{token: "apns-provider-token"}, "com.example.product",
		APNsProduction)
	if err != nil {
		t.Fatal(err)
	}
	provider.endpoint = server.URL + "/3/device/"
	result, err := provider.Send(context.Background(), deviceToken)
	if err != nil || result != DeliveryAccepted {
		t.Fatalf("result=%d err=%v", result, err)
	}
}

func TestAPNsProviderClassifiesPermanentAndTemporaryFailures(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   DeliveryResult
	}{
		{"unregistered", http.StatusGone, `{"reason":"Unregistered","timestamp":1}`,
			DeliveryInvalidInstallation},
		{"bad-token", http.StatusBadRequest, `{"reason":"BadDeviceToken"}`,
			DeliveryInvalidInstallation},
		{"rate", http.StatusTooManyRequests, `{"reason":"TooManyRequests"}`,
			DeliveryRetry},
		{"auth", http.StatusForbidden, `{"reason":"InvalidProviderToken"}`,
			DeliveryRetry},
		{"unavailable", http.StatusServiceUnavailable, `{"reason":"Shutdown"}`,
			DeliveryRetry},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			server, client := http2TestServer(t, func(writer http.ResponseWriter,
				_ *http.Request) {
				writer.WriteHeader(testCase.status)
				_, _ = writer.Write([]byte(testCase.body))
			})
			provider, _ := NewAPNsProvider(client,
				bearerStub{token: "apns-provider-token"},
				"com.example.product", APNsProduction)
			provider.endpoint = server.URL + "/3/device/"
			result, err := provider.Send(context.Background(), strings.Repeat("ab", 32))
			if result != testCase.want {
				t.Fatalf("result=%d err=%v", result, err)
			}
			if testCase.want == DeliveryInvalidInstallation && err != nil {
				t.Fatalf("permanent result error=%v", err)
			}
			if testCase.name == "auth" &&
				(!errors.Is(err, ErrCredentialRejected) ||
					!errors.Is(err, ErrUnavailable)) {
				t.Fatalf("APNs credential rejection was not typed: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), testCase.body) {
				t.Fatal("provider response body escaped classification boundary")
			}
		})
	}
}

func TestFCMProviderSendsFixedDataEnvelope(t *testing.T) {
	registrationToken := "fcm-token:abcdefghijklmnopqrstuvwxyz_0123456789"
	server, client := http2TestServer(t, func(writer http.ResponseWriter,
		request *http.Request) {
		if request.Method != http.MethodPost ||
			request.URL.Path != "/v1/projects/product-123/messages:send" ||
			request.Header.Get("Authorization") != "Bearer fcm-oauth-access-token" ||
			request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected FCM request: %#v", request)
		}
		body, _ := io.ReadAll(request.Body)
		var envelope struct {
			Message struct {
				Token   string            `json:"token"`
				Data    map[string]string `json:"data"`
				Android struct {
					Priority string `json:"priority"`
					TTL      string `json:"ttl"`
				} `json:"android"`
			} `json:"message"`
		}
		if json.Unmarshal(body, &envelope) != nil ||
			envelope.Message.Token != registrationToken ||
			envelope.Message.Data["version"] != "1" ||
			envelope.Message.Data["kind"] != "action-consent-wake" ||
			len(envelope.Message.Data) != 2 ||
			envelope.Message.Android.Priority != "normal" ||
			envelope.Message.Android.TTL != "0s" {
			t.Errorf("unexpected FCM body %q", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"name":"projects/product-123/messages/1"}`))
	})
	provider, err := NewFCMProvider(client,
		bearerStub{token: "fcm-oauth-access-token"}, "product-123")
	if err != nil {
		t.Fatal(err)
	}
	provider.endpoint = server.URL + "/v1/projects/product-123/messages:send"
	result, err := provider.Send(context.Background(), registrationToken)
	if err != nil || result != DeliveryAccepted {
		t.Fatalf("result=%d err=%v", result, err)
	}
}

func TestFCMProviderRequiresTypedTokenErrorBeforeInvalidation(t *testing.T) {
	typed := `{"error":{"code":404,"status":"NOT_FOUND","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}`
	generic := `{"error":{"code":404,"status":"NOT_FOUND","message":"project missing"}}`
	for _, testCase := range []struct {
		name string
		body string
		want DeliveryResult
	}{
		{"typed-unregistered", typed, DeliveryInvalidInstallation},
		{"generic-not-found", generic, DeliveryRetry},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server, client := http2TestServer(t, func(writer http.ResponseWriter,
				_ *http.Request) {
				writer.WriteHeader(http.StatusNotFound)
				_, _ = writer.Write([]byte(testCase.body))
			})
			provider, _ := NewFCMProvider(client,
				bearerStub{token: "fcm-oauth-access-token"}, "product-123")
			provider.endpoint = server.URL
			result, err := provider.Send(context.Background(),
				"fcm-token:abcdefghijklmnopqrstuvwxyz_0123456789")
			if result != testCase.want {
				t.Fatalf("result=%d err=%v", result, err)
			}
			if testCase.want == DeliveryInvalidInstallation && err != nil {
				t.Fatalf("invalid result error=%v", err)
			}
		})
	}
}

func TestProvidersFailClosedOnCredentialErrors(t *testing.T) {
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{
		Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
	}}
	apns, _ := NewAPNsProvider(client, bearerStub{err: errors.New("KMS down")},
		"com.example.product", APNsProduction)
	if result, err := apns.Send(context.Background(), strings.Repeat("ab", 32)); result != DeliveryRetry || !errors.Is(err, ErrUnavailable) ||
		strings.Contains(err.Error(), "KMS down") {
		t.Fatalf("APNs credential result=%d err=%v", result, err)
	}
	fcm, _ := NewFCMProvider(client, bearerStub{token: "short"}, "product-123")
	if result, err := fcm.Send(context.Background(),
		"fcm-token:abcdefghijklmnopqrstuvwxyz_0123456789"); result != DeliveryRetry || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("FCM credential result=%d err=%v", result, err)
	}
}
