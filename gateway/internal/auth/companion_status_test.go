package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type companionRoundTripFunc func(*http.Request) (*http.Response, error)

func (function companionRoundTripFunc) RoundTrip(
	request *http.Request) (*http.Response, error) {
	return function(request)
}

func companionStatusClaims(now time.Time) Claims {
	return Claims{
		DeviceID: "device-1", Subject: "user-1", TenantID: "tenant-1",
		Action: CompanionConsentAction, TokenID: "token-1",
		IssuedAt: now.Add(-time.Minute).Unix(),
		Expires:  now.Add(4 * time.Minute).Unix(),
	}
}

func companionStatusHTTPResponse(status int, body []byte) *http.Response {
	header := make(http.Header)
	header.Set("Cache-Control", "no-store")
	header.Set("X-Xiaozhi-Companion-Authorization",
		CompanionAuthorizationContract)
	if status == http.StatusOK {
		header.Set("Content-Type", "application/json")
	}
	return &http.Response{
		StatusCode: status, Header: header,
		Body:          io.NopCloser(strings.NewReader(string(body))),
		ContentLength: int64(len(body)),
		TLS:           &tls.ConnectionState{Version: tls.VersionTLS13},
	}
}

func TestCompanionIntrospectionBindsExactTokenAndUsesNoRawBearer(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	claims := companionStatusClaims(now)
	output := companionIntrospectionResponse{
		Version: 1, Status: "active", TokenID: claims.TokenID,
		Subject: claims.Subject, TenantID: claims.TenantID,
		Action: claims.Action, DeviceID: claims.DeviceID,
		AccountRevision: 7, ValidUntil: claims.Expires,
	}
	body, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	client := &http.Client{Transport: companionRoundTripFunc(
		func(request *http.Request) (*http.Response, error) {
			called++
			if request.Method != http.MethodPost || request.URL.String() !=
				"https://accounts.example/v1/companion-tokens/introspect" ||
				request.Header.Get("Authorization") != "" ||
				request.Header.Get("Cache-Control") != "no-store" ||
				request.Header.Get("Content-Type") != "application/json" ||
				request.Header.Get("Accept") != "application/json" ||
				request.Header.Get("X-Xiaozhi-Companion-Authorization") !=
					CompanionAuthorizationContract {
				t.Fatalf("unexpected introspection request: %#v", request)
			}
			requestBody, readErr := io.ReadAll(request.Body)
			if readErr != nil {
				t.Fatal(readErr)
			}
			expected, marshalErr := json.Marshal(companionIntrospectionRequest{
				Version: 1, TokenID: claims.TokenID, Subject: claims.Subject,
				TenantID: claims.TenantID, Action: claims.Action,
				DeviceID: claims.DeviceID, IssuedAt: claims.IssuedAt,
				ExpiresAt: claims.Expires,
			})
			if marshalErr != nil || string(requestBody) != string(expected) {
				t.Fatalf("request body=%s expected=%s err=%v",
					requestBody, expected, marshalErr)
			}
			return companionStatusHTTPResponse(http.StatusOK, body), nil
		})}
	introspector, err := NewCompanionTokenIntrospector(
		"https://accounts.example/v1/companion-tokens/introspect", client)
	if err != nil {
		t.Fatal(err)
	}
	if err := introspector.Authorize(context.Background(), claims, now); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("introspection calls=%d", called)
	}
}

func TestCompanionIntrospectionRevocationAndOutageFailClosed(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	claims := companionStatusClaims(now)
	tests := []struct {
		name   string
		status int
		body   []byte
		want   error
	}{
		{name: "revoked", status: http.StatusNoContent,
			want: ErrCompanionInactive},
		{name: "service-unavailable", status: http.StatusServiceUnavailable,
			body: []byte("unavailable"), want: ErrCompanionUnavailable},
		{name: "malformed-active", status: http.StatusOK,
			body: []byte(`{"version":1}`), want: ErrCompanionUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: companionRoundTripFunc(
				func(*http.Request) (*http.Response, error) {
					return companionStatusHTTPResponse(test.status, test.body), nil
				})}
			introspector, err := NewCompanionTokenIntrospector(
				"https://accounts.example/v1/companion-tokens/introspect", client)
			if err != nil {
				t.Fatal(err)
			}
			if err := introspector.Authorize(context.Background(), claims, now); !errors.Is(err, test.want) {
				t.Fatalf("Authorize=%v want=%v", err, test.want)
			}
		})
	}

	called := false
	client := &http.Client{Transport: companionRoundTripFunc(
		func(*http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("must not be called")
		})}
	introspector, err := NewCompanionTokenIntrospector(
		"https://accounts.example/v1/companion-tokens/introspect", client)
	if err != nil {
		t.Fatal(err)
	}
	expired := claims
	expired.Expires = now.Unix()
	if err := introspector.Authorize(context.Background(), expired, now); !errors.Is(err, ErrCompanionInactive) || called {
		t.Fatalf("expired token err=%v called=%v", err, called)
	}
}

func TestCompanionIntrospectionRejectsConfusedActiveResponses(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	claims := companionStatusClaims(now)
	base := companionIntrospectionResponse{
		Version: 1, Status: "active", TokenID: claims.TokenID,
		Subject: claims.Subject, TenantID: claims.TenantID,
		Action: claims.Action, DeviceID: claims.DeviceID,
		AccountRevision: 3, ValidUntil: claims.Expires,
	}
	mutations := []func(*companionIntrospectionResponse){
		func(value *companionIntrospectionResponse) { value.TokenID = "token-2" },
		func(value *companionIntrospectionResponse) { value.Subject = "user-2" },
		func(value *companionIntrospectionResponse) { value.TenantID = "tenant-2" },
		func(value *companionIntrospectionResponse) { value.DeviceID = "device-2" },
		func(value *companionIntrospectionResponse) { value.Action = CompanionReleaseAction },
		func(value *companionIntrospectionResponse) { value.AccountRevision = 0 },
		func(value *companionIntrospectionResponse) { value.ValidUntil = claims.Expires + 1 },
	}
	for index, mutate := range mutations {
		output := base
		mutate(&output)
		body, err := json.Marshal(output)
		if err != nil {
			t.Fatal(err)
		}
		client := &http.Client{Transport: companionRoundTripFunc(
			func(*http.Request) (*http.Response, error) {
				return companionStatusHTTPResponse(http.StatusOK, body), nil
			})}
		introspector, err := NewCompanionTokenIntrospector(
			"https://accounts.example/v1/companion-tokens/introspect", client)
		if err != nil {
			t.Fatal(err)
		}
		if err := introspector.Authorize(context.Background(), claims, now); !errors.Is(err, ErrCompanionUnavailable) {
			t.Fatalf("mutation %d accepted: %v", index, err)
		}
	}
}

func TestCompanionIntrospectionConfigurationAndMTLSClient(t *testing.T) {
	client := &http.Client{}
	for _, endpoint := range []string{
		"http://accounts.example/v1/companion-tokens/introspect",
		"https://user@accounts.example/v1/companion-tokens/introspect",
		"https://accounts.example/v1/other",
		"https://accounts.example/v1/companion-tokens/introspect?x=1",
	} {
		if _, err := NewCompanionTokenIntrospector(endpoint, client); err == nil {
			t.Fatalf("unsafe endpoint accepted: %s", endpoint)
		}
	}

	caPEM, certificatePEM, keyPEM := companionTestPKI(t)
	mtls, err := NewCompanionIntrospectionMTLSClient(
		caPEM, certificatePEM, keyPEM, 750*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := mtls.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || !transport.DisableCompression ||
		transport.TLSClientConfig == nil ||
		transport.TLSClientConfig.MinVersion != tls.VersionTLS12 ||
		transport.TLSClientConfig.RootCAs == nil ||
		len(transport.TLSClientConfig.Certificates) != 1 ||
		mtls.Timeout != 750*time.Millisecond {
		t.Fatalf("unsafe mTLS client: %#v", mtls)
	}
	if _, err := NewCompanionIntrospectionMTLSClient(
		[]byte("bad"), certificatePEM, keyPEM, time.Second); err == nil {
		t.Fatal("invalid CA accepted")
	}
	directory := t.TempDir()
	caFile := filepath.Join(directory, "ca.pem")
	certificateFile := filepath.Join(directory, "client.pem")
	keyFile := filepath.Join(directory, "client-key.pem")
	for path, data := range map[string][]byte{
		caFile: caPEM, certificateFile: certificatePEM, keyFile: keyPEM,
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadCompanionIntrospectionMTLSClient(
		caFile, certificateFile, keyFile, time.Second); err != nil {
		t.Fatalf("load bounded credential files: %v", err)
	}
	if _, err := LoadCompanionIntrospectionMTLSClient(
		directory, certificateFile, keyFile, time.Second); err == nil {
		t.Fatal("non-regular credential accepted")
	}
}

func companionTestPKI(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate,
		caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "control-plane"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate,
		caTemplate, clientPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
}
