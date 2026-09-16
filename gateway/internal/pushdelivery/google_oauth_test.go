package pushdelivery

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestGoogleServiceAccountTokenSourceSignsExactOAuthAssertion(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	server, client := http2TestServer(t, func(writer http.ResponseWriter,
		request *http.Request) {
		if request.Method != http.MethodPost ||
			request.Header.Get("Content-Type") !=
				"application/x-www-form-urlencoded" ||
			request.Header.Get("Accept") != "application/json" {
			t.Errorf("unexpected OAuth request")
		}
		body, _ := io.ReadAll(request.Body)
		form, formErr := url.ParseQuery(string(body))
		if formErr != nil || form.Get("grant_type") != googleJWTGrantType ||
			len(form) != 2 {
			t.Fatalf("form=%v err=%v", form, formErr)
		}
		parts := strings.Split(form.Get("assertion"), ".")
		if len(parts) != 3 {
			t.Fatalf("assertion parts=%d", len(parts))
		}
		decode := func(part string, output any) {
			decoded, decodeErr := base64.RawURLEncoding.DecodeString(part)
			if decodeErr != nil || json.Unmarshal(decoded, output) != nil {
				t.Fatal("invalid assertion segment")
			}
		}
		var header map[string]any
		var claims struct {
			Issuer, Scope, Audience string
			Expires, IssuedAt       int64
		}
		decodedClaims, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var wireClaims struct {
			Issuer   string `json:"iss"`
			Scope    string `json:"scope"`
			Audience string `json:"aud"`
			Expires  int64  `json:"exp"`
			IssuedAt int64  `json:"iat"`
		}
		decode(parts[0], &header)
		if json.Unmarshal(decodedClaims, &wireClaims) != nil {
			t.Fatal("invalid claims")
		}
		claims.Issuer, claims.Scope, claims.Audience = wireClaims.Issuer,
			wireClaims.Scope, wireClaims.Audience
		claims.Expires, claims.IssuedAt = wireClaims.Expires, wireClaims.IssuedAt
		if header["alg"] != "RS256" || header["typ"] != "JWT" ||
			header["kid"] != "google-key-1234" ||
			claims.Issuer != "push@product-123.iam.gserviceaccount.com" ||
			claims.Scope != googleFCMScope ||
			claims.Audience != googleOAuthTokenEndpoint ||
			claims.IssuedAt != now.Unix() ||
			claims.Expires != now.Add(time.Hour).Unix() {
			t.Fatalf("header=%v claims=%+v", header, claims)
		}
		signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256,
			digest[:], signature) != nil {
			t.Fatal("invalid assertion signature")
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(
			`{"access_token":"fcm-oauth-access-token","token_type":"Bearer","expires_in":3600}`))
	})
	source, err := NewGoogleServiceAccountTokenSource(client, key,
		"push@product-123.iam.gserviceaccount.com", "google-key-1234")
	if err != nil {
		t.Fatal(err)
	}
	source.endpoint = server.URL
	source.now = func() time.Time { return now }
	token, err := source.AccessToken(context.Background())
	if err != nil || token.Value != "fcm-oauth-access-token" ||
		!token.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("token=%+v err=%v", token, err)
	}
}

func TestGoogleServiceAccountTokenSourceTypesOnlyExplicitCredentialRejection(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range []struct {
		name, body string
		status     int
		wantTyped  bool
	}{
		{"invalid-grant", `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`,
			http.StatusBadRequest, true},
		{"invalid-client", `{"error":"invalid_client"}`,
			http.StatusUnauthorized, true},
		{"rate", `{"error":"temporarily_unavailable"}`,
			http.StatusBadRequest, false},
		{"server", `{"error":"invalid_grant"}`,
			http.StatusServiceUnavailable, false},
		{"duplicate", `{"error":"temporarily_unavailable","error":"invalid_grant"}`,
			http.StatusBadRequest, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server, client := http2TestServer(t, func(writer http.ResponseWriter,
				_ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(testCase.status)
				_, _ = writer.Write([]byte(testCase.body))
			})
			source, sourceErr := NewGoogleServiceAccountTokenSource(client, key,
				"push@product-123.iam.gserviceaccount.com", "google-key-1234")
			if sourceErr != nil {
				t.Fatal(sourceErr)
			}
			source.endpoint = server.URL
			_, probeErr := source.AccessToken(context.Background())
			if errors.Is(probeErr, ErrCredentialRejected) != testCase.wantTyped ||
				!errors.Is(probeErr, ErrUnavailable) {
				t.Fatalf("err=%v typed=%t", probeErr, testCase.wantTyped)
			}
		})
	}
}

func TestGoogleMetadataTokenSourceUsesPinnedProtocol(t *testing.T) {
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter,
		request *http.Request) {
		if request.Method != http.MethodGet ||
			request.Header.Get("Metadata-Flavor") != "Google" ||
			request.Header.Get("Accept") != "application/json" ||
			request.URL.Path != "/computeMetadata/v1/instance/service-accounts/default/token" ||
			request.URL.Query().Get("enforce_scopes") != "true" ||
			request.URL.Query().Get("scopes") != googleFCMScope ||
			len(request.URL.Query()) != 2 {
			t.Errorf("unexpected metadata request: %s", request.URL.String())
		}
		writer.Header().Set("Metadata-Flavor", "Google")
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(
			`{"access_token":"metadata-access-token","token_type":"Bearer","expires_in":1800}`))
	}))
	defer server.Close()
	client := &http.Client{Timeout: time.Second,
		Transport: &http.Transport{Proxy: nil}}
	source, err := NewGoogleMetadataTokenSource(client)
	if err != nil {
		t.Fatal(err)
	}
	source.endpoint = server.URL +
		"/computeMetadata/v1/instance/service-accounts/default/token?enforce_scopes=true&scopes=" +
		url.QueryEscape(googleFCMScope)
	source.now = func() time.Time { return now }
	token, err := source.AccessToken(context.Background())
	if err != nil || token.Value != "metadata-access-token" ||
		!token.ExpiresAt.Equal(now.Add(30*time.Minute)) {
		t.Fatalf("token=%+v err=%v", token, err)
	}
}

func TestGoogleCredentialSourcesRejectUnsafeInputs(t *testing.T) {
	smallKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	client := &http.Client{Timeout: time.Second,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
	if _, err := NewGoogleServiceAccountTokenSource(client, smallKey,
		"push@product.iam.gserviceaccount.com", "google-key-1234"); err == nil {
		t.Fatal("accepted weak RSA key or proxy-enabled client")
	}
	if _, err := NewGoogleMetadataTokenSource(client); err == nil {
		t.Fatal("accepted proxy-enabled metadata client")
	}
}
