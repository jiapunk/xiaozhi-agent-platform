// Command factorytimefixture is a test-only cross-language fixture. Its
// deterministic private key must never be used outside automated tests.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"xiaozhi-agent-platform/gateway/internal/factorytime"
)

type fixtureStore struct {
	station     factorytime.Station
	certificate [32]byte
	now         time.Time
}

func (store fixtureStore) Reserve(_ context.Context,
	reservation factorytime.Reservation, _ time.Duration) (time.Time, error) {
	if reservation.Request.Station != store.station ||
		subtle.ConstantTimeCompare(reservation.ClientCertificateSHA256[:],
			store.certificate[:]) != 1 {
		return time.Time{}, factorytime.ErrUnauthorized
	}
	return store.now, nil
}

type fixtureSigner struct{ key ed25519.PrivateKey }

func (fixtureSigner) KeyID() string { return "m61-go-test-key" }
func (signer fixtureSigner) Sign(_ context.Context,
	payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.key, payload), nil
}

type output struct {
	RequestB64URL      string `json:"request_b64url"`
	ReceiptB64URL      string `json:"receipt_b64url"`
	PublicKeyPEMB64URL string `json:"public_key_pem_b64url"`
}

func main() {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	nonce := make([]byte, 32)
	for index := range nonce {
		nonce[index] = 0x31
	}
	request := factorytime.Request{
		Schema: factorytime.RequestSchema, Environment: factorytime.Environment,
		Scope: factorytime.Scope, RequestID: "time-m61-cross-language",
		NonceB64URL: base64.RawURLEncoding.EncodeToString(nonce),
		Ledger: factorytime.Ledger{
			PolicySHA256: repeat("1", 64), PolicyID: "policy-1", LedgerID: "ledger-1",
		},
		Authorization: factorytime.Authorization{
			PlanSHA256: repeat("2", 64), PlanID: "plan-1",
			IssuedAt: "2030-01-02T03:03:05Z", ExpiresAt: "2030-01-02T03:05:05Z",
		},
		Transaction: factorytime.Transaction{
			AttemptID: "attempt-1", DeviceID: "xz-aabbccddeeff",
			BaseMAC: "AA:BB:CC:DD:EE:FF",
		},
		Station: factorytime.Station{
			ID: "station-1", FixtureID: "fixture-1", FixtureVersion: "v1",
		},
		Result: factorytime.RequestResult,
	}
	requestBody, fail := factorytime.CanonicalJSON(request)
	if fail != nil {
		die(fail)
	}
	certificateDER := []byte("M61 cross-language test certificate DER")
	seed := sha256.Sum256([]byte("M61 CROSS LANGUAGE TEST KEY ONLY"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	store := fixtureStore{station: request.Station,
		certificate: sha256.Sum256(certificateDER), now: now}
	authority, fail := factorytime.NewAuthority(store,
		fixtureSigner{key: privateKey}, 5*time.Second)
	if fail != nil {
		die(fail)
	}
	handler, fail := factorytime.NewHandler(authority)
	if fail != nil {
		die(fail)
	}
	httpRequest := httptest.NewRequest(http.MethodPost,
		"https://factory.example"+factorytime.EndpointPath,
		bytes.NewReader(requestBody))
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Cache-Control", "no-store")
	certificate := &x509.Certificate{Raw: certificateDER}
	httpRequest.TLS = &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httpRequest)
	if response.Code != http.StatusOK {
		die(fmt.Errorf("handler returned %d", response.Code))
	}
	publicDER, fail := x509.MarshalPKIXPublicKey(privateKey.Public())
	if fail != nil {
		die(fail)
	}
	publicPEM := []byte("-----BEGIN PUBLIC KEY-----\n")
	publicPEM = append(publicPEM,
		[]byte(base64.StdEncoding.EncodeToString(publicDER))...)
	publicPEM = append(publicPEM, []byte("\n-----END PUBLIC KEY-----\n")...)
	encoded, fail := json.Marshal(output{
		RequestB64URL:      base64.RawURLEncoding.EncodeToString(requestBody),
		ReceiptB64URL:      base64.RawURLEncoding.EncodeToString(response.Body.Bytes()),
		PublicKeyPEMB64URL: base64.RawURLEncoding.EncodeToString(publicPEM),
	})
	if fail != nil {
		die(fail)
	}
	_, _ = os.Stdout.Write(append(encoded, '\n'))
}

func repeat(value string, count int) string {
	result := ""
	for index := 0; index < count; index++ {
		result += value
	}
	return result
}

func die(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
