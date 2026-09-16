package factorytime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

type memoryStore struct {
	mu          sync.Mutex
	now         time.Time
	station     Station
	certificate [32]byte
	requests    map[[32]byte]struct{}
	requestIDs  map[string]struct{}
	nonces      map[[32]byte]struct{}
}

func (store *memoryStore) Reserve(_ context.Context, reservation Reservation,
	lifetime time.Duration) (time.Time, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if reservation.Request.Station != store.station ||
		subtle.ConstantTimeCompare(reservation.ClientCertificateSHA256[:],
			store.certificate[:]) != 1 {
		return time.Time{}, ErrUnauthorized
	}
	issued, _ := parseTimestamp(reservation.Request.Authorization.IssuedAt)
	expires, _ := parseTimestamp(reservation.Request.Authorization.ExpiresAt)
	if store.now.Before(issued) || store.now.After(expires) {
		return time.Time{}, ErrOutsideWindow
	}
	if _, exists := store.requests[reservation.RequestSHA256]; exists {
		return time.Time{}, ErrReplay
	}
	if _, exists := store.requestIDs[reservation.Request.RequestID]; exists {
		return time.Time{}, ErrReplay
	}
	if _, exists := store.nonces[reservation.NonceSHA256]; exists {
		return time.Time{}, ErrReplay
	}
	if lifetime < time.Second || lifetime > 10*time.Second {
		return time.Time{}, ErrInvalid
	}
	store.requests[reservation.RequestSHA256] = struct{}{}
	store.requestIDs[reservation.Request.RequestID] = struct{}{}
	store.nonces[reservation.NonceSHA256] = struct{}{}
	return store.now, nil
}

type testSigner struct {
	keyID string
	key   ed25519.PrivateKey
	err   error
}

func (signer testSigner) KeyID() string { return signer.keyID }
func (signer testSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	if signer.err != nil {
		return nil, signer.err
	}
	return ed25519.Sign(signer.key, payload), nil
}

func fixtureRequest(now time.Time) Request {
	return Request{
		Schema: RequestSchema, Environment: Environment, Scope: Scope,
		RequestID:   "time-0123456789abcdef0123456789abcdef",
		NonceB64URL: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		Ledger: Ledger{
			PolicySHA256: strings64("1"), PolicyID: "policy-1", LedgerID: "ledger-1",
		},
		Authorization: Authorization{
			PlanSHA256: strings64("2"), PlanID: "plan-1",
			IssuedAt:  now.Add(-time.Minute).Format("2006-01-02T15:04:05Z"),
			ExpiresAt: now.Add(time.Minute).Format("2006-01-02T15:04:05Z"),
		},
		Transaction: Transaction{
			AttemptID: "attempt-1", DeviceID: "xz-aabbccddeeff",
			BaseMAC: "AA:BB:CC:DD:EE:FF",
		},
		Station: Station{ID: "station-1", FixtureID: "fixture-1",
			FixtureVersion: "v1"},
		Result: RequestResult,
	}
}

func strings64(value string) string {
	return value + value + value + value + value + value + value + value +
		value + value + value + value + value + value + value + value +
		value + value + value + value + value + value + value + value +
		value + value + value + value + value + value + value + value +
		value + value + value + value + value + value + value + value +
		value + value + value + value + value + value + value + value +
		value + value + value + value + value + value + value + value +
		value + value + value + value + value + value + value + value
}

func authorityFixture(t *testing.T) (*Authority, *memoryStore,
	ed25519.PublicKey, []byte, Request) {
	t.Helper()
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	request := fixtureRequest(now)
	certificateDER := []byte("test-only-station-certificate-der")
	seed := sha256.Sum256([]byte("m61-test-only-ed25519-signer"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	store := &memoryStore{
		now: now, station: request.Station,
		certificate: sha256.Sum256(certificateDER),
		requests:    make(map[[32]byte]struct{}), requestIDs: make(map[string]struct{}),
		nonces: make(map[[32]byte]struct{}),
	}
	authority, err := NewAuthority(store,
		testSigner{keyID: "factory-time-key-1", key: privateKey}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return authority, store, privateKey.Public().(ed25519.PublicKey),
		certificateDER, request
}

func handlerRequest(t *testing.T, request Request,
	certificateDER []byte) *http.Request {
	t.Helper()
	body, err := CanonicalJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	httpRequest := httptest.NewRequest(http.MethodPost,
		"https://factory.example"+EndpointPath, bytes.NewReader(body))
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Cache-Control", "no-store")
	certificate := &x509.Certificate{Raw: certificateDER}
	httpRequest.TLS = &tls.ConnectionState{
		Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains: [][]*x509.Certificate{{certificate}},
	}
	return httpRequest
}

func TestHandlerIssuesM60CompatibleCanonicalReceipt(t *testing.T) {
	authority, _, publicKey, certificateDER, request := authorityFixture(t)
	handler, _ := NewHandler(authority)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, handlerRequest(t, request, certificateDER))
	if response.Code != http.StatusOK ||
		response.Header().Get("Content-Type") != "application/json" ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Content-Length") != strconv.Itoa(response.Body.Len()) ||
		response.Header().Get("Transfer-Encoding") != "" ||
		response.Header().Get("Content-Encoding") != "" ||
		response.Header().Get("Location") != "" {
		t.Fatalf("response code=%d headers=%v body=%s", response.Code,
			response.Header(), response.Body.String())
	}
	if rejectDuplicateMembers(response.Body.Bytes()) != nil {
		t.Fatal("receipt contains duplicate JSON members")
	}
	var receipt Receipt
	if err := json.Unmarshal(response.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalJSON(receipt)
	if err != nil || !bytes.Equal(canonical, response.Body.Bytes()) {
		t.Fatal("receipt is not canonical JSON")
	}
	requestBody, _ := CanonicalJSON(request)
	requestDigest := sha256.Sum256(requestBody)
	if receipt.RequestSHA256 != hex.EncodeToString(requestDigest[:]) ||
		receipt.RequestID != request.RequestID || receipt.NonceB64URL != request.NonceB64URL ||
		receipt.Ledger != request.Ledger || receipt.Authorization != request.Authorization ||
		receipt.Transaction != request.Transaction || receipt.Station != request.Station ||
		receipt.ObservedAt != "2030-01-02T03:04:05Z" ||
		receipt.ExpiresAt != "2030-01-02T03:04:10Z" {
		t.Fatalf("receipt request/time binding differs: %#v", receipt)
	}
	signature, err := base64.RawURLEncoding.DecodeString(receipt.SignatureB64URL)
	if err != nil || len(signature) != ed25519.SignatureSize {
		t.Fatal("invalid signature encoding")
	}
	receipt.SignatureB64URL = ""
	unsigned, _ := CanonicalJSON(receipt)
	payload := append(append([]byte{}, []byte(SignatureDomain)...), unsigned...)
	if !ed25519.Verify(publicKey, payload, signature) {
		t.Fatal("receipt signature does not verify over the M60 domain")
	}
}

func TestHandlerRejectsReplayWrongCertificateAndTransport(t *testing.T) {
	authority, _, _, certificateDER, request := authorityFixture(t)
	handler, _ := NewHandler(authority)
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, handlerRequest(t, request, certificateDER))
	if first.Code != http.StatusOK {
		t.Fatal(first.Code)
	}
	replay := httptest.NewRecorder()
	handler.ServeHTTP(replay, handlerRequest(t, request, certificateDER))
	if replay.Code != http.StatusConflict || replay.Body.Len() != 0 {
		t.Fatalf("replay code=%d body=%q", replay.Code, replay.Body.String())
	}

	authority, _, _, certificateDER, request = authorityFixture(t)
	handler, _ = NewHandler(authority)
	tests := []struct {
		name   string
		mutate func(*http.Request)
		status int
	}{
		{"wrong certificate", func(r *http.Request) {
			r.TLS.PeerCertificates[0].Raw = []byte("other")
		}, http.StatusForbidden},
		{"TLS 1.2", func(r *http.Request) { r.TLS.Version = tls.VersionTLS12 }, http.StatusBadRequest},
		{"unverified", func(r *http.Request) { r.TLS.VerifiedChains = nil }, http.StatusBadRequest},
		{"query", func(r *http.Request) { r.URL.RawQuery = "debug=1" }, http.StatusBadRequest},
		{"chunked", func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, http.StatusBadRequest},
		{"encoded", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, http.StatusBadRequest},
		{"duplicate accept", func(r *http.Request) { r.Header.Add("Accept", "application/json") }, http.StatusBadRequest},
		{"wrong length", func(r *http.Request) { r.ContentLength++ }, http.StatusBadRequest},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			authority, _, _, certificateDER, request := authorityFixture(t)
			handler, _ := NewHandler(authority)
			httpRequest := handlerRequest(t, request, certificateDER)
			testCase.mutate(httpRequest)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httpRequest)
			if response.Code != testCase.status || response.Body.Len() != 0 {
				t.Fatalf("code=%d body=%q", response.Code, response.Body.String())
			}
		})
	}
}

func TestFailedSignerStillConsumesNonce(t *testing.T) {
	_, store, _, certificateDER, request := authorityFixture(t)
	failing, err := NewAuthority(store,
		testSigner{keyID: "factory-time-key-1", err: errors.New("HSM offline")},
		5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := CanonicalJSON(request)
	digest := sha256.Sum256(body)
	if _, err := failing.Issue(context.Background(), request, digest,
		certificateDER); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("signer failure: %v", err)
	}
	seed := sha256.Sum256([]byte("replacement-test-key"))
	retry, _ := NewAuthority(store, testSigner{keyID: "factory-time-key-2",
		key: ed25519.NewKeyFromSeed(seed[:])}, 5*time.Second)
	if _, err := retry.Issue(context.Background(), request, digest,
		certificateDER); !errors.Is(err, ErrReplay) {
		t.Fatalf("spent nonce was revived after signer failure: %v", err)
	}
}

func TestAuthorityRejectsCallerSuppliedRequestDigest(t *testing.T) {
	authority, store, _, certificateDER, request := authorityFixture(t)
	if _, err := authority.Issue(context.Background(), request, [32]byte{},
		certificateDER); !errors.Is(err, ErrInvalid) {
		t.Fatalf("caller-supplied digest accepted: %v", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.requests) != 0 || len(store.nonces) != 0 {
		t.Fatal("invalid digest crossed the replay ledger boundary")
	}
}

func TestParseRequestRejectsDuplicateUnknownAndNoncanonicalJSON(t *testing.T) {
	_, _, _, _, request := authorityFixture(t)
	canonical, _ := CanonicalJSON(request)
	if _, _, err := ParseRequest(canonical); err != nil {
		t.Fatal(err)
	}
	mutations := [][]byte{
		append([]byte(" \n"), canonical...),
		bytes.Replace(canonical, []byte(`"scope":`),
			[]byte(`"scope":"duplicate","scope":`), 1),
		bytes.Replace(canonical, []byte(`"ledger_id":`),
			[]byte(`"unknown":"x","ledger_id":`), 1),
		bytes.Replace(canonical, []byte(`"device_id":"xz-aabbccddeeff"`),
			[]byte(`"device_id":"xz-aabbccddeefe"`), 1),
	}
	for index, mutation := range mutations {
		if _, _, err := ParseRequest(mutation); !errors.Is(err, ErrInvalid) {
			t.Fatalf("mutation %d accepted: %v", index, err)
		}
	}
}
