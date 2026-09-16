package factorytime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

type signerTestAuthorizer struct {
	schemaErr         error
	authorizeErr      error
	authorizeSequence []error
	schemaCalls       int
	authorizes        int
}

func (authorizer *signerTestAuthorizer) VerifySchema() error {
	authorizer.schemaCalls++
	return authorizer.schemaErr
}

func (authorizer *signerTestAuthorizer) AuthorizeSigning(
	context.Context, Receipt) error {
	authorizer.authorizes++
	if len(authorizer.authorizeSequence) >= authorizer.authorizes {
		return authorizer.authorizeSequence[authorizer.authorizes-1]
	}
	return authorizer.authorizeErr
}

type signerTestBackend struct {
	key        ed25519.PrivateKey
	readyErr   error
	signErr    error
	bad        bool
	readyCalls int
	signCalls  int
	payload    []byte
}

func (backend *signerTestBackend) Ready(context.Context) error {
	backend.readyCalls++
	return backend.readyErr
}

func (backend *signerTestBackend) Sign(_ context.Context,
	payload []byte) ([]byte, error) {
	backend.signCalls++
	backend.payload = append([]byte(nil), payload...)
	if backend.signErr != nil {
		return nil, backend.signErr
	}
	signature := ed25519.Sign(backend.key, payload)
	if backend.bad {
		signature[0] ^= 1
	}
	return signature, nil
}

func signerRequestBodyForTest(t *testing.T, keyID string) ([]byte, []byte) {
	t.Helper()
	unsigned := unsignedReceiptForRemoteSigner(t, keyID)
	digest := sha256.Sum256(unsigned)
	request := signerRequest{
		Schema: SignerRequestSchema, KeyID: keyID,
		SignatureAlgorithm: SignatureAlgorithm,
		SignatureDomainB64URL: base64.RawURLEncoding.
			EncodeToString([]byte(SignatureDomain)),
		UnsignedReceiptB64URL: base64.RawURLEncoding.EncodeToString(unsigned),
		UnsignedReceiptSHA256: hex.EncodeToString(digest[:]),
		Result:                SignerRequestResult,
	}
	body, err := CanonicalJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	return body, unsigned
}

func newSignerServiceForTest(t *testing.T) (*ReceiptSignerService,
	*signerTestAuthorizer, *signerTestBackend, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorizer := &signerTestAuthorizer{}
	backend := &signerTestBackend{key: privateKey}
	service, err := NewReceiptSignerService(authorizer, backend,
		"factory-time-key-1", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return service, authorizer, backend, publicKey
}

func signerTLSState(certificateDER []byte, version uint16) *tls.ConnectionState {
	certificate := &x509.Certificate{Raw: append([]byte(nil), certificateDER...)}
	return &tls.ConnectionState{Version: version,
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}}}
}

func signerHTTPRequest(t *testing.T, body []byte,
	certificateDER []byte) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost,
		"https://signer.example"+SignerEndpointPath, bytes.NewReader(body))
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.TLS = signerTLSState(certificateDER, tls.VersionTLS13)
	return request
}

func TestSignerRequestParserIsCanonicalReceiptOnly(t *testing.T) {
	body, unsigned := signerRequestBodyForTest(t, "factory-time-key-1")
	request, receipt, parsedUnsigned, err := parseSignerRequest(body)
	if err != nil || request.KeyID != "factory-time-key-1" ||
		receipt.AuthorityKeyID != request.KeyID ||
		!bytes.Equal(parsedUnsigned, unsigned) {
		t.Fatalf("request=%#v receipt=%#v err=%v", request, receipt, err)
	}
	var value map[string]any
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal(err)
	}
	mutations := []func(map[string]any){
		func(item map[string]any) { item["schema"] = "xz-factory-time-sign-request-v0" },
		func(item map[string]any) { item["key_id"] = "other-key" },
		func(item map[string]any) { item["signature_domain_b64url"] = "YQ" },
		func(item map[string]any) { item["unsigned_receipt_sha256"] = strings64("0") },
		func(item map[string]any) { item["extra"] = true },
	}
	for index, mutate := range mutations {
		copyValue := make(map[string]any, len(value))
		for key, item := range value {
			copyValue[key] = item
		}
		mutate(copyValue)
		mutated, _ := CanonicalJSON(copyValue)
		if _, _, _, err := parseSignerRequest(mutated); !errors.Is(err, ErrInvalid) {
			t.Fatalf("mutation %d accepted: %v", index, err)
		}
	}
	noncanonical := append(append([]byte(nil), body...), '\n')
	if _, _, _, err := parseSignerRequest(noncanonical); !errors.Is(err, ErrInvalid) {
		t.Fatalf("noncanonical request accepted: %v", err)
	}
	duplicate := append([]byte(`{"key_id":"duplicate",`), body[1:]...)
	if _, _, _, err := parseSignerRequest(duplicate); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate request accepted: %v", err)
	}
}

func TestReceiptSignerServiceAuthorizesBeforeBackendAndVerifiesResult(t *testing.T) {
	service, authorizer, backend, publicKey := newSignerServiceForTest(t)
	body, unsigned := signerRequestBodyForTest(t, service.KeyID())
	responseBody, err := service.SignRequest(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	response, err := parseSignerResponse(responseBody)
	if err != nil {
		t.Fatal(err)
	}
	signature, _ := base64.RawURLEncoding.DecodeString(response.SignatureB64URL)
	payload := append(append([]byte{}, []byte(SignatureDomain)...), unsigned...)
	if authorizer.authorizes != 2 || backend.signCalls != 1 ||
		!bytes.Equal(backend.payload, payload) ||
		!ed25519.Verify(publicKey, payload, signature) {
		t.Fatal("signer did not preserve authorize-then-sign receipt binding")
	}
	authorizer.authorizeErr = ErrUnauthorized
	if _, err := service.SignRequest(context.Background(), body); !errors.Is(err, ErrUnauthorized) || backend.signCalls != 1 || authorizer.authorizes != 3 {
		t.Fatalf("unauthorized request reached backend: err=%v calls=%d",
			err, backend.signCalls)
	}
	authorizer.authorizeErr = nil
	backend.bad = true
	if _, err := service.SignRequest(context.Background(), body); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("bad HSM signature accepted: %v", err)
	}
	if _, err := service.SignRequest(context.Background(),
		[]byte(`{"payload":"arbitrary"}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("arbitrary oracle payload accepted: %v", err)
	}
}

func TestReceiptSignerDoesNotReleaseSignatureThatExpiresDuringBackendCall(t *testing.T) {
	service, authorizer, backend, _ := newSignerServiceForTest(t)
	authorizer.authorizeSequence = []error{nil, ErrOutsideWindow}
	body, _ := signerRequestBodyForTest(t, service.KeyID())
	if _, err := service.SignRequest(context.Background(), body); !errors.Is(err, ErrOutsideWindow) || backend.signCalls != 1 ||
		authorizer.authorizes != 2 {
		t.Fatalf("expired post-sign receipt err=%v authorize=%d sign=%d",
			err, authorizer.authorizes, backend.signCalls)
	}
}

func TestReceiptSignerHandlerPinsAuthorityTLSAndStrictTransport(t *testing.T) {
	service, authorizer, backend, _ := newSignerServiceForTest(t)
	certificateDER := []byte("M63 exact authority client certificate DER")
	digest := sha256.Sum256(certificateDER)
	handler, err := NewReceiptSignerHandler(service,
		hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := signerRequestBodyForTest(t, service.KeyID())
	request := signerHTTPRequest(t, body, certificateDER)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		response.Header().Get("Content-Type") != "application/json" ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("code=%d headers=%v body=%q", response.Code,
			response.Header(), response.Body.String())
	}

	ready := httptest.NewRequest(http.MethodGet,
		"https://signer.example"+SignerReadinessPath, nil)
	ready.Header.Set("Accept", "application/json")
	ready.Header.Set("Cache-Control", "no-store")
	ready.TLS = signerTLSState(certificateDER, tls.VersionTLS13)
	readyResponse := httptest.NewRecorder()
	handler.ServeHTTP(readyResponse, ready)
	if readyResponse.Code != http.StatusNoContent ||
		readyResponse.Header().Get(SignerKeyIDHeader) != service.KeyID() ||
		authorizer.schemaCalls != 1 || backend.readyCalls != 1 {
		t.Fatalf("readiness code=%d headers=%v schema=%d backend=%d",
			readyResponse.Code, readyResponse.Header(), authorizer.schemaCalls,
			backend.readyCalls)
	}

	wrongCertificate := signerHTTPRequest(t, body, []byte("other certificate"))
	wrongResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongResponse, wrongCertificate)
	if wrongResponse.Code != http.StatusForbidden {
		t.Fatalf("wrong authority certificate code=%d", wrongResponse.Code)
	}
	downgrade := signerHTTPRequest(t, body, certificateDER)
	downgrade.TLS.Version = tls.VersionTLS12
	downgradeResponse := httptest.NewRecorder()
	handler.ServeHTTP(downgradeResponse, downgrade)
	if downgradeResponse.Code != http.StatusForbidden {
		t.Fatalf("TLS downgrade code=%d", downgradeResponse.Code)
	}
	chunked := signerHTTPRequest(t, body, certificateDER)
	chunked.TransferEncoding = []string{"chunked"}
	chunkedResponse := httptest.NewRecorder()
	handler.ServeHTTP(chunkedResponse, chunked)
	if chunkedResponse.Code != http.StatusBadRequest {
		t.Fatalf("chunked request code=%d", chunkedResponse.Code)
	}
}

func TestRemoteSignerAndReceiptSignerHandlerInteroperateOverRealTLS13MTLS(t *testing.T) {
	fixture := newRemoteSignerFixture(t)
	fixture.server.Close()
	clientCertificatePEM, err := os.ReadFile(fixture.files.ClientCertificateFile)
	if err != nil {
		t.Fatal(err)
	}
	block, trailing := pem.Decode(clientCertificatePEM)
	if block == nil || block.Type != "CERTIFICATE" ||
		len(bytes.TrimSpace(trailing)) != 0 {
		t.Fatal("client certificate fixture is invalid")
	}
	certificateDigest := sha256.Sum256(block.Bytes)
	authorizer := &signerTestAuthorizer{}
	backend := &signerTestBackend{key: fixture.state.key}
	service, err := NewReceiptSignerService(authorizer, backend,
		fixture.files.KeyID, fixture.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewReceiptSignerHandler(service,
		hex.EncodeToString(certificateDigest[:]))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = fixture.server.TLS.Clone()
	server.StartTLS()
	t.Cleanup(server.Close)
	files := fixture.files
	files.Endpoint = server.URL + SignerEndpointPath
	client, err := LoadRemoteSigner(files)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	unsigned := unsignedReceiptForRemoteSigner(t, files.KeyID)
	payload := append(append([]byte{}, []byte(SignatureDomain)...), unsigned...)
	signature, err := client.Sign(context.Background(), payload)
	if err != nil || !ed25519.Verify(fixture.publicKey, payload, signature) {
		t.Fatalf("real client/server signature err=%v", err)
	}
	if authorizer.schemaCalls != 1 || authorizer.authorizes != 2 ||
		backend.readyCalls != 1 || backend.signCalls != 1 {
		t.Fatalf("schema=%d authorize=%d ready=%d sign=%d",
			authorizer.schemaCalls, authorizer.authorizes,
			backend.readyCalls, backend.signCalls)
	}
}

func TestReceiptSignerConstructorsRejectIncompleteTrustBoundaries(t *testing.T) {
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	authorizer := &signerTestAuthorizer{}
	backend := &signerTestBackend{}
	for index, fixture := range []struct {
		authorizer ReceiptSigningAuthorizer
		backend    ReceiptSigningBackend
		keyID      string
		publicKey  ed25519.PublicKey
	}{
		{nil, backend, "factory-time-key-1", publicKey},
		{authorizer, nil, "factory-time-key-1", publicKey},
		{authorizer, backend, "", publicKey},
		{authorizer, backend, "factory-time-key-1", publicKey[:3]},
	} {
		if _, err := NewReceiptSignerService(fixture.authorizer,
			fixture.backend, fixture.keyID, fixture.publicKey); err == nil {
			t.Fatalf("invalid service fixture %d accepted", index)
		}
	}
	service, _, _, _ := newSignerServiceForTest(t)
	if _, err := NewReceiptSignerHandler(service, strings64("A")); err == nil {
		t.Fatal("uppercase authority pin accepted")
	}
	body, _ := signerRequestBodyForTest(t, service.KeyID())
	if _, err := service.SignRequest(nil, body); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil signing context: %v", err)
	}
	if err := service.Ready(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil readiness context: %v", err)
	}
}

func TestReceiptSignerReadinessFailsClosed(t *testing.T) {
	service, authorizer, backend, _ := newSignerServiceForTest(t)
	authorizer.schemaErr = errors.New("database down")
	if err := service.Ready(context.Background()); !errors.Is(err, ErrUnavailable) ||
		backend.readyCalls != 0 {
		t.Fatalf("database readiness err=%v backend=%d", err, backend.readyCalls)
	}
	authorizer.schemaErr = nil
	backend.readyErr = errors.New("HSM down")
	if err := service.Ready(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("backend readiness err=%v", err)
	}
}

func TestSignerRequestBodyStaysBelowContractLimit(t *testing.T) {
	body, _ := signerRequestBodyForTest(t, "factory-time-key-1")
	if len(body) == 0 || len(body) > MaximumSignerBodyBytes {
		t.Fatalf("request size=%d", len(body))
	}
	if time.Duration(maximumSignerTimeout) != 2*time.Second {
		t.Fatal("signer timeout policy changed")
	}
}
