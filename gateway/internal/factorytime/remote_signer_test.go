package factorytime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

type remoteSignerServer struct {
	mu       sync.Mutex
	keyID    string
	key      ed25519.PrivateKey
	mode     string
	ready    int
	requests int
}

func (server *remoteSignerServer) ServeHTTP(writer http.ResponseWriter,
	request *http.Request) {
	server.mu.Lock()
	defer server.mu.Unlock()
	if request.TLS == nil || request.TLS.Version != tls.VersionTLS13 ||
		len(request.TLS.PeerCertificates) == 0 ||
		len(request.TLS.VerifiedChains) == 0 {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	if request.Method == http.MethodGet && request.URL.Path == SignerReadinessPath {
		server.ready++
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set(SignerKeyIDHeader, server.keyID)
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	server.requests++
	if request.Method != http.MethodPost || request.URL.Path != SignerEndpointPath ||
		singleHeader(request.Header, "Accept") != "application/json" ||
		singleHeader(request.Header, "Content-Type") != "application/json" ||
		singleHeader(request.Header, "Cache-Control") != "no-store" ||
		request.ContentLength <= 0 || request.ContentLength > MaximumSignerBodyBytes ||
		len(request.TransferEncoding) != 0 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, MaximumSignerBodyBytes+1))
	if err != nil || int64(len(body)) != request.ContentLength ||
		rejectDuplicateMembers(body) != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var signRequest signerRequest
	if err := decoder.Decode(&signRequest); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	canonical, _ := CanonicalJSON(signRequest)
	unsigned, decodeErr := base64.RawURLEncoding.DecodeString(
		signRequest.UnsignedReceiptB64URL)
	digest := sha256.Sum256(unsigned)
	if !bytes.Equal(canonical, body) || decodeErr != nil ||
		signRequest.Schema != SignerRequestSchema ||
		signRequest.KeyID != server.keyID ||
		signRequest.SignatureAlgorithm != SignatureAlgorithm ||
		signRequest.SignatureDomainB64URL != base64.RawURLEncoding.
			EncodeToString([]byte(SignatureDomain)) ||
		signRequest.UnsignedReceiptSHA256 != hex.EncodeToString(digest[:]) ||
		signRequest.Result != SignerRequestResult {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	receipt, err := ParseUnsignedReceipt(unsigned)
	if err != nil || receipt.AuthorityKeyID != server.keyID {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	payload := append(append([]byte{}, []byte(SignatureDomain)...), unsigned...)
	signature := ed25519.Sign(server.key, payload)
	if server.mode == "bad-signature" {
		signature[0] ^= 1
	}
	response := signerResponse{
		Schema: SignerResponseSchema, KeyID: server.keyID,
		SignatureAlgorithm:    SignatureAlgorithm,
		SignatureB64URL:       base64.RawURLEncoding.EncodeToString(signature),
		UnsignedReceiptSHA256: hex.EncodeToString(digest[:]),
		Result:                SignerResponseResult,
	}
	responseBody, _ := CanonicalJSON(response)
	if server.mode == "noncanonical" {
		responseBody = append(responseBody, '\n')
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Content-Length", strconv.Itoa(len(responseBody)))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(responseBody)
}

type remoteSignerFixture struct {
	server        *httptest.Server
	state         *remoteSignerServer
	files         RemoteSignerFiles
	publicKey     ed25519.PublicKey
	clientKeyFile string
}

func newRemoteSignerFixture(t *testing.T) remoteSignerFixture {
	t.Helper()
	root := t.TempDir()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "M62 test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate,
		caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	issue := func(serial int64, commonName string, usage x509.ExtKeyUsage,
		ips []net.IP) ([]byte, []byte) {
		public, private, issueErr := ed25519.GenerateKey(rand.Reader)
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: commonName},
			NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: ips,
		}
		der, issueErr := x509.CreateCertificate(rand.Reader, template,
			caTemplate, public, caPrivate)
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		privateDER, issueErr := x509.MarshalPKCS8PrivateKey(private)
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	}
	serverCertificatePEM, serverKeyPEM := issue(102, "127.0.0.1",
		x509.ExtKeyUsageServerAuth, []net.IP{net.ParseIP("127.0.0.1")})
	clientCertificatePEM, clientKeyPEM := issue(103, "m62-authority-client",
		x509.ExtKeyUsageClientAuth, nil)
	serverIdentity, err := tls.X509KeyPair(serverCertificatePEM, serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(caPEM) {
		t.Fatal("test CA failed")
	}
	signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state := &remoteSignerServer{keyID: "factory-time-key-1", key: signingPrivate}
	server := httptest.NewUnstartedServer(state)
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{serverIdentity},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: clientRoots,
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	write := func(name string, data []byte, mode os.FileMode) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	caFile := write("ca.pem", caPEM, 0o644)
	clientCertificateFile := write("client.pem", clientCertificatePEM, 0o644)
	clientKeyFile := write("client.key", clientKeyPEM, 0o600)
	publicDER, err := x509.MarshalPKIXPublicKey(signingPublic)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	publicFile := write("signer.pub", publicPEM, 0o644)
	publicDigest := sha256.Sum256(publicDER)
	return remoteSignerFixture{
		server: server, state: state, publicKey: signingPublic,
		clientKeyFile: clientKeyFile,
		files: RemoteSignerFiles{
			Endpoint: server.URL + SignerEndpointPath,
			KeyID:    state.keyID, PublicKeyFile: publicFile,
			PublicKeySHA256:   hex.EncodeToString(publicDigest[:]),
			CACertificateFile: caFile, CACertificateSHA256: fileDigest(caPEM),
			ClientCertificateFile:   clientCertificateFile,
			ClientCertificateSHA256: fileDigest(clientCertificatePEM),
			ClientPrivateKeyFile:    clientKeyFile, Timeout: time.Second,
		},
	}
}

func unsignedReceiptForRemoteSigner(t *testing.T, keyID string) []byte {
	t.Helper()
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	request := fixtureRequest(now)
	requestBody, _ := CanonicalJSON(request)
	requestDigest := sha256.Sum256(requestBody)
	receipt := Receipt{
		Schema: ReceiptSchema, Environment: Environment, Scope: Scope,
		RequestSHA256: hex.EncodeToString(requestDigest[:]),
		RequestID:     request.RequestID, NonceB64URL: request.NonceB64URL,
		Ledger: request.Ledger, Authorization: request.Authorization,
		Transaction: request.Transaction, Station: request.Station,
		AuthorityKeyID: keyID, ObservedAt: "2030-01-02T03:04:05Z",
		ExpiresAt: "2030-01-02T03:04:10Z", Result: ReceiptResult,
		SignatureAlgorithm: SignatureAlgorithm,
	}
	body, err := CanonicalJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestRemoteSignerUsesPinnedTLS13MTLSAndVerifiesSignature(t *testing.T) {
	fixture := newRemoteSignerFixture(t)
	signer, err := LoadRemoteSigner(fixture.files)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	unsigned := unsignedReceiptForRemoteSigner(t, fixture.files.KeyID)
	payload := append(append([]byte{}, []byte(SignatureDomain)...), unsigned...)
	signature, err := signer.Sign(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(fixture.publicKey, payload, signature) {
		t.Fatal("remote signature failed independent verification")
	}
	fixture.state.mu.Lock()
	defer fixture.state.mu.Unlock()
	if fixture.state.ready != 1 || fixture.state.requests != 1 {
		t.Fatalf("ready=%d requests=%d", fixture.state.ready,
			fixture.state.requests)
	}
}

func TestRemoteSignerRejectsInvalidSignatureAndNoncanonicalResponse(t *testing.T) {
	fixture := newRemoteSignerFixture(t)
	signer, err := LoadRemoteSigner(fixture.files)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := unsignedReceiptForRemoteSigner(t, fixture.files.KeyID)
	payload := append(append([]byte{}, []byte(SignatureDomain)...), unsigned...)
	for _, mode := range []string{"bad-signature", "noncanonical"} {
		fixture.state.mu.Lock()
		fixture.state.mode = mode
		fixture.state.mu.Unlock()
		if _, err := signer.Sign(context.Background(), payload); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("mode=%s err=%v", mode, err)
		}
	}
	if _, err := signer.Sign(context.Background(), []byte("arbitrary oracle payload")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("arbitrary payload: %v", err)
	}
}

func TestRemoteSignerRejectsPinsUnsafeKeyModeAndEndpointBeforeNetwork(t *testing.T) {
	fixture := newRemoteSignerFixture(t)
	mutations := []func(*RemoteSignerFiles){
		func(files *RemoteSignerFiles) { files.PublicKeySHA256 = strings64("0") },
		func(files *RemoteSignerFiles) { files.CACertificateSHA256 = strings64("0") },
		func(files *RemoteSignerFiles) { files.ClientCertificateSHA256 = strings64("0") },
		func(files *RemoteSignerFiles) { files.Endpoint += "?debug=1" },
		func(files *RemoteSignerFiles) { files.KeyID = "" },
	}
	for index, mutate := range mutations {
		files := fixture.files
		mutate(&files)
		if _, err := LoadRemoteSigner(files); err == nil {
			t.Fatalf("unsafe mutation %d accepted", index)
		}
	}
	if err := os.Chmod(fixture.clientKeyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRemoteSigner(fixture.files); err == nil {
		t.Fatal("group/other-readable signer client key accepted")
	}
}

func TestUnsignedReceiptParserRejectsSignedOrOutOfWindowReceipt(t *testing.T) {
	body := unsignedReceiptForRemoteSigner(t, "factory-time-key-1")
	if _, err := ParseUnsignedReceipt(body); err != nil {
		t.Fatal(err)
	}
	var receipt Receipt
	if err := json.Unmarshal(body, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt.SignatureB64URL = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	signed, _ := CanonicalJSON(receipt)
	if _, err := ParseUnsignedReceipt(signed); !errors.Is(err, ErrInvalid) {
		t.Fatalf("signed receipt accepted by unsigned parser: %v", err)
	}
	receipt.SignatureB64URL = ""
	receipt.ObservedAt = "2030-01-02T03:06:05Z"
	receipt.ExpiresAt = "2030-01-02T03:06:10Z"
	outOfWindow, _ := CanonicalJSON(receipt)
	if _, err := ParseUnsignedReceipt(outOfWindow); !errors.Is(err, ErrInvalid) {
		t.Fatalf("out-of-window receipt accepted: %v", err)
	}
}
