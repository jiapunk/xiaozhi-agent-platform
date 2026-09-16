package provisioning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type remoteIdentityDocument struct {
	payload  []byte
	revision uint64
	etag     string
}

type remoteIdentityState struct {
	mu          sync.RWMutex
	documents   map[string]remoteIdentityDocument
	lastMinimum map[string]string
	requests    map[string]int
}

func (state *remoteIdentityState) set(path string,
	document remoteIdentityDocument) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.documents[path] = document
}

func (state *remoteIdentityState) handler(writer http.ResponseWriter,
	request *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()
	document, found := state.documents[request.URL.Path]
	if !found || request.Method != http.MethodGet ||
		request.Header.Get("Accept") != IdentitySnapshotMediaType ||
		request.Header.Get("User-Agent") != "xiaozhi-identity-client/1" ||
		request.TLS == nil || len(request.TLS.PeerCertificates) != 1 {
		http.Error(writer, "not found", http.StatusNotFound)
		return
	}
	state.requests[request.URL.Path]++
	state.lastMinimum[request.URL.Path] =
		request.Header.Get(identityMinimumHeader)
	writer.Header().Set("Cache-Control", "private, no-store")
	writer.Header().Set(identityRevisionHeader,
		strconv.FormatUint(document.revision, 10))
	writer.Header().Set("ETag", document.etag)
	if request.Header.Get("If-None-Match") == document.etag {
		writer.WriteHeader(http.StatusNotModified)
		return
	}
	writer.Header().Set("Content-Type", IdentitySnapshotMediaType)
	_, _ = writer.Write(document.payload)
}

func (state *remoteIdentityState) minimum(path string) string {
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.lastMinimum[path]
}

func signedRemoteIdentity(t *testing.T, purpose string, revision uint64,
	disabled bool, now time.Time) remoteIdentityDocument {
	t.Helper()
	publicKey, privateKey := identityTestKey()
	_ = publicKey
	secret := ""
	if purpose == ProofSnapshotPurpose && !disabled {
		secret = `,"secret_b64":"` +
			base64.RawURLEncoding.EncodeToString(testDeviceSecret) + `"`
	}
	unsigned := fmt.Sprintf(
		`{"version":2,"revision":%d,"purpose":"%s",`+
			`"issued_at":"%s","valid_until":"%s",`+
			`"devices":[{"device_id":"device-1"%s,"disabled":%t}]}`,
		revision, purpose, now.Add(-time.Minute).Format(time.RFC3339),
		now.Add(10*time.Minute).Format(time.RFC3339), secret, disabled)
	payload, err := SignRegistrySnapshot(strings.NewReader(unsigned),
		"identity-test-1", privateKey, now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ParseSignedRegistrySnapshot(bytesReader(payload), publicKey,
		"identity-test-1", now)
	if err != nil {
		t.Fatal(err)
	}
	return remoteIdentityDocument{
		payload: payload, revision: revision,
		etag: fmt.Sprintf("\"sha256:%x\"", snapshot.digest),
	}
}

type identityTestPKI struct {
	serverCertificate tls.Certificate
	client            *http.Client
	caPool            *x509.CertPool
	caPath            string
	clientCertPath    string
	clientKeyPath     string
}

func newIdentityTestPKI(t *testing.T) identityTestPKI {
	t.Helper()
	now := time.Now().UTC()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "identity-test-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate,
		caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	createLeaf := func(serial int64, commonName string,
		usage x509.ExtKeyUsage, server bool) (tls.Certificate, []byte, []byte) {
		publicKey, privateKey, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: commonName},
			NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{usage},
		}
		if server {
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		certificateDER, certificateErr := x509.CreateCertificate(rand.Reader,
			template, caCertificate, publicKey, caPrivate)
		if certificateErr != nil {
			t.Fatal(certificateErr)
		}
		keyDER, keyErr := x509.MarshalPKCS8PrivateKey(privateKey)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		certificatePEM := pem.EncodeToMemory(
			&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
		keyPEM := pem.EncodeToMemory(
			&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		keypair, keyErr := tls.X509KeyPair(certificatePEM, keyPEM)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		return keypair, certificatePEM, keyPEM
	}
	serverCertificate, _, _ := createLeaf(2, "identity-source",
		x509.ExtKeyUsageServerAuth, true)
	_, clientCertificatePEM, clientKeyPEM := createLeaf(3,
		"gateway-workload", x509.ExtKeyUsageClientAuth, false)
	directory := t.TempDir()
	caPath := filepath.Join(directory, "ca.pem")
	clientCertificatePath := filepath.Join(directory, "client.pem")
	clientKeyPath := filepath.Join(directory, "client-key.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := os.WriteFile(caPath, caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientCertificatePath,
		clientCertificatePEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientKeyPath, clientKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewIdentityMTLSClient(caPath, clientCertificatePath,
		clientKeyPath, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCertificate)
	return identityTestPKI{
		serverCertificate: serverCertificate,
		client:            client,
		caPool:            pool,
		caPath:            caPath,
		clientCertPath:    clientCertificatePath,
		clientKeyPath:     clientKeyPath,
	}
}

func startIdentityMTLSServer(t *testing.T, pki identityTestPKI,
	handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{pki.serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.caPool,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func writeIdentityPublicKey(t *testing.T) string {
	t.Helper()
	publicKey, _ := identityTestKey()
	path := filepath.Join(t.TempDir(), "identity.pub")
	if err := os.WriteFile(path, []byte(
		base64.RawURLEncoding.EncodeToString(publicKey)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRemoteIdentityReloadUsesMTLSConditionalFetchAndRejectsRollback(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	path := "/v1/device-identity/access"
	state := &remoteIdentityState{
		documents: map[string]remoteIdentityDocument{
			path: signedRemoteIdentity(t, AccessSnapshotPurpose, 50, false, now),
		},
		lastMinimum: make(map[string]string), requests: make(map[string]int),
	}
	pki := newIdentityTestPKI(t)
	server := startIdentityMTLSServer(t, pki, http.HandlerFunc(state.handler))
	registry, reloader, err := LoadRemoteReloadableRegistry(context.Background(),
		server.URL+path, writeIdentityPublicKey(t), "identity-test-1",
		AccessSnapshotPurpose, 50, pki.client, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if registry.Status().Revision != 50 || !registry.DeviceAllowed("device-1") ||
		state.minimum(path) != "50" {
		t.Fatalf("initial remote registry: status=%#v min=%q",
			registry.Status(), state.minimum(path))
	}
	if changed, status, err := reloader.Reload(); err != nil || changed ||
		status.Revision != 50 {
		t.Fatalf("conditional reload: changed=%v status=%#v err=%v",
			changed, status, err)
	}
	state.set(path, signedRemoteIdentity(t, AccessSnapshotPurpose, 51, true, now))
	if changed, status, err := reloader.Reload(); err != nil || !changed ||
		status.Revision != 51 || registry.DeviceAllowed("device-1") {
		t.Fatalf("remote revoke: changed=%v status=%#v err=%v",
			changed, status, err)
	}
	state.set(path, signedRemoteIdentity(t, AccessSnapshotPurpose, 50, false, now))
	if changed, _, err := reloader.Reload(); changed ||
		!errors.Is(err, ErrSnapshotRollback) {
		t.Fatalf("remote rollback: changed=%v err=%v", changed, err)
	}
	if state.minimum(path) != "51" {
		t.Fatalf("active revision not sent as minimum: %q", state.minimum(path))
	}
	state.set(path, signedRemoteIdentity(t, AccessSnapshotPurpose, 51, false, now))
	if changed, _, err := reloader.Reload(); changed ||
		!errors.Is(err, ErrSnapshotEquivocation) {
		t.Fatalf("remote equivocation: changed=%v err=%v", changed, err)
	}
}

func TestRemoteIdentityFourConsumersConvergeOnOneFleetRevision(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	accessPath := "/v1/device-identity/access"
	proofPath := "/v1/device-identity/proof"
	state := &remoteIdentityState{
		documents: map[string]remoteIdentityDocument{
			accessPath: signedRemoteIdentity(t, AccessSnapshotPurpose, 70, false, now),
			proofPath:  signedRemoteIdentity(t, ProofSnapshotPurpose, 70, false, now),
		},
		lastMinimum: make(map[string]string), requests: make(map[string]int),
	}
	pki := newIdentityTestPKI(t)
	server := startIdentityMTLSServer(t, pki, http.HandlerFunc(state.handler))
	publicKeyPath := writeIdentityPublicKey(t)
	type consumer struct {
		registry *Registry
		reloader *RemoteRegistryReloader
	}
	consumers := make([]consumer, 0, 4)
	for _, purpose := range []string{
		AccessSnapshotPurpose, AccessSnapshotPurpose,
		AccessSnapshotPurpose, ProofSnapshotPurpose,
	} {
		registry, reloader, err := LoadRemoteReloadableRegistry(
			context.Background(), server.URL+"/v1/device-identity/"+purpose,
			publicKeyPath, "identity-test-1", purpose, 70, pki.client,
			func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		consumers = append(consumers, consumer{registry: registry, reloader: reloader})
	}
	state.set(accessPath,
		signedRemoteIdentity(t, AccessSnapshotPurpose, 71, true, now))
	state.set(proofPath,
		signedRemoteIdentity(t, ProofSnapshotPurpose, 71, true, now))
	var wait sync.WaitGroup
	errorsFound := make(chan error, len(consumers))
	for index := range consumers {
		wait.Add(1)
		go func(current consumer) {
			defer wait.Done()
			changed, status, err := current.reloader.Reload()
			if err != nil || !changed || status.Revision != 71 ||
				current.registry.DeviceAllowed("device-1") {
				errorsFound <- fmt.Errorf("changed=%v status=%#v err=%w",
					changed, status, err)
			}
		}(consumers[index])
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
}

func TestRemoteIdentityRejectsTransportAndResponsePolicyViolations(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	publicKeyPath := writeIdentityPublicKey(t)
	pki := newIdentityTestPKI(t)
	document := signedRemoteIdentity(t, AccessSnapshotPurpose, 80, false, now)
	validHeaders := func(writer http.ResponseWriter) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Type", IdentitySnapshotMediaType)
		writer.Header().Set(identityRevisionHeader, "80")
		writer.Header().Set("ETag", document.etag)
	}
	cases := map[string]func(http.ResponseWriter, *http.Request){
		"redirect": func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Location", "/other")
			writer.WriteHeader(http.StatusFound)
		},
		"cacheable": func(writer http.ResponseWriter, _ *http.Request) {
			validHeaders(writer)
			writer.Header().Set("Cache-Control", "max-age=60")
			_, _ = writer.Write(document.payload)
		},
		"compressed": func(writer http.ResponseWriter, _ *http.Request) {
			validHeaders(writer)
			writer.Header().Set("Content-Encoding", "gzip")
			_, _ = writer.Write(document.payload)
		},
		"wrong content type": func(writer http.ResponseWriter, _ *http.Request) {
			validHeaders(writer)
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write(document.payload)
		},
		"wrong revision": func(writer http.ResponseWriter, _ *http.Request) {
			validHeaders(writer)
			writer.Header().Set(identityRevisionHeader, "81")
			_, _ = writer.Write(document.payload)
		},
		"weak etag": func(writer http.ResponseWriter, _ *http.Request) {
			validHeaders(writer)
			writer.Header().Set("ETag", "W/"+document.etag)
			_, _ = writer.Write(document.payload)
		},
	}
	for name, handler := range cases {
		t.Run(name, func(t *testing.T) {
			server := startIdentityMTLSServer(t, pki, http.HandlerFunc(handler))
			if _, _, err := LoadRemoteReloadableRegistry(context.Background(),
				server.URL+"/v1/device-identity/access", publicKeyPath,
				"identity-test-1", AccessSnapshotPurpose, 80, pki.client,
				func() time.Time { return now }); err == nil {
				t.Fatal("remote response policy violation was accepted")
			}
		})
	}
	plain := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter,
		_ *http.Request) {
		validHeaders(writer)
		_, _ = writer.Write(document.payload)
	}))
	defer plain.Close()
	if _, _, err := LoadRemoteReloadableRegistry(context.Background(),
		plain.URL+"/v1/device-identity/access", publicKeyPath,
		"identity-test-1", AccessSnapshotPurpose, 80, pki.client,
		func() time.Time { return now }); err == nil {
		t.Fatal("plaintext remote identity endpoint was accepted")
	}

	server := startIdentityMTLSServer(t, pki, http.HandlerFunc(func(
		writer http.ResponseWriter, _ *http.Request) {
		validHeaders(writer)
		_, _ = writer.Write(document.payload)
	}))
	noClientCertificate := server.Client()
	noClientCertificate.Timeout = 2 * time.Second
	if _, _, err := LoadRemoteReloadableRegistry(context.Background(),
		server.URL+"/v1/device-identity/access", publicKeyPath,
		"identity-test-1", AccessSnapshotPurpose, 80, noClientCertificate,
		func() time.Time { return now }); err == nil {
		t.Fatal("identity source accepted a client without workload certificate")
	}
	if _, _, err := LoadRemoteReloadableRegistry(context.Background(),
		server.URL+"/v1/device-identity/proof", publicKeyPath,
		"identity-test-1", AccessSnapshotPurpose, 80, pki.client,
		func() time.Time { return now }); err == nil {
		t.Fatal("access consumer accepted proof endpoint URL")
	}
	if err := os.Chmod(pki.clientKeyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewIdentityMTLSClient(pki.caPath, pki.clientCertPath,
		pki.clientKeyPath, 2*time.Second); err == nil {
		t.Fatal("broadly readable workload private key was accepted")
	}
}

func TestRemoteIdentityRequestTimeoutFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	pki := newIdentityTestPKI(t)
	server := startIdentityMTLSServer(t, pki, http.HandlerFunc(func(
		_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	client := *pki.client
	client.Timeout = time.Second
	started := time.Now()
	registry, _, err := LoadRemoteReloadableRegistry(context.Background(),
		server.URL+"/v1/device-identity/access", writeIdentityPublicKey(t),
		"identity-test-1", AccessSnapshotPurpose, 1, &client,
		func() time.Time { return now })
	if err == nil || registry != nil || time.Since(started) > 2*time.Second {
		t.Fatalf("timeout fail closed: registry=%v elapsed=%s err=%v",
			registry, time.Since(started), err)
	}
}
