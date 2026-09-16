package telemetry

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"xiaozhi-agent-platform/gateway/internal/speechidentity"
)

type telemetryTestAuthority struct {
	certificate *x509.Certificate
	key         ed25519.PrivateKey
	pem         []byte
}

func newTelemetryAuthority(t *testing.T) telemetryTestAuthority {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: "telemetry-test-ca"},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template,
		publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return telemetryTestAuthority{certificate: certificate, key: privateKey,
		pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func newTelemetryIdentity(t *testing.T, authority telemetryTestAuthority,
	name string, usage x509.ExtKeyUsage) (tls.Certificate, []byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	if usage == x509.ExtKeyUsageServerAuth {
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, template,
		authority.certificate, publicKey, authority.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair, certificatePEM, privateKeyPEM
}

func telemetryIdentityFiles(t *testing.T, authority telemetryTestAuthority,
	certificatePEM, keyPEM []byte) speechidentity.Files {
	t.Helper()
	directory := t.TempDir()
	files := speechidentity.Files{
		CACertificateFile:     filepath.Join(directory, "telemetry-ca.pem"),
		ClientCertificateFile: filepath.Join(directory, "telemetry-client.crt"),
		ClientPrivateKeyFile:  filepath.Join(directory, "telemetry-client.key"),
	}
	for path, value := range map[string][]byte{
		files.CACertificateFile:     authority.pem,
		files.ClientCertificateFile: certificatePEM,
		files.ClientPrivateKeyFile:  keyPEM,
	} {
		mode := os.FileMode(0o444)
		if path == files.ClientPrivateKeyFile {
			mode = 0o600
		}
		if err := os.WriteFile(path, value, mode); err != nil {
			t.Fatal(err)
		}
	}
	return files
}

func TestRuntimeExportsContentFreeOTLPOverExactTLS13MTLS(t *testing.T) {
	authority := newTelemetryAuthority(t)
	clientPair, clientPEM, clientKey := newTelemetryIdentity(
		t, authority, "gateway-telemetry", x509.ExtKeyUsageClientAuth)
	_ = clientPair
	serverPair, _, _ := newTelemetryIdentity(
		t, authority, "collector", x509.ExtKeyUsageServerAuth)
	roots := x509.NewCertPool()
	roots.AddCert(authority.certificate)
	requests := make(chan int, 1)
	collector := httptest.NewUnstartedServer(http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodPost || request.URL.Path != "/v1/traces" ||
				request.URL.RawQuery != "" || request.TLS == nil ||
				request.TLS.Version != tls.VersionTLS13 ||
				len(request.TLS.PeerCertificates) != 1 ||
				request.Header.Get("Authorization") != "" ||
				request.Header.Get("baggage") != "" {
				t.Error("unsafe OTLP request")
			}
			body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20))
			if err != nil || len(body) == 0 {
				t.Errorf("empty OTLP body: len=%d err=%v", len(body), err)
			}
			requests <- len(body)
			writer.WriteHeader(http.StatusOK)
		}))
	collector.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{serverPair},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: roots,
	}
	collector.StartTLS()
	defer collector.Close()

	runtime, err := New(context.Background(), Settings{
		Enabled: true, Service: "gateway", DeploymentID: "pilot-test",
		Endpoint:       collector.URL + "/v1/traces",
		IdentityFiles:  telemetryIdentityFiles(t, authority, clientPEM, clientKey),
		SampleRatioPPM: 1_000_000, ExportTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, span := runtime.tracer().Start(context.Background(), "gateway.device")
	_ = ctx
	span.SetAttributes(attribute.String("xiaozhi.result_class", "success"))
	span.End()
	shutdownContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := runtime.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	select {
	case size := <-requests:
		if size <= 0 {
			t.Fatal("collector received an empty request")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("collector did not receive OTLP trace")
	}
	if runtime.CertificateBinding().CATrustSetSHA256 == "" ||
		runtime.CertificateBinding().ClientLeafSHA256 == "" {
		t.Fatal("telemetry certificate binding was not retained")
	}
}

func TestRuntimeRejectsWeakTelemetryPrivateKeyPermissions(t *testing.T) {
	authority := newTelemetryAuthority(t)
	_, clientPEM, clientKey := newTelemetryIdentity(
		t, authority, "gateway-telemetry", x509.ExtKeyUsageClientAuth)
	files := telemetryIdentityFiles(t, authority, clientPEM, clientKey)
	if err := os.Chmod(files.ClientPrivateKeyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), Settings{
		Enabled: true, Service: "gateway", DeploymentID: "pilot-test",
		Endpoint: "https://collector.example/v1/traces", IdentityFiles: files,
		SampleRatioPPM: 1_000_000, ExportTimeout: time.Second,
	}); err == nil {
		t.Fatal("world-readable telemetry key was accepted")
	}
}

func TestRuntimeRevalidatesDirectSettings(t *testing.T) {
	clearTelemetryEnvironment(t)
	for _, settings := range []Settings{
		{Service: "unknown"},
		{Service: "gateway", Endpoint: "https://collector.example/v1/traces"},
		{Enabled: true, Service: "gateway", DeploymentID: "pilot-test",
			Endpoint: "http://collector.example/v1/traces",
			IdentityFiles: speechidentity.Files{
				CACertificateFile: "ca", ClientCertificateFile: "cert",
				ClientPrivateKeyFile: "key"},
			SampleRatioPPM: 1_000_000, ExportTimeout: time.Second},
		{Enabled: true, Service: "gateway", DeploymentID: "pilot-test",
			Endpoint: "https://collector.example/v1/traces",
			IdentityFiles: speechidentity.Files{
				CACertificateFile: "relative-ca", ClientCertificateFile: "relative-cert",
				ClientPrivateKeyFile: "relative-key"},
			SampleRatioPPM: 1_000_000, ExportTimeout: time.Second},
	} {
		if _, err := New(context.Background(), settings); err == nil {
			t.Fatalf("unsafe direct telemetry settings were accepted: %#v", settings)
		}
	}
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "authorization=private")
	if _, err := New(context.Background(), Settings{Service: "gateway"}); err == nil {
		t.Fatal("direct runtime ignored a standard OTel environment override")
	}
}
