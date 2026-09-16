package accountauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

type testPKI struct {
	caPEM         []byte
	serverCertPEM []byte
	serverKeyPEM  []byte
	clientCertPEM []byte
	clientKeyPEM  []byte
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	now := time.Now().UTC()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "product-test-ca"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
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
	issue := func(serial int64, commonName string,
		usage x509.ExtKeyUsage, server bool) ([]byte, []byte) {
		publicKey, privateKey, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: commonName},
			NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{usage},
		}
		if server {
			template.DNSNames = []string{"localhost"}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
		}
		certificateDER, certificateErr := x509.CreateCertificate(rand.Reader,
			template, caCertificate, publicKey, caPrivate)
		if certificateErr != nil {
			t.Fatal(certificateErr)
		}
		privateDER, marshalErr := x509.MarshalPKCS8PrivateKey(privateKey)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE",
				Bytes: certificateDER}), pem.EncodeToMemory(&pem.Block{
				Type: "PRIVATE KEY", Bytes: privateDER})
	}
	serverCertificate, serverKey := issue(2, "account-service",
		x509.ExtKeyUsageServerAuth, true)
	clientCertificate, clientKey := issue(3, "control-plane",
		x509.ExtKeyUsageClientAuth, false)
	return testPKI{
		caPEM:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		serverCertPEM: serverCertificate, serverKeyPEM: serverKey,
		clientCertPEM: clientCertificate, clientKeyPEM: clientKey,
	}
}

func TestRealMTLSHandshakeConnectsControlPlaneIntrospector(t *testing.T) {
	_, _, handler, _, issued := activeHandlerFixture(t)
	pki := newTestPKI(t)
	serverTLS, err := NewIntrospectionMTLSServerConfig(
		pki.caPEM, pki.serverCertPEM, pki.serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()
	client, err := auth.NewCompanionIntrospectionMTLSClient(
		pki.caPEM, pki.clientCertPEM, pki.clientKeyPEM, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	introspector, err := auth.NewCompanionTokenIntrospector(
		server.URL+auth.CompanionIntrospectionPath, client)
	if err != nil {
		t.Fatal(err)
	}
	if err := introspector.Authorize(context.Background(), issued.Claims,
		time.Now().UTC()); err != nil {
		t.Fatalf("real mTLS introspection: %v", err)
	}

	unauthenticated := server.Client()
	unauthenticated.Transport.(*http.Transport).TLSClientConfig.Certificates = nil
	request, err := http.NewRequest(http.MethodPost,
		server.URL+auth.CompanionIntrospectionPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unauthenticated.Do(request); err == nil {
		t.Fatal("client without workload certificate reached account service")
	}
}

func TestServerTLSConfigurationAndCredentialFilesAreStrict(t *testing.T) {
	pki := newTestPKI(t)
	configuration, err := NewIntrospectionMTLSServerConfig(
		pki.caPEM, pki.serverCertPEM, pki.serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.MinVersion == 0 ||
		configuration.ClientAuth != tls.RequireAndVerifyClientCert ||
		configuration.ClientCAs == nil ||
		!configuration.SessionTicketsDisabled {
		t.Fatalf("unsafe server TLS configuration: %#v", configuration)
	}
	if _, err := NewIntrospectionMTLSServerConfig(nil,
		pki.serverCertPEM, pki.serverKeyPEM); err == nil {
		t.Fatal("missing client CA accepted")
	}
	directory := t.TempDir()
	caFile := filepath.Join(directory, "ca.pem")
	certFile := filepath.Join(directory, "server.pem")
	keyFile := filepath.Join(directory, "server.key")
	for path, data := range map[string][]byte{
		caFile: pki.caPEM, certFile: pki.serverCertPEM, keyFile: pki.serverKeyPEM,
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadIntrospectionMTLSServerConfig(
		caFile, certFile, keyFile); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIntrospectionMTLSServerConfig(
		directory, certFile, keyFile); err == nil {
		t.Fatal("directory credential accepted")
	}
}
