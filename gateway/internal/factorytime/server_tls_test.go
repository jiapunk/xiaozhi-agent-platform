package factorytime

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestMTLSServerConfigRequiresTLS13AndVerifiedClients(t *testing.T) {
	caPEM, certificatePEM, keyPEM := testServerCredentials(t)
	configuration, err := NewMTLSServerConfig(caPEM, certificatePEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.MinVersion != tls.VersionTLS13 ||
		configuration.MaxVersion != tls.VersionTLS13 ||
		configuration.ClientAuth != tls.RequireAndVerifyClientCert ||
		configuration.ClientCAs == nil ||
		!configuration.SessionTicketsDisabled ||
		len(configuration.Certificates) != 1 {
		t.Fatalf("unsafe TLS configuration: %#v", configuration)
	}
	for _, input := range [][3][]byte{
		{nil, certificatePEM, keyPEM},
		{caPEM, nil, keyPEM},
		{caPEM, certificatePEM, nil},
		{[]byte("not a CA"), certificatePEM, keyPEM},
		{caPEM, []byte("not a certificate"), keyPEM},
	} {
		if _, err := NewMTLSServerConfig(input[0], input[1], input[2]); err == nil {
			t.Fatal("invalid TLS material accepted")
		}
	}
}

func testServerCredentials(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "M61 test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate,
		caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "factory.example"},
		DNSNames: []string{"factory.example"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate,
		caTemplate, serverPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(serverPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
}
