package speechidentity

import (
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
	"sort"
	"strings"
	"testing"
	"time"
)

type testAuthority struct {
	certificate    *x509.Certificate
	key            ed25519.PrivateKey
	certificatePEM []byte
}

type testIdentity struct {
	certificatePEM []byte
	privateKeyPEM  []byte
	tlsCertificate tls.Certificate
}

func newAuthority(t *testing.T, name string) testAuthority {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testAuthority{certificate: certificate, key: privateKey,
		certificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func newIdentity(t *testing.T, authority testAuthority, name string,
	usage x509.ExtKeyUsage, notBefore, notAfter time.Time, isCA bool) testIdentity {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: notBefore, NotAfter: notAfter, BasicConstraintsValid: true, IsCA: isCA,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	if usage == x509.ExtKeyUsageServerAuth {
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, template, authority.certificate, publicKey, authority.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return testIdentity{certificatePEM: certificatePEM,
		privateKeyPEM: privateKeyPEM, tlsCertificate: pair}
}

func writeFiles(t *testing.T, authority testAuthority, identity testIdentity) Files {
	t.Helper()
	directory := t.TempDir()
	files := Files{
		CACertificateFile:     filepath.Join(directory, "ca.pem"),
		ClientCertificateFile: filepath.Join(directory, "client.crt"),
		ClientPrivateKeyFile:  filepath.Join(directory, "client.key"),
	}
	for name, value := range map[string][]byte{
		files.CACertificateFile:     authority.certificatePEM,
		files.ClientCertificateFile: identity.certificatePEM,
		files.ClientPrivateKeyFile:  identity.privateKeyPEM,
	} {
		mode := os.FileMode(0o444)
		if name == files.ClientPrivateKeyFile {
			mode = 0o600
		}
		if err := os.WriteFile(name, value, mode); err != nil {
			t.Fatal(err)
		}
	}
	return files
}

func newFixture(t *testing.T, name string) (testAuthority, testIdentity, testIdentity, Files) {
	t.Helper()
	now := time.Now()
	authority := newAuthority(t, name+"-ca")
	client := newIdentity(t, authority, name+"-client", x509.ExtKeyUsageClientAuth,
		now.Add(-time.Hour), now.Add(12*time.Hour), false)
	server := newIdentity(t, authority, name+"-server", x509.ExtKeyUsageServerAuth,
		now.Add(-time.Hour), now.Add(12*time.Hour), false)
	return authority, client, server, writeFiles(t, authority, client)
}

func startMTLSServer(t *testing.T, authority testAuthority, server testIdentity,
	minimum, maximum uint16, handler http.Handler) *httptest.Server {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(authority.certificate)
	service := httptest.NewUnstartedServer(handler)
	service.TLS = &tls.Config{
		MinVersion: minimum, MaxVersion: maximum,
		Certificates: []tls.Certificate{server.tlsCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: roots,
	}
	service.StartTLS()
	t.Cleanup(service.Close)
	return service
}

func TestMTLSClientPresentsIdentityAndRequiresTLS13(t *testing.T) {
	authority, _, serverIdentity, files := newFixture(t, "stt")
	seen := make(chan uint16, 1)
	service := startMTLSServer(t, authority, serverIdentity,
		tls.VersionTLS13, tls.VersionTLS13, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.TLS == nil || len(request.TLS.PeerCertificates) != 1 {
				t.Error("server did not receive one client leaf")
			}
			seen <- request.TLS.Version
			writer.WriteHeader(http.StatusNoContent)
		}))
	client, binding, err := LoadMTLSClient(files, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(service.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent || <-seen != tls.VersionTLS13 ||
		!validDigest(binding.CATrustSetSHA256) || !validDigest(binding.ClientLeafSHA256) {
		t.Fatalf("unexpected mTLS response or binding: status=%d binding=%#v", response.StatusCode, binding)
	}
	if _, err := http.Get(service.URL); err == nil {
		t.Fatal("anonymous speech client was accepted")
	}
}

func TestMTLSClientRejectsWrongCAAndTLS12(t *testing.T) {
	_, _, _, files := newFixture(t, "client")
	client, _, err := LoadMTLSClient(files, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	otherCA, _, otherServer, _ := newFixture(t, "other")
	wrongCA := startMTLSServer(t, otherCA, otherServer,
		tls.VersionTLS13, tls.VersionTLS13, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if _, err := client.Get(wrongCA.URL); err == nil {
		t.Fatal("speech server under an unrelated CA was accepted")
	}

	authority, _, server, compatibleFiles := newFixture(t, "legacy")
	legacyClient, _, err := LoadMTLSClient(compatibleFiles, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	legacy := startMTLSServer(t, authority, server,
		tls.VersionTLS12, tls.VersionTLS12, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if _, err := legacyClient.Get(legacy.URL); err == nil {
		t.Fatal("TLS 1.2 speech service was accepted")
	}
}

func TestMTLSClientDisablesRedirects(t *testing.T) {
	authority, _, server, files := newFixture(t, "redirect")
	service := startMTLSServer(t, authority, server,
		tls.VersionTLS13, tls.VersionTLS13, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			http.Redirect(writer, request, "/other", http.StatusFound)
		}))
	client, _, err := LoadMTLSClient(files, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(service.URL); err == nil || !strings.Contains(err.Error(), "redirects are disabled") {
		t.Fatalf("redirect was not rejected: %v", err)
	}
}

func TestLoadRejectsInvalidIdentityMaterial(t *testing.T) {
	now := time.Now()
	authority := newAuthority(t, "policy-ca")
	valid := newIdentity(t, authority, "valid", x509.ExtKeyUsageClientAuth,
		now.Add(-time.Hour), now.Add(time.Hour), false)
	serverOnly := newIdentity(t, authority, "server", x509.ExtKeyUsageServerAuth,
		now.Add(-time.Hour), now.Add(time.Hour), false)
	expired := newIdentity(t, authority, "expired", x509.ExtKeyUsageClientAuth,
		now.Add(-2*time.Hour), now.Add(-time.Hour), false)
	caLeaf := newIdentity(t, authority, "ca-leaf", x509.ExtKeyUsageClientAuth,
		now.Add(-time.Hour), now.Add(time.Hour), true)
	otherAuthority := newAuthority(t, "other-ca")
	other := newIdentity(t, otherAuthority, "other", x509.ExtKeyUsageClientAuth,
		now.Add(-time.Hour), now.Add(time.Hour), false)

	for name, identity := range map[string]testIdentity{
		"server-only": serverOnly, "expired": expired, "ca-leaf": caLeaf,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := LoadMTLSClient(writeFiles(t, authority, identity), time.Second); err == nil {
				t.Fatal("invalid client leaf was accepted")
			}
		})
	}
	t.Run("key-mismatch", func(t *testing.T) {
		files := writeFiles(t, authority, valid)
		if err := os.WriteFile(files.ClientPrivateKeyFile, other.privateKeyPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadMTLSClient(files, time.Second); err == nil {
			t.Fatal("mismatched private key was accepted")
		}
	})
	t.Run("weak-key-mode", func(t *testing.T) {
		files := writeFiles(t, authority, valid)
		if err := os.Chmod(files.ClientPrivateKeyFile, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadMTLSClient(files, time.Second); err == nil {
			t.Fatal("world-readable private key was accepted")
		}
	})
	t.Run("malformed-ca", func(t *testing.T) {
		files := writeFiles(t, authority, valid)
		if err := os.Chmod(files.CACertificateFile, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(files.CACertificateFile, []byte("junk\n"), 0o444); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadMTLSClient(files, time.Second); err == nil {
			t.Fatal("malformed CA was accepted")
		}
	})
	t.Run("duplicate-ca", func(t *testing.T) {
		files := writeFiles(t, authority, valid)
		if err := os.Chmod(files.CACertificateFile, 0o644); err != nil {
			t.Fatal(err)
		}
		duplicate := append(append([]byte(nil), authority.certificatePEM...),
			authority.certificatePEM...)
		if err := os.WriteFile(files.CACertificateFile, duplicate, 0o444); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadMTLSClient(files, time.Second); err == nil {
			t.Fatal("duplicate CA certificate was accepted")
		}
	})
}

func TestBindingIsolationUsesCertificateContent(t *testing.T) {
	_, _, _, sttFiles := newFixture(t, "stt-isolation")
	_, _, _, ttsFiles := newFixture(t, "tts-isolation")
	_, stt, err := LoadMTLSClient(sttFiles, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, tts, err := LoadMTLSClient(ttsFiles, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateIsolation(stt, tts); err != nil || !validDigest(BindingSetDigest(stt, tts)) {
		t.Fatalf("isolated bindings rejected: %v", err)
	}
	if err := ValidateIsolation(stt, stt); err == nil || BindingSetDigest(stt, stt) != "" {
		t.Fatal("shared speech identity was accepted")
	}
	sharedCA := tts
	sharedCA.CATrustSetSHA256 = stt.CATrustSetSHA256
	if err := ValidateIsolation(stt, sharedCA); err == nil {
		t.Fatal("shared speech trust set was accepted")
	}
	overlappingCA := tts
	overlappingCA.caDigests = append([]string(nil), tts.caDigests...)
	overlappingCA.caDigests = append(overlappingCA.caDigests, stt.caDigests[0])
	sort.Strings(overlappingCA.caDigests)
	if err := ValidateIsolation(stt, overlappingCA); err == nil {
		t.Fatal("overlapping speech CA certificate was accepted")
	}
}
