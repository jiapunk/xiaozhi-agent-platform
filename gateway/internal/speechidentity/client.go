package speechidentity

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	maximumCertificateBytes = 1 << 20
	maximumPrivateKeyBytes  = 64 << 10
)

var bindingSetDomain = []byte("XIAOZHI-SPEECH-WORKLOAD-BINDINGS-V1\x00")

// Files identifies one private speech-adapter trust boundary. STT and TTS must
// each use a different Files set and are checked for content-level isolation.
type Files struct {
	CACertificateFile     string
	ClientCertificateFile string
	ClientPrivateKeyFile  string
}

// Binding contains only non-secret certificate digests suitable for receipts.
type Binding struct {
	CATrustSetSHA256 string
	ClientLeafSHA256 string
	caDigests        []string
}

// LoadMTLSClient loads a private trust store and client identity into a
// proxy-free, redirect-free, TLS-1.3-only HTTP client.
func LoadMTLSClient(files Files, handshakeTimeout time.Duration) (*http.Client, Binding, error) {
	return loadMTLSClient(files, handshakeTimeout, time.Now())
}

func loadMTLSClient(files Files, handshakeTimeout time.Duration, now time.Time) (*http.Client, Binding, error) {
	if handshakeTimeout < 100*time.Millisecond || handshakeTimeout > 30*time.Second || now.IsZero() {
		return nil, Binding{}, fmt.Errorf("speech mTLS timing policy is invalid")
	}
	caPEM, err := readCredential(files.CACertificateFile, maximumCertificateBytes, false)
	if err != nil {
		return nil, Binding{}, fmt.Errorf("speech CA: %w", err)
	}
	certificatePEM, err := readCredential(files.ClientCertificateFile, maximumCertificateBytes, false)
	if err != nil {
		return nil, Binding{}, fmt.Errorf("speech client certificate: %w", err)
	}
	keyPEM, err := readCredential(files.ClientPrivateKeyFile, maximumPrivateKeyBytes, true)
	if err != nil {
		return nil, Binding{}, fmt.Errorf("speech client private key: %w", err)
	}

	roots, caDigest, caDigests, err := parseCAs(caPEM, now)
	if err != nil {
		return nil, Binding{}, err
	}
	leaf, leafDigest, err := parseClientChain(certificatePEM, now)
	if err != nil {
		return nil, Binding{}, err
	}
	if err := validatePrivateKeyPEM(keyPEM); err != nil {
		return nil, Binding{}, err
	}
	identity, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, Binding{}, fmt.Errorf("speech client certificate and key do not match")
	}
	identity.Leaf = leaf

	dialer := &net.Dialer{Timeout: handshakeTimeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     false,
		DisableCompression:    true,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   handshakeTimeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:             tls.VersionTLS13,
			MaxVersion:             tls.VersionTLS13,
			RootCAs:                roots,
			Certificates:           []tls.Certificate{identity},
			SessionTicketsDisabled: true,
		},
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("speech workload redirects are disabled")
		},
	}
	return client, Binding{
		CATrustSetSHA256: caDigest, ClientLeafSHA256: leafDigest,
		caDigests: caDigests,
	}, nil
}

// ValidateIsolation rejects shared server trust or client identity between the
// STT and TTS boundaries, even when different filesystem paths were supplied.
func ValidateIsolation(stt, tts Binding) error {
	if !validDigest(stt.CATrustSetSHA256) || !validDigest(stt.ClientLeafSHA256) ||
		!validDigest(tts.CATrustSetSHA256) || !validDigest(tts.ClientLeafSHA256) ||
		!validDigestList(stt.caDigests) || !validDigestList(tts.caDigests) {
		return fmt.Errorf("speech workload binding is invalid")
	}
	if stt.CATrustSetSHA256 == tts.CATrustSetSHA256 {
		return fmt.Errorf("STT and TTS must not share a CA trust set")
	}
	if stt.ClientLeafSHA256 == tts.ClientLeafSHA256 {
		return fmt.Errorf("STT and TTS must not share a client identity")
	}
	sttCAs := make(map[string]bool, len(stt.caDigests))
	for _, digest := range stt.caDigests {
		sttCAs[digest] = true
	}
	for _, digest := range tts.caDigests {
		if sttCAs[digest] {
			return fmt.Errorf("STT and TTS must not share a CA certificate")
		}
	}
	return nil
}

// BindingSetDigest binds a qualification receipt to both isolated mTLS
// identities without disclosing certificate material.
func BindingSetDigest(stt, tts Binding) string {
	if ValidateIsolation(stt, tts) != nil {
		return ""
	}
	hash := sha256.New()
	_, _ = hash.Write(bindingSetDomain)
	for _, value := range []string{
		"stt_ca=" + stt.CATrustSetSHA256,
		"stt_client=" + stt.ClientLeafSHA256,
		"tts_ca=" + tts.CATrustSetSHA256,
		"tts_client=" + tts.ClientLeafSHA256,
	} {
		_, _ = hash.Write([]byte(value + "\n"))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func readCredential(name string, maximum int64, confidential bool) ([]byte, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("credential file is required")
	}
	info, err := os.Stat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum {
		return nil, fmt.Errorf("credential must be a bounded regular file")
	}
	if confidential && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("private key permissions must be 0600 or stricter")
	}
	data, err := os.ReadFile(name)
	if err != nil || int64(len(data)) != info.Size() {
		return nil, fmt.Errorf("cannot read credential file")
	}
	return data, nil
}

func parseCAs(data []byte, now time.Time) (*x509.CertPool, string, []string, error) {
	certificates, err := parseCertificatePEM(data)
	if err != nil || len(certificates) == 0 {
		return nil, "", nil, fmt.Errorf("speech CA bundle is invalid")
	}
	canonical := make([][]byte, 0, len(certificates))
	certificateDigests := make([]string, 0, len(certificates))
	seen := make(map[string]bool, len(certificates))
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		if !certificate.BasicConstraintsValid || !certificate.IsCA ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
			now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return nil, "", nil, fmt.Errorf("speech CA certificate is not a currently valid signing CA")
		}
		key := string(certificate.Raw)
		if seen[key] {
			return nil, "", nil, fmt.Errorf("speech CA bundle contains a duplicate certificate")
		}
		seen[key] = true
		canonical = append(canonical, certificate.Raw)
		digest := sha256.Sum256(certificate.Raw)
		certificateDigests = append(certificateDigests, hex.EncodeToString(digest[:]))
		pool.AddCert(certificate)
	}
	sort.Slice(canonical, func(left, right int) bool {
		return bytes.Compare(canonical[left], canonical[right]) < 0
	})
	sort.Strings(certificateDigests)
	hash := sha256.New()
	_, _ = hash.Write([]byte("XIAOZHI-SPEECH-CA-TRUST-SET-V1\x00"))
	var length [4]byte
	for _, der := range canonical {
		binary.BigEndian.PutUint32(length[:], uint32(len(der)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(der)
	}
	return pool, hex.EncodeToString(hash.Sum(nil)), certificateDigests, nil
}

func parseClientChain(data []byte, now time.Time) (*x509.Certificate, string, error) {
	certificates, err := parseCertificatePEM(data)
	if err != nil || len(certificates) == 0 {
		return nil, "", fmt.Errorf("speech client certificate chain is invalid")
	}
	leaf := certificates[0]
	clientAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if leaf.IsCA || !leaf.BasicConstraintsValid || !clientAuth ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, "", fmt.Errorf("speech client leaf is not a currently valid client-auth certificate")
	}
	for index := 1; index < len(certificates); index++ {
		if !certificates[index].IsCA || !certificates[index].BasicConstraintsValid ||
			certificates[index].KeyUsage&x509.KeyUsageCertSign == 0 ||
			now.Before(certificates[index].NotBefore) || !now.Before(certificates[index].NotAfter) ||
			certificates[index-1].CheckSignatureFrom(certificates[index]) != nil {
			return nil, "", fmt.Errorf("speech client certificate chain is invalid")
		}
	}
	digest := sha256.Sum256(leaf.Raw)
	return leaf, hex.EncodeToString(digest[:]), nil
}

func parseCertificatePEM(data []byte) ([]*x509.Certificate, error) {
	rest := bytes.TrimSpace(data)
	var certificates []*x509.Certificate
	for len(rest) > 0 {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, fmt.Errorf("unexpected PEM data")
		}
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("invalid certificate PEM")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
		rest = bytes.TrimSpace(remaining)
	}
	return certificates, nil
}

func validatePrivateKeyPEM(data []byte) error {
	rest := bytes.TrimSpace(data)
	if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
		return fmt.Errorf("speech client private key PEM is invalid")
	}
	block, remaining := pem.Decode(rest)
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(remaining)) != 0 {
		return fmt.Errorf("speech client private key PEM is invalid")
	}
	switch block.Type {
	case "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY":
		return nil
	default:
		return fmt.Errorf("speech client private key PEM type is invalid")
	}
}

func validDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validDigestList(values []string) bool {
	if len(values) == 0 {
		return false
	}
	previous := ""
	for _, value := range values {
		if !validDigest(value) || (previous != "" && value <= previous) {
			return false
		}
		previous = value
	}
	return true
}
