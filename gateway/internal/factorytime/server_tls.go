package factorytime

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
)

const maximumCredentialBytes = 64 * 1024

func NewMTLSServerConfig(clientCAPEM, certificatePEM,
	keyPEM []byte) (*tls.Config, error) {
	if len(clientCAPEM) == 0 || len(certificatePEM) == 0 || len(keyPEM) == 0 {
		return nil, fmt.Errorf("invalid factory-time TLS configuration")
	}
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(clientCAPEM) {
		return nil, fmt.Errorf("invalid factory-time client CA")
	}
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid factory-time server identity: %w", err)
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{certificate},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              clientRoots,
		SessionTicketsDisabled: true,
		NextProtos:             []string{"h2", "http/1.1"},
	}, nil
}

func LoadMTLSServerConfig(clientCAFile, certificateFile,
	keyFile string) (*tls.Config, error) {
	clientCAPEM, err := readCredential(clientCAFile, false)
	if err != nil {
		return nil, err
	}
	certificatePEM, err := readCredential(certificateFile, false)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readCredential(keyFile, true)
	if err != nil {
		return nil, err
	}
	return NewMTLSServerConfig(clientCAPEM, certificatePEM, keyPEM)
}

func readCredential(path string, private bool) ([]byte, error) {
	linkStatus, err := os.Lstat(path)
	if err != nil || !linkStatus.Mode().IsRegular() ||
		(private && linkStatus.Mode().Perm()&0o077 != 0) {
		return nil, fmt.Errorf("invalid factory-time credential path or mode")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open factory-time credential: %w", err)
	}
	defer file.Close()
	status, err := file.Stat()
	if err != nil || !os.SameFile(linkStatus, status) ||
		!status.Mode().IsRegular() || status.Size() <= 0 ||
		status.Size() > maximumCredentialBytes {
		return nil, fmt.Errorf("invalid factory-time credential file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumCredentialBytes+1))
	if err != nil || len(data) == 0 || len(data) > maximumCredentialBytes {
		return nil, fmt.Errorf("read factory-time credential")
	}
	return data, nil
}
