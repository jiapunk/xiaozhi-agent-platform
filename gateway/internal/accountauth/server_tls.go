package accountauth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
)

const maximumServerCredentialBytes = 64 * 1024

// NewIntrospectionMTLSServerConfig constructs the private account-service TLS
// boundary. Only workload certificates chaining to clientCAPEM can reach the
// introspection handler.
func NewIntrospectionMTLSServerConfig(clientCAPEM, certificatePEM,
	keyPEM []byte) (*tls.Config, error) {
	if len(clientCAPEM) == 0 || len(certificatePEM) == 0 || len(keyPEM) == 0 {
		return nil, fmt.Errorf("invalid Companion introspection server TLS configuration")
	}
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(clientCAPEM) {
		return nil, fmt.Errorf("invalid Companion introspection client CA")
	}
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid Companion introspection server identity: %w", err)
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS12,
		Certificates:           []tls.Certificate{certificate},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              clientRoots,
		SessionTicketsDisabled: true,
		NextProtos:             []string{"h2", "http/1.1"},
	}, nil
}

func LoadIntrospectionMTLSServerConfig(clientCAFile, certificateFile,
	keyFile string) (*tls.Config, error) {
	clientCAPEM, err := readServerCredential(clientCAFile)
	if err != nil {
		return nil, err
	}
	certificatePEM, err := readServerCredential(certificateFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readServerCredential(keyFile)
	if err != nil {
		return nil, err
	}
	return NewIntrospectionMTLSServerConfig(
		clientCAPEM, certificatePEM, keyPEM)
}

func readServerCredential(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open Companion introspection server credential: %w", err)
	}
	defer file.Close()
	status, err := file.Stat()
	if err != nil || !status.Mode().IsRegular() || status.Size() <= 0 ||
		status.Size() > maximumServerCredentialBytes {
		return nil, fmt.Errorf("invalid Companion introspection server credential file")
	}
	data, err := io.ReadAll(io.LimitReader(file,
		maximumServerCredentialBytes+1))
	if err != nil || len(data) == 0 || len(data) > maximumServerCredentialBytes {
		return nil, fmt.Errorf("read Companion introspection server credential")
	}
	return data, nil
}
