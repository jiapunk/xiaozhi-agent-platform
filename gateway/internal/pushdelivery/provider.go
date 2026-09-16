// Package pushdelivery implements provider transports for the fixed,
// content-free action-consent wake. It never accepts arbitrary notification
// text, URLs, challenge identifiers or model output.
package pushdelivery

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
)

var (
	ErrInvalid            = errors.New("invalid push delivery")
	ErrUnavailable        = errors.New("push delivery unavailable")
	ErrCredentialRejected = errors.New("provider credential rejected")
)

type DeliveryResult uint8

const (
	DeliveryAccepted DeliveryResult = iota + 1
	DeliveryInvalidInstallation
	DeliveryRetry
)

type Provider interface {
	Send(context.Context, string) (DeliveryResult, error)
}

type BearerTokenProvider interface {
	BearerToken(context.Context) (string, error)
}

func validBearer(value string) bool {
	if len(value) < 16 || len(value) > 8*1024 {
		return false
	}
	for _, character := range []byte(value) {
		if character <= 0x20 || character >= 0x7f {
			return false
		}
	}
	return true
}

func hardenedHTTPClient(client *http.Client, requireClientCertificate bool,
	minimumTLS uint16) (*http.Client, error) {
	if client == nil || minimumTLS < tls.VersionTLS12 {
		return nil, ErrInvalid
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport == nil || transport.Proxy != nil {
		return nil, ErrInvalid
	}
	cloneTransport := transport.Clone()
	tlsConfiguration := cloneTransport.TLSClientConfig
	if tlsConfiguration == nil {
		tlsConfiguration = &tls.Config{}
	} else {
		tlsConfiguration = tlsConfiguration.Clone()
	}
	if tlsConfiguration.InsecureSkipVerify ||
		(tlsConfiguration.MaxVersion != 0 &&
			tlsConfiguration.MaxVersion < minimumTLS) ||
		(requireClientCertificate && len(tlsConfiguration.Certificates) == 0) {
		return nil, ErrInvalid
	}
	if tlsConfiguration.MinVersion < minimumTLS {
		tlsConfiguration.MinVersion = minimumTLS
	}
	cloneTransport.Proxy = nil
	cloneTransport.ForceAttemptHTTP2 = true
	cloneTransport.TLSClientConfig = tlsConfiguration
	copyClient := *client
	copyClient.Transport = cloneTransport
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &copyClient, nil
}
