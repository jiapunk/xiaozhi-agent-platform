package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	CompanionAuthorizationContract = "xz-companion-authorization-v1"
	CompanionIntrospectionPath     = "/v1/companion-tokens/introspect"
	MaximumIntrospectionBodyBytes  = 1024
	maximumIntrospectionPEMBytes   = 64 * 1024
)

var (
	ErrCompanionInactive    = errors.New("Companion authorization is inactive")
	ErrCompanionUnavailable = errors.New("Companion authorization is unavailable")
)

// CompanionStatusAuthorizer is the online account-service boundary used after
// local JWT verification. Production implementations must fail closed when
// logout, account suspension, session rotation or the account service makes a
// still-unexpired token inactive.
type CompanionStatusAuthorizer interface {
	Authorize(context.Context, Claims, time.Time) error
}

type CompanionTokenIntrospector struct {
	endpoint string
	client   *http.Client
}

// CompanionIntrospectionRequest is the canonical request shared by the
// control-plane client and account-authorization service. It contains only
// verified JWT claims, never the raw bearer.
type CompanionIntrospectionRequest struct {
	Version   int    `json:"version"`
	TokenID   string `json:"token_id"`
	Subject   string `json:"subject"`
	TenantID  string `json:"tenant_id"`
	Action    string `json:"action"`
	DeviceID  string `json:"device_id"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}

// CompanionIntrospectionResponse is returned only for an exact active token.
type CompanionIntrospectionResponse struct {
	Version         int    `json:"version"`
	Status          string `json:"status"`
	TokenID         string `json:"token_id"`
	Subject         string `json:"subject"`
	TenantID        string `json:"tenant_id"`
	Action          string `json:"action"`
	DeviceID        string `json:"device_id"`
	AccountRevision uint64 `json:"account_revision"`
	ValidUntil      int64  `json:"valid_until"`
}

// Keep package-local aliases so existing white-box contract tests continue to
// exercise the same wire types while the account service imports them.
type companionIntrospectionRequest = CompanionIntrospectionRequest
type companionIntrospectionResponse = CompanionIntrospectionResponse

func NewCompanionTokenIntrospector(endpoint string,
	client *http.Client) (*CompanionTokenIntrospector, error) {
	if !ValidCompanionIntrospectionURL(endpoint) || client == nil {
		return nil, fmt.Errorf("invalid Companion introspection configuration")
	}
	clientCopy := *client
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("Companion introspection redirects are forbidden")
	}
	return &CompanionTokenIntrospector{
		endpoint: endpoint,
		client:   &clientCopy,
	}, nil
}

func ValidCompanionIntrospectionURL(endpoint string) bool {
	parsed, err := url.Parse(endpoint)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" &&
		parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" &&
		parsed.Path == CompanionIntrospectionPath && parsed.RawPath == "" &&
		parsed.String() == endpoint
}

// NewCompanionIntrospectionMTLSClient constructs a no-proxy, no-redirect
// client. The caller owns the CA and workload certificate bytes and may clear
// its buffers after construction.
func NewCompanionIntrospectionMTLSClient(caPEM, certificatePEM, keyPEM []byte,
	timeout time.Duration) (*http.Client, error) {
	if len(caPEM) == 0 || len(certificatePEM) == 0 || len(keyPEM) == 0 ||
		timeout < 100*time.Millisecond || timeout > 2*time.Second {
		return nil, fmt.Errorf("invalid Companion introspection TLS configuration")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("invalid Companion introspection CA")
	}
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid Companion introspection client identity: %w", err)
	}
	transport := &http.Transport{
		Proxy:               nil,
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			RootCAs:      roots,
			Certificates: []tls.Certificate{certificate},
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("Companion introspection redirects are forbidden")
		},
	}, nil
}

func LoadCompanionIntrospectionMTLSClient(caFile, certificateFile, keyFile string,
	timeout time.Duration) (*http.Client, error) {
	caPEM, err := readCompanionPEM(caFile)
	if err != nil {
		return nil, err
	}
	certificatePEM, err := readCompanionPEM(certificateFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readCompanionPEM(keyFile)
	if err != nil {
		return nil, err
	}
	return NewCompanionIntrospectionMTLSClient(
		caPEM, certificatePEM, keyPEM, timeout)
}

func readCompanionPEM(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open Companion introspection credential: %w", err)
	}
	defer file.Close()
	status, err := file.Stat()
	if err != nil || !status.Mode().IsRegular() || status.Size() <= 0 ||
		status.Size() > maximumIntrospectionPEMBytes {
		return nil, fmt.Errorf("invalid Companion introspection credential file")
	}
	data, err := io.ReadAll(io.LimitReader(file,
		maximumIntrospectionPEMBytes+1))
	if err != nil || len(data) == 0 || len(data) > maximumIntrospectionPEMBytes {
		return nil, fmt.Errorf("read Companion introspection credential")
	}
	return data, nil
}

func (introspector *CompanionTokenIntrospector) Authorize(ctx context.Context,
	claims Claims, now time.Time) error {
	if introspector == nil || introspector.client == nil || ctx == nil ||
		!ValidIdentifier(claims.TokenID, 128) ||
		!ValidIdentifier(claims.Subject, 128) ||
		!ValidIdentifier(claims.TenantID, 128) ||
		!validCompanionActionDevice(claims.Action, claims.DeviceID) ||
		claims.IssuedAt <= 0 || claims.Expires <= claims.IssuedAt ||
		claims.Expires <= now.Unix() {
		return ErrCompanionInactive
	}
	input := companionIntrospectionRequest{
		Version: 1, TokenID: claims.TokenID, Subject: claims.Subject,
		TenantID: claims.TenantID, Action: claims.Action,
		DeviceID: claims.DeviceID, IssuedAt: claims.IssuedAt,
		ExpiresAt: claims.Expires,
	}
	body, err := json.Marshal(input)
	if err != nil || len(body) == 0 || len(body) > MaximumIntrospectionBodyBytes {
		return ErrCompanionUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		introspector.endpoint, bytes.NewReader(body))
	if err != nil {
		return ErrCompanionUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("X-Xiaozhi-Companion-Authorization",
		CompanionAuthorizationContract)
	response, err := introspector.client.Do(request)
	if err != nil {
		return ErrCompanionUnavailable
	}
	defer response.Body.Close()
	if response.TLS == nil || response.TLS.Version < tls.VersionTLS12 ||
		singleResponseHeader(response.Header, "Cache-Control") != "no-store" ||
		singleResponseHeader(response.Header,
			"X-Xiaozhi-Companion-Authorization") !=
			CompanionAuthorizationContract {
		return ErrCompanionUnavailable
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body,
		MaximumIntrospectionBodyBytes+1))
	if err != nil || len(responseBody) > MaximumIntrospectionBodyBytes {
		return ErrCompanionUnavailable
	}
	if response.StatusCode == http.StatusNoContent {
		if len(responseBody) != 0 || response.ContentLength > 0 ||
			len(response.Header.Values("Content-Type")) != 0 {
			return ErrCompanionUnavailable
		}
		return ErrCompanionInactive
	}
	if response.StatusCode != http.StatusOK ||
		singleResponseHeader(response.Header, "Content-Type") !=
			"application/json" || len(responseBody) == 0 ||
		response.ContentLength != int64(len(responseBody)) {
		return ErrCompanionUnavailable
	}
	var output companionIntrospectionResponse
	if err := decodeStrictJSON(responseBody, &output); err != nil {
		return ErrCompanionUnavailable
	}
	canonical, err := json.Marshal(output)
	if err != nil || !bytes.Equal(canonical, responseBody) ||
		output.Version != 1 || output.Status != "active" ||
		output.TokenID != claims.TokenID || output.Subject != claims.Subject ||
		output.TenantID != claims.TenantID || output.Action != claims.Action ||
		output.DeviceID != claims.DeviceID || output.AccountRevision == 0 ||
		output.ValidUntil <= now.Unix() || output.ValidUntil > claims.Expires {
		return ErrCompanionUnavailable
	}
	return nil
}

func singleResponseHeader(header http.Header, name string) string {
	values := header.Values(name)
	if len(values) != 1 {
		return ""
	}
	return values[0]
}
