package factorytime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	SignerEndpointPath     = "/v1/factory/trusted-time/sign"
	SignerReadinessPath    = "/readyz"
	SignerRequestSchema    = "xz-factory-time-sign-request-v1"
	SignerResponseSchema   = "xz-factory-time-sign-response-v1"
	SignerRequestResult    = "FACTORY_TIME_SIGNATURE_REQUESTED"
	SignerResponseResult   = "FACTORY_TIME_RECEIPT_SIGNED"
	MaximumSignerBodyBytes = 16 * 1024
	SignerKeyIDHeader      = "X-Xiaozhi-Factory-Time-Key-ID"
	minimumSignerTimeout   = 100 * time.Millisecond
	maximumSignerTimeout   = 2 * time.Second
)

type signerRequest struct {
	Schema                string `json:"schema"`
	KeyID                 string `json:"key_id"`
	SignatureAlgorithm    string `json:"signature_algorithm"`
	SignatureDomainB64URL string `json:"signature_domain_b64url"`
	UnsignedReceiptB64URL string `json:"unsigned_receipt_b64url"`
	UnsignedReceiptSHA256 string `json:"unsigned_receipt_sha256"`
	Result                string `json:"result"`
}

type signerResponse struct {
	Schema                string `json:"schema"`
	KeyID                 string `json:"key_id"`
	SignatureAlgorithm    string `json:"signature_algorithm"`
	SignatureB64URL       string `json:"signature_b64url"`
	UnsignedReceiptSHA256 string `json:"unsigned_receipt_sha256"`
	Result                string `json:"result"`
}

type RemoteSigner struct {
	keyID     string
	publicKey ed25519.PublicKey
	endpoint  string
	readyURL  string
	client    *http.Client
}

var _ Signer = (*RemoteSigner)(nil)

type RemoteSignerFiles struct {
	Endpoint                string
	KeyID                   string
	PublicKeyFile           string
	PublicKeySHA256         string
	CACertificateFile       string
	CACertificateSHA256     string
	ClientCertificateFile   string
	ClientCertificateSHA256 string
	ClientPrivateKeyFile    string
	Timeout                 time.Duration
}

func LoadRemoteSigner(files RemoteSignerFiles) (*RemoteSigner, error) {
	if !validIdentifier(files.KeyID) ||
		!validDigest(files.PublicKeySHA256) ||
		!validDigest(files.CACertificateSHA256) ||
		!validDigest(files.ClientCertificateSHA256) ||
		files.Timeout < minimumSignerTimeout ||
		files.Timeout > maximumSignerTimeout {
		return nil, ErrInvalid
	}
	endpoint, readyURL, err := validateSignerEndpoint(files.Endpoint)
	if err != nil {
		return nil, err
	}
	publicPEM, err := readCredential(files.PublicKeyFile, false)
	if err != nil {
		return nil, err
	}
	publicKey, publicDigest, err := parseSignerPublicKey(publicPEM)
	if err != nil || publicDigest != files.PublicKeySHA256 {
		return nil, fmt.Errorf("%w: signer public key pin differs", ErrInvalid)
	}
	caPEM, err := readCredential(files.CACertificateFile, false)
	if err != nil || fileDigest(caPEM) != files.CACertificateSHA256 {
		return nil, fmt.Errorf("%w: signer CA pin differs", ErrInvalid)
	}
	clientCertificatePEM, err := readCredential(
		files.ClientCertificateFile, false)
	if err != nil || fileDigest(clientCertificatePEM) !=
		files.ClientCertificateSHA256 {
		return nil, fmt.Errorf("%w: signer client certificate pin differs", ErrInvalid)
	}
	clientKeyPEM, err := readCredential(files.ClientPrivateKeyFile, true)
	if err != nil {
		return nil, err
	}
	clientIdentity, err := tls.X509KeyPair(clientCertificatePEM, clientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: signer client identity differs", ErrInvalid)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%w: signer CA is invalid", ErrInvalid)
	}
	dialer := &net.Dialer{Timeout: files.Timeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext,
		ForceAttemptHTTP2:     false,
		DisableCompression:    true,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   files.Timeout,
		ResponseHeaderTimeout: files.Timeout,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			RootCAs: roots, Certificates: []tls.Certificate{clientIdentity},
			SessionTicketsDisabled: true,
		},
	}
	client := &http.Client{
		Transport: transport, Timeout: files.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("factory-time signer redirects are disabled")
		},
	}
	return &RemoteSigner{keyID: files.KeyID, publicKey: publicKey,
		endpoint: endpoint, readyURL: readyURL, client: client}, nil
}

func (signer *RemoteSigner) KeyID() string {
	if signer == nil {
		return ""
	}
	return signer.keyID
}

// WrapTransport adds product-owned middleware without exposing or replacing
// the signer's pinned TLS transport.
func (signer *RemoteSigner) WrapTransport(
	wrapper func(http.RoundTripper) (http.RoundTripper, error)) error {
	if signer == nil || signer.client == nil || signer.client.Transport == nil ||
		wrapper == nil {
		return ErrInvalid
	}
	wrapped, err := wrapper(signer.client.Transport)
	if err != nil || wrapped == nil {
		return ErrInvalid
	}
	signer.client.Transport = wrapped
	return nil
}

func (signer *RemoteSigner) Sign(ctx context.Context,
	payload []byte) ([]byte, error) {
	if signer == nil || signer.client == nil || !validIdentifier(signer.keyID) ||
		len(payload) <= len(SignatureDomain) ||
		!bytes.Equal(payload[:len(SignatureDomain)], []byte(SignatureDomain)) {
		return nil, ErrInvalid
	}
	unsigned := payload[len(SignatureDomain):]
	receipt, err := ParseUnsignedReceipt(unsigned)
	if err != nil || receipt.AuthorityKeyID != signer.keyID {
		return nil, ErrInvalid
	}
	unsignedDigest := sha256.Sum256(unsigned)
	requestValue := signerRequest{
		Schema: SignerRequestSchema, KeyID: signer.keyID,
		SignatureAlgorithm: SignatureAlgorithm,
		SignatureDomainB64URL: base64.RawURLEncoding.
			EncodeToString([]byte(SignatureDomain)),
		UnsignedReceiptB64URL: base64.RawURLEncoding.EncodeToString(unsigned),
		UnsignedReceiptSHA256: hex.EncodeToString(unsignedDigest[:]),
		Result:                SignerRequestResult,
	}
	requestBody, err := CanonicalJSON(requestValue)
	if err != nil || len(requestBody) == 0 ||
		len(requestBody) > MaximumSignerBodyBytes {
		return nil, ErrInvalid
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost,
		signer.endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return nil, unavailable("create signer request", err)
	}
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Cache-Control", "no-store")
	httpResponse, err := signer.client.Do(httpRequest)
	if err != nil {
		return nil, unavailable("call external signer", err)
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode != http.StatusOK ||
		!verifiedSignerResponseTLS(httpResponse) ||
		singleHeader(httpResponse.Header, "Content-Type") != "application/json" ||
		singleHeader(httpResponse.Header, "Cache-Control") != "no-store" ||
		httpResponse.Header.Get("Content-Encoding") != "" ||
		httpResponse.Header.Get("Location") != "" ||
		len(httpResponse.TransferEncoding) != 0 ||
		httpResponse.ContentLength <= 0 ||
		httpResponse.ContentLength > MaximumSignerBodyBytes {
		return nil, unavailable("external signer response contract", ErrUnavailable)
	}
	responseBody, err := io.ReadAll(io.LimitReader(httpResponse.Body,
		MaximumSignerBodyBytes+1))
	if err != nil || int64(len(responseBody)) != httpResponse.ContentLength ||
		len(responseBody) > MaximumSignerBodyBytes {
		return nil, unavailable("read external signer response", err)
	}
	responseValue, err := parseSignerResponse(responseBody)
	if err != nil || responseValue.KeyID != signer.keyID ||
		responseValue.UnsignedReceiptSHA256 != hex.EncodeToString(unsignedDigest[:]) {
		return nil, unavailable("verify external signer response", ErrUnavailable)
	}
	signature, err := base64.RawURLEncoding.DecodeString(
		responseValue.SignatureB64URL)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(signer.publicKey, payload, signature) {
		return nil, unavailable("verify external signer signature", ErrUnavailable)
	}
	return signature, nil
}

func (signer *RemoteSigner) Ready(ctx context.Context) error {
	if signer == nil || signer.client == nil {
		return ErrUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		signer.readyURL, nil)
	if err != nil {
		return unavailable("create signer readiness request", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	response, err := signer.client.Do(request)
	if err != nil {
		return unavailable("call signer readiness", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent || response.ContentLength > 0 ||
		!verifiedSignerResponseTLS(response) ||
		singleHeader(response.Header, "Cache-Control") != "no-store" ||
		singleHeader(response.Header, SignerKeyIDHeader) != signer.keyID ||
		response.Header.Get("Content-Encoding") != "" ||
		response.Header.Get("Location") != "" ||
		len(response.TransferEncoding) != 0 {
		return unavailable("signer readiness response contract", ErrUnavailable)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1))
	if err != nil || len(body) != 0 {
		return unavailable("read signer readiness response", err)
	}
	return nil
}

func parseSignerResponse(data []byte) (signerResponse, error) {
	if len(data) == 0 || len(data) > MaximumSignerBodyBytes ||
		rejectDuplicateMembers(data) != nil {
		return signerResponse{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var response signerResponse
	if err := decoder.Decode(&response); err != nil {
		return signerResponse{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return signerResponse{}, ErrInvalid
	}
	canonical, err := CanonicalJSON(response)
	if err != nil || !bytes.Equal(canonical, data) ||
		response.Schema != SignerResponseSchema ||
		response.Result != SignerResponseResult ||
		response.SignatureAlgorithm != SignatureAlgorithm ||
		!validIdentifier(response.KeyID) ||
		!validDigest(response.UnsignedReceiptSHA256) {
		return signerResponse{}, ErrInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(response.SignatureB64URL)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != response.SignatureB64URL {
		return signerResponse{}, ErrInvalid
	}
	return response, nil
}

func parseSignerRequest(data []byte) (signerRequest, Receipt, []byte, error) {
	if len(data) == 0 || len(data) > MaximumSignerBodyBytes ||
		rejectDuplicateMembers(data) != nil {
		return signerRequest{}, Receipt{}, nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request signerRequest
	if err := decoder.Decode(&request); err != nil {
		return signerRequest{}, Receipt{}, nil, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return signerRequest{}, Receipt{}, nil, ErrInvalid
	}
	canonical, err := CanonicalJSON(request)
	if err != nil || !bytes.Equal(canonical, data) ||
		request.Schema != SignerRequestSchema ||
		request.Result != SignerRequestResult ||
		request.SignatureAlgorithm != SignatureAlgorithm ||
		request.SignatureDomainB64URL != base64.RawURLEncoding.
			EncodeToString([]byte(SignatureDomain)) ||
		!validIdentifier(request.KeyID) ||
		!validDigest(request.UnsignedReceiptSHA256) {
		return signerRequest{}, Receipt{}, nil, ErrInvalid
	}
	unsigned, err := base64.RawURLEncoding.DecodeString(
		request.UnsignedReceiptB64URL)
	if err != nil || len(unsigned) == 0 || len(unsigned) > MaximumResponseBytes ||
		base64.RawURLEncoding.EncodeToString(unsigned) !=
			request.UnsignedReceiptB64URL {
		return signerRequest{}, Receipt{}, nil, ErrInvalid
	}
	digest := sha256.Sum256(unsigned)
	if hex.EncodeToString(digest[:]) != request.UnsignedReceiptSHA256 {
		return signerRequest{}, Receipt{}, nil, ErrInvalid
	}
	receipt, err := ParseUnsignedReceipt(unsigned)
	if err != nil || receipt.AuthorityKeyID != request.KeyID {
		return signerRequest{}, Receipt{}, nil, ErrInvalid
	}
	return request, receipt, unsigned, nil
}

func validateSignerEndpoint(value string) (string, string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.Path != SignerEndpointPath ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Opaque != "" {
		return "", "", fmt.Errorf("%w: signer endpoint is not exact HTTPS", ErrInvalid)
	}
	if parsed.Hostname() == "" {
		return "", "", ErrInvalid
	}
	if portText := parsed.Port(); portText != "" {
		port, portErr := strconv.Atoi(portText)
		if portErr != nil || port < 1 || port > 65535 ||
			strconv.Itoa(port) != portText {
			return "", "", ErrInvalid
		}
	}
	ready := *parsed
	ready.Path = SignerReadinessPath
	return parsed.String(), ready.String(), nil
}

func parseSignerPublicKey(data []byte) (ed25519.PublicKey, string, error) {
	if len(data) == 0 || bytes.Contains(data, []byte("PRIVATE KEY")) {
		return nil, "", ErrInvalid
	}
	block, trailing := pemDecode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(trailing)) != 0 {
		return nil, "", ErrInvalid
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || len(key) != ed25519.PublicKeySize {
		return nil, "", ErrInvalid
	}
	digest := sha256.Sum256(block.Bytes)
	return append(ed25519.PublicKey(nil), key...), hex.EncodeToString(digest[:]), nil
}

func fileDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func verifiedSignerResponseTLS(response *http.Response) bool {
	return response.TLS != nil && response.TLS.Version == tls.VersionTLS13 &&
		len(response.TLS.PeerCertificates) > 0 &&
		len(response.TLS.VerifiedChains) > 0
}

// Kept behind a tiny wrapper so the PEM parser is easy to fuzz independently.
var pemDecode = func(data []byte) (*pem.Block, []byte) { return pem.Decode(data) }
