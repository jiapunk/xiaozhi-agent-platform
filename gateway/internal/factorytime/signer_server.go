package factorytime

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
)

// ReceiptSigningAuthorizer independently proves that the unsigned receipt was
// committed by the trusted-time authority and is still live. Production
// implementations must use a read-only identity.
type ReceiptSigningAuthorizer interface {
	VerifySchema() error
	AuthorizeSigning(context.Context, Receipt) error
}

// ReceiptSigningBackend is the only provider-specific boundary. It is expected
// to use one non-exportable Ed25519 HSM/KMS key. The service never accepts a
// key ID or arbitrary payload from the backend caller.
type ReceiptSigningBackend interface {
	Ready(context.Context) error
	Sign(context.Context, []byte) ([]byte, error)
}

type ReceiptSignerService struct {
	authorizer ReceiptSigningAuthorizer
	backend    ReceiptSigningBackend
	keyID      string
	publicKey  ed25519.PublicKey
}

func NewReceiptSignerService(authorizer ReceiptSigningAuthorizer,
	backend ReceiptSigningBackend, keyID string,
	publicKey ed25519.PublicKey) (*ReceiptSignerService, error) {
	if authorizer == nil || backend == nil || !validIdentifier(keyID) ||
		len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalid
	}
	return &ReceiptSignerService{authorizer: authorizer, backend: backend,
		keyID: keyID, publicKey: append(ed25519.PublicKey(nil), publicKey...)}, nil
}

func (service *ReceiptSignerService) KeyID() string {
	if service == nil {
		return ""
	}
	return service.keyID
}

func (service *ReceiptSignerService) Ready(ctx context.Context) error {
	if service == nil || service.authorizer == nil || service.backend == nil ||
		ctx == nil {
		return ErrUnavailable
	}
	if err := service.authorizer.VerifySchema(); err != nil {
		return unavailable("verify signer ledger schema", err)
	}
	if err := service.backend.Ready(ctx); err != nil {
		return unavailable("verify signing backend", err)
	}
	return nil
}

func (service *ReceiptSignerService) SignRequest(ctx context.Context,
	requestBody []byte) ([]byte, error) {
	if service == nil || service.authorizer == nil || service.backend == nil ||
		ctx == nil || !validIdentifier(service.keyID) ||
		len(service.publicKey) != ed25519.PublicKeySize {
		return nil, ErrUnavailable
	}
	request, receipt, unsigned, err := parseSignerRequest(requestBody)
	if err != nil || request.KeyID != service.keyID ||
		receipt.AuthorityKeyID != service.keyID {
		return nil, ErrInvalid
	}
	if err := service.authorizer.AuthorizeSigning(ctx, receipt); err != nil {
		return nil, err
	}
	payload := make([]byte, 0, len(SignatureDomain)+len(unsigned))
	payload = append(payload, []byte(SignatureDomain)...)
	payload = append(payload, unsigned...)
	signature, err := service.backend.Sign(ctx, payload)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(service.publicKey, payload, signature) {
		return nil, unavailable("sign or verify trusted-time receipt", err)
	}
	// Re-read database time after the HSM/KMS call. A signature produced after
	// the short receipt window is never released, even if the backend started
	// while the committed row was still live.
	if err := service.authorizer.AuthorizeSigning(ctx, receipt); err != nil {
		return nil, err
	}
	response := signerResponse{
		Schema: SignerResponseSchema, KeyID: service.keyID,
		SignatureAlgorithm:    SignatureAlgorithm,
		SignatureB64URL:       base64.RawURLEncoding.EncodeToString(signature),
		UnsignedReceiptSHA256: request.UnsignedReceiptSHA256,
		Result:                SignerResponseResult,
	}
	responseBody, err := CanonicalJSON(response)
	if err != nil || len(responseBody) == 0 ||
		len(responseBody) > MaximumSignerBodyBytes {
		return nil, unavailable("encode signer response", err)
	}
	return responseBody, nil
}

type ReceiptSignerHandler struct {
	service                    *ReceiptSignerService
	authorityCertificateSHA256 [sha256.Size]byte
}

func NewReceiptSignerHandler(service *ReceiptSignerService,
	authorityCertificateSHA256 string) (*ReceiptSignerHandler, error) {
	digest, err := hex.DecodeString(authorityCertificateSHA256)
	if service == nil || err != nil || len(digest) != sha256.Size ||
		hex.EncodeToString(digest) != authorityCertificateSHA256 {
		return nil, ErrInvalid
	}
	handler := &ReceiptSignerHandler{service: service}
	copy(handler.authorityCertificateSHA256[:], digest)
	return handler, nil
}

func (handler *ReceiptSignerHandler) ServeHTTP(writer http.ResponseWriter,
	request *http.Request) {
	setSignerResponseHeaders(writer.Header())
	if handler == nil || handler.service == nil || request == nil ||
		request.URL == nil || !verifiedSignerAuthorityTLS(request,
		handler.authorityCertificateSHA256) {
		writer.WriteHeader(http.StatusForbidden)
		return
	}
	if request.Method == http.MethodGet &&
		request.URL.Path == SignerReadinessPath {
		handler.serveReadiness(writer, request)
		return
	}
	if request.Method != http.MethodPost ||
		request.URL.Path != SignerEndpointPath || request.URL.RawPath != "" ||
		request.URL.RawQuery != "" || request.URL.Fragment != "" ||
		singleHeader(request.Header, "Content-Type") != "application/json" ||
		singleHeader(request.Header, "Accept") != "application/json" ||
		singleHeader(request.Header, "Cache-Control") != "no-store" ||
		len(request.Header.Values("Content-Encoding")) != 0 ||
		request.ContentLength <= 0 ||
		request.ContentLength > MaximumSignerBodyBytes ||
		len(request.TransferEncoding) != 0 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body,
		MaximumSignerBodyBytes+1))
	if err != nil || int64(len(body)) != request.ContentLength ||
		len(body) > MaximumSignerBodyBytes {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	response, err := handler.service.SignRequest(request.Context(), body)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalid):
			writer.WriteHeader(http.StatusBadRequest)
		case errors.Is(err, ErrUnauthorized), errors.Is(err, ErrOutsideWindow):
			writer.WriteHeader(http.StatusForbidden)
		default:
			writer.Header().Set("Retry-After", "1")
			writer.WriteHeader(http.StatusServiceUnavailable)
		}
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Content-Length", strconv.Itoa(len(response)))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(response)
}

func (handler *ReceiptSignerHandler) serveReadiness(writer http.ResponseWriter,
	request *http.Request) {
	if request.URL.RawPath != "" || request.URL.RawQuery != "" ||
		request.URL.Fragment != "" || request.ContentLength != 0 ||
		len(request.TransferEncoding) != 0 ||
		singleHeader(request.Header, "Accept") != "application/json" ||
		singleHeader(request.Header, "Cache-Control") != "no-store" ||
		len(request.Header.Values("Content-Type")) != 0 ||
		len(request.Header.Values("Content-Encoding")) != 0 {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	if err := handler.service.Ready(request.Context()); err != nil {
		writer.Header().Set("Retry-After", "1")
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set(SignerKeyIDHeader, handler.service.KeyID())
	writer.WriteHeader(http.StatusNoContent)
}

func verifiedSignerAuthorityTLS(request *http.Request,
	wanted [sha256.Size]byte) bool {
	if request.TLS == nil || request.TLS.Version != tls.VersionTLS13 ||
		len(request.TLS.PeerCertificates) == 0 ||
		len(request.TLS.PeerCertificates[0].Raw) == 0 ||
		len(request.TLS.VerifiedChains) == 0 ||
		len(request.TLS.VerifiedChains[0]) == 0 ||
		!request.TLS.PeerCertificates[0].Equal(
			request.TLS.VerifiedChains[0][0]) {
		return false
	}
	digest := sha256.Sum256(request.TLS.PeerCertificates[0].Raw)
	return equalDigest(digest[:], wanted[:])
}

func setSignerResponseHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
}
