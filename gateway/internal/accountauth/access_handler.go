package accountauth

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const (
	ActionConsentAccessPath     = "/v1/companion/action-consent-access"
	ActionConsentAccessContract = "xz-companion-access-v1"
	maximumAccessRequestBytes   = 256
	maximumAccessResponseBytes  = 6 * 1024
)

var (
	ErrAppSessionUnauthorized = errors.New("Companion App session unauthorized")
	ErrAppOwnershipChanged    = errors.New("Companion App ownership changed")
	ErrAppSessionUnavailable  = errors.New("Companion App session unavailable")
)

// ActionConsentAccessAuthenticator is implemented by the selected product IdP
// BFF. It must authenticate the fresh App session, enforce required MFA/risk
// policy, and verify exact current ownership before returning a revision-fenced
// account session. The access handler never implements login itself.
type ActionConsentAccessAuthenticator interface {
	AuthenticateActionConsentAccess(*http.Request, string, uint64) (Session, error)
}

type actionConsentAccessRequest struct {
	Version       uint32 `json:"version"`
	DeviceID      string `json:"device_id"`
	OwnerRevision uint64 `json:"owner_revision"`
	Purpose       string `json:"purpose"`
}

type actionConsentAccessResponse struct {
	Version       uint32 `json:"version"`
	DeviceID      string `json:"device_id"`
	OwnerRevision uint64 `json:"owner_revision"`
	ExpiresAtUnix int64  `json:"expires_at_unix"`
	AccessToken   string `json:"access_token"`
}

// ActionConsentAccessHandler is an external BFF building block. It must be
// mounted only behind the selected App-session authenticator, never on the
// private introspection reader command.
type ActionConsentAccessHandler struct {
	service       *Service
	authenticator ActionConsentAccessAuthenticator
}

func NewActionConsentAccessHandler(service *Service,
	authenticator ActionConsentAccessAuthenticator) (*ActionConsentAccessHandler, error) {
	if service == nil || authenticator == nil {
		return nil, ErrInvalid
	}
	return &ActionConsentAccessHandler{service: service,
		authenticator: authenticator}, nil
}

func (handler *ActionConsentAccessHandler) ServeHTTP(writer http.ResponseWriter,
	request *http.Request) {
	setActionConsentAccessHeaders(writer.Header())
	if handler == nil || handler.service == nil || handler.authenticator == nil ||
		request == nil || request.Method != http.MethodPost ||
		request.URL.Path != ActionConsentAccessPath || request.URL.RawPath != "" ||
		request.URL.RawQuery != "" || request.URL.Fragment != "" ||
		request.TLS == nil || request.TLS.Version < tls.VersionTLS12 ||
		singleHeader(request.Header, "Content-Type") != "application/json" ||
		singleHeader(request.Header, "Accept") != "application/json" ||
		singleHeader(request.Header, "Cache-Control") != "no-store" ||
		singleHeader(request.Header, "X-Xiaozhi-Companion-Access") !=
			ActionConsentAccessContract ||
		!validAppAuthorization(singleHeader(request.Header, "Authorization")) ||
		request.ContentLength <= 0 ||
		request.ContentLength > maximumAccessRequestBytes ||
		len(request.TransferEncoding) != 0 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body,
		maximumAccessRequestBytes+1))
	if err != nil || int64(len(body)) != request.ContentLength ||
		len(body) > maximumAccessRequestBytes {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	var input actionConsentAccessRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	canonical, err := json.Marshal(input)
	if err != nil || !bytes.Equal(canonical, body) || input.Version != 1 ||
		!auth.ValidIdentifier(input.DeviceID, 64) ||
		!ValidAccountRevision(input.OwnerRevision) ||
		input.Purpose != string(PurposeActionConsent) {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	session, err := handler.authenticator.AuthenticateActionConsentAccess(
		request, input.DeviceID, input.OwnerRevision)
	if err != nil {
		writeAccessAuthorizationError(writer, err)
		return
	}
	if !ValidSession(session) {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	issued, err := handler.service.Issue(request.Context(), session,
		PurposeActionConsent, input.DeviceID)
	if err != nil {
		writeAccessIssueError(writer, err)
		return
	}
	if issued.Bearer == "" || issued.Claims.Action != auth.CompanionConsentAction ||
		issued.Claims.DeviceID != input.DeviceID ||
		issued.Claims.Expires <= issued.Claims.IssuedAt ||
		issued.Claims.Expires-issued.Claims.IssuedAt >
			int64(MaximumActionConsentTokenLifetime.Seconds()) ||
		issued.Authorization.Binding.TokenID != issued.Claims.TokenID ||
		issued.Authorization.ValidUntil != issued.Claims.Expires {
		writer.Header().Set("Retry-After", "1")
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	output := actionConsentAccessResponse{
		Version: 1, DeviceID: input.DeviceID,
		OwnerRevision: input.OwnerRevision,
		ExpiresAtUnix: issued.Claims.Expires,
		AccessToken:   issued.Bearer,
	}
	responseBody, err := json.Marshal(output)
	if err != nil || len(responseBody) == 0 ||
		len(responseBody) > maximumAccessResponseBytes {
		writer.Header().Set("Retry-After", "1")
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Content-Length", strconv.Itoa(len(responseBody)))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(responseBody)
}

func validAppAuthorization(value string) bool {
	if !strings.HasPrefix(value, "Bearer ") || len(value) <= len("Bearer ") ||
		len(value) > 8*1024 {
		return false
	}
	for _, character := range []byte(value[len("Bearer "):]) {
		if character <= 0x20 || character >= 0x7f {
			return false
		}
	}
	return true
}

func writeAccessAuthorizationError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrAppSessionUnauthorized):
		writer.WriteHeader(http.StatusUnauthorized)
	case errors.Is(err, ErrAppOwnershipChanged):
		writer.WriteHeader(http.StatusConflict)
	default:
		writer.Header().Set("Retry-After", "1")
		writer.WriteHeader(http.StatusServiceUnavailable)
	}
}

func writeAccessIssueError(writer http.ResponseWriter, err error) {
	if errors.Is(err, ErrStaleSession) || errors.Is(err, ErrSuspended) ||
		errors.Is(err, ErrInactive) || errors.Is(err, ErrNotFound) {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	writer.Header().Set("Retry-After", "1")
	writer.WriteHeader(http.StatusServiceUnavailable)
}

func setActionConsentAccessHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("X-Xiaozhi-Companion-Access", ActionConsentAccessContract)
}
