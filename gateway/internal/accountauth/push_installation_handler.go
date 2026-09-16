package accountauth

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const (
	PushInstallationPathPrefix   = "/v1/companion/push-installations/"
	PushInstallationContract     = "xz-companion-push-v1"
	maximumPushRegistrationBytes = 5 * 1024
)

// PushInstallationAuthenticator is supplied by the selected product IdP BFF.
// It must authenticate the current App session and enforce applicable
// MFA/risk policy. This handler has no development-principal fallback.
type PushInstallationAuthenticator interface {
	AuthenticatePushInstallation(*http.Request) (Session, error)
}

type pushInstallationRequest struct {
	Version  uint32       `json:"version"`
	Platform PushPlatform `json:"platform"`
	Token    string       `json:"token"`
}

// PushInstallationHandler is an external BFF building block. It must not be
// mounted on the private accountauthorization introspection listener.
type PushInstallationHandler struct {
	store         PushInstallationStore
	protector     PushTokenProtector
	authenticator PushInstallationAuthenticator
}

func NewPushInstallationHandler(store PushInstallationStore,
	protector PushTokenProtector, authenticator PushInstallationAuthenticator) (
	*PushInstallationHandler, error) {
	if store == nil || protector == nil || authenticator == nil {
		return nil, ErrInvalid
	}
	return &PushInstallationHandler{store: store, protector: protector,
		authenticator: authenticator}, nil
}

func (handler *PushInstallationHandler) ServeHTTP(writer http.ResponseWriter,
	request *http.Request) {
	setPushInstallationHeaders(writer.Header())
	if handler == nil || handler.store == nil || handler.protector == nil ||
		handler.authenticator == nil || request == nil ||
		(request.Method != http.MethodPut && request.Method != http.MethodDelete) ||
		!strings.HasPrefix(request.URL.Path, PushInstallationPathPrefix) ||
		request.URL.RawPath != "" || request.URL.RawQuery != "" ||
		request.URL.Fragment != "" || request.TLS == nil ||
		request.TLS.Version < tls.VersionTLS12 ||
		singleHeader(request.Header, "Accept") != "application/json" ||
		singleHeader(request.Header, "Cache-Control") != "no-store" ||
		singleHeader(request.Header, "X-Xiaozhi-Companion-Push") !=
			PushInstallationContract ||
		!validAppAuthorization(singleHeader(request.Header, "Authorization")) ||
		len(request.TransferEncoding) != 0 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	installationID := strings.TrimPrefix(request.URL.Path,
		PushInstallationPathPrefix)
	if !ValidPushInstallationID(installationID) {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	session, err := handler.authenticator.AuthenticatePushInstallation(request)
	if err != nil {
		writePushInstallationError(writer, err)
		return
	}
	if !ValidSession(session) {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	if request.Method == http.MethodDelete {
		if request.ContentLength != 0 ||
			singleHeader(request.Header, "Content-Type") != "" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := handler.store.RemovePushInstallation(request.Context(), session,
			installationID); err != nil {
			writePushInstallationError(writer, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if singleHeader(request.Header, "Content-Type") != "application/json" ||
		request.ContentLength <= 0 ||
		request.ContentLength > maximumPushRegistrationBytes {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body,
		maximumPushRegistrationBytes+1))
	if err != nil || int64(len(body)) != request.ContentLength ||
		len(body) > maximumPushRegistrationBytes {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	var input pushInstallationRequest
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
		!ValidRawPushToken(input.Platform, input.Token) {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	binding := PushTokenBinding{Principal: session.Principal,
		InstallationID: installationID, Platform: input.Platform}
	protected, err := handler.protector.Seal(request.Context(), binding,
		input.Token)
	if err != nil {
		writer.Header().Set("Retry-After", "1")
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	_, err = handler.store.UpsertPushInstallation(request.Context(), session,
		PushInstallationRegistration{InstallationID: installationID,
			Platform: input.Platform, Token: protected})
	if err != nil {
		writePushInstallationError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func writePushInstallationError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrAppSessionUnauthorized),
		errors.Is(err, ErrStaleSession), errors.Is(err, ErrSuspended),
		errors.Is(err, ErrInactive), errors.Is(err, ErrNotFound):
		writer.WriteHeader(http.StatusUnauthorized)
	case errors.Is(err, ErrConflict), errors.Is(err, ErrCapacity):
		writer.WriteHeader(http.StatusConflict)
	default:
		writer.Header().Set("Retry-After", "1")
		writer.WriteHeader(http.StatusServiceUnavailable)
	}
}

func setPushInstallationHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("X-Xiaozhi-Companion-Push", PushInstallationContract)
}
