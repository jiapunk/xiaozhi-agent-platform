package accountauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"
)

const (
	ServiceEntitlementUpdateContract  = "xz-service-entitlement-update-v1"
	ServiceEntitlementUpdatePath      = "/v1/service-entitlements/apply"
	EntitlementUpdateContractHeader   = "X-Xiaozhi-Entitlement-Update"
	EntitlementUpdateKeyIDHeader      = "X-Xiaozhi-Entitlement-Key-ID"
	EntitlementUpdateSignatureHeader  = "X-Xiaozhi-Entitlement-Signature"
	maximumEntitlementUpdateBodyBytes = 1536
	entitlementUpdateSignatureDomain  = "xiaozhi-service-entitlement-update-v1\x00"
	entitlementUpdateClockSkew        = 30 * time.Second
)

type serviceEntitlementUpdateRequest struct {
	Version                int              `json:"version"`
	SourceEventID          string           `json:"source_event_id"`
	TenantID               string           `json:"tenant_id"`
	Subject                string           `json:"subject"`
	PreviousRevision       uint64           `json:"previous_revision"`
	Revision               uint64           `json:"revision"`
	PlanID                 string           `json:"plan_id"`
	State                  EntitlementState `json:"state"`
	VoiceEnabled           bool             `json:"voice_enabled"`
	AgentEnabled           bool             `json:"agent_enabled"`
	AccessUntil            int64            `json:"access_until"`
	AuthorizedAt           int64            `json:"authorized_at"`
	AuthorizationExpiresAt int64            `json:"authorization_expires_at"`
}

type serviceEntitlementUpdateResponse struct {
	Version       int    `json:"version"`
	Status        string `json:"status"`
	SourceEventID string `json:"source_event_id"`
	Revision      uint64 `json:"revision"`
}

// ServiceEntitlementUpdateHandler accepts only normalized commercial state.
// It deliberately has no fields for payment instruments, receipts, prices,
// provider customer IDs, or raw webhook content.
type ServiceEntitlementUpdateHandler struct {
	ledger           ServiceEntitlementLedger
	keyring          *EntitlementUpdateKeyring
	authorizationTTL time.Duration
	now              func() time.Time
}

func NewServiceEntitlementUpdateHandler(ledger ServiceEntitlementLedger,
	keyring *EntitlementUpdateKeyring, authorizationTTL time.Duration) (
	*ServiceEntitlementUpdateHandler, error) {
	if ledger == nil || keyring == nil || keyring.Revision() == 0 ||
		authorizationTTL < time.Minute || authorizationTTL > 5*time.Minute {
		return nil, ErrInvalid
	}
	return &ServiceEntitlementUpdateHandler{ledger: ledger, keyring: keyring,
		authorizationTTL: authorizationTTL, now: time.Now}, nil
}

func (handler *ServiceEntitlementUpdateHandler) ServeHTTP(
	writer http.ResponseWriter, request *http.Request) {
	setServiceEntitlementUpdateHeaders(writer.Header())
	if handler == nil || handler.ledger == nil || handler.keyring == nil ||
		handler.now == nil || request == nil || request.Method != http.MethodPost ||
		request.URL.Path != ServiceEntitlementUpdatePath ||
		request.URL.RawPath != "" || request.URL.RawQuery != "" ||
		request.URL.Fragment != "" || !verifiedWorkloadTLS(request) ||
		singleHeader(request.Header, "Content-Type") != "application/json" ||
		singleHeader(request.Header, "Accept") != "application/json" ||
		singleHeader(request.Header, "Cache-Control") != "no-store" ||
		singleHeader(request.Header, EntitlementUpdateContractHeader) !=
			ServiceEntitlementUpdateContract || request.ContentLength <= 0 ||
		request.ContentLength > maximumEntitlementUpdateBodyBytes ||
		len(request.TransferEncoding) != 0 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body,
		maximumEntitlementUpdateBodyBytes+1))
	if err != nil || int64(len(body)) != request.ContentLength ||
		len(body) > maximumEntitlementUpdateBodyBytes {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	var input serviceEntitlementUpdateRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	canonical, err := json.Marshal(input)
	accessUntil := time.Unix(input.AccessUntil, 0).UTC()
	authorizedAt := time.Unix(input.AuthorizedAt, 0).UTC()
	authorizationExpiresAt := time.Unix(
		input.AuthorizationExpiresAt, 0).UTC()
	update := ServiceEntitlementUpdate{
		Principal:        Principal{TenantID: input.TenantID, Subject: input.Subject},
		SourceEventID:    input.SourceEventID,
		PreviousRevision: input.PreviousRevision, Revision: input.Revision,
		PlanID: input.PlanID, State: input.State,
		VoiceEnabled: input.VoiceEnabled, AgentEnabled: input.AgentEnabled,
		AccessUntil: accessUntil,
	}
	if err != nil || !bytes.Equal(canonical, body) || input.Version != 1 ||
		!validEntitlementTime(authorizedAt) ||
		!validEntitlementTime(authorizationExpiresAt) ||
		!authorizationExpiresAt.After(authorizedAt) ||
		authorizationExpiresAt.Sub(authorizedAt) > handler.authorizationTTL ||
		!ValidServiceEntitlementUpdate(update, authorizedAt) {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	now := handler.now().UTC().Truncate(time.Second)
	if authorizedAt.After(now.Add(entitlementUpdateClockSkew)) ||
		!authorizationExpiresAt.After(now) {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	keyID := singleHeader(request.Header, EntitlementUpdateKeyIDHeader)
	signatureText := singleHeader(request.Header,
		EntitlementUpdateSignatureHeader)
	signature, decodeErr := base64.RawURLEncoding.Strict().DecodeString(
		signatureText)
	if decodeErr != nil || base64.RawURLEncoding.EncodeToString(signature) !=
		signatureText || !handler.keyring.verify(keyID,
		serviceEntitlementUpdateSigningMessage(body), signature,
		authorizationExpiresAt, now) {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	entitlement, applied, err := handler.ledger.ApplyServiceEntitlement(
		request.Context(), update)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalid):
			writer.WriteHeader(http.StatusBadRequest)
		case errors.Is(err, ErrNotFound):
			writer.WriteHeader(http.StatusNotFound)
		case errors.Is(err, ErrConflict), errors.Is(err, ErrStaleEntitlement):
			writer.WriteHeader(http.StatusConflict)
		default:
			writer.Header().Set("Retry-After", "1")
			writer.WriteHeader(http.StatusServiceUnavailable)
		}
		return
	}
	if entitlement.SourceEventID != input.SourceEventID ||
		entitlement.Revision != input.Revision {
		writer.Header().Set("Retry-After", "1")
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	status := "replayed"
	if applied {
		status = "applied"
	}
	output := serviceEntitlementUpdateResponse{Version: 1, Status: status,
		SourceEventID: entitlement.SourceEventID,
		Revision:      entitlement.Revision}
	responseBody, err := json.Marshal(output)
	if err != nil || len(responseBody) == 0 ||
		len(responseBody) > maximumEntitlementUpdateBodyBytes {
		writer.Header().Set("Retry-After", "1")
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Content-Length", strconv.Itoa(len(responseBody)))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(responseBody)
}

func serviceEntitlementUpdateSigningMessage(body []byte) []byte {
	message := make([]byte, 0,
		len(entitlementUpdateSignatureDomain)+len(body))
	message = append(message, entitlementUpdateSignatureDomain...)
	return append(message, body...)
}

func setServiceEntitlementUpdateHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set(EntitlementUpdateContractHeader,
		ServiceEntitlementUpdateContract)
}
