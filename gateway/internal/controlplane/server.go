package controlplane

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
	"xiaozhi-agent-platform/gateway/internal/actionconsent"
	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/deviceclaim"
	"xiaozhi-agent-platform/gateway/internal/generation"
	productota "xiaozhi-agent-platform/gateway/internal/ota"
	"xiaozhi-agent-platform/gateway/internal/provisioning"
	"xiaozhi-agent-platform/gateway/internal/runtimecoordination"
)

const (
	minimumUnixTime = int64(1609459200)
	maximumUnixTime = int64(4102444800)
)

type Config struct {
	SessionProof                *provisioning.ProofVerifier
	AgentProof                  *provisioning.ProofVerifier
	VoiceIssuer                 *auth.Issuer
	AgentIssuer                 *auth.Issuer
	OTAProof                    *provisioning.ProofVerifier
	OTARegistry                 *productota.Registry
	OTAIssuer                   *auth.Issuer
	OTARolloutKey               []byte
	GenerationGate              generation.ServingGate
	PublicDeviceWSS             string
	Logger                      *slog.Logger
	Now                         func() time.Time
	ClaimProof                  *provisioning.ProofVerifier
	AppVerifier                 auth.AuthorizationVerifier
	CompanionStatus             auth.CompanionStatusAuthorizer
	ClaimStore                  deviceclaim.OwnershipStore
	Ownership                   deviceclaim.OwnershipResolver
	ActionConsents              actionconsent.DecisionStore
	ActionConsentChallengeProof *provisioning.ProofVerifier
	ActionConsentResultProof    *provisioning.ProofVerifier
	RuntimeCoordinator          runtimecoordination.Coordinator
	ServiceEntitlements         accountauth.ServiceEntitlementAuthorizer
	RequireServiceEntitlement   bool
}

type Server struct {
	config Config
	mux    *http.ServeMux
	stats  metrics
}

type metrics struct {
	timeIssued             atomic.Uint64
	timeRejected           atomic.Uint64
	voiceIssued            atomic.Uint64
	agentIssued            atomic.Uint64
	proofRejected          atomic.Uint64
	proofReplay            atomic.Uint64
	proofRateLimited       atomic.Uint64
	otaOffered             atomic.Uint64
	otaUpToDate            atomic.Uint64
	otaDeferred            atomic.Uint64
	otaGenerationBlocked   atomic.Uint64
	claimsStarted          atomic.Uint64
	claimsBound            atomic.Uint64
	claimsRejected         atomic.Uint64
	ownershipDenied        atomic.Uint64
	ownershipReleased      atomic.Uint64
	consentsAccepted       atomic.Uint64
	consentsRejected       atomic.Uint64
	consentChallenges      atomic.Uint64
	consentDevicePending   atomic.Uint64
	consentDelivered       atomic.Uint64
	consentDeviceRejected  atomic.Uint64
	consentInboxDelivered  atomic.Uint64
	consentInboxEmpty      atomic.Uint64
	companionRevoked       atomic.Uint64
	companionUnavailable   atomic.Uint64
	entitlementDenied      atomic.Uint64
	entitlementUnavailable atomic.Uint64
	entitlementGrace       atomic.Uint64
}

type timeResponse struct {
	Version     int    `json:"version"`
	DeviceID    string `json:"device_id"`
	ClientID    string `json:"client_id"`
	Nonce       string `json:"nonce"`
	UnixSeconds int64  `json:"unix_seconds"`
}

type tokenResponse struct {
	Version          int    `json:"version"`
	DeviceID         string `json:"device_id"`
	Audience         string `json:"audience"`
	BindingID        string `json:"binding_id"`
	BindingRevision  uint64 `json:"binding_revision"`
	BearerToken      string `json:"bearer_token"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"`
}

type sessionResponse struct {
	Version         int          `json:"version"`
	DeviceID        string       `json:"device_id"`
	BindingID       string       `json:"binding_id"`
	BindingRevision uint64       `json:"binding_revision"`
	Voice           sessionVoice `json:"voice"`
}

type sessionVoice struct {
	URI              string `json:"uri"`
	BearerToken      string `json:"bearer_token"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"`
}

type otaAvailableResponse struct {
	Version          int    `json:"version"`
	Status           string `json:"status"`
	DeviceID         string `json:"device_id"`
	ManifestB64URL   string `json:"manifest_b64url"`
	DownloadToken    string `json:"download_token"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"`
}

type otaWaitResponse struct {
	Version           int    `json:"version"`
	Status            string `json:"status"`
	DeviceID          string `json:"device_id"`
	RetryAfterSeconds uint32 `json:"retry_after_seconds"`
}

type claimResponse struct {
	Version          int                `json:"version"`
	RequestID        string             `json:"request_id"`
	DeviceID         string             `json:"device_id"`
	Status           deviceclaim.Status `json:"status"`
	ExpiresInSeconds int64              `json:"expires_in_seconds"`
}

type deviceClaimResponse struct {
	Version  int                `json:"version"`
	DeviceID string             `json:"device_id"`
	Status   deviceclaim.Status `json:"status"`
}

type ownershipReleaseResponse struct {
	Version         int    `json:"version"`
	DeviceID        string `json:"device_id"`
	Status          string `json:"status"`
	BindingRevision uint64 `json:"binding_revision"`
}

type actionConsentArguments struct {
	IndicatorOn bool `json:"on"`
}

type actionConsentDecisionRequest struct {
	Version       int                    `json:"version"`
	ChallengeID   string                 `json:"challenge_id"`
	DeviceID      string                 `json:"device_id"`
	OwnerRevision uint64                 `json:"owner_revision"`
	SessionID     string                 `json:"session_id"`
	RequestID     uint32                 `json:"request_id"`
	Capability    string                 `json:"capability"`
	Arguments     actionConsentArguments `json:"arguments"`
	Decision      actionconsent.Decision `json:"decision"`
}

type actionConsentDecisionResponse struct {
	Version     int    `json:"version"`
	ChallengeID string `json:"challenge_id"`
	Status      string `json:"status"`
}

type actionConsentDeviceChallengeRequest struct {
	Version       int                    `json:"version"`
	ChallengeID   string                 `json:"challenge_id"`
	SessionID     string                 `json:"session_id"`
	RequestID     uint32                 `json:"request_id"`
	Capability    string                 `json:"capability"`
	Arguments     actionConsentArguments `json:"arguments"`
	ExpiresAtUnix int64                  `json:"expires_at_unix"`
}

type actionConsentChallengeResponse struct {
	Version       int                    `json:"version"`
	ChallengeID   string                 `json:"challenge_id"`
	DeviceID      string                 `json:"device_id"`
	OwnerRevision uint64                 `json:"owner_revision"`
	SessionID     string                 `json:"session_id"`
	RequestID     uint32                 `json:"request_id"`
	Capability    string                 `json:"capability"`
	Arguments     actionConsentArguments `json:"arguments"`
	ExpiresAtUnix int64                  `json:"expires_at_unix"`
}

type actionConsentDeviceResultRequest struct {
	Version       int                    `json:"version"`
	ChallengeID   string                 `json:"challenge_id"`
	OwnerRevision uint64                 `json:"owner_revision"`
	SessionID     string                 `json:"session_id"`
	RequestID     uint32                 `json:"request_id"`
	Capability    string                 `json:"capability"`
	Arguments     actionConsentArguments `json:"arguments"`
}

type actionConsentDevicePendingResponse struct {
	Version           int    `json:"version"`
	ChallengeID       string `json:"challenge_id"`
	Status            string `json:"status"`
	RetryAfterSeconds uint32 `json:"retry_after_seconds"`
}

type actionConsentDeviceResultResponse struct {
	Version     int                    `json:"version"`
	ChallengeID string                 `json:"challenge_id"`
	Decision    actionconsent.Decision `json:"decision"`
}

func New(config Config) (*Server, error) {
	if config.Ownership == nil && config.ClaimStore != nil {
		config.Ownership = config.ClaimStore
	}
	if config.SessionProof == nil || config.AgentProof == nil ||
		config.VoiceIssuer == nil || config.AgentIssuer == nil ||
		config.Ownership == nil ||
		config.PublicDeviceWSS == "" {
		return nil, fmt.Errorf("control-plane dependencies are required")
	}
	if config.RequireServiceEntitlement && config.ServiceEntitlements == nil {
		return nil, fmt.Errorf("service entitlement authorization is required")
	}
	otaParts := 0
	if config.OTAProof != nil {
		otaParts++
	}
	if config.OTARegistry != nil {
		otaParts++
	}
	if config.OTAIssuer != nil {
		otaParts++
	}
	if len(config.OTARolloutKey) != 0 {
		otaParts++
	}
	if config.GenerationGate != nil {
		otaParts++
	}
	if otaParts != 0 && (otaParts != 5 || len(config.OTARolloutKey) < 32) {
		return nil, fmt.Errorf("OTA control-plane dependencies must be configured together")
	}
	claimParts := 0
	if config.ClaimProof != nil {
		claimParts++
	}
	if config.ClaimStore != nil {
		claimParts++
	}
	if claimParts != 0 && (claimParts != 2 || config.AppVerifier == nil ||
		!config.AppVerifier.AcceptsAudience(auth.CompanionAudience)) {
		return nil, fmt.Errorf("device claim dependencies must be configured together")
	}
	if config.CompanionStatus != nil && (config.AppVerifier == nil ||
		!config.AppVerifier.AcceptsAudience(auth.CompanionAudience)) {
		return nil, fmt.Errorf("Companion status requires the Companion verifier")
	}
	actionConsentParts := 0
	if config.ActionConsents != nil {
		actionConsentParts++
	}
	if config.ActionConsentChallengeProof != nil {
		actionConsentParts++
	}
	if config.ActionConsentResultProof != nil {
		actionConsentParts++
	}
	if actionConsentParts != 0 && (actionConsentParts != 3 ||
		config.AppVerifier == nil ||
		!config.AppVerifier.AcceptsAudience(auth.CompanionAudience)) {
		return nil, fmt.Errorf("action consent dependencies must be configured together")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	server := &Server{config: config}
	server.mux = http.NewServeMux()
	server.mux.HandleFunc("GET /healthz", server.health)
	server.mux.HandleFunc("GET /readyz", server.ready)
	server.mux.HandleFunc("GET /metrics", server.metrics)
	server.mux.HandleFunc("POST /v1/time", server.issueTime)
	server.mux.HandleFunc("POST /v1/session", server.issueVoice)
	server.mux.HandleFunc("POST /v1/agent-token", server.issueAgent)
	if otaParts == 5 {
		server.mux.HandleFunc("POST /v1/ota/offer", server.issueOTAOffer)
	}
	if claimParts == 2 {
		server.mux.HandleFunc("POST /v1/device-claim/app", server.beginDeviceClaim)
		server.mux.HandleFunc("POST /v1/device-claim/device", server.confirmDeviceClaim)
		server.mux.HandleFunc("GET /v1/device-claim/status", server.deviceClaimStatus)
		server.mux.HandleFunc("POST /v1/device-ownership/release", server.releaseOwnership)
	}
	if actionConsentParts == 3 {
		server.mux.HandleFunc("POST /v1/action-consents/device/challenge",
			server.registerDeviceActionConsent)
		server.mux.HandleFunc("POST /v1/action-consents/device/result",
			server.consumeDeviceActionConsent)
		server.mux.HandleFunc(
			"GET /v1/devices/{device_id}/action-consents/pending",
			server.pendingActionConsent)
		server.mux.HandleFunc(
			"POST /v1/devices/{device_id}/action-consents/{challenge_id}/decision",
			server.decideActionConsent)
	}
	return server, nil
}

func (server *Server) pendingActionConsent(writer http.ResponseWriter,
	request *http.Request) {
	setActionConsentHeaders(writer)
	claims, ok := server.authorizeCompanion(
		writer, request, auth.CompanionConsentAction)
	if !ok {
		server.stats.consentsRejected.Add(1)
		return
	}
	deviceID := request.PathValue("device_id")
	accept, acceptOK := singleHeader(request, "Accept")
	cacheControl, cacheOK := singleHeader(request, "Cache-Control")
	contract, contractOK := singleHeader(request, "X-Xiaozhi-Action-Consent")
	if request.URL.RawQuery != "" || len(request.TransferEncoding) != 0 ||
		request.ContentLength != 0 ||
		len(request.Header.Values("Content-Type")) != 0 ||
		accept != "application/json" || !acceptOK ||
		cacheControl != "no-store" || !cacheOK ||
		contract != actionconsent.Contract || !contractOK ||
		claims.DeviceID != deviceID ||
		!auth.ValidIdentifier(deviceID, 64) {
		server.rejectActionConsent(writer, actionconsent.ErrInvalid)
		return
	}
	owner, owned, err := server.config.Ownership.Owner(deviceID)
	if err != nil {
		server.rejectActionConsent(writer, actionconsent.ErrUnavailable)
		return
	}
	if !owned || owner.OwnerID != claims.Subject ||
		owner.TenantID != claims.TenantID {
		server.stats.ownershipDenied.Add(1)
		server.rejectActionConsent(writer, actionconsent.ErrNotFound)
		return
	}
	record, found, err := server.config.ActionConsents.Pending(
		actionconsent.Actor{
			OwnerID: claims.Subject, TenantID: claims.TenantID,
			DeviceID: deviceID, OwnerRevision: owner.BindingRevision,
		}, server.config.Now().UTC())
	if err != nil {
		server.rejectActionConsent(writer, err)
		return
	}
	if !found {
		writer.WriteHeader(http.StatusNoContent)
		server.stats.consentInboxEmpty.Add(1)
		return
	}
	challenge := record.Challenge
	writeCanonicalJSON(writer, http.StatusOK, actionConsentChallengeResponse{
		Version: 1, ChallengeID: challenge.ChallengeID,
		DeviceID: challenge.DeviceID, OwnerRevision: challenge.OwnerRevision,
		SessionID: challenge.SessionID, RequestID: challenge.RequestID,
		Capability: actionconsent.Capability,
		Arguments: actionConsentArguments{
			IndicatorOn: challenge.Action.IndicatorOn,
		},
		ExpiresAtUnix: challenge.ExpiresAt.Unix(),
	})
	server.stats.consentInboxDelivered.Add(1)
}

func (server *Server) registerDeviceActionConsent(writer http.ResponseWriter,
	request *http.Request) {
	setActionConsentHeaders(writer)
	var input actionConsentDeviceChallengeRequest
	body, err := readCanonicalActionConsentBody(request, &input)
	if err != nil {
		server.rejectDeviceActionConsent(writer, err)
		return
	}
	deviceID, err := server.config.ActionConsentChallengeProof.AuthorizeBody(
		request, body)
	if err != nil {
		server.rejectDeviceActionConsentProof(writer, err)
		return
	}
	if input.Version != 1 ||
		!actionconsent.ValidChallengeID(input.ChallengeID) ||
		input.Capability != actionconsent.Capability {
		server.rejectDeviceActionConsent(writer, actionconsent.ErrInvalid)
		return
	}
	owner, owned, err := server.config.Ownership.Owner(deviceID)
	if err != nil {
		server.rejectDeviceActionConsent(writer, actionconsent.ErrUnavailable)
		return
	}
	if !owned {
		server.stats.ownershipDenied.Add(1)
		server.rejectDeviceActionConsent(writer, actionconsent.ErrNotFound)
		return
	}
	now := server.config.Now().UTC()
	challenge := actionconsent.Challenge{
		ChallengeID: input.ChallengeID, DeviceID: deviceID,
		OwnerID: owner.OwnerID, TenantID: owner.TenantID,
		OwnerRevision: owner.BindingRevision, SessionID: input.SessionID,
		RequestID: input.RequestID,
		Action:    actionconsent.Action{IndicatorOn: input.Arguments.IndicatorOn},
		ExpiresAt: time.Unix(input.ExpiresAtUnix, 0).UTC(),
	}
	if !actionconsent.ValidChallenge(challenge, now) {
		server.rejectDeviceActionConsent(writer, actionconsent.ErrInvalid)
		return
	}
	if err := server.config.ActionConsents.Register(challenge, now); err != nil {
		server.rejectDeviceActionConsent(writer, err)
		return
	}
	writeCanonicalJSON(writer, http.StatusCreated,
		actionConsentChallengeResponse{
			Version: 1, ChallengeID: challenge.ChallengeID,
			DeviceID:      challenge.DeviceID,
			OwnerRevision: challenge.OwnerRevision,
			SessionID:     challenge.SessionID, RequestID: challenge.RequestID,
			Capability: actionconsent.Capability,
			Arguments: actionConsentArguments{
				IndicatorOn: challenge.Action.IndicatorOn,
			},
			ExpiresAtUnix: challenge.ExpiresAt.Unix(),
		})
	server.stats.consentChallenges.Add(1)
}

func (server *Server) consumeDeviceActionConsent(writer http.ResponseWriter,
	request *http.Request) {
	setActionConsentHeaders(writer)
	var input actionConsentDeviceResultRequest
	body, err := readCanonicalActionConsentBody(request, &input)
	if err != nil {
		server.rejectDeviceActionConsent(writer, err)
		return
	}
	deviceID, err := server.config.ActionConsentResultProof.AuthorizeBody(
		request, body)
	if err != nil {
		server.rejectDeviceActionConsentProof(writer, err)
		return
	}
	if input.Version != 1 ||
		!actionconsent.ValidChallengeID(input.ChallengeID) ||
		input.Capability != actionconsent.Capability {
		server.rejectDeviceActionConsent(writer, actionconsent.ErrInvalid)
		return
	}
	owner, owned, err := server.config.Ownership.Owner(deviceID)
	if err != nil {
		server.rejectDeviceActionConsent(writer, actionconsent.ErrUnavailable)
		return
	}
	if !owned || owner.BindingRevision != input.OwnerRevision {
		server.stats.ownershipDenied.Add(1)
		server.rejectDeviceActionConsent(writer, actionconsent.ErrConflict)
		return
	}
	record, err := server.config.ActionConsents.Consume(
		actionconsent.DeviceRequest{
			ChallengeID: input.ChallengeID, DeviceID: deviceID,
			OwnerRevision: input.OwnerRevision, SessionID: input.SessionID,
			RequestID: input.RequestID,
			Action: actionconsent.Action{
				IndicatorOn: input.Arguments.IndicatorOn,
			},
		}, server.config.Now().UTC())
	if errors.Is(err, actionconsent.ErrPending) {
		writer.Header().Set("Retry-After", "1")
		writeCanonicalJSON(writer, http.StatusAccepted,
			actionConsentDevicePendingResponse{
				Version: 1, ChallengeID: input.ChallengeID,
				Status: "pending", RetryAfterSeconds: 1,
			})
		server.stats.consentDevicePending.Add(1)
		return
	}
	if err != nil {
		server.rejectDeviceActionConsent(writer, err)
		return
	}
	writeCanonicalJSON(writer, http.StatusOK,
		actionConsentDeviceResultResponse{
			Version: 1, ChallengeID: input.ChallengeID,
			Decision: record.Decision,
		})
	server.stats.consentDelivered.Add(1)
}

func readCanonicalActionConsentBody(request *http.Request, target any) ([]byte, error) {
	if request == nil || request.URL == nil || target == nil {
		return nil, actionconsent.ErrInvalid
	}
	contentType, contentTypeOK := singleHeader(request, "Content-Type")
	accept, acceptOK := singleHeader(request, "Accept")
	cacheControl, cacheOK := singleHeader(request, "Cache-Control")
	contract, contractOK := singleHeader(request, "X-Xiaozhi-Action-Consent")
	if request.URL.RawQuery != "" ||
		len(request.TransferEncoding) != 0 || request.ContentLength <= 0 ||
		request.ContentLength > 1024 || contentType != "application/json" ||
		!contentTypeOK || accept != "application/json" || !acceptOK ||
		cacheControl != "no-store" || !cacheOK ||
		contract != actionconsent.Contract || !contractOK {
		return nil, actionconsent.ErrInvalid
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 1025))
	if err != nil || len(body) == 0 || len(body) > 1024 ||
		int64(len(body)) != request.ContentLength {
		return nil, actionconsent.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return nil, actionconsent.ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, actionconsent.ErrInvalid
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, actionconsent.ErrInvalid
	}
	return body, nil
}

func setActionConsentHeaders(writer http.ResponseWriter) {
	setSecurityHeaders(writer)
	writer.Header().Set("X-Xiaozhi-Action-Consent", actionconsent.Contract)
}

func (server *Server) rejectDeviceActionConsentProof(writer http.ResponseWriter,
	err error) {
	server.stats.consentDeviceRejected.Add(1)
	server.rejectProof(writer, err)
}

func (server *Server) rejectDeviceActionConsent(writer http.ResponseWriter,
	err error) {
	server.stats.consentDeviceRejected.Add(1)
	server.writeActionConsentError(writer, err)
}

func (server *Server) decideActionConsent(writer http.ResponseWriter,
	request *http.Request) {
	setActionConsentHeaders(writer)
	claims, ok := server.authorizeCompanion(
		writer, request, auth.CompanionConsentAction)
	if !ok {
		server.stats.consentsRejected.Add(1)
		return
	}
	deviceID := request.PathValue("device_id")
	challengeID := request.PathValue("challenge_id")
	contentType, contentTypeOK := singleHeader(request, "Content-Type")
	accept, acceptOK := singleHeader(request, "Accept")
	cacheControl, cacheOK := singleHeader(request, "Cache-Control")
	contract, contractOK := singleHeader(request, "X-Xiaozhi-Action-Consent")
	if request.URL.RawQuery != "" || len(request.TransferEncoding) != 0 ||
		request.ContentLength <= 0 || request.ContentLength > 1024 ||
		contentType != "application/json" || !contentTypeOK ||
		accept != "application/json" || !acceptOK ||
		cacheControl != "no-store" || !cacheOK ||
		contract != actionconsent.Contract || !contractOK ||
		claims.DeviceID != deviceID ||
		!actionconsent.ValidChallengeID(challengeID) {
		server.rejectActionConsent(writer, actionconsent.ErrInvalid)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 1025))
	if err != nil || len(body) == 0 || len(body) > 1024 ||
		int64(len(body)) != request.ContentLength {
		server.rejectActionConsent(writer, actionconsent.ErrInvalid)
		return
	}
	var decision actionConsentDecisionRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decision); err != nil {
		server.rejectActionConsent(writer, actionconsent.ErrInvalid)
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		server.rejectActionConsent(writer, actionconsent.ErrInvalid)
		return
	}
	canonical, err := json.Marshal(decision)
	if err != nil || !bytes.Equal(canonical, body) || decision.Version != 1 ||
		decision.ChallengeID != challengeID || decision.DeviceID != deviceID ||
		decision.Capability != actionconsent.Capability {
		server.rejectActionConsent(writer, actionconsent.ErrInvalid)
		return
	}
	owner, owned, err := server.config.Ownership.Owner(deviceID)
	if err != nil {
		server.rejectActionConsent(writer, actionconsent.ErrUnavailable)
		return
	}
	if !owned || owner.OwnerID != claims.Subject ||
		owner.TenantID != claims.TenantID ||
		owner.BindingRevision != decision.OwnerRevision {
		server.stats.ownershipDenied.Add(1)
		server.rejectActionConsent(writer, actionconsent.ErrNotFound)
		return
	}
	_, err = server.config.ActionConsents.Decide(actionconsent.Actor{
		OwnerID: claims.Subject, TenantID: claims.TenantID,
		DeviceID: deviceID, OwnerRevision: owner.BindingRevision,
	}, actionconsent.Request{
		ChallengeID: challengeID, DeviceID: deviceID,
		OwnerRevision: decision.OwnerRevision,
		SessionID:     decision.SessionID, RequestID: decision.RequestID,
		Action:   actionconsent.Action{IndicatorOn: decision.Arguments.IndicatorOn},
		Decision: decision.Decision,
	}, server.config.Now().UTC())
	if err != nil {
		server.rejectActionConsent(writer, err)
		return
	}
	response, _ := json.Marshal(actionConsentDecisionResponse{
		Version: 1, ChallengeID: challengeID, Status: "accepted",
	})
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(response)
	server.stats.consentsAccepted.Add(1)
}

func (server *Server) rejectActionConsent(writer http.ResponseWriter, err error) {
	server.stats.consentsRejected.Add(1)
	server.writeActionConsentError(writer, err)
}

func (server *Server) writeActionConsentError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, actionconsent.ErrUnavailable):
		writer.Header().Set("Retry-After", "5")
		http.Error(writer, "action consent unavailable", http.StatusServiceUnavailable)
	case errors.Is(err, actionconsent.ErrReplay),
		errors.Is(err, actionconsent.ErrConflict):
		http.Error(writer, "action consent conflict", http.StatusConflict)
	case errors.Is(err, actionconsent.ErrExpired):
		http.Error(writer, "action consent expired", http.StatusGone)
	case errors.Is(err, actionconsent.ErrCapacity):
		writer.Header().Set("Retry-After", "5")
		http.Error(writer, "action consent capacity reached",
			http.StatusTooManyRequests)
	case errors.Is(err, actionconsent.ErrNotFound):
		http.Error(writer, "action consent not found", http.StatusNotFound)
	default:
		http.Error(writer, "invalid action consent", http.StatusBadRequest)
	}
}

func (server *Server) beginDeviceClaim(writer http.ResponseWriter,
	request *http.Request) {
	setSecurityHeaders(writer)
	claims, ok := server.authorizeCompanion(
		writer, request, auth.CompanionClaimAction)
	if !ok {
		return
	}
	deviceID, deviceOK := singleHeader(request, provisioning.HeaderDeviceID)
	claim, claimOK := singleHeader(request, provisioning.HeaderDeviceClaim)
	appNonce, nonceOK := singleHeader(request, "X-App-Nonce")
	if request.URL.RawQuery != "" || request.ContentLength != 0 ||
		!deviceOK || !claimOK || !nonceOK {
		server.rejectClaim(writer, deviceclaim.ErrInvalid)
		return
	}
	now := server.config.Now().UTC()
	record, err := server.config.ClaimStore.Begin(
		claims.Subject, claims.TenantID, deviceID, claim, appNonce, now)
	if err != nil {
		server.rejectClaim(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, claimResponse{
		Version: 1, RequestID: record.RequestID, DeviceID: record.DeviceID,
		Status:           record.Status,
		ExpiresInSeconds: max(0, record.ExpiresAt.Unix()-now.Unix()),
	})
	server.stats.claimsStarted.Add(1)
}

func (server *Server) confirmDeviceClaim(writer http.ResponseWriter,
	request *http.Request) {
	setSecurityHeaders(writer)
	deviceID, err := server.config.ClaimProof.Authorize(request)
	if err != nil {
		server.rejectProof(writer, err)
		return
	}
	claim, ok := singleHeader(request, provisioning.HeaderDeviceClaim)
	if !ok {
		server.rejectClaim(writer, deviceclaim.ErrInvalid)
		return
	}
	record, err := server.config.ClaimStore.Confirm(
		deviceID, claim, server.config.Now().UTC())
	if err != nil {
		server.rejectClaim(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, deviceClaimResponse{
		Version: 1, DeviceID: record.DeviceID, Status: record.Status,
	})
	server.stats.claimsBound.Add(1)
}

func (server *Server) deviceClaimStatus(writer http.ResponseWriter,
	request *http.Request) {
	setSecurityHeaders(writer)
	claims, ok := server.authorizeCompanion(
		writer, request, auth.CompanionClaimAction)
	if !ok {
		return
	}
	requestID, requestOK := singleHeader(request, "X-Claim-Request-ID")
	if request.URL.RawQuery != "" || request.ContentLength != 0 || !requestOK {
		server.rejectClaim(writer, deviceclaim.ErrInvalid)
		return
	}
	now := server.config.Now().UTC()
	record, err := server.config.ClaimStore.Lookup(
		claims.Subject, claims.TenantID, requestID, now)
	if err != nil {
		server.rejectClaim(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, claimResponse{
		Version: 1, RequestID: record.RequestID, DeviceID: record.DeviceID,
		Status:           record.Status,
		ExpiresInSeconds: max(0, record.ExpiresAt.Unix()-now.Unix()),
	})
}

func (server *Server) releaseOwnership(writer http.ResponseWriter,
	request *http.Request) {
	setSecurityHeaders(writer)
	claims, ok := server.authorizeCompanion(
		writer, request, auth.CompanionReleaseAction)
	if !ok {
		return
	}
	deviceID, deviceOK := singleHeader(request, provisioning.HeaderDeviceID)
	if request.URL.RawQuery != "" || request.ContentLength != 0 ||
		!deviceOK || claims.DeviceID != deviceID {
		server.rejectClaim(writer, deviceclaim.ErrInvalid)
		return
	}
	released, err := server.config.ClaimStore.Release(
		claims.Subject, claims.TenantID, deviceID, server.config.Now().UTC())
	if err != nil {
		server.rejectClaim(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, ownershipReleaseResponse{
		Version: 1, DeviceID: deviceID, Status: "released",
		BindingRevision: released.BindingRevision,
	})
	server.stats.ownershipReleased.Add(1)
}

func (server *Server) authorizeCompanion(writer http.ResponseWriter,
	request *http.Request, expectedAction string) (auth.Claims, bool) {
	authorization, ok := singleHeader(request, "Authorization")
	if !ok {
		server.stats.claimsRejected.Add(1)
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return auth.Claims{}, false
	}
	claims, err := server.config.AppVerifier.VerifyAuthorization(authorization)
	if err != nil || claims.Subject == "" || claims.Action != expectedAction {
		server.stats.claimsRejected.Add(1)
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return auth.Claims{}, false
	}
	if server.config.CompanionStatus != nil {
		err = server.config.CompanionStatus.Authorize(
			request.Context(), claims, server.config.Now().UTC())
		if errors.Is(err, auth.ErrCompanionInactive) {
			server.stats.claimsRejected.Add(1)
			server.stats.companionRevoked.Add(1)
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return auth.Claims{}, false
		}
		if err != nil {
			server.stats.claimsRejected.Add(1)
			server.stats.companionUnavailable.Add(1)
			writer.Header().Set("Retry-After", "1")
			http.Error(writer, "account authorization unavailable",
				http.StatusServiceUnavailable)
			return auth.Claims{}, false
		}
	}
	return claims, true
}

func (server *Server) rejectClaim(writer http.ResponseWriter, err error) {
	server.stats.claimsRejected.Add(1)
	switch {
	case errors.Is(err, deviceclaim.ErrUnavailable):
		writer.Header().Set("Retry-After", "5")
		http.Error(writer, "ownership unavailable", http.StatusServiceUnavailable)
	case errors.Is(err, deviceclaim.ErrReplay),
		errors.Is(err, deviceclaim.ErrConflict):
		http.Error(writer, "device claim conflict", http.StatusConflict)
	case errors.Is(err, deviceclaim.ErrCapacity):
		writer.Header().Set("Retry-After", "5")
		http.Error(writer, "device claim capacity reached", http.StatusTooManyRequests)
	case errors.Is(err, deviceclaim.ErrExpired):
		http.Error(writer, "device claim expired", http.StatusGone)
	case errors.Is(err, deviceclaim.ErrNotFound),
		errors.Is(err, deviceclaim.ErrUnauthorized):
		http.Error(writer, "device claim not found", http.StatusNotFound)
	default:
		http.Error(writer, "invalid device claim", http.StatusBadRequest)
	}
}

func (server *Server) issueOTAOffer(writer http.ResponseWriter,
	request *http.Request) {
	setSecurityHeaders(writer)
	if !server.config.GenerationGate.AllowOTA() {
		server.stats.otaGenerationBlocked.Add(1)
		writer.Header().Set("Retry-After", "5")
		http.Error(writer, "OTA generation unavailable", http.StatusServiceUnavailable)
		return
	}
	deviceID, err := server.config.OTAProof.Authorize(request)
	if err != nil {
		server.rejectProof(writer, err)
		return
	}
	board, boardOK := singleHeader(request, provisioning.HeaderOTABoard)
	channel, channelOK := singleHeader(request, provisioning.HeaderOTAChannel)
	sequenceText, sequenceOK := singleHeader(request,
		provisioning.HeaderOTASequence)
	sequence, sequenceErr := strconv.ParseUint(sequenceText, 10, 31)
	if !boardOK || !channelOK || !sequenceOK || sequenceErr != nil ||
		sequence == 0 {
		http.Error(writer, "invalid OTA state", http.StatusBadRequest)
		return
	}
	release, status, retry := server.config.OTARegistry.Select(
		deviceID, board, channel, uint32(sequence), server.config.Now(),
		server.config.OTARolloutKey)
	if !server.config.GenerationGate.AllowOTA() {
		server.stats.otaGenerationBlocked.Add(1)
		writer.Header().Set("Retry-After", "5")
		http.Error(writer, "OTA generation unavailable", http.StatusServiceUnavailable)
		return
	}
	if status != productota.OfferAvailable {
		writeJSON(writer, http.StatusOK, otaWaitResponse{
			Version: 1, Status: string(status), DeviceID: deviceID,
			RetryAfterSeconds: retry,
		})
		if status == productota.OfferUpToDate {
			server.stats.otaUpToDate.Add(1)
		} else {
			server.stats.otaDeferred.Add(1)
		}
		return
	}
	token, claims, err := server.config.OTAIssuer.IssueForRelease(
		deviceID, release.ReleaseID, release.ImageSHA256)
	if err != nil || claims.Audience != auth.OTAAudience ||
		claims.ReleaseID != release.ReleaseID ||
		claims.ImageSHA256 != release.ImageSHA256 {
		server.config.Logger.Error("OTA token issuance failed",
			"device_id", deviceID, "release_id", release.ReleaseID,
			"error_class", "token_issuance_failed")
		http.Error(writer, "OTA offer unavailable", http.StatusInternalServerError)
		return
	}
	if !server.config.GenerationGate.AllowOTA() {
		server.stats.otaGenerationBlocked.Add(1)
		writer.Header().Set("Retry-After", "5")
		http.Error(writer, "OTA generation unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(writer, http.StatusOK, otaAvailableResponse{
		Version: 1, Status: string(status), DeviceID: deviceID,
		ManifestB64URL:   base64.RawURLEncoding.EncodeToString(release.Manifest),
		DownloadToken:    token,
		ExpiresInSeconds: claims.Expires - claims.IssuedAt,
	})
	server.stats.otaOffered.Add(1)
}

func (server *Server) Handler() http.Handler { return server.mux }

func (server *Server) health(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (server *Server) ready(writer http.ResponseWriter, _ *http.Request) {
	if !server.config.SessionProof.RegistryReady() ||
		!server.config.AgentProof.RegistryReady() ||
		(server.config.OTAProof != nil && !server.config.OTAProof.RegistryReady()) ||
		(server.config.ClaimProof != nil && !server.config.ClaimProof.RegistryReady()) ||
		(server.config.ActionConsentChallengeProof != nil &&
			!server.config.ActionConsentChallengeProof.RegistryReady()) ||
		(server.config.ActionConsentResultProof != nil &&
			!server.config.ActionConsentResultProof.RegistryReady()) {
		http.Error(writer, "device identity unavailable", http.StatusServiceUnavailable)
		return
	}
	if server.config.RuntimeCoordinator != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := server.config.RuntimeCoordinator.VerifySchema(ctx); err != nil {
			http.Error(writer, "runtime coordination unavailable",
				http.StatusServiceUnavailable)
			return
		}
	}
	if ownership, ok := server.config.Ownership.(deviceclaim.ReadyOwnershipResolver); ok {
		if err := ownership.VerifySchema(); err != nil {
			http.Error(writer, "ownership unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	if consents, ok := server.config.ActionConsents.(actionconsent.ReadyDecisionStore); ok {
		if err := consents.VerifySchema(); err != nil {
			http.Error(writer, "action consent unavailable",
				http.StatusServiceUnavailable)
			return
		}
	}
	if server.config.GenerationGate != nil && !server.config.GenerationGate.Ready() {
		http.Error(writer, "OTA generation unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
}

func (server *Server) issueTime(writer http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(writer)
	deviceID, deviceOK := singleHeader(request, provisioning.HeaderDeviceID)
	clientID, clientOK := singleHeader(request, provisioning.HeaderClientID)
	nonceText, nonceOK := singleHeader(request, provisioning.HeaderNonce)
	nonce, nonceErr := base64.RawURLEncoding.DecodeString(nonceText)
	now := server.config.Now().UTC().Unix()
	if request.URL.RawQuery != "" || request.ContentLength != 0 ||
		!deviceOK || !clientOK || !nonceOK ||
		!auth.ValidIdentifier(deviceID, 64) ||
		!auth.ValidIdentifier(clientID, 64) || nonceErr != nil ||
		len(nonce) != 16 ||
		base64.RawURLEncoding.EncodeToString(nonce) != nonceText ||
		!server.config.SessionProof.DeviceAllowed(deviceID) ||
		now < minimumUnixTime || now > maximumUnixTime {
		server.stats.timeRejected.Add(1)
		http.Error(writer, "invalid time request", http.StatusBadRequest)
		return
	}
	writeJSON(writer, http.StatusOK, timeResponse{
		Version: 1, DeviceID: deviceID, ClientID: clientID,
		Nonce: nonceText, UnixSeconds: now,
	})
	server.stats.timeIssued.Add(1)
}

func (server *Server) issueVoice(writer http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(writer)
	deviceID, token, claims, ok := server.authorizeAndIssue(
		writer, request, server.config.SessionProof,
		server.config.VoiceIssuer, auth.VoiceAudience)
	if !ok {
		return
	}
	writeJSON(writer, http.StatusOK, sessionResponse{
		Version: 2, DeviceID: deviceID,
		BindingID: claims.BindingID, BindingRevision: claims.BindingRevision,
		Voice: sessionVoice{
			URI: server.config.PublicDeviceWSS, BearerToken: token,
			ExpiresInSeconds: claims.Expires - claims.IssuedAt,
		},
	})
	server.stats.voiceIssued.Add(1)
}

func (server *Server) issueAgent(writer http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(writer)
	deviceID, token, claims, ok := server.authorizeAndIssue(
		writer, request, server.config.AgentProof,
		server.config.AgentIssuer, auth.AgentAudience)
	if !ok {
		return
	}
	writeJSON(writer, http.StatusOK, tokenResponse{
		Version: 2, DeviceID: deviceID, Audience: auth.AgentAudience,
		BindingID: claims.BindingID, BindingRevision: claims.BindingRevision,
		BearerToken: token, ExpiresInSeconds: claims.Expires - claims.IssuedAt,
	})
	server.stats.agentIssued.Add(1)
}

func (server *Server) authorizeAndIssue(writer http.ResponseWriter,
	request *http.Request, proof *provisioning.ProofVerifier,
	issuer *auth.Issuer, audience string) (string, string, auth.Claims, bool) {
	deviceID, err := proof.Authorize(request)
	if err != nil {
		server.rejectProof(writer, err)
		return "", "", auth.Claims{}, false
	}
	ownership, owned, ownerErr := server.config.Ownership.Owner(deviceID)
	if ownerErr != nil {
		server.stats.ownershipDenied.Add(1)
		http.Error(writer, "ownership unavailable",
			http.StatusServiceUnavailable)
		return "", "", auth.Claims{}, false
	}
	if !owned {
		server.stats.ownershipDenied.Add(1)
		http.Error(writer, "device ownership required",
			http.StatusForbidden)
		return "", "", auth.Claims{}, false
	}
	var entitlementUntil time.Time
	if server.config.ServiceEntitlements != nil {
		service := accountauth.ProductServiceVoice
		if audience == auth.AgentAudience {
			service = accountauth.ProductServiceAgent
		}
		grant, allowed, entitlementErr :=
			server.config.ServiceEntitlements.AuthorizeService(
				request.Context(), accountauth.Principal{
					TenantID: ownership.TenantID, Subject: ownership.OwnerID,
				}, service)
		if entitlementErr != nil {
			server.stats.entitlementUnavailable.Add(1)
			writer.Header().Set("Retry-After", "1")
			http.Error(writer, "service entitlement unavailable",
				http.StatusServiceUnavailable)
			return "", "", auth.Claims{}, false
		}
		if !allowed {
			server.stats.entitlementDenied.Add(1)
			http.Error(writer, "service entitlement required",
				http.StatusPaymentRequired)
			return "", "", auth.Claims{}, false
		}
		now := server.config.Now().UTC()
		if !accountauth.ValidAccountRevision(grant.Revision) ||
			(grant.State != accountauth.EntitlementActive &&
				grant.State != accountauth.EntitlementGrace) ||
			grant.ValidUntil.Location() != time.UTC ||
			grant.ValidUntil.Nanosecond() != 0 ||
			grant.ValidUntil.Unix()-now.Unix() < int64(time.Minute/time.Second) {
			server.stats.entitlementUnavailable.Add(1)
			writer.Header().Set("Retry-After", "1")
			http.Error(writer, "service entitlement unavailable",
				http.StatusServiceUnavailable)
			return "", "", auth.Claims{}, false
		}
		if grant.State == accountauth.EntitlementGrace {
			server.stats.entitlementGrace.Add(1)
		}
		entitlementUntil = grant.ValidUntil
	}
	var token string
	var claims auth.Claims
	err = proof.WithDeviceAllowed(deviceID, func() error {
		var issueErr error
		if entitlementUntil.IsZero() {
			token, claims, issueErr = issuer.IssueOwned(
				deviceID, ownership.OwnerID, ownership.TenantID,
				ownership.BindingID, ownership.BindingRevision)
		} else {
			token, claims, issueErr = issuer.IssueOwnedUntil(
				deviceID, ownership.OwnerID, ownership.TenantID,
				ownership.BindingID, ownership.BindingRevision,
				entitlementUntil)
		}
		return issueErr
	})
	if errors.Is(err, provisioning.ErrUnauthorized) {
		server.rejectProof(writer, err)
		return "", "", auth.Claims{}, false
	}
	if err != nil || claims.Audience != audience {
		server.config.Logger.Error("device token issuance failed",
			"device_id", deviceID, "audience", audience,
			"error_class", "token_issuance_failed")
		http.Error(writer, "token unavailable", http.StatusInternalServerError)
		return "", "", auth.Claims{}, false
	}
	return deviceID, token, claims, true
}

func (server *Server) rejectProof(writer http.ResponseWriter, err error) {
	server.stats.proofRejected.Add(1)
	switch {
	case errors.Is(err, provisioning.ErrMalformedProof):
		http.Error(writer, "malformed device proof", http.StatusBadRequest)
	case errors.Is(err, provisioning.ErrReplay):
		server.stats.proofReplay.Add(1)
		http.Error(writer, "device proof already used", http.StatusConflict)
	case errors.Is(err, provisioning.ErrRateLimited):
		server.stats.proofRateLimited.Add(1)
		writer.Header().Set("Retry-After", "5")
		http.Error(writer, "token issuance rate limited", http.StatusTooManyRequests)
	case errors.Is(err, provisioning.ErrUnavailable):
		http.Error(writer, "device proof coordination unavailable",
			http.StatusServiceUnavailable)
	default:
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
	}
}

func (server *Server) metrics(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(writer,
		"xiaozhi_control_time_issued_total %d\n"+
			"xiaozhi_control_time_rejected_total %d\n"+
			"xiaozhi_control_voice_tokens_issued_total %d\n"+
			"xiaozhi_control_agent_tokens_issued_total %d\n"+
			"xiaozhi_control_proofs_rejected_total %d\n"+
			"xiaozhi_control_proof_replays_total %d\n"+
			"xiaozhi_control_proof_rate_limited_total %d\n"+
			"xiaozhi_control_ota_offered_total %d\n"+
			"xiaozhi_control_ota_up_to_date_total %d\n"+
			"xiaozhi_control_ota_deferred_total %d\n"+
			"xiaozhi_control_ota_generation_blocked_total %d\n"+
			"xiaozhi_control_device_claims_started_total %d\n"+
			"xiaozhi_control_device_claims_bound_total %d\n"+
			"xiaozhi_control_device_claims_rejected_total %d\n"+
			"xiaozhi_control_ownership_denied_total %d\n"+
			"xiaozhi_control_ownership_released_total %d\n"+
			"xiaozhi_control_action_consents_accepted_total %d\n"+
			"xiaozhi_control_action_consents_rejected_total %d\n"+
			"xiaozhi_control_action_consent_challenges_registered_total %d\n"+
			"xiaozhi_control_action_consent_device_pending_total %d\n"+
			"xiaozhi_control_action_consent_device_delivered_total %d\n"+
			"xiaozhi_control_action_consent_device_rejected_total %d\n"+
			"xiaozhi_control_action_consent_inbox_delivered_total %d\n"+
			"xiaozhi_control_action_consent_inbox_empty_total %d\n"+
			"xiaozhi_control_companion_tokens_revoked_total %d\n"+
			"xiaozhi_control_companion_authorization_unavailable_total %d\n"+
			"xiaozhi_control_service_entitlement_denied_total %d\n"+
			"xiaozhi_control_service_entitlement_unavailable_total %d\n"+
			"xiaozhi_control_service_entitlement_grace_total %d\n",
		server.stats.timeIssued.Load(), server.stats.timeRejected.Load(),
		server.stats.voiceIssued.Load(), server.stats.agentIssued.Load(),
		server.stats.proofRejected.Load(), server.stats.proofReplay.Load(),
		server.stats.proofRateLimited.Load(), server.stats.otaOffered.Load(),
		server.stats.otaUpToDate.Load(), server.stats.otaDeferred.Load(),
		server.stats.otaGenerationBlocked.Load(),
		server.stats.claimsStarted.Load(), server.stats.claimsBound.Load(),
		server.stats.claimsRejected.Load(),
		server.stats.ownershipDenied.Load(),
		server.stats.ownershipReleased.Load(),
		server.stats.consentsAccepted.Load(),
		server.stats.consentsRejected.Load(),
		server.stats.consentChallenges.Load(),
		server.stats.consentDevicePending.Load(),
		server.stats.consentDelivered.Load(),
		server.stats.consentDeviceRejected.Load(),
		server.stats.consentInboxDelivered.Load(),
		server.stats.consentInboxEmpty.Load(),
		server.stats.companionRevoked.Load(),
		server.stats.companionUnavailable.Load(),
		server.stats.entitlementDenied.Load(),
		server.stats.entitlementUnavailable.Load(),
		server.stats.entitlementGrace.Load())
}

func singleHeader(request *http.Request, name string) (string, bool) {
	values := request.Header.Values(name)
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1 && returnValue != ""
}

func setSecurityHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeCanonicalJSON(writer http.ResponseWriter, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		http.Error(writer, "response unavailable", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}
