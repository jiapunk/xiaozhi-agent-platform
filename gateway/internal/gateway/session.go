package gateway

import (
	"encoding/json"
	"errors"
	"net/http"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/provisioning"
)

type sessionResponse struct {
	Version         int                  `json:"version"`
	DeviceID        string               `json:"device_id"`
	BindingID       string               `json:"binding_id"`
	BindingRevision uint64               `json:"binding_revision"`
	Voice           sessionVoiceResponse `json:"voice"`
}

type sessionVoiceResponse struct {
	URI              string `json:"uri"`
	BearerToken      string `json:"bearer_token"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"`
}

func (server *Server) session(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	deviceID, err := server.config.SessionProof.Authorize(request)
	if err != nil {
		server.rejectSession(writer, err)
		return
	}
	ownership, owned, err := server.config.Ownership.Owner(deviceID)
	if err != nil {
		http.Error(writer, "ownership unavailable", http.StatusServiceUnavailable)
		return
	}
	if !owned {
		http.Error(writer, "device ownership required", http.StatusForbidden)
		return
	}
	var token string
	var claims auth.Claims
	err = server.config.SessionProof.WithDeviceAllowed(deviceID, func() error {
		var issueErr error
		token, claims, issueErr = server.config.SessionIssuer.IssueOwned(
			deviceID, ownership.OwnerID, ownership.TenantID,
			ownership.BindingID, ownership.BindingRevision)
		return issueErr
	})
	if err != nil {
		if errors.Is(err, provisioning.ErrUnauthorized) {
			server.rejectSession(writer, err)
			return
		}
		server.config.Logger.Error("device session token issuance failed",
			"device_id", deviceID, "error_class", "token_issuance_failed")
		http.Error(writer, "session unavailable", http.StatusInternalServerError)
		return
	}

	response := sessionResponse{
		Version: 2, DeviceID: deviceID,
		BindingID: claims.BindingID, BindingRevision: claims.BindingRevision,
		Voice: sessionVoiceResponse{
			URI: server.config.PublicDeviceWSS, BearerToken: token,
			ExpiresInSeconds: claims.Expires - claims.IssuedAt,
		},
	}
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(response); err != nil {
		server.config.Logger.Info("device session response ended",
			"device_id", deviceID, "error_class", "response_write_failed")
		return
	}
	server.metrics.sessionIssued.Add(1)
}

func (server *Server) rejectSession(writer http.ResponseWriter, err error) {
	server.metrics.sessionProofErrors.Add(1)
	switch {
	case errors.Is(err, provisioning.ErrMalformedProof):
		http.Error(writer, "malformed device proof", http.StatusBadRequest)
	case errors.Is(err, provisioning.ErrReplay):
		server.metrics.sessionReplays.Add(1)
		http.Error(writer, "device proof already used", http.StatusConflict)
	case errors.Is(err, provisioning.ErrRateLimited):
		server.metrics.sessionRateLimited.Add(1)
		writer.Header().Set("Retry-After", "5")
		http.Error(writer, "session issuance rate limited", http.StatusTooManyRequests)
	case errors.Is(err, provisioning.ErrUnavailable):
		http.Error(writer, "device proof coordination unavailable",
			http.StatusServiceUnavailable)
	default:
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
	}
}
