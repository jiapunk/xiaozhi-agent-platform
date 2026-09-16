package accountauth

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

// IntrospectionHandler serves only the private workload endpoint. The TLS
// listener must require and verify a product workload client certificate; the
// handler checks that verified TLS state is still present before consulting
// the ledger.
type IntrospectionHandler struct {
	ledger Ledger
}

func NewIntrospectionHandler(ledger Ledger) (*IntrospectionHandler, error) {
	if ledger == nil {
		return nil, ErrInvalid
	}
	return &IntrospectionHandler{ledger: ledger}, nil
}

func (handler *IntrospectionHandler) ServeHTTP(writer http.ResponseWriter,
	request *http.Request) {
	setIntrospectionHeaders(writer.Header())
	if handler == nil || handler.ledger == nil || request == nil ||
		request.Method != http.MethodPost ||
		request.URL.Path != auth.CompanionIntrospectionPath ||
		request.URL.RawPath != "" || request.URL.RawQuery != "" ||
		request.URL.Fragment != "" || !verifiedWorkloadTLS(request) ||
		singleHeader(request.Header, "Content-Type") != "application/json" ||
		singleHeader(request.Header, "Accept") != "application/json" ||
		singleHeader(request.Header, "Cache-Control") != "no-store" ||
		singleHeader(request.Header,
			"X-Xiaozhi-Companion-Authorization") !=
			auth.CompanionAuthorizationContract ||
		request.ContentLength <= 0 ||
		request.ContentLength > auth.MaximumIntrospectionBodyBytes ||
		len(request.TransferEncoding) != 0 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body,
		auth.MaximumIntrospectionBodyBytes+1))
	if err != nil || int64(len(body)) != request.ContentLength ||
		len(body) > auth.MaximumIntrospectionBodyBytes {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	var input auth.CompanionIntrospectionRequest
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
	if err != nil || !bytes.Equal(canonical, body) || input.Version != 1 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	binding := TokenBinding{
		TokenID: input.TokenID, Subject: input.Subject,
		TenantID: input.TenantID, Action: input.Action,
		DeviceID: input.DeviceID, IssuedAt: input.IssuedAt,
		ExpiresAt: input.ExpiresAt,
	}
	if !ValidTokenBinding(binding) {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	authorization, active, err := handler.ledger.Introspect(
		request.Context(), binding)
	if err != nil {
		writer.Header().Set("Retry-After", "1")
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if !active {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if authorization.Binding != binding ||
		!ValidAccountRevision(authorization.AccountRevision) ||
		authorization.ValidUntil <= 0 ||
		authorization.ValidUntil > binding.ExpiresAt {
		writer.Header().Set("Retry-After", "1")
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	output := auth.CompanionIntrospectionResponse{
		Version: 1, Status: "active", TokenID: binding.TokenID,
		Subject: binding.Subject, TenantID: binding.TenantID,
		Action: binding.Action, DeviceID: binding.DeviceID,
		AccountRevision: authorization.AccountRevision,
		ValidUntil:      authorization.ValidUntil,
	}
	responseBody, err := json.Marshal(output)
	if err != nil || len(responseBody) == 0 ||
		len(responseBody) > auth.MaximumIntrospectionBodyBytes {
		writer.Header().Set("Retry-After", "1")
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Content-Length", strconv.Itoa(len(responseBody)))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(responseBody)
}

func verifiedWorkloadTLS(request *http.Request) bool {
	return request.TLS != nil && request.TLS.Version >= tls.VersionTLS12 &&
		len(request.TLS.PeerCertificates) > 0 &&
		len(request.TLS.VerifiedChains) > 0
}

func setIntrospectionHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("X-Xiaozhi-Companion-Authorization",
		auth.CompanionAuthorizationContract)
}

func singleHeader(header http.Header, name string) string {
	values := header.Values(name)
	if len(values) != 1 {
		return ""
	}
	return values[0]
}
