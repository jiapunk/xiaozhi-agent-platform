package accountauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	ServiceEntitlementAuthorizationPath = "/v1/service-entitlements/authorize"
	maximumEntitlementHTTPBodyBytes     = 512
)

type serviceEntitlementAuthorizationRequest struct {
	Version  int            `json:"version"`
	TenantID string         `json:"tenant_id"`
	Subject  string         `json:"subject"`
	Service  ProductService `json:"service"`
}

type serviceEntitlementAuthorizationResponse struct {
	Version    int              `json:"version"`
	Status     EntitlementState `json:"status"`
	Revision   uint64           `json:"revision"`
	ValidUntil int64            `json:"valid_until"`
}

type ServiceEntitlementAuthorizationHandler struct {
	authorizer ServiceEntitlementAuthorizer
}

func NewServiceEntitlementAuthorizationHandler(
	authorizer ServiceEntitlementAuthorizer) (
	*ServiceEntitlementAuthorizationHandler, error) {
	if authorizer == nil {
		return nil, ErrInvalid
	}
	return &ServiceEntitlementAuthorizationHandler{
		authorizer: authorizer}, nil
}

func (handler *ServiceEntitlementAuthorizationHandler) ServeHTTP(
	writer http.ResponseWriter, request *http.Request) {
	setServiceEntitlementHeaders(writer.Header())
	if handler == nil || handler.authorizer == nil || request == nil ||
		request.Method != http.MethodPost ||
		request.URL.Path != ServiceEntitlementAuthorizationPath ||
		request.URL.RawPath != "" || request.URL.RawQuery != "" ||
		request.URL.Fragment != "" || !verifiedWorkloadTLS(request) ||
		singleHeader(request.Header, "Content-Type") != "application/json" ||
		singleHeader(request.Header, "Accept") != "application/json" ||
		singleHeader(request.Header, "Cache-Control") != "no-store" ||
		singleHeader(request.Header, "X-Xiaozhi-Service-Entitlement") !=
			ServiceEntitlementContract || request.ContentLength <= 0 ||
		request.ContentLength > maximumEntitlementHTTPBodyBytes ||
		len(request.TransferEncoding) != 0 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body,
		maximumEntitlementHTTPBodyBytes+1))
	if err != nil || int64(len(body)) != request.ContentLength ||
		len(body) > maximumEntitlementHTTPBodyBytes {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	var input serviceEntitlementAuthorizationRequest
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
	principal := Principal{TenantID: input.TenantID, Subject: input.Subject}
	if err != nil || !bytes.Equal(canonical, body) || input.Version != 1 ||
		!ValidPrincipal(principal) || !ValidProductService(input.Service) {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	grant, allowed, err := handler.authorizer.AuthorizeService(
		request.Context(), principal, input.Service)
	if err != nil {
		writer.Header().Set("Retry-After", "1")
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if !allowed {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if !ValidAccountRevision(grant.Revision) ||
		(grant.State != EntitlementActive && grant.State != EntitlementGrace) ||
		!validEntitlementTime(grant.ValidUntil) {
		writer.Header().Set("Retry-After", "1")
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	output := serviceEntitlementAuthorizationResponse{
		Version: 1, Status: grant.State, Revision: grant.Revision,
		ValidUntil: grant.ValidUntil.Unix(),
	}
	responseBody, err := json.Marshal(output)
	if err != nil || len(responseBody) == 0 ||
		len(responseBody) > maximumEntitlementHTTPBodyBytes {
		writer.Header().Set("Retry-After", "1")
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Content-Length", strconv.Itoa(len(responseBody)))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(responseBody)
}

type HTTPServiceEntitlementAuthorizer struct {
	endpoint string
	client   *http.Client
}

func NewHTTPServiceEntitlementAuthorizer(endpoint string,
	client *http.Client) (*HTTPServiceEntitlementAuthorizer, error) {
	if !ValidServiceEntitlementAuthorizationURL(endpoint) || client == nil {
		return nil, fmt.Errorf("invalid service entitlement authorization configuration")
	}
	clientCopy := *client
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("service entitlement redirects are forbidden")
	}
	return &HTTPServiceEntitlementAuthorizer{
		endpoint: endpoint, client: &clientCopy}, nil
}

func ValidServiceEntitlementAuthorizationURL(endpoint string) bool {
	parsed, err := url.Parse(endpoint)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" &&
		parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" &&
		parsed.Path == ServiceEntitlementAuthorizationPath &&
		parsed.RawPath == "" && parsed.String() == endpoint
}

func (authorizer *HTTPServiceEntitlementAuthorizer) AuthorizeService(
	ctx context.Context, principal Principal, service ProductService) (
	ServiceEntitlementGrant, bool, error) {
	if authorizer == nil || authorizer.client == nil || ctx == nil ||
		!ValidPrincipal(principal) || !ValidProductService(service) {
		return ServiceEntitlementGrant{}, false, ErrInvalid
	}
	input := serviceEntitlementAuthorizationRequest{
		Version: 1, TenantID: principal.TenantID,
		Subject: principal.Subject, Service: service,
	}
	body, err := json.Marshal(input)
	if err != nil || len(body) == 0 ||
		len(body) > maximumEntitlementHTTPBodyBytes {
		return ServiceEntitlementGrant{}, false, ErrUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		authorizer.endpoint, bytes.NewReader(body))
	if err != nil {
		return ServiceEntitlementGrant{}, false, ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("X-Xiaozhi-Service-Entitlement",
		ServiceEntitlementContract)
	response, err := authorizer.client.Do(request)
	if err != nil {
		return ServiceEntitlementGrant{}, false, ErrUnavailable
	}
	defer response.Body.Close()
	if response.TLS == nil || response.TLS.Version < tls.VersionTLS12 ||
		singleEntitlementResponseHeader(response.Header, "Cache-Control") !=
			"no-store" || singleEntitlementResponseHeader(response.Header,
		"X-Xiaozhi-Service-Entitlement") != ServiceEntitlementContract {
		return ServiceEntitlementGrant{}, false, ErrUnavailable
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body,
		maximumEntitlementHTTPBodyBytes+1))
	if err != nil || len(responseBody) > maximumEntitlementHTTPBodyBytes {
		return ServiceEntitlementGrant{}, false, ErrUnavailable
	}
	if response.StatusCode == http.StatusNoContent {
		if len(responseBody) != 0 || response.ContentLength > 0 ||
			len(response.Header.Values("Content-Type")) != 0 {
			return ServiceEntitlementGrant{}, false, ErrUnavailable
		}
		return ServiceEntitlementGrant{}, false, nil
	}
	if response.StatusCode != http.StatusOK ||
		singleEntitlementResponseHeader(response.Header, "Content-Type") !=
			"application/json" || len(responseBody) == 0 ||
		response.ContentLength != int64(len(responseBody)) {
		return ServiceEntitlementGrant{}, false, ErrUnavailable
	}
	var output serviceEntitlementAuthorizationResponse
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&output); err != nil {
		return ServiceEntitlementGrant{}, false, ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ServiceEntitlementGrant{}, false, ErrUnavailable
	}
	canonical, err := json.Marshal(output)
	validUntil := time.Unix(output.ValidUntil, 0).UTC()
	if err != nil || !bytes.Equal(canonical, responseBody) ||
		output.Version != 1 || !ValidAccountRevision(output.Revision) ||
		(output.Status != EntitlementActive && output.Status != EntitlementGrace) ||
		!validEntitlementTime(validUntil) ||
		!validUntil.After(time.Now().UTC()) {
		return ServiceEntitlementGrant{}, false, ErrUnavailable
	}
	return ServiceEntitlementGrant{Revision: output.Revision,
		State: output.Status, ValidUntil: validUntil}, true, nil
}

func setServiceEntitlementHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("X-Xiaozhi-Service-Entitlement",
		ServiceEntitlementContract)
}

func singleEntitlementResponseHeader(header http.Header, name string) string {
	values := header.Values(name)
	if len(values) != 1 {
		return ""
	}
	return values[0]
}
