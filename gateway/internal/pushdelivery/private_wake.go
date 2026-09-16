package pushdelivery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
	"xiaozhi-agent-platform/gateway/internal/actionconsent"
	"xiaozhi-agent-platform/gateway/internal/auth"
)

const (
	PrivateWakePath          = "/v1/companion-notifications/action-consent-wake"
	PrivateWakeContract      = "xz-private-wake-dispatch-v1"
	maximumPrivateWakeBytes  = 512
	maximumPrivateWakeResult = 64
)

type privateWakeRequest struct {
	Version       uint32 `json:"version"`
	TenantID      string `json:"tenant_id"`
	Subject       string `json:"subject"`
	DeviceID      string `json:"device_id"`
	OwnerRevision uint64 `json:"owner_revision"`
}

// PrivateWakeHandler belongs on the existing accountauthorization mTLS
// listener. It receives routing metadata from controlplane, then performs the
// provider fan-out locally so account database access and provider credentials
// do not cross the service boundary.
type PrivateWakeHandler struct {
	sender actionconsent.WakeSender
}

func NewPrivateWakeHandler(sender actionconsent.WakeSender) (
	*PrivateWakeHandler, error) {
	if sender == nil {
		return nil, ErrInvalid
	}
	return &PrivateWakeHandler{sender: sender}, nil
}

func (handler *PrivateWakeHandler) ServeHTTP(writer http.ResponseWriter,
	request *http.Request) {
	setPrivateWakeHeaders(writer.Header())
	if handler == nil || handler.sender == nil || request == nil ||
		request.Method != http.MethodPost || request.URL.Path != PrivateWakePath ||
		request.URL.RawPath != "" || request.URL.RawQuery != "" ||
		request.URL.Fragment != "" || request.TLS == nil ||
		request.TLS.Version < tls.VersionTLS13 ||
		len(request.TLS.VerifiedChains) == 0 ||
		len(request.TLS.PeerCertificates) == 0 ||
		exactHeader(request.Header, "Content-Type") != "application/json" ||
		exactHeader(request.Header, "Accept") != "application/json" ||
		exactHeader(request.Header, "Cache-Control") != "no-store" ||
		exactHeader(request.Header, "X-Xiaozhi-Private-Wake") !=
			PrivateWakeContract || request.ContentLength <= 0 ||
		request.ContentLength > maximumPrivateWakeBytes ||
		len(request.TransferEncoding) != 0 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body,
		maximumPrivateWakeBytes+1))
	if err != nil || int64(len(body)) != request.ContentLength ||
		len(body) > maximumPrivateWakeBytes {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	var input privateWakeRequest
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
	principal := accountauth.Principal{TenantID: input.TenantID,
		Subject: input.Subject}
	if err != nil || !bytes.Equal(canonical, body) || input.Version != 1 ||
		!accountauth.ValidPrincipal(principal) ||
		!auth.ValidIdentifier(input.DeviceID, 64) ||
		!accountauth.ValidAccountRevision(input.OwnerRevision) {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	disposition, err := handler.sender.SendWake(request.Context(),
		actionconsent.Actor{OwnerID: input.Subject, TenantID: input.TenantID,
			DeviceID: input.DeviceID, OwnerRevision: input.OwnerRevision},
		actionconsent.WakeContract, actionconsent.CanonicalWakePayload())
	if err != nil || (disposition != actionconsent.WakeSendAccepted &&
		disposition != actionconsent.WakeSendNoInstallation) {
		writer.Header().Set("Retry-After", "1")
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	result := "accepted"
	if disposition == actionconsent.WakeSendNoInstallation {
		result = "no-installation"
	}
	writer.Header().Set("X-Xiaozhi-Wake-Disposition", result)
	writer.WriteHeader(http.StatusNoContent)
}

// MTLSWakeClient implements the controlplane side of the existing private
// service boundary. Its http.Client must carry the controlplane certificate
// and pinned product CA; redirects are always disabled here.
type MTLSWakeClient struct {
	client   *http.Client
	endpoint string
}

// PrivateWakeTransportEvidence exposes only the negotiated transport identity
// needed by the release qualification path. It deliberately excludes request,
// account, device, provider and credential material.
type PrivateWakeTransportEvidence struct {
	TLSVersion           uint16
	NegotiatedProtocol   string
	ServerLeafCertSHA256 string
}

var _ actionconsent.WakeSender = (*MTLSWakeClient)(nil)

func NewMTLSWakeClient(authority string, client *http.Client) (
	*MTLSWakeClient, error) {
	parsed, err := url.Parse(authority)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") || client == nil ||
		client.Timeout < 100*time.Millisecond || client.Timeout > 8*time.Second {
		return nil, ErrInvalid
	}
	hardenedClient, err := hardenedHTTPClient(client, true, tls.VersionTLS13)
	if err != nil {
		return nil, err
	}
	parsed.Path = PrivateWakePath
	return &MTLSWakeClient{client: hardenedClient,
		endpoint: parsed.String()}, nil
}

func (client *MTLSWakeClient) SendWake(ctx context.Context,
	actor actionconsent.Actor, contract string,
	payload []byte) (actionconsent.WakeSendDisposition, error) {
	disposition, _, err := client.SendWakeWithTransportEvidence(
		ctx, actor, contract, payload)
	return disposition, err
}

// SendWakeWithTransportEvidence uses the exact production request path while
// returning a content-free summary of the authenticated TLS channel. Normal
// delivery callers use SendWake and cannot accidentally persist this data.
func (client *MTLSWakeClient) SendWakeWithTransportEvidence(ctx context.Context,
	actor actionconsent.Actor, contract string, payload []byte) (
	actionconsent.WakeSendDisposition, PrivateWakeTransportEvidence, error) {
	evidence := PrivateWakeTransportEvidence{}
	input := privateWakeRequest{Version: 1, TenantID: actor.TenantID,
		Subject: actor.OwnerID, DeviceID: actor.DeviceID,
		OwnerRevision: actor.OwnerRevision}
	principal := accountauth.Principal{TenantID: actor.TenantID,
		Subject: actor.OwnerID}
	if client == nil || ctx == nil || client.client == nil ||
		!accountauth.ValidPrincipal(principal) ||
		!auth.ValidIdentifier(actor.DeviceID, 64) ||
		!accountauth.ValidAccountRevision(actor.OwnerRevision) ||
		contract != actionconsent.WakeContract ||
		!bytes.Equal(payload, actionconsent.CanonicalWakePayload()) {
		return actionconsent.WakeSendRetry, evidence, ErrInvalid
	}
	body, err := json.Marshal(input)
	if err != nil || len(body) > maximumPrivateWakeBytes {
		return actionconsent.WakeSendRetry, evidence, ErrInvalid
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		client.endpoint, bytes.NewReader(body))
	if err != nil {
		return actionconsent.WakeSendRetry, evidence, ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("Content-Length", strconv.Itoa(len(body)))
	request.Header.Set("X-Xiaozhi-Private-Wake", PrivateWakeContract)
	response, err := client.client.Do(request)
	if err != nil {
		return actionconsent.WakeSendRetry, evidence,
			fmt.Errorf("%w: private wake transport", ErrUnavailable)
	}
	defer response.Body.Close()
	if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 ||
		len(response.TLS.PeerCertificates) == 0 {
		return actionconsent.WakeSendRetry, evidence,
			fmt.Errorf("%w: private wake TLS evidence", ErrUnavailable)
	}
	serverDigest := sha256.Sum256(response.TLS.PeerCertificates[0].Raw)
	evidence = PrivateWakeTransportEvidence{
		TLSVersion:           response.TLS.Version,
		NegotiatedProtocol:   response.TLS.NegotiatedProtocol,
		ServerLeafCertSHA256: hex.EncodeToString(serverDigest[:]),
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body,
		maximumPrivateWakeResult+1))
	if readErr != nil || len(responseBody) != 0 ||
		response.Header.Get("Cache-Control") != "no-store" ||
		response.Header.Get("X-Xiaozhi-Private-Wake") != PrivateWakeContract {
		return actionconsent.WakeSendRetry, evidence,
			fmt.Errorf("%w: private wake response", ErrUnavailable)
	}
	if response.StatusCode != http.StatusNoContent {
		return actionconsent.WakeSendRetry, evidence,
			fmt.Errorf("%w: private wake rejected", ErrUnavailable)
	}
	switch response.Header.Get("X-Xiaozhi-Wake-Disposition") {
	case "accepted":
		return actionconsent.WakeSendAccepted, evidence, nil
	case "no-installation":
		return actionconsent.WakeSendNoInstallation, evidence, nil
	default:
		return actionconsent.WakeSendRetry, evidence,
			fmt.Errorf("%w: private wake disposition", ErrUnavailable)
	}
}

func exactHeader(header http.Header, name string) string {
	values := header.Values(name)
	if len(values) != 1 {
		return ""
	}
	return values[0]
}

func setPrivateWakeHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("X-Xiaozhi-Private-Wake", PrivateWakeContract)
}
