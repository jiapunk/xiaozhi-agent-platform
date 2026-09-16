package accountauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

var ErrEntitlementUpdateUnauthorized = errors.New(
	"service entitlement update signature is unauthorized")

type EntitlementUpdateDisposition string

const (
	EntitlementUpdateApplied  EntitlementUpdateDisposition = "applied"
	EntitlementUpdateReplayed EntitlementUpdateDisposition = "replayed"
)

type EntitlementUpdateResult struct {
	Disposition   EntitlementUpdateDisposition
	SourceEventID string
	Revision      uint64
}

// EntitlementUpdateSigner is the narrow boundary implemented by an external
// HSM/KMS adapter. Sign receives the domain-separated canonical wire payload;
// implementations must return exactly one raw Ed25519 signature.
type EntitlementUpdateSigner interface {
	KeyID() string
	Sign(context.Context, []byte) ([]byte, error)
}

// HTTPServiceEntitlementUpdater is the adapter-side half of the M84 write
// contract. Apply performs exactly one HTTP request. It never retries because
// a transport timeout or 503 must be reconciled against the provider event and
// current product revision before the adapter re-signs a fresh delivery.
type HTTPServiceEntitlementUpdater struct {
	endpoint         string
	client           *http.Client
	signer           EntitlementUpdateSigner
	keyID            string
	authorizationTTL time.Duration
	now              func() time.Time
}

// EntitlementUpdateMTLSClient can only be constructed from an explicit product
// CA and client identity. The raw client remains private so adapter code cannot
// silently replace it with http.DefaultClient or an ambient proxy transport.
type EntitlementUpdateMTLSClient struct {
	client *http.Client
}

func NewHTTPServiceEntitlementUpdater(endpoint string,
	transport *EntitlementUpdateMTLSClient,
	signer EntitlementUpdateSigner, authorizationTTL time.Duration) (
	*HTTPServiceEntitlementUpdater, error) {
	keyID := ""
	if signer != nil {
		keyID = signer.KeyID()
	}
	if !ValidServiceEntitlementUpdateURL(endpoint) || transport == nil ||
		transport.client == nil ||
		transport.client.Timeout < 100*time.Millisecond ||
		transport.client.Timeout > 2*time.Second ||
		!auth.ValidIdentifier(keyID, 64) ||
		authorizationTTL < time.Minute || authorizationTTL > 5*time.Minute ||
		authorizationTTL%time.Second != 0 {
		return nil, fmt.Errorf("invalid service entitlement updater configuration")
	}
	clientCopy := *transport.client
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("service entitlement update redirects are forbidden")
	}
	return &HTTPServiceEntitlementUpdater{
		endpoint: endpoint, client: &clientCopy, signer: signer,
		keyID: keyID, authorizationTTL: authorizationTTL,
		now: time.Now,
	}, nil
}

func ValidServiceEntitlementUpdateURL(endpoint string) bool {
	parsed, err := url.Parse(endpoint)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" &&
		parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" &&
		parsed.Path == ServiceEntitlementUpdatePath && parsed.RawPath == "" &&
		parsed.String() == endpoint
}

// NewServiceEntitlementUpdateMTLSClient returns the same bounded, no-proxy,
// no-redirect product mTLS transport used by account introspection. Keeping
// transport construction here prevents a selected adapter from accidentally
// inheriting HTTP_PROXY or a default root store.
func NewServiceEntitlementUpdateMTLSClient(caPEM, certificatePEM, keyPEM []byte,
	timeout time.Duration) (*EntitlementUpdateMTLSClient, error) {
	client, err := auth.NewCompanionIntrospectionMTLSClient(
		caPEM, certificatePEM, keyPEM, timeout)
	if err != nil {
		return nil, err
	}
	return &EntitlementUpdateMTLSClient{client: client}, nil
}

func (updater *HTTPServiceEntitlementUpdater) Apply(ctx context.Context,
	update ServiceEntitlementUpdate) (EntitlementUpdateResult, error) {
	if updater == nil || updater.client == nil || updater.signer == nil ||
		updater.now == nil || ctx == nil || ctx.Err() != nil ||
		updater.signer.KeyID() != updater.keyID {
		return EntitlementUpdateResult{}, ErrInvalid
	}
	now := updater.now().UTC().Truncate(time.Second)
	update.AccessUntil = update.AccessUntil.UTC()
	if !ValidServiceEntitlementUpdate(update, now) {
		return EntitlementUpdateResult{}, ErrInvalid
	}
	input := serviceEntitlementUpdateRequest{
		Version: 1, SourceEventID: update.SourceEventID,
		TenantID: update.Principal.TenantID, Subject: update.Principal.Subject,
		PreviousRevision: update.PreviousRevision, Revision: update.Revision,
		PlanID: update.PlanID, State: update.State,
		VoiceEnabled: update.VoiceEnabled, AgentEnabled: update.AgentEnabled,
		AccessUntil: update.AccessUntil.Unix(), AuthorizedAt: now.Unix(),
		AuthorizationExpiresAt: now.Add(updater.authorizationTTL).Unix(),
	}
	body, err := json.Marshal(input)
	if err != nil || len(body) == 0 ||
		len(body) > maximumEntitlementUpdateBodyBytes {
		return EntitlementUpdateResult{}, ErrInvalid
	}
	signature, err := updater.signer.Sign(ctx,
		serviceEntitlementUpdateSigningMessage(body))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return EntitlementUpdateResult{}, fmt.Errorf(
			"%w: entitlement update signer failed", ErrUnavailable)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		updater.endpoint, bytes.NewReader(body))
	if err != nil {
		return EntitlementUpdateResult{}, ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("Content-Length", strconv.Itoa(len(body)))
	request.Header.Set(EntitlementUpdateContractHeader,
		ServiceEntitlementUpdateContract)
	request.Header.Set(EntitlementUpdateKeyIDHeader, updater.keyID)
	request.Header.Set(EntitlementUpdateSignatureHeader,
		base64.RawURLEncoding.EncodeToString(signature))
	response, err := updater.client.Do(request)
	if err != nil {
		return EntitlementUpdateResult{}, fmt.Errorf(
			"%w: entitlement update transport", ErrUnavailable)
	}
	defer response.Body.Close()
	if !validEntitlementUpdateResponseTransport(response) {
		return EntitlementUpdateResult{}, ErrUnavailable
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body,
		maximumEntitlementUpdateBodyBytes+1))
	if err != nil || len(responseBody) > maximumEntitlementUpdateBodyBytes {
		return EntitlementUpdateResult{}, ErrUnavailable
	}
	if response.StatusCode != http.StatusOK {
		return EntitlementUpdateResult{}, classifyEntitlementUpdateFailure(
			response, responseBody)
	}
	if singleEntitlementUpdateResponseHeader(response.Header,
		"Content-Type") != "application/json" ||
		response.ContentLength != int64(len(responseBody)) ||
		len(responseBody) == 0 ||
		len(response.Header.Values("Retry-After")) != 0 {
		return EntitlementUpdateResult{}, ErrUnavailable
	}
	var output serviceEntitlementUpdateResponse
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&output); err != nil {
		return EntitlementUpdateResult{}, ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return EntitlementUpdateResult{}, ErrUnavailable
	}
	canonical, err := json.Marshal(output)
	disposition := EntitlementUpdateDisposition(output.Status)
	if err != nil || !bytes.Equal(canonical, responseBody) ||
		output.Version != 1 ||
		(disposition != EntitlementUpdateApplied &&
			disposition != EntitlementUpdateReplayed) ||
		output.SourceEventID != update.SourceEventID ||
		output.Revision != update.Revision {
		return EntitlementUpdateResult{}, ErrUnavailable
	}
	return EntitlementUpdateResult{Disposition: disposition,
		SourceEventID: output.SourceEventID, Revision: output.Revision}, nil
}

func validEntitlementUpdateResponseTransport(response *http.Response) bool {
	return response != nil && response.TLS != nil &&
		response.TLS.Version >= tls.VersionTLS12 &&
		len(response.TLS.PeerCertificates) > 0 &&
		singleEntitlementUpdateResponseHeader(response.Header,
			"Cache-Control") == "no-store" &&
		singleEntitlementUpdateResponseHeader(response.Header,
			EntitlementUpdateContractHeader) ==
			ServiceEntitlementUpdateContract &&
		response.Header.Get("Content-Encoding") == "" &&
		response.Header.Get("Location") == "" &&
		len(response.TransferEncoding) == 0
}

func classifyEntitlementUpdateFailure(response *http.Response,
	body []byte) error {
	if response == nil || len(body) != 0 || response.ContentLength > 0 ||
		len(response.Header.Values("Content-Type")) != 0 {
		return ErrUnavailable
	}
	retryAfter := response.Header.Values("Retry-After")
	switch response.StatusCode {
	case http.StatusBadRequest:
		if len(retryAfter) == 0 {
			return ErrInvalid
		}
	case http.StatusUnauthorized:
		if len(retryAfter) == 0 {
			return ErrEntitlementUpdateUnauthorized
		}
	case http.StatusNotFound:
		if len(retryAfter) == 0 {
			return ErrNotFound
		}
	case http.StatusConflict:
		if len(retryAfter) == 0 {
			return ErrConflict
		}
	case http.StatusServiceUnavailable:
		if len(retryAfter) == 1 && retryAfter[0] == "1" {
			return ErrUnavailable
		}
	}
	return ErrUnavailable
}

func singleEntitlementUpdateResponseHeader(header http.Header,
	name string) string {
	values := header.Values(name)
	if len(values) != 1 {
		return ""
	}
	return values[0]
}
