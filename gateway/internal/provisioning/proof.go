package provisioning

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/runtimecoordination"
)

const (
	HeaderDeviceID                = "Device-Id"
	HeaderClientID                = "Client-Id"
	HeaderTimestamp               = "X-Device-Timestamp"
	HeaderNonce                   = "X-Device-Nonce"
	HeaderSignature               = "X-Device-Signature"
	HeaderOTABoard                = "X-OTA-Board"
	HeaderOTAChannel              = "X-OTA-Channel"
	HeaderOTASequence             = "X-OTA-Release-Sequence"
	HeaderOTAVersion              = "X-OTA-Version"
	HeaderDeviceClaim             = "X-Device-Claim"
	HeaderActionConsentBodySHA256 = "X-Action-Consent-Body-SHA256"
	maximumNonces                 = 64
)

type ProofScope uint8

const (
	SessionProofScope ProofScope = iota + 1
	AgentTokenProofScope
	OTAOfferProofScope
	DeviceClaimProofScope
	ActionConsentChallengeProofScope
	ActionConsentResultProofScope
)

var (
	ErrMalformedProof = errors.New("malformed device proof")
	ErrUnauthorized   = errors.New("unauthorized device proof")
	ErrReplay         = errors.New("replayed device proof")
	ErrRateLimited    = errors.New("device session issuance rate limited")
	ErrUnavailable    = errors.New("device proof coordination unavailable")
)

type ProofVerifier struct {
	registry    *Registry
	scope       ProofScope
	maxSkew     time.Duration
	minInterval time.Duration
	now         func() time.Time
	mu          sync.Mutex
	usedNonces  map[string]map[string]time.Time
	lastIssued  map[string]time.Time
	coordinator runtimecoordination.Coordinator
}

func NewProofVerifier(registry *Registry,
	maxSkew, minInterval time.Duration) (*ProofVerifier, error) {
	return NewScopedProofVerifier(registry, SessionProofScope,
		maxSkew, minInterval)
}

func NewScopedProofVerifier(registry *Registry, scope ProofScope,
	maxSkew, minInterval time.Duration) (*ProofVerifier, error) {
	if registry == nil || !registry.ProofReady() ||
		maxSkew < 10*time.Second || maxSkew > 5*time.Minute ||
		minInterval < 0 || minInterval > time.Minute || proofPath(scope) == "" {
		return nil, fmt.Errorf("invalid device proof verifier configuration")
	}
	return &ProofVerifier{
		registry: registry, scope: scope, maxSkew: maxSkew,
		minInterval: minInterval,
		now:         time.Now, usedNonces: make(map[string]map[string]time.Time),
		lastIssued: make(map[string]time.Time),
	}, nil
}

func CanonicalProof(deviceID, clientID, timestamp, nonce string) string {
	return CanonicalScopedProof(SessionProofScope, deviceID, clientID,
		timestamp, nonce)
}

func CanonicalScopedProof(scope ProofScope, deviceID, clientID,
	timestamp, nonce string) string {
	if scope == OTAOfferProofScope || scope == DeviceClaimProofScope ||
		isActionConsentProof(scope) {
		return ""
	}
	domain := proofDomain(scope)
	path := proofPath(scope)
	if domain == "" || path == "" {
		return ""
	}
	return domain + "\nPOST\n" + path + "\n" +
		deviceID + "\n" + clientID + "\n" + timestamp + "\n" + nonce
}

func CanonicalActionConsentProof(scope ProofScope, deviceID, clientID,
	timestamp, nonce, bodySHA256 string) string {
	if !isActionConsentProof(scope) || !validSHA256(bodySHA256) {
		return ""
	}
	return proofDomain(scope) + "\nPOST\n" + proofPath(scope) + "\n" +
		deviceID + "\n" + clientID + "\n" + timestamp + "\n" + nonce +
		"\n" + bodySHA256
}

func CanonicalOTAProof(deviceID, clientID, timestamp, nonce, board,
	channel, releaseSequence, version string) string {
	return proofDomain(OTAOfferProofScope) + "\nPOST\n" +
		proofPath(OTAOfferProofScope) + "\n" + deviceID + "\n" + clientID +
		"\n" + timestamp + "\n" + nonce + "\n" + board + "\n" + channel +
		"\n" + releaseSequence + "\n" + version
}

func CanonicalDeviceClaimProof(deviceID, clientID, timestamp, nonce,
	claim string) string {
	if !canonicalBase64URL(claim, 32) {
		return ""
	}
	return proofDomain(DeviceClaimProofScope) + "\nPOST\n" +
		proofPath(DeviceClaimProofScope) + "\n" + deviceID + "\n" + clientID +
		"\n" + timestamp + "\n" + nonce + "\n" + claim
}

func proofDomain(scope ProofScope) string {
	switch scope {
	case SessionProofScope:
		return "xiaozhi-session-proof-v1"
	case AgentTokenProofScope:
		return "xiaozhi-agent-token-proof-v1"
	case OTAOfferProofScope:
		return "xiaozhi-ota-offer-proof-v1"
	case DeviceClaimProofScope:
		return "xiaozhi-device-claim-proof-v1"
	case ActionConsentChallengeProofScope:
		return "xiaozhi-action-consent-challenge-proof-v1"
	case ActionConsentResultProofScope:
		return "xiaozhi-action-consent-result-proof-v1"
	default:
		return ""
	}
}

func proofPath(scope ProofScope) string {
	switch scope {
	case SessionProofScope:
		return "/v1/session"
	case AgentTokenProofScope:
		return "/v1/agent-token"
	case OTAOfferProofScope:
		return "/v1/ota/offer"
	case DeviceClaimProofScope:
		return "/v1/device-claim/device"
	case ActionConsentChallengeProofScope:
		return "/v1/action-consents/device/challenge"
	case ActionConsentResultProofScope:
		return "/v1/action-consents/device/result"
	default:
		return ""
	}
}

func (verifier *ProofVerifier) Authorize(request *http.Request) (string, error) {
	return verifier.authorize(request, nil, false)
}

// AuthorizeBody verifies one strict action-consent payload. The body digest is
// part of the protected device proof, so a valid proof cannot be replayed with
// different session/request/action bytes.
func (verifier *ProofVerifier) AuthorizeBody(request *http.Request,
	body []byte) (string, error) {
	return verifier.authorize(request, body, true)
}

func (verifier *ProofVerifier) authorize(request *http.Request, body []byte,
	withBody bool) (string, error) {
	if verifier == nil || request == nil || request.Method != http.MethodPost ||
		request.URL == nil || request.URL.Path != proofPath(verifier.scope) ||
		request.URL.RawQuery != "" {
		return "", ErrMalformedProof
	}
	actionConsentScope := isActionConsentProof(verifier.scope)
	if actionConsentScope {
		if !withBody || len(body) == 0 || len(body) > 1024 ||
			request.ContentLength != int64(len(body)) ||
			len(request.TransferEncoding) != 0 {
			return "", ErrMalformedProof
		}
	} else if withBody || request.ContentLength != 0 {
		return "", ErrMalformedProof
	}
	deviceID, deviceOK := singleHeader(request, HeaderDeviceID)
	clientID, clientOK := singleHeader(request, HeaderClientID)
	timestampText, timestampOK := singleHeader(request, HeaderTimestamp)
	nonceText, nonceOK := singleHeader(request, HeaderNonce)
	signatureText, signatureOK := singleHeader(request, HeaderSignature)
	if !deviceOK || !clientOK || !timestampOK || !nonceOK || !signatureOK {
		return "", ErrMalformedProof
	}
	if !auth.ValidIdentifier(deviceID, 64) ||
		!auth.ValidIdentifier(clientID, 64) {
		return "", ErrMalformedProof
	}
	board := ""
	channel := ""
	releaseSequence := ""
	version := ""
	claim := ""
	bodySHA256 := ""
	if verifier.scope == OTAOfferProofScope {
		var boardOK, channelOK, sequenceOK, versionOK bool
		board, boardOK = singleHeader(request, HeaderOTABoard)
		channel, channelOK = singleHeader(request, HeaderOTAChannel)
		releaseSequence, sequenceOK = singleHeader(request, HeaderOTASequence)
		version, versionOK = singleHeader(request, HeaderOTAVersion)
		sequence, sequenceErr := strconv.ParseUint(releaseSequence, 10, 31)
		if !boardOK || !channelOK || !sequenceOK || !versionOK ||
			!auth.ValidIdentifier(board, 32) ||
			!auth.ValidIdentifier(channel, 32) ||
			!validVersion(version) || sequenceErr != nil || sequence == 0 ||
			strconv.FormatUint(sequence, 10) != releaseSequence {
			return "", ErrMalformedProof
		}
	}
	if verifier.scope == DeviceClaimProofScope {
		var claimOK bool
		claim, claimOK = singleHeader(request, HeaderDeviceClaim)
		if !claimOK || !canonicalBase64URL(claim, 32) {
			return "", ErrMalformedProof
		}
	}
	if actionConsentScope {
		var digestOK bool
		bodySHA256, digestOK = singleHeader(request,
			HeaderActionConsentBodySHA256)
		digest := sha256.Sum256(body)
		if !digestOK || !validSHA256(bodySHA256) ||
			bodySHA256 != fmt.Sprintf("%x", digest[:]) {
			return "", ErrMalformedProof
		}
	}
	timestamp, err := strconv.ParseInt(timestampText, 10, 64)
	if err != nil || timestamp <= 0 || strconv.FormatInt(timestamp, 10) != timestampText {
		return "", ErrMalformedProof
	}
	nonce, err := base64.RawURLEncoding.DecodeString(nonceText)
	if err != nil || len(nonce) < 16 || len(nonce) > 32 ||
		base64.RawURLEncoding.EncodeToString(nonce) != nonceText {
		return "", ErrMalformedProof
	}
	signature, err := base64.RawURLEncoding.DecodeString(signatureText)
	if err != nil || len(signature) != sha256.Size ||
		base64.RawURLEncoding.EncodeToString(signature) != signatureText {
		return "", ErrMalformedProof
	}
	record, found, identityRevision := verifier.registry.lookupVersioned(deviceID)
	if !found || record.disabled {
		return "", ErrUnauthorized
	}
	canonical := CanonicalScopedProof(verifier.scope, deviceID, clientID,
		timestampText, nonceText)
	if verifier.scope == OTAOfferProofScope {
		profile, ok := verifier.registry.OTAProfile(deviceID)
		if !ok || profile.Board != board || profile.Channel != channel {
			return "", ErrUnauthorized
		}
		canonical = CanonicalOTAProof(deviceID, clientID, timestampText,
			nonceText, board, channel, releaseSequence, version)
	} else if verifier.scope == DeviceClaimProofScope {
		canonical = CanonicalDeviceClaimProof(deviceID, clientID,
			timestampText, nonceText, claim)
	} else if actionConsentScope {
		canonical = CanonicalActionConsentProof(verifier.scope, deviceID,
			clientID, timestampText, nonceText, bodySHA256)
	}
	mac := hmac.New(sha256.New, record.secret)
	_, _ = mac.Write([]byte(canonical))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return "", ErrUnauthorized
	}

	now := verifier.now().UTC()
	proofTime := time.Unix(timestamp, 0).UTC()
	if proofTime.Before(now.Add(-verifier.maxSkew)) ||
		proofTime.After(now.Add(verifier.maxSkew)) {
		return "", ErrUnauthorized
	}
	if err := verifier.reserve(request.Context(), deviceID, nonceText, now); err != nil {
		return "", err
	}
	if !verifier.registry.stillAllowedAtRevision(deviceID, identityRevision) {
		return "", ErrUnauthorized
	}
	return deviceID, nil
}

func isActionConsentProof(scope ProofScope) bool {
	return scope == ActionConsentChallengeProofScope ||
		scope == ActionConsentResultProofScope
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func canonicalBase64URL(value string, size int) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == size &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validVersion(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '.' || char == '+' ||
			char == '-' || char == '_' {
			continue
		}
		return false
	}
	return true
}

func (verifier *ProofVerifier) DeviceAllowed(deviceID string) bool {
	if verifier == nil {
		return false
	}
	record, found := verifier.registry.lookup(deviceID)
	return found && !record.disabled
}

func (verifier *ProofVerifier) RegistryReady() bool {
	return verifier != nil && verifier.registry.ProofReady()
}

func (verifier *ProofVerifier) Registry() *Registry {
	if verifier == nil {
		return nil
	}
	return verifier.registry
}

// SetCoordinator replaces replica-local replay and issuance state with one
// shared fail-closed coordinator. It must be called before serving requests.
func (verifier *ProofVerifier) SetCoordinator(
	coordinator runtimecoordination.Coordinator) error {
	if verifier == nil || coordinator == nil {
		return fmt.Errorf("invalid device proof coordinator")
	}
	verifier.coordinator = coordinator
	return nil
}

func (verifier *ProofVerifier) WithDeviceAllowed(deviceID string,
	action func() error) error {
	if verifier == nil {
		return ErrUnauthorized
	}
	return verifier.registry.withDeviceAllowed(deviceID, action)
}

func singleHeader(request *http.Request, name string) (string, bool) {
	values := request.Header.Values(name)
	if len(values) != 1 || values[0] == "" {
		return "", false
	}
	return values[0], true
}

func (verifier *ProofVerifier) reserve(ctx context.Context, deviceID, nonce string,
	now time.Time) error {
	if verifier.coordinator != nil {
		err := verifier.coordinator.ReserveProof(ctx, uint8(verifier.scope),
			deviceID, nonce, verifier.maxSkew, verifier.minInterval)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, runtimecoordination.ErrReplay):
			return ErrReplay
		case errors.Is(err, runtimecoordination.ErrRateLimited):
			return ErrRateLimited
		default:
			return ErrUnavailable
		}
	}
	verifier.mu.Lock()
	defer verifier.mu.Unlock()

	nonces := verifier.usedNonces[deviceID]
	if nonces == nil {
		nonces = make(map[string]time.Time)
		verifier.usedNonces[deviceID] = nonces
	}
	for existing, expires := range nonces {
		if !expires.After(now) {
			delete(nonces, existing)
		}
	}
	if _, exists := nonces[nonce]; exists {
		return ErrReplay
	}
	if len(nonces) >= maximumNonces {
		return ErrRateLimited
	}
	/* Reserve every authenticated nonce, including a rate-limited request. */
	nonces[nonce] = now.Add(2 * verifier.maxSkew)
	if previous, exists := verifier.lastIssued[deviceID]; exists &&
		now.Sub(previous) < verifier.minInterval {
		return ErrRateLimited
	}
	verifier.lastIssued[deviceID] = now
	return nil
}
