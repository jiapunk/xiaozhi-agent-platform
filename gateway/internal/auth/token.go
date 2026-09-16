package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const (
	VoiceAudience          = "xiaozhi-agent-gateway"
	AgentAudience          = "xiaozhi-agent-proxy"
	OTAAudience            = "xiaozhi-product-ota"
	CompanionAudience      = "xiaozhi-companion-claim"
	CompanionClaimAction   = "device:claim"
	CompanionReleaseAction = "device:release"
	CompanionConsentAction = "device:action-consent"
	MaximumBindingRevision = uint64(1<<32 - 1)
	maxTokenBytes          = 2048
	maxDeviceID            = 64
)

var (
	ErrMalformed  = errors.New("malformed device token")
	ErrSignature  = errors.New("invalid device token signature")
	ErrClaims     = errors.New("invalid device token claims")
	ErrExpired    = errors.New("expired device token")
	ErrKeyRetired = errors.New("retired device token key")
)

type Claims struct {
	DeviceID        string `json:"device_id,omitempty"`
	Subject         string `json:"sub,omitempty"`
	Issuer          string `json:"iss,omitempty"`
	OwnerID         string `json:"owner_id,omitempty"`
	TenantID        string `json:"tenant_id,omitempty"`
	BindingID       string `json:"binding_id,omitempty"`
	BindingRevision uint64 `json:"binding_revision,omitempty"`
	Action          string `json:"action,omitempty"`
	Audience        string `json:"aud"`
	IssuedAt        int64  `json:"iat"`
	Expires         int64  `json:"exp"`
	TokenID         string `json:"jti,omitempty"`
	ReleaseID       string `json:"release_id,omitempty"`
	ImageSHA256     string `json:"image_sha256,omitempty"`
	SigningKeyID    string `json:"-"`
}

type AuthorizationVerifier interface {
	AcceptsAudience(audience string) bool
	VerifyAuthorization(header string) (Claims, error)
}

var _ AuthorizationVerifier = (*Verifier)(nil)

type Verifier struct {
	secrets  [][]byte
	managed  *ManagedTokenKeyring
	audience string
	maxTTL   time.Duration
	skew     time.Duration
	now      func() time.Time
}

func (v *Verifier) AcceptsAudience(audience string) bool {
	return v != nil && v.audience == audience
}

func NewVerifier(secret []byte, maxTTL time.Duration) (*Verifier, error) {
	return NewKeyringVerifier([][]byte{secret}, maxTTL)
}

func NewKeyringVerifier(secrets [][]byte, maxTTL time.Duration) (*Verifier, error) {
	return NewKeyringVerifierForAudience(secrets, maxTTL, VoiceAudience)
}

func NewVerifierForAudience(secret []byte, maxTTL time.Duration,
	audience string) (*Verifier, error) {
	return NewKeyringVerifierForAudience([][]byte{secret}, maxTTL, audience)
}

func NewKeyringVerifierForAudience(secrets [][]byte, maxTTL time.Duration,
	audience string) (*Verifier, error) {
	if len(secrets) == 0 || len(secrets) > 3 {
		return nil, fmt.Errorf("device token keyring must contain 1 through 3 keys")
	}
	if maxTTL <= 0 || !ValidIdentifier(audience, 64) {
		return nil, fmt.Errorf("device token maximum TTL/audience is invalid")
	}
	keyring := make([][]byte, len(secrets))
	for index, secret := range secrets {
		if len(secret) < 32 {
			return nil, fmt.Errorf("device token HMAC key must be at least 32 bytes")
		}
		keyring[index] = append([]byte(nil), secret...)
	}
	return &Verifier{
		secrets:  keyring,
		audience: audience,
		maxTTL:   maxTTL,
		skew:     30 * time.Second,
		now:      time.Now,
	}, nil
}

func NewManagedKeyringVerifier(keyring *ManagedTokenKeyring,
	maxTTL time.Duration) (*Verifier, error) {
	return NewManagedKeyringVerifierForAudience(keyring, maxTTL, VoiceAudience)
}

func NewManagedKeyringVerifierForAudience(keyring *ManagedTokenKeyring,
	maxTTL time.Duration, audience string) (*Verifier, error) {
	if keyring == nil || len(keyring.keys) < 1 || maxTTL <= 0 ||
		!ValidIdentifier(audience, 64) {
		return nil, fmt.Errorf("managed token verifier configuration is invalid")
	}
	now := time.Now().UTC()
	skew := 30 * time.Second
	active, found := keyring.keys[keyring.activeKeyID]
	if !found || active.state != "active" ||
		active.verifyUntil.Before(now.Add(maxTTL+skew)) {
		return nil, fmt.Errorf("managed active token key expires before issued tokens")
	}
	for _, key := range keyring.keys {
		if key.state == "retiring" &&
			key.verifyUntil.Before(key.issueBefore.Add(maxTTL+skew)) {
			return nil, fmt.Errorf("managed retiring token key window is too short")
		}
	}
	return &Verifier{managed: keyring, audience: audience, maxTTL: maxTTL,
		skew: skew, now: time.Now}, nil
}

func (v *Verifier) VerifyAuthorization(header string) (Claims, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) || len(header) <= len(prefix) {
		return Claims{}, ErrMalformed
	}
	return v.Verify(strings.TrimSpace(header[len(prefix):]))
}

// VerifyAuthorizationForRelease is the OTA origin/CDN authorization boundary.
// It prevents a valid token for one release or image from being replayed for
// another object, even when both objects are served by the same origin.
func (v *Verifier) VerifyAuthorizationForRelease(header, releaseID,
	imageSHA256 string) (Claims, error) {
	if v == nil || v.audience != OTAAudience ||
		!ValidIdentifier(releaseID, 64) || !validSHA256(imageSHA256) {
		return Claims{}, ErrClaims
	}
	claims, err := v.VerifyAuthorization(header)
	if err != nil {
		return Claims{}, err
	}
	if !hmac.Equal([]byte(claims.ReleaseID), []byte(releaseID)) ||
		!hmac.Equal([]byte(claims.ImageSHA256), []byte(imageSHA256)) {
		return Claims{}, ErrClaims
	}
	return claims, nil
}

func (v *Verifier) Verify(token string) (Claims, error) {
	if v == nil || len(token) == 0 || len(token) > maxTokenBytes {
		return Claims{}, ErrMalformed
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 && len(parts) != 4 {
		return Claims{}, ErrMalformed
	}
	version := parts[0]
	payloadIndex, signatureIndex := 1, 2
	var verificationKey *managedTokenKey
	legacyManaged := false
	if len(parts) == 4 {
		if v.managed == nil || (version != "v2" && version != "v4") ||
			!ValidIdentifier(parts[1], 64) || parts[2] == "" || parts[3] == "" {
			return Claims{}, ErrMalformed
		}
		key, found := v.managed.keys[parts[1]]
		if !found {
			return Claims{}, ErrSignature
		}
		verificationKey = &key
		payloadIndex, signatureIndex = 2, 3
	} else {
		if (version != "v1" && version != "v3") || parts[1] == "" || parts[2] == "" {
			return Claims{}, ErrMalformed
		}
		if v.managed != nil {
			if v.managed.legacyUnkeyedKeyID == "" ||
				!v.now().Before(v.managed.legacyVerifyUntil) {
				return Claims{}, ErrKeyRetired
			}
			key, found := v.managed.keys[v.managed.legacyUnkeyedKeyID]
			if !found || key.state != "retiring" {
				return Claims{}, ErrKeyRetired
			}
			verificationKey = &key
			legacyManaged = true
		} else if len(v.secrets) == 0 {
			return Claims{}, ErrMalformed
		}
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[payloadIndex])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[signatureIndex])
	if err != nil || len(signature) != sha256.Size {
		return Claims{}, ErrMalformed
	}

	signingInput := strings.Join(parts[:signatureIndex], ".")
	validSignature := false
	if verificationKey != nil {
		if !v.now().Before(verificationKey.verifyUntil) {
			return Claims{}, ErrKeyRetired
		}
		mac := hmac.New(sha256.New, verificationKey.secret)
		_, _ = mac.Write([]byte(signingInput))
		validSignature = hmac.Equal(signature, mac.Sum(nil))
	}
	for _, secret := range v.secrets {
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write([]byte(signingInput))
		if hmac.Equal(signature, mac.Sum(nil)) {
			validSignature = true
		}
	}
	if !validSignature {
		return Claims{}, ErrSignature
	}

	var claims Claims
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil {
		return Claims{}, ErrClaims
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Claims{}, ErrClaims
	}
	if err := v.validateClaims(version, claims); err != nil {
		return Claims{}, err
	}
	if verificationKey != nil {
		if claims.Expires > verificationKey.verifyUntil.Unix() ||
			(verificationKey.state == "retiring" &&
				(claims.IssuedAt >= verificationKey.issueBefore.Unix() ||
					(legacyManaged && claims.Expires > v.managed.legacyVerifyUntil.Unix()))) {
			return Claims{}, ErrKeyRetired
		}
		claims.SigningKeyID = verificationKey.id
	}
	return claims, nil
}

func (v *Verifier) validateClaims(version string, claims Claims) error {
	now := v.now().Unix()
	skewSeconds := int64(v.skew / time.Second)
	maxTTLSeconds := int64(v.maxTTL / time.Second)

	if claims.Audience != v.audience || claims.IssuedAt <= 0 ||
		claims.Expires <= claims.IssuedAt ||
		claims.Expires-claims.IssuedAt > maxTTLSeconds {
		return ErrClaims
	}
	if claims.IssuedAt > now+skewSeconds {
		return ErrClaims
	}
	if claims.Expires <= now-skewSeconds {
		return ErrExpired
	}
	if claims.TokenID != "" && !ValidIdentifier(claims.TokenID, 128) {
		return ErrClaims
	}
	switch claims.Audience {
	case CompanionAudience:
		if (version != "v1" && version != "v2") || !ValidIdentifier(claims.Subject, 128) ||
			!ValidIdentifier(claims.TenantID, 128) ||
			claims.Issuer != "" ||
			claims.OwnerID != "" ||
			claims.BindingID != "" || claims.BindingRevision != 0 ||
			claims.TokenID == "" || claims.ReleaseID != "" ||
			claims.ImageSHA256 != "" ||
			!validCompanionActionDevice(claims.Action, claims.DeviceID) {
			return ErrClaims
		}
	case VoiceAudience, AgentAudience:
		if (version != "v3" && version != "v4") ||
			!ValidIdentifier(claims.DeviceID, maxDeviceID) ||
			!ValidIdentifier(claims.OwnerID, 128) ||
			!ValidIdentifier(claims.TenantID, 128) ||
			!ValidBindingID(claims.BindingID) ||
			!ValidBindingRevision(claims.BindingRevision) ||
			claims.TokenID == "" ||
			claims.Subject != "" || claims.Issuer != "" ||
			claims.Action != "" ||
			claims.ReleaseID != "" ||
			claims.ImageSHA256 != "" {
			return ErrClaims
		}
	case OTAAudience:
		if (version != "v1" && version != "v2") ||
			!ValidIdentifier(claims.DeviceID, maxDeviceID) ||
			claims.Subject != "" || claims.Issuer != "" ||
			claims.OwnerID != "" ||
			claims.TenantID != "" ||
			claims.BindingID != "" || claims.BindingRevision != 0 ||
			claims.Action != "" ||
			!ValidIdentifier(claims.ReleaseID, 64) ||
			!validSHA256(claims.ImageSHA256) || claims.TokenID == "" {
			return ErrClaims
		}
	default:
		if (version != "v1" && version != "v2") ||
			!ValidIdentifier(claims.DeviceID, maxDeviceID) ||
			claims.Subject != "" || claims.Issuer != "" ||
			claims.OwnerID != "" ||
			claims.TenantID != "" || claims.BindingID != "" ||
			claims.BindingRevision != 0 || claims.ReleaseID != "" ||
			claims.Action != "" ||
			claims.ImageSHA256 != "" {
			return ErrClaims
		}
	}
	return nil
}

func validCompanionActionDevice(action, deviceID string) bool {
	switch action {
	case CompanionClaimAction:
		return deviceID == ""
	case CompanionReleaseAction, CompanionConsentAction:
		return ValidIdentifier(deviceID, maxDeviceID)
	default:
		return false
	}
}

// OwnedDeviceScope is an internal authorization/rate/replay key. It must never
// be sent to a model provider or logged as a user-facing identifier.
func OwnedDeviceScope(claims Claims) (string, bool) {
	if (claims.Audience != VoiceAudience && claims.Audience != AgentAudience) ||
		!ValidIdentifier(claims.DeviceID, maxDeviceID) ||
		!ValidIdentifier(claims.OwnerID, 128) ||
		!ValidIdentifier(claims.TenantID, 128) ||
		!ValidBindingID(claims.BindingID) ||
		!ValidBindingRevision(claims.BindingRevision) {
		return "", false
	}
	return claims.BindingID + "\x00" +
		strconv.FormatUint(claims.BindingRevision, 10) + "\x00" +
		claims.DeviceID, true
}

func ValidBindingID(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 16 &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}

func ValidBindingRevision(value uint64) bool {
	return value > 0 && value <= MaximumBindingRevision
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

func ValidIdentifier(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == ':' || char == '-' ||
			char == '_' || char == '.' {
			continue
		}
		return false
	}
	return true
}
