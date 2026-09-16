package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

const (
	minimumIssuedTTL = time.Minute
	maximumIssuedTTL = time.Hour
	tokenIDBytes     = 16
)

type Issuer struct {
	secret      []byte
	keyID       string
	verifyUntil time.Time
	managed     bool
	ttl         time.Duration
	audience    string
	now         func() time.Time
	random      io.Reader
}

func NewManagedIssuerForAudience(keyring *ManagedTokenKeyring,
	ttl time.Duration, audience string) (*Issuer, error) {
	if keyring == nil || !ValidIdentifier(keyring.activeKeyID, 64) {
		return nil, fmt.Errorf("managed token issuer keyring is invalid")
	}
	key, found := keyring.keys[keyring.activeKeyID]
	if !found || key.state != "active" {
		return nil, fmt.Errorf("managed token issuer active key is invalid")
	}
	issuer, err := NewIssuerForAudience(key.secret, ttl, audience)
	if err != nil {
		return nil, err
	}
	if key.verifyUntil.Before(issuer.now().UTC().Add(ttl + 30*time.Second)) {
		return nil, fmt.Errorf("managed token issuer key expires before issued tokens")
	}
	issuer.keyID = key.id
	issuer.verifyUntil = key.verifyUntil
	issuer.managed = true
	return issuer, nil
}

func NewIssuer(secret []byte, ttl time.Duration) (*Issuer, error) {
	return NewIssuerForAudience(secret, ttl, VoiceAudience)
}

func NewIssuerForAudience(secret []byte, ttl time.Duration,
	audience string) (*Issuer, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("device token HMAC key must be at least 32 bytes")
	}
	if ttl < minimumIssuedTTL || ttl > maximumIssuedTTL {
		return nil, fmt.Errorf("device token TTL must be from 60 through 3600 seconds")
	}
	if !ValidIdentifier(audience, 64) {
		return nil, fmt.Errorf("device token audience is invalid")
	}
	return &Issuer{
		secret:   append([]byte(nil), secret...),
		ttl:      ttl,
		audience: audience,
		now:      time.Now,
		random:   rand.Reader,
	}, nil
}

func (issuer *Issuer) Issue(deviceID string) (string, Claims, error) {
	if issuer == nil || issuer.audience == VoiceAudience ||
		issuer.audience == AgentAudience || issuer.audience == OTAAudience ||
		issuer.audience == CompanionAudience {
		return "", Claims{}, ErrClaims
	}
	return issuer.issue(deviceID, "", "", "", "", 0, "", "", "")
}

// IssueCompanion is used only by the product auth service. The Companion App
// receives the resulting short-lived bearer token; it never receives the HMAC
// key shared between the auth service and claim verifier. Tenant is explicit;
// it is never inferred from the user subject.
func (issuer *Issuer) IssueCompanion(subject, tenantID string) (string, Claims, error) {
	if issuer == nil || issuer.audience != CompanionAudience ||
		!ValidIdentifier(subject, 128) || !ValidIdentifier(tenantID, 128) {
		return "", Claims{}, ErrClaims
	}
	return issuer.issue("", subject, "", tenantID, "", 0, "", "",
		CompanionClaimAction)
}

func (issuer *Issuer) IssueCompanionRelease(subject, tenantID,
	deviceID string) (string, Claims, error) {
	if issuer == nil || issuer.audience != CompanionAudience ||
		!ValidIdentifier(subject, 128) || !ValidIdentifier(tenantID, 128) ||
		!ValidIdentifier(deviceID, maxDeviceID) {
		return "", Claims{}, ErrClaims
	}
	return issuer.issue(deviceID, subject, "", tenantID, "", 0, "", "",
		CompanionReleaseAction)
}

func (issuer *Issuer) IssueCompanionActionConsent(subject, tenantID,
	deviceID string) (string, Claims, error) {
	if issuer == nil || issuer.audience != CompanionAudience ||
		!ValidIdentifier(subject, 128) || !ValidIdentifier(tenantID, 128) ||
		!ValidIdentifier(deviceID, maxDeviceID) {
		return "", Claims{}, ErrClaims
	}
	return issuer.issue(deviceID, subject, "", tenantID, "", 0, "", "",
		CompanionConsentAction)
}

func (issuer *Issuer) IssueOwned(deviceID, ownerID, tenantID, bindingID string,
	bindingRevision uint64) (string, Claims, error) {
	return issuer.issueOwnedUntil(deviceID, ownerID, tenantID, bindingID,
		bindingRevision, time.Time{})
}

// IssueOwnedUntil prevents a Voice or Agent token from outliving the account's
// current commercial access window. It never extends the configured issuer
// TTL, and refuses a residual lifetime below the protocol's 60-second minimum.
func (issuer *Issuer) IssueOwnedUntil(deviceID, ownerID, tenantID,
	bindingID string, bindingRevision uint64, validUntil time.Time) (
	string, Claims, error) {
	if validUntil.IsZero() || validUntil.Location() != time.UTC ||
		validUntil.Nanosecond() != 0 {
		return "", Claims{}, ErrClaims
	}
	return issuer.issueOwnedUntil(deviceID, ownerID, tenantID, bindingID,
		bindingRevision, validUntil)
}

func (issuer *Issuer) issueOwnedUntil(deviceID, ownerID, tenantID,
	bindingID string, bindingRevision uint64, validUntil time.Time) (
	string, Claims, error) {
	if issuer == nil ||
		(issuer.audience != VoiceAudience &&
			issuer.audience != AgentAudience) ||
		!ValidIdentifier(deviceID, maxDeviceID) ||
		!ValidIdentifier(ownerID, 128) ||
		!ValidIdentifier(tenantID, 128) || !ValidBindingID(bindingID) ||
		!ValidBindingRevision(bindingRevision) {
		return "", Claims{}, ErrClaims
	}
	return issuer.issueUntil(deviceID, "", ownerID, tenantID, bindingID,
		bindingRevision, "", "", "", validUntil)
}

func (issuer *Issuer) IssueForRelease(deviceID, releaseID,
	imageSHA256 string) (string, Claims, error) {
	if issuer == nil || issuer.audience != OTAAudience ||
		!ValidIdentifier(releaseID, 64) || !validSHA256(imageSHA256) {
		return "", Claims{}, ErrClaims
	}
	return issuer.issue(deviceID, "", "", "", "", 0, releaseID, imageSHA256,
		"")
}

func (issuer *Issuer) issue(deviceID, subject, ownerID, tenantID, bindingID string,
	bindingRevision uint64, releaseID, imageSHA256, action string) (string, Claims, error) {
	return issuer.issueUntil(deviceID, subject, ownerID, tenantID, bindingID,
		bindingRevision, releaseID, imageSHA256, action, time.Time{})
}

func (issuer *Issuer) issueUntil(deviceID, subject, ownerID, tenantID,
	bindingID string, bindingRevision uint64, releaseID, imageSHA256,
	action string, validUntil time.Time) (string, Claims, error) {
	if issuer == nil ||
		(subject == "" && !ValidIdentifier(deviceID, maxDeviceID)) ||
		(subject != "" && deviceID != "" &&
			action != CompanionReleaseAction && action != CompanionConsentAction) {
		return "", Claims{}, ErrClaims
	}
	tokenID := make([]byte, tokenIDBytes)
	if _, err := io.ReadFull(issuer.random, tokenID); err != nil {
		return "", Claims{}, fmt.Errorf("generate token id: %w", err)
	}
	now := issuer.now().UTC()
	expiresAt := now.Add(issuer.ttl).Truncate(time.Second)
	if !validUntil.IsZero() && validUntil.Before(expiresAt) {
		expiresAt = validUntil
	}
	if expiresAt.Unix()-now.Unix() < int64(minimumIssuedTTL/time.Second) {
		return "", Claims{}, ErrClaims
	}
	if issuer.managed && (!ValidIdentifier(issuer.keyID, 64) ||
		issuer.verifyUntil.Before(expiresAt.Add(30*time.Second))) {
		return "", Claims{}, ErrKeyRetired
	}
	claims := Claims{
		DeviceID:        deviceID,
		Subject:         subject,
		OwnerID:         ownerID,
		TenantID:        tenantID,
		BindingID:       bindingID,
		BindingRevision: bindingRevision,
		Action:          action,
		Audience:        issuer.audience,
		IssuedAt:        now.Unix(),
		Expires:         expiresAt.Unix(),
		TokenID:         base64.RawURLEncoding.EncodeToString(tokenID),
		ReleaseID:       releaseID,
		ImageSHA256:     imageSHA256,
		SigningKeyID:    issuer.keyID,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", Claims{}, fmt.Errorf("encode claims: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	version := "v1"
	if issuer.audience == VoiceAudience || issuer.audience == AgentAudience {
		version = "v3"
	}
	signingInput := version + "." + encoded
	if issuer.managed {
		version = "v2"
		if issuer.audience == VoiceAudience || issuer.audience == AgentAudience {
			version = "v4"
		}
		signingInput = version + "." + issuer.keyID + "." + encoded
	}
	mac := hmac.New(sha256.New, issuer.secret)
	_, _ = mac.Write([]byte(signingInput))
	token := signingInput + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if len(token) > maxTokenBytes {
		return "", Claims{}, ErrMalformed
	}
	return token, claims, nil
}
