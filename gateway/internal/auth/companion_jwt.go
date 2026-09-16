package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

const maximumIssuerBytes = 256

type companionJWTHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

type CompanionJWTVerifier struct {
	keys     map[string]ed25519.PublicKey
	issuer   string
	maxTTL   time.Duration
	skew     time.Duration
	now      func() time.Time
	audience string
}

var _ AuthorizationVerifier = (*CompanionJWTVerifier)(nil)

func NewCompanionJWTVerifier(keys map[string]ed25519.PublicKey,
	issuer string, maxTTL time.Duration) (*CompanionJWTVerifier, error) {
	if len(keys) == 0 || len(keys) > 3 || !ValidHTTPSIssuer(issuer) ||
		maxTTL < minimumIssuedTTL || maxTTL > maximumIssuedTTL {
		return nil, fmt.Errorf("invalid Companion JWT verifier configuration")
	}
	keyring := make(map[string]ed25519.PublicKey, len(keys))
	for keyID, publicKey := range keys {
		if !ValidIdentifier(keyID, 64) || len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Companion JWT keyring")
		}
		keyring[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	return &CompanionJWTVerifier{
		keys: keyring, issuer: issuer, maxTTL: maxTTL,
		skew: 30 * time.Second, now: time.Now,
		audience: CompanionAudience,
	}, nil
}

func (verifier *CompanionJWTVerifier) AcceptsAudience(audience string) bool {
	return verifier != nil && audience == CompanionAudience
}

func (verifier *CompanionJWTVerifier) VerifyAuthorization(
	header string) (Claims, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) || len(header) <= len(prefix) {
		return Claims{}, ErrMalformed
	}
	return verifier.Verify(strings.TrimSpace(header[len(prefix):]))
}

func (verifier *CompanionJWTVerifier) Verify(token string) (Claims, error) {
	if verifier == nil || len(token) == 0 || len(token) > maxTokenBytes {
		return Claims{}, ErrMalformed
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Claims{}, ErrMalformed
	}
	headerBytes, err := decodeCanonicalBase64URL(parts[0])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	var header companionJWTHeader
	if err := decodeStrictJSON(headerBytes, &header); err != nil ||
		header.Algorithm != "EdDSA" || header.Type != "JWT" ||
		!ValidIdentifier(header.KeyID, 64) {
		return Claims{}, ErrClaims
	}
	publicKey, found := verifier.keys[header.KeyID]
	if !found {
		return Claims{}, ErrSignature
	}
	signature, err := decodeCanonicalBase64URL(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Claims{}, ErrMalformed
	}
	if !ed25519.Verify(publicKey,
		[]byte(parts[0]+"."+parts[1]), signature) {
		return Claims{}, ErrSignature
	}
	payload, err := decodeCanonicalBase64URL(parts[1])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	var claims Claims
	if err := decodeStrictJSON(payload, &claims); err != nil {
		return Claims{}, ErrClaims
	}
	if err := verifier.validateClaims(claims); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

func (verifier *CompanionJWTVerifier) validateClaims(claims Claims) error {
	now := verifier.now().Unix()
	skewSeconds := int64(verifier.skew / time.Second)
	maxTTLSeconds := int64(verifier.maxTTL / time.Second)
	if claims.Audience != CompanionAudience || claims.Issuer != verifier.issuer ||
		claims.IssuedAt <= 0 || claims.Expires <= claims.IssuedAt ||
		claims.Expires-claims.IssuedAt > maxTTLSeconds ||
		claims.IssuedAt > now+skewSeconds {
		return ErrClaims
	}
	if claims.Expires <= now-skewSeconds {
		return ErrExpired
	}
	if !ValidIdentifier(claims.Subject, 128) ||
		!ValidIdentifier(claims.TenantID, 128) ||
		!ValidIdentifier(claims.TokenID, 128) ||
		claims.OwnerID != "" || claims.BindingID != "" ||
		claims.BindingRevision != 0 ||
		claims.ReleaseID != "" || claims.ImageSHA256 != "" ||
		!validCompanionActionDevice(claims.Action, claims.DeviceID) {
		return ErrClaims
	}
	return nil
}

type CompanionJWTIssuer struct {
	privateKey ed25519.PrivateKey
	keyID      string
	issuer     string
	ttl        time.Duration
	now        func() time.Time
	random     io.Reader
}

func NewCompanionJWTIssuer(privateKey ed25519.PrivateKey, keyID, issuer string,
	ttl time.Duration) (*CompanionJWTIssuer, error) {
	if len(privateKey) != ed25519.PrivateKeySize ||
		!ValidIdentifier(keyID, 64) || !ValidHTTPSIssuer(issuer) ||
		ttl < minimumIssuedTTL || ttl > maximumIssuedTTL {
		return nil, fmt.Errorf("invalid Companion JWT issuer configuration")
	}
	return &CompanionJWTIssuer{
		privateKey: append(ed25519.PrivateKey(nil), privateKey...),
		keyID:      keyID, issuer: issuer, ttl: ttl,
		now: time.Now, random: rand.Reader,
	}, nil
}

func (issuer *CompanionJWTIssuer) Issue(subject,
	tenantID string) (string, Claims, error) {
	return issuer.issue(subject, tenantID, CompanionClaimAction, "")
}

func (issuer *CompanionJWTIssuer) IssueRelease(subject, tenantID,
	deviceID string) (string, Claims, error) {
	return issuer.issue(subject, tenantID, CompanionReleaseAction, deviceID)
}

func (issuer *CompanionJWTIssuer) IssueActionConsent(subject, tenantID,
	deviceID string) (string, Claims, error) {
	return issuer.issue(subject, tenantID, CompanionConsentAction, deviceID)
}

func (issuer *CompanionJWTIssuer) issue(subject, tenantID, action,
	deviceID string) (string, Claims, error) {
	if issuer == nil || !ValidIdentifier(subject, 128) ||
		!ValidIdentifier(tenantID, 128) ||
		!validCompanionActionDevice(action, deviceID) {
		return "", Claims{}, ErrClaims
	}
	tokenID := make([]byte, tokenIDBytes)
	if _, err := io.ReadFull(issuer.random, tokenID); err != nil {
		return "", Claims{}, fmt.Errorf("generate token id: %w", err)
	}
	now := issuer.now().UTC()
	claims := Claims{
		DeviceID: deviceID, Subject: subject, Issuer: issuer.issuer,
		TenantID: tenantID, Action: action,
		Audience: CompanionAudience, IssuedAt: now.Unix(),
		Expires: now.Add(issuer.ttl).Unix(),
		TokenID: base64.RawURLEncoding.EncodeToString(tokenID),
	}
	headerBytes, err := json.Marshal(companionJWTHeader{
		Algorithm: "EdDSA", KeyID: issuer.keyID, Type: "JWT",
	})
	if err != nil {
		return "", Claims{}, err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", Claims{}, err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerBytes) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(issuer.privateKey, []byte(signingInput))
	token := signingInput + "." +
		base64.RawURLEncoding.EncodeToString(signature)
	if len(token) > maxTokenBytes {
		return "", Claims{}, ErrMalformed
	}
	return token, claims, nil
}

func ValidHTTPSIssuer(value string) bool {
	if len(value) == 0 || len(value) > maximumIssuerBytes {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" &&
		parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" &&
		parsed.String() == value
}

func decodeCanonicalBase64URL(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrMalformed
	}
	return decoded, nil
}

func decodeStrictJSON(data []byte, target any) error {
	keys := make(map[string]bool)
	keyDecoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := keyDecoder.Token()
	if err != nil || opening != json.Delim('{') {
		return ErrClaims
	}
	for keyDecoder.More() {
		keyToken, err := keyDecoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok || keys[key] {
			return ErrClaims
		}
		keys[key] = true
		var value json.RawMessage
		if err := keyDecoder.Decode(&value); err != nil {
			return err
		}
	}
	closing, err := keyDecoder.Token()
	if err != nil || closing != json.Delim('}') {
		return ErrClaims
	}
	var keyTrailing any
	if err := keyDecoder.Decode(&keyTrailing); !errors.Is(err, io.EOF) {
		return ErrClaims
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrClaims
	}
	return nil
}
