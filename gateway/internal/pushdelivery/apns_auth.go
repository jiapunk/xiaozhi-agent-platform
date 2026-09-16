package pushdelivery

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"
)

const (
	apnsTokenRefreshAge = 40 * time.Minute
	apnsTokenMaximumAge = 50 * time.Minute
)

type APNsJWTBearerProvider struct {
	signer crypto.Signer
	keyID  string
	teamID string
	now    func() time.Time

	mu       sync.Mutex
	token    string
	issuedAt time.Time
}

var _ BearerTokenProvider = (*APNsJWTBearerProvider)(nil)

func NewAPNsJWTBearerProvider(signer crypto.Signer, keyID, teamID string) (
	*APNsJWTBearerProvider, error) {
	if signer == nil || !validAppleIdentifier(keyID) ||
		!validAppleIdentifier(teamID) {
		return nil, ErrInvalid
	}
	publicKey, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || publicKey == nil || publicKey.Curve != elliptic.P256() ||
		publicKey.X == nil || publicKey.Y == nil ||
		!publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return nil, ErrInvalid
	}
	return &APNsJWTBearerProvider{signer: signer, keyID: keyID,
		teamID: teamID, now: time.Now}, nil
}

func (provider *APNsJWTBearerProvider) BearerToken(ctx context.Context) (
	string, error) {
	if provider == nil || provider.signer == nil || ctx == nil {
		return "", ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("%w: APNs token context", ErrUnavailable)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	now := provider.now().UTC()
	if !provider.issuedAt.IsZero() && now.Before(provider.issuedAt.Add(-30*time.Second)) {
		return "", fmt.Errorf("%w: APNs token clock moved backward", ErrUnavailable)
	}
	age := now.Sub(provider.issuedAt)
	if provider.token != "" && age >= 0 && age < apnsTokenRefreshAge {
		return provider.token, nil
	}
	token, err := provider.sign(now)
	if err != nil {
		if provider.token != "" && age >= 0 && age < apnsTokenMaximumAge {
			return provider.token, nil
		}
		return "", fmt.Errorf("%w: APNs token signing", ErrUnavailable)
	}
	provider.token = token
	provider.issuedAt = now
	return token, nil
}

func (provider *APNsJWTBearerProvider) sign(now time.Time) (string, error) {
	header, err := json.Marshal(struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}{Algorithm: "ES256", KeyID: provider.keyID})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(struct {
		Issuer   string `json:"iss"`
		IssuedAt int64  `json:"iat"`
	}{Issuer: provider.teamID, IssuedAt: now.Unix()})
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	der, err := provider.signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	var signature struct {
		R, S *big.Int
	}
	trailing, err := asn1.Unmarshal(der, &signature)
	publicKey, ok := provider.signer.Public().(*ecdsa.PublicKey)
	if err != nil || len(trailing) != 0 || !ok || signature.R == nil ||
		signature.S == nil || signature.R.Sign() <= 0 || signature.S.Sign() <= 0 ||
		signature.R.Cmp(publicKey.Params().N) >= 0 ||
		signature.S.Cmp(publicKey.Params().N) >= 0 ||
		!ecdsa.Verify(publicKey, digest[:], signature.R, signature.S) {
		return "", ErrInvalid
	}
	raw := make([]byte, 64)
	signature.R.FillBytes(raw[:32])
	signature.S.FillBytes(raw[32:])
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(raw), nil
}

func validAppleIdentifier(value string) bool {
	if len(value) != 10 {
		return false
	}
	for _, character := range []byte(value) {
		if !(character >= 'A' && character <= 'Z') &&
			!(character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}
