package pushdelivery

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"
)

type switchECDSASigner struct {
	key  *ecdsa.PrivateKey
	fail bool
}

func (signer *switchECDSASigner) Public() crypto.PublicKey {
	return signer.key.Public()
}

func (signer *switchECDSASigner) Sign(random io.Reader, digest []byte,
	options crypto.SignerOpts) ([]byte, error) {
	if signer.fail {
		return nil, errors.New("signing unavailable")
	}
	return signer.key.Sign(random, digest, options)
}

func TestAPNsJWTBearerProviderSignsAndCachesBoundedToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := &switchECDSASigner{key: key}
	provider, err := NewAPNsJWTBearerProvider(signer,
		"ABC123DEFG", "TEAM12ABCD")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	provider.now = func() time.Time { return now }
	token, err := provider.BearerToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token parts=%d", len(parts))
	}
	decode := func(part string, output any) {
		t.Helper()
		encoded, decodeErr := base64.RawURLEncoding.DecodeString(part)
		if decodeErr != nil || json.Unmarshal(encoded, output) != nil {
			t.Fatalf("invalid JWT segment %q", part)
		}
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	var claims struct {
		Issuer   string `json:"iss"`
		IssuedAt int64  `json:"iat"`
	}
	decode(parts[0], &header)
	decode(parts[1], &claims)
	if header.Algorithm != "ES256" || header.KeyID != "ABC123DEFG" ||
		claims.Issuer != "TEAM12ABCD" || claims.IssuedAt != now.Unix() {
		t.Fatalf("header=%+v claims=%+v", header, claims)
	}
	rawSignature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(rawSignature) != 64 {
		t.Fatalf("signature length=%d err=%v", len(rawSignature), err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&key.PublicKey, digest[:],
		new(big.Int).SetBytes(rawSignature[:32]),
		new(big.Int).SetBytes(rawSignature[32:])) {
		t.Fatal("APNs JWT signature verification failed")
	}

	signer.fail = true
	now = now.Add(39 * time.Minute)
	if cached, cacheErr := provider.BearerToken(context.Background()); cacheErr != nil || cached != token {
		t.Fatalf("cached=%q err=%v", cached, cacheErr)
	}
	now = now.Add(2 * time.Minute)
	if fallback, fallbackErr := provider.BearerToken(context.Background()); fallbackErr != nil || fallback != token {
		t.Fatalf("fallback=%q err=%v", fallback, fallbackErr)
	}
	now = now.Add(10 * time.Minute)
	if _, expiredErr := provider.BearerToken(context.Background()); !errors.Is(expiredErr, ErrUnavailable) {
		t.Fatalf("expired fallback err=%v", expiredErr)
	}
}

func TestAPNsJWTBearerProviderRefreshAndClockFence(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	provider, err := NewAPNsJWTBearerProvider(key,
		"ABC123DEFG", "TEAM12ABCD")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	provider.now = func() time.Time { return now }
	first, _ := provider.BearerToken(context.Background())
	now = now.Add(40 * time.Minute)
	second, refreshErr := provider.BearerToken(context.Background())
	if refreshErr != nil || second == first {
		t.Fatalf("token did not refresh: err=%v", refreshErr)
	}
	now = now.Add(-time.Minute)
	if _, err := provider.BearerToken(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("clock rollback err=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provider.BearerToken(cancelled); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cancelled context err=%v", err)
	}
}
