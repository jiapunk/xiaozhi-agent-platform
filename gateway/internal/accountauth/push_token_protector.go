package accountauth

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const pushTokenProtectionDomain = "xz-companion-push-token-v1"

var ErrPushTokenAuthentication = errors.New("push token authentication failed")

type PushTokenBinding struct {
	Principal      Principal
	InstallationID string
	Platform       PushPlatform
}

type PushTokenProtector interface {
	Seal(context.Context, PushTokenBinding, string) (ProtectedPushToken, error)
	Open(context.Context, PushTokenBinding, ProtectedPushToken) (string, error)
}

type PushTokenKeyMaterial struct {
	EncryptionKey []byte
	LookupKey     []byte
}

type pushTokenKey struct {
	encryption [32]byte
	lookup     [32]byte
}

// AESGCMPushTokenProtector is a local cryptographic adapter. Production key
// bytes must be injected from a secret manager/workload identity and rotated by
// constructing a keyring containing the current and still-readable old keys.
type AESGCMPushTokenProtector struct {
	currentKeyID string
	keys         map[string]pushTokenKey
	random       io.Reader
}

var _ PushTokenProtector = (*AESGCMPushTokenProtector)(nil)

func NewAESGCMPushTokenProtector(currentKeyID string,
	materials map[string]PushTokenKeyMaterial) (*AESGCMPushTokenProtector, error) {
	if len(materials) < 1 || len(materials) > 8 ||
		!authIdentifier(currentKeyID) {
		return nil, ErrInvalid
	}
	protector := &AESGCMPushTokenProtector{
		currentKeyID: currentKeyID,
		keys:         make(map[string]pushTokenKey, len(materials)),
		random:       rand.Reader,
	}
	for keyID, material := range materials {
		if !authIdentifier(keyID) || len(material.EncryptionKey) != 32 ||
			len(material.LookupKey) != 32 ||
			subtle.ConstantTimeCompare(material.EncryptionKey,
				material.LookupKey) == 1 {
			return nil, ErrInvalid
		}
		var key pushTokenKey
		copy(key.encryption[:], material.EncryptionKey)
		copy(key.lookup[:], material.LookupKey)
		protector.keys[keyID] = key
	}
	if _, found := protector.keys[currentKeyID]; !found {
		return nil, ErrInvalid
	}
	return protector, nil
}

func (protector *AESGCMPushTokenProtector) Seal(ctx context.Context,
	binding PushTokenBinding, rawToken string) (ProtectedPushToken, error) {
	if protector == nil || ctx == nil || !ValidPushTokenBinding(binding) ||
		!ValidRawPushToken(binding.Platform, rawToken) {
		return ProtectedPushToken{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return ProtectedPushToken{}, unavailable("seal push token", err)
	}
	key, found := protector.keys[protector.currentKeyID]
	if !found {
		return ProtectedPushToken{}, ErrUnavailable
	}
	block, err := aes.NewCipher(key.encryption[:])
	if err != nil {
		return ProtectedPushToken{}, ErrUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return ProtectedPushToken{}, ErrUnavailable
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(protector.random, nonce); err != nil {
		return ProtectedPushToken{}, unavailable("generate push token nonce", err)
	}
	aad := pushTokenAAD(binding, protector.currentKeyID)
	ciphertext := append(nonce, aead.Seal(nil, nonce, []byte(rawToken), aad)...)
	digest := pushTokenDigest(key.lookup, binding.Platform, rawToken)
	return ProtectedPushToken{Ciphertext: ciphertext,
		KeyID: protector.currentKeyID, Digest: digest}, nil
}

func (protector *AESGCMPushTokenProtector) Open(ctx context.Context,
	binding PushTokenBinding, protected ProtectedPushToken) (string, error) {
	if protector == nil || ctx == nil || !ValidPushTokenBinding(binding) ||
		!ValidProtectedPushToken(protected) {
		return "", ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return "", unavailable("open push token", err)
	}
	key, found := protector.keys[protected.KeyID]
	if !found {
		return "", ErrPushTokenAuthentication
	}
	block, err := aes.NewCipher(key.encryption[:])
	if err != nil {
		return "", ErrUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(protected.Ciphertext) <= aead.NonceSize() {
		return "", ErrPushTokenAuthentication
	}
	nonce := protected.Ciphertext[:aead.NonceSize()]
	plaintext, err := aead.Open(nil, nonce,
		protected.Ciphertext[aead.NonceSize():],
		pushTokenAAD(binding, protected.KeyID))
	if err != nil {
		return "", ErrPushTokenAuthentication
	}
	rawToken := string(plaintext)
	if !ValidRawPushToken(binding.Platform, rawToken) {
		return "", ErrPushTokenAuthentication
	}
	expected := pushTokenDigest(key.lookup, binding.Platform, rawToken)
	if subtle.ConstantTimeCompare(expected[:], protected.Digest[:]) != 1 {
		return "", ErrPushTokenAuthentication
	}
	return rawToken, nil
}

func ValidPushTokenBinding(binding PushTokenBinding) bool {
	return ValidPrincipal(binding.Principal) &&
		ValidPushInstallationID(binding.InstallationID) &&
		ValidPushPlatform(binding.Platform)
}

func ValidRawPushToken(platform PushPlatform, rawToken string) bool {
	switch platform {
	case PushPlatformAPNSProduction, PushPlatformAPNSDevelopment:
		if len(rawToken) < 32 || len(rawToken) > 512 || len(rawToken)%2 != 0 {
			return false
		}
		decoded, err := hex.DecodeString(rawToken)
		return err == nil && hex.EncodeToString(decoded) == rawToken
	case PushPlatformFCM:
		if len(rawToken) < 20 || len(rawToken) > 4096 {
			return false
		}
		for _, character := range []byte(rawToken) {
			if !(character >= 'A' && character <= 'Z') &&
				!(character >= 'a' && character <= 'z') &&
				!(character >= '0' && character <= '9') &&
				character != ':' && character != '_' && character != '-' &&
				character != '.' && character != '~' {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func pushTokenAAD(binding PushTokenBinding, keyID string) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		pushTokenProtectionDomain, binding.Principal.TenantID,
		binding.Principal.Subject, binding.InstallationID,
		binding.Platform, keyID))
}

func pushTokenDigest(key [32]byte, platform PushPlatform,
	rawToken string) [32]byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(pushTokenProtectionDomain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(platform))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(rawToken))
	var digest [32]byte
	copy(digest[:], mac.Sum(nil))
	return digest
}

func authIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, character := range []byte(value) {
		if !(character >= 'A' && character <= 'Z') &&
			!(character >= 'a' && character <= 'z') &&
			!(character >= '0' && character <= '9') &&
			!bytes.ContainsRune([]byte(":_.-"), rune(character)) {
			return false
		}
	}
	return true
}
