package mtlsdispatchqualification

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

func signDomainPayload(domain, payload []byte, privateKeyPath string) (string, error) {
	privateKey, err := loadEd25519PrivateKey(privateKeyPath)
	if err != nil {
		return "", err
	}
	message := append(append([]byte(nil), domain...), payload...)
	return base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(privateKey, message)), nil
}

func verifyDomainPayload(domain, payload []byte, signature,
	publicKeyPath string) error {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(signature)
	if err != nil || len(decoded) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(decoded) != signature {
		return fmt.Errorf("mTLS dispatch qualification signature is invalid")
	}
	publicKey, err := loadEd25519PublicKey(publicKeyPath)
	if err != nil {
		return err
	}
	message := append(append([]byte(nil), domain...), payload...)
	if !ed25519.Verify(publicKey, message, decoded) {
		return fmt.Errorf("mTLS dispatch qualification signature is invalid")
	}
	return nil
}

func loadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	payload, err := readRegular(path, 16*1024, true)
	if err != nil {
		return nil, fmt.Errorf("mTLS dispatch qualification private key: %w", err)
	}
	block, rest := pem.Decode(payload)
	if block == nil || block.Type != "PRIVATE KEY" ||
		len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("mTLS dispatch qualification private key is invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok || len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("mTLS dispatch qualification private key is invalid")
	}
	return key, nil
}

func loadEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	payload, err := readRegular(path, 16*1024, false)
	if err != nil {
		return nil, fmt.Errorf("mTLS dispatch qualification public key: %w", err)
	}
	block, rest := pem.Decode(payload)
	if block == nil || block.Type != "PUBLIC KEY" ||
		len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("mTLS dispatch qualification public key is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("mTLS dispatch qualification public key is invalid")
	}
	return key, nil
}
