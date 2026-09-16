package pushdelivery

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"xiaozhi-agent-platform/gateway/internal/strictjson"
)

const maximumCredentialFileBytes = 64 * 1024

type GoogleServiceAccountCredential struct {
	ProjectID string
	Email     string
	KeyID     string
	Signer    crypto.Signer
}

func LoadAPNsPrivateKey(path string) (crypto.Signer, error) {
	payload, err := readCredentialFile(path)
	if err != nil {
		return nil, fmt.Errorf("invalid APNs private key file")
	}
	defer wipe(payload)
	block, rest := pem.Decode(payload)
	if block == nil || block.Type != "PRIVATE KEY" ||
		len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("invalid APNs private key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || key == nil || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("invalid APNs ES256 private key")
	}
	return key, nil
}

func LoadGoogleServiceAccountCredential(path string) (
	GoogleServiceAccountCredential, error) {
	payload, err := readCredentialFile(path)
	if err != nil {
		return GoogleServiceAccountCredential{},
			fmt.Errorf("invalid Google service account file")
	}
	defer wipe(payload)
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return GoogleServiceAccountCredential{},
			fmt.Errorf("invalid Google service account JSON")
	}
	var document struct {
		Type         string `json:"type"`
		ProjectID    string `json:"project_id"`
		PrivateKeyID string `json:"private_key_id"`
		PrivateKey   string `json:"private_key"`
		ClientEmail  string `json:"client_email"`
		TokenURI     string `json:"token_uri"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&document); err != nil {
		return GoogleServiceAccountCredential{},
			fmt.Errorf("invalid Google service account JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF ||
		document.Type != "service_account" ||
		!validFCMProjectID(document.ProjectID) ||
		!validServiceAccountEmail(document.ClientEmail) ||
		!validGoogleKeyID(document.PrivateKeyID) ||
		document.TokenURI != googleOAuthTokenEndpoint {
		return GoogleServiceAccountCredential{},
			fmt.Errorf("invalid Google service account fields")
	}
	keyPayload := []byte(document.PrivateKey)
	defer wipe(keyPayload)
	block, rest := pem.Decode(keyPayload)
	if block == nil || block.Type != "PRIVATE KEY" ||
		len(bytes.TrimSpace(rest)) != 0 {
		return GoogleServiceAccountCredential{},
			fmt.Errorf("invalid Google service account private key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(*rsa.PrivateKey)
	if err != nil || !ok || key == nil || key.N == nil || key.N.BitLen() < 2048 {
		return GoogleServiceAccountCredential{},
			fmt.Errorf("invalid Google service account RSA private key")
	}
	return GoogleServiceAccountCredential{ProjectID: document.ProjectID,
		Email: document.ClientEmail, KeyID: document.PrivateKeyID,
		Signer: key}, nil
}

func readCredentialFile(path string) ([]byte, error) {
	if path == "" {
		return nil, ErrInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	status, err := file.Stat()
	if err != nil || !status.Mode().IsRegular() || status.Size() <= 0 ||
		status.Size() > maximumCredentialFileBytes {
		return nil, ErrInvalid
	}
	payload, err := io.ReadAll(io.LimitReader(file,
		maximumCredentialFileBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maximumCredentialFileBytes {
		return nil, ErrInvalid
	}
	return payload, nil
}

func wipe(payload []byte) {
	for index := range payload {
		payload[index] = 0
	}
}
