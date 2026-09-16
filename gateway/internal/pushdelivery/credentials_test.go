package pushdelivery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialLoadersAcceptOnlyExpectedKeyTypes(t *testing.T) {
	directory := t.TempDir()
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	apnsPath := filepath.Join(directory, "AuthKey.p8")
	if err := os.WriteFile(apnsPath, pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: ecDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if signer, err := LoadAPNsPrivateKey(apnsPath); err != nil || signer == nil {
		t.Fatalf("APNs signer=%T err=%v", signer, err)
	}

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaDER, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	document := map[string]any{
		"type": "service_account", "project_id": "product-123",
		"private_key_id": "google-key-1234",
		"private_key": string(pem.EncodeToMemory(&pem.Block{
			Type: "PRIVATE KEY", Bytes: rsaDER})),
		"client_email": "push@product-123.iam.gserviceaccount.com",
		"token_uri":    googleOAuthTokenEndpoint,
		"auth_uri":     "https://accounts.google.com/o/oauth2/auth",
	}
	payload, _ := json.Marshal(document)
	googlePath := filepath.Join(directory, "google.json")
	if err := os.WriteFile(googlePath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	credential, err := LoadGoogleServiceAccountCredential(googlePath)
	if err != nil || credential.ProjectID != "product-123" ||
		credential.Email != "push@product-123.iam.gserviceaccount.com" ||
		credential.Signer == nil {
		t.Fatalf("credential=%+v err=%v", credential, err)
	}

	document["token_uri"] = "https://attacker.example/token"
	payload, _ = json.Marshal(document)
	if err := os.WriteFile(googlePath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGoogleServiceAccountCredential(googlePath); err == nil {
		t.Fatal("untrusted OAuth endpoint accepted")
	}

	privateKey := string(pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: rsaDER}))
	duplicateTokenURI := `{"type":"service_account",` +
		`"project_id":"product-123",` +
		`"private_key_id":"google-key-1234",` +
		`"private_key":` + string(mustJSON(t, privateKey)) + `,` +
		`"client_email":"push@product-123.iam.gserviceaccount.com",` +
		`"token_uri":"` + googleOAuthTokenEndpoint + `",` +
		`"token_uri":"` + googleOAuthTokenEndpoint + `"}`
	if err := os.WriteFile(googlePath, []byte(duplicateTokenURI), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGoogleServiceAccountCredential(googlePath); err == nil {
		t.Fatal("duplicate Google credential JSON field accepted")
	}
}

func mustJSON(t *testing.T, value string) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
