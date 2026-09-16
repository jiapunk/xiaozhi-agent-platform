package pushqualification

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"time"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
	"xiaozhi-agent-platform/gateway/internal/auth"
)

var receiptSignatureDomain = []byte(
	"XIAOZHI-PUSH-PROVIDER-QUALIFICATION-V1\x00")

type VerifyOptions struct {
	TrustedPublicKey        string
	ExpectedSigningKeyID    string
	ExpectedQualificationID string
	ExpectedEnvironment     string
	ExpectedConfigSHA256    string
	ExpectedToolSHA256      string
	RequireLive             bool
}

func SignReceipt(receipt Receipt, privateKeyPath,
	signingKeyID string) ([]byte, error) {
	if !auth.ValidIdentifier(signingKeyID, 64) {
		return nil, fmt.Errorf("push qualification signing key ID is invalid")
	}
	receipt.SigningKeyID = signingKeyID
	receipt.SignatureAlgorithm = "Ed25519"
	receipt.SignatureB64URL = ""
	if err := validateReceipt(receipt, VerifyOptions{
		ExpectedSigningKeyID: signingKeyID}); err != nil {
		return nil, err
	}
	privateKey, err := loadEd25519PrivateKey(privateKeyPath)
	if err != nil {
		return nil, err
	}
	payload, err := signaturePayload(receipt)
	if err != nil {
		return nil, err
	}
	receipt.SignatureB64URL = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(privateKey, payload))
	return canonicalReceipt(receipt)
}

func VerifyReceiptFile(path string, options VerifyOptions) (Receipt, error) {
	payload, err := readRegular(path, 1<<20, false)
	if err != nil {
		return Receipt{}, fmt.Errorf("push qualification receipt: %w", err)
	}
	return VerifyReceipt(payload, options)
}

func VerifyReceipt(payload []byte, options VerifyOptions) (Receipt, error) {
	var receipt Receipt
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, fmt.Errorf("push qualification receipt JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Receipt{}, fmt.Errorf("push qualification receipt has trailing JSON")
	}
	canonical, err := canonicalReceipt(receipt)
	if err != nil || !bytes.Equal(canonical, payload) {
		return Receipt{}, fmt.Errorf("push qualification receipt is not canonical JSON")
	}
	if err := validateReceipt(receipt, options); err != nil {
		return Receipt{}, err
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(
		receipt.SignatureB64URL)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) !=
			receipt.SignatureB64URL {
		return Receipt{}, fmt.Errorf("push qualification signature is invalid")
	}
	publicKey, err := loadEd25519PublicKey(options.TrustedPublicKey)
	if err != nil {
		return Receipt{}, err
	}
	payloadToVerify, err := signaturePayload(receipt)
	if err != nil || !ed25519.Verify(publicKey, payloadToVerify, signature) {
		return Receipt{}, fmt.Errorf("push qualification signature is invalid")
	}
	return receipt, nil
}

func WriteNewReceipt(path string, payload []byte) error {
	if len(payload) == 0 || len(payload) > 1<<20 {
		return fmt.Errorf("push qualification receipt size is invalid")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return fmt.Errorf("refusing to overwrite push qualification receipt: %w", err)
	}
	success := false
	defer func() {
		_ = file.Close()
		if !success {
			_ = os.Remove(path)
		}
	}()
	if written, err := file.Write(payload); err != nil || written != len(payload) {
		return fmt.Errorf("write push qualification receipt")
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync push qualification receipt")
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close push qualification receipt")
	}
	success = true
	return nil
}

func validateReceipt(receipt Receipt, options VerifyOptions) error {
	if receipt.Schema != ReceiptSchema ||
		!auth.ValidIdentifier(receipt.QualificationID, 64) ||
		(receipt.Environment != "staging" && receipt.Environment != "production") ||
		!validSHA256(receipt.ConfigSHA256) ||
		!validSHA256(receipt.QualificationToolSHA256) || !receipt.SecretFree ||
		receipt.ProductionReady || len(receipt.Providers) < 1 ||
		len(receipt.Providers) > 3 ||
		!reflect.DeepEqual(receipt.UnresolvedProductionGates,
			unresolvedProductionGates) ||
		!sort.StringsAreSorted(receipt.UnresolvedProductionGates) ||
		!auth.ValidIdentifier(receipt.SigningKeyID, 64) ||
		receipt.SignatureAlgorithm != "Ed25519" {
		return fmt.Errorf("push qualification receipt fields are invalid")
	}
	if receipt.DevelopmentOnly {
		if receipt.Result != FixtureResult || receipt.Environment != "staging" {
			return fmt.Errorf("fixture qualification overstates its evidence")
		}
	} else if receipt.Result != LiveResult {
		return fmt.Errorf("live push qualification result is invalid")
	}
	if options.RequireLive && receipt.DevelopmentOnly {
		return fmt.Errorf("live push qualification evidence is required")
	}
	started, err := time.Parse(time.RFC3339, receipt.StartedAt)
	if err != nil || started.Format(time.RFC3339) != receipt.StartedAt {
		return fmt.Errorf("push qualification start time is invalid")
	}
	finished, err := time.Parse(time.RFC3339, receipt.FinishedAt)
	if err != nil || finished.Format(time.RFC3339) != receipt.FinishedAt ||
		finished.Before(started) || finished.Sub(started) > maximumRunTime {
		return fmt.Errorf("push qualification finish time is invalid")
	}
	seen := make(map[accountauth.PushPlatform]bool, len(receipt.Providers))
	for index, provider := range receipt.Providers {
		if !accountauth.ValidPushPlatform(provider.Platform) ||
			seen[provider.Platform] || !auth.ValidIdentifier(provider.ApplicationID, 128) ||
			!validCredentialID(provider.CurrentCredentialID) ||
			!validCredentialID(provider.NextCredentialID) ||
			provider.CurrentCredentialID == provider.NextCredentialID ||
			!provider.CurrentAccepted || !provider.NextAccepted ||
			!provider.InvalidTargetClassified ||
			!provider.CanceledRequestRetried ||
			provider.CurrentLatencyMS < 0 ||
			provider.CurrentLatencyMS > maximumProbeTime.Milliseconds() ||
			provider.NextLatencyMS < 0 ||
			provider.NextLatencyMS > maximumProbeTime.Milliseconds() ||
			provider.InvalidClassificationMS < 0 ||
			provider.InvalidClassificationMS > maximumProbeTime.Milliseconds() ||
			(index > 0 && receipt.Providers[index-1].Platform >= provider.Platform) {
			return fmt.Errorf("push qualification provider evidence is invalid")
		}
		seen[provider.Platform] = true
	}
	checks := []struct {
		actual, expected string
		label            string
	}{
		{receipt.SigningKeyID, options.ExpectedSigningKeyID, "signing key ID"},
		{receipt.QualificationID, options.ExpectedQualificationID, "qualification ID"},
		{receipt.Environment, options.ExpectedEnvironment, "environment"},
		{receipt.ConfigSHA256, options.ExpectedConfigSHA256, "config digest"},
		{receipt.QualificationToolSHA256, options.ExpectedToolSHA256, "tool digest"},
	}
	for _, check := range checks {
		if check.expected != "" && check.actual != check.expected {
			return fmt.Errorf("push qualification %s does not match", check.label)
		}
	}
	return nil
}

func signaturePayload(receipt Receipt) ([]byte, error) {
	receipt.SignatureB64URL = ""
	compact, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), receiptSignatureDomain...), compact...), nil
}

func canonicalReceipt(receipt Receipt) ([]byte, error) {
	payload, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func loadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	payload, err := readRegular(path, 16*1024, true)
	if err != nil {
		return nil, fmt.Errorf("push qualification private key: %w", err)
	}
	block, rest := pem.Decode(payload)
	if block == nil || block.Type != "PRIVATE KEY" ||
		len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("push qualification private key is invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok || len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("push qualification private key is invalid")
	}
	return key, nil
}

func loadEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	payload, err := readRegular(path, 16*1024, false)
	if err != nil {
		return nil, fmt.Errorf("push qualification public key: %w", err)
	}
	block, rest := pem.Decode(payload)
	if block == nil || block.Type != "PUBLIC KEY" ||
		len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("push qualification public key is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("push qualification public key is invalid")
	}
	return key, nil
}

func readRegular(path string, maximum int64, private bool) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("path is empty")
	}
	status, err := os.Lstat(path)
	if err != nil || !status.Mode().IsRegular() || status.Size() <= 0 ||
		status.Size() > maximum || (private && status.Mode().Perm()&0o077 != 0) {
		return nil, fmt.Errorf("file mode, type, or size is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(payload) == 0 || int64(len(payload)) > maximum {
		return nil, fmt.Errorf("file read is invalid")
	}
	return payload, nil
}
