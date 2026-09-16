package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testKeyringDocument struct {
	Schema                       string             `json:"schema"`
	Revision                     uint64             `json:"revision"`
	ActiveKeyID                  string             `json:"active_key_id"`
	LegacyUnkeyedKeyID           string             `json:"legacy_unkeyed_key_id"`
	LegacyUnkeyedVerifyUntilUnix int64              `json:"legacy_unkeyed_verify_until_unix"`
	Keys                         []testKeyringEntry `json:"keys"`
}

type testKeyringEntry struct {
	KeyID           string `json:"key_id"`
	HMACKeyB64URL   string `json:"hmac_key_b64url"`
	State           string `json:"state"`
	IssueBeforeUnix int64  `json:"issue_before_unix"`
	VerifyUntilUnix int64  `json:"verify_until_unix"`
}

func writeTestKeyring(t *testing.T, path string, document testKeyringDocument) {
	t.Helper()
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
}

func preflightArguments(current, target, output string) []string {
	return []string{
		"--domain", "voice", "--transition", "rotate",
		"--current-keyring", current, "--current-min-revision", "10",
		"--target-keyring", target, "--target-min-revision", "11",
		"--expected-current-revision", "10",
		"--expected-target-revision", "11",
		"--expected-current-active-key-id", "voice-old",
		"--expected-target-active-key-id", "voice-new",
		"--max-token-ttl-seconds", "900", "--output", output,
	}
}

func TestRunWritesCanonicalNonsecretPreflightReceipt(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	currentPath := filepath.Join(directory, "current.json")
	targetPath := filepath.Join(directory, "target.json")
	outputPath := filepath.Join(directory, "receipt.json")
	oldSecret := base64.RawURLEncoding.EncodeToString(
		[]byte(strings.Repeat("o", 32)))
	newSecret := base64.RawURLEncoding.EncodeToString(
		[]byte(strings.Repeat("n", 32)))
	writeTestKeyring(t, currentPath, testKeyringDocument{
		Schema: "xz-hmac-token-keyring-v1", Revision: 10,
		ActiveKeyID: "voice-old", Keys: []testKeyringEntry{{
			KeyID: "voice-old", HMACKeyB64URL: oldSecret, State: "active",
			VerifyUntilUnix: now.Add(24 * time.Hour).Unix(),
		}},
	})
	writeTestKeyring(t, targetPath, testKeyringDocument{
		Schema: "xz-hmac-token-keyring-v1", Revision: 11,
		ActiveKeyID: "voice-new", Keys: []testKeyringEntry{
			{KeyID: "voice-new", HMACKeyB64URL: newSecret, State: "active",
				VerifyUntilUnix: now.Add(48 * time.Hour).Unix()},
			{KeyID: "voice-old", HMACKeyB64URL: oldSecret, State: "retiring",
				IssueBeforeUnix: now.Add(2 * time.Hour).Unix(),
				VerifyUntilUnix: now.Add(24 * time.Hour).Unix()},
		},
	})
	if err := run(preflightArguments(currentPath, targetPath, outputPath),
		func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte(oldSecret)) ||
		bytes.Contains(payload, []byte(newSecret)) {
		t.Fatal("preflight receipt disclosed key material")
	}
	var receipt preflightReceipt
	if err := json.Unmarshal(payload, &receipt); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(payload, canonical) {
		t.Fatalf("receipt is not canonical: err=%v", err)
	}
	if receipt.Schema != preflightSchema ||
		receipt.Result != "SOFTWARE_PREFLIGHT_PASS" || !receipt.SoftwareOnly ||
		receipt.Domain != "voice" || receipt.Transition != "rotate" ||
		receipt.CurrentRevision != 10 || receipt.TargetRevision != 11 ||
		receipt.CurrentActiveKeyID != "voice-old" ||
		receipt.TargetActiveKeyID != "voice-new" ||
		receipt.CutoverUnix != now.Add(2*time.Hour).Unix() ||
		receipt.MinimumDrainUntilUnix != now.Add(
			2*time.Hour+15*time.Minute+30*time.Second).Unix() {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
	status, err := os.Stat(outputPath)
	if err != nil || status.Mode().Perm() != 0o444 {
		t.Fatalf("receipt permissions are unsafe: status=%v err=%v", status, err)
	}
	if err := run(preflightArguments(currentPath, targetPath, outputPath),
		func() time.Time { return now }); err == nil {
		t.Fatal("preflight overwrote an existing receipt")
	}
}

func TestRunRequiresExactOperatorExpectations(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	currentPath := filepath.Join(directory, "current.json")
	targetPath := filepath.Join(directory, "target.json")
	oldSecret := base64.RawURLEncoding.EncodeToString(
		[]byte(strings.Repeat("o", 32)))
	newSecret := base64.RawURLEncoding.EncodeToString(
		[]byte(strings.Repeat("n", 32)))
	writeTestKeyring(t, currentPath, testKeyringDocument{
		Schema: "xz-hmac-token-keyring-v1", Revision: 10,
		ActiveKeyID: "voice-old", Keys: []testKeyringEntry{{
			KeyID: "voice-old", HMACKeyB64URL: oldSecret, State: "active",
			VerifyUntilUnix: now.Add(24 * time.Hour).Unix(),
		}},
	})
	writeTestKeyring(t, targetPath, testKeyringDocument{
		Schema: "xz-hmac-token-keyring-v1", Revision: 11,
		ActiveKeyID: "voice-new", Keys: []testKeyringEntry{
			{KeyID: "voice-new", HMACKeyB64URL: newSecret, State: "active",
				VerifyUntilUnix: now.Add(48 * time.Hour).Unix()},
			{KeyID: "voice-old", HMACKeyB64URL: oldSecret, State: "retiring",
				IssueBeforeUnix: now.Add(2 * time.Hour).Unix(),
				VerifyUntilUnix: now.Add(24 * time.Hour).Unix()},
		},
	})
	arguments := preflightArguments(currentPath, targetPath,
		filepath.Join(directory, "wrong.json"))
	for index := range arguments {
		if arguments[index] == "voice-new" {
			arguments[index] = "voice-unexpected"
			break
		}
	}
	if err := run(arguments, func() time.Time { return now }); err == nil {
		t.Fatal("preflight accepted unexpected active key metadata")
	}
	floorArguments := preflightArguments(currentPath, targetPath,
		filepath.Join(directory, "weak-floor.json"))
	for index := range floorArguments {
		if floorArguments[index] == "--current-min-revision" {
			floorArguments[index+1] = "9"
			break
		}
	}
	if err := run(floorArguments, func() time.Time { return now }); err == nil {
		t.Fatal("preflight accepted a floor below the expected current revision")
	}
}
