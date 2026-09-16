package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSecretRequiresPrivateRegularToken(t *testing.T) {
	directory := t.TempDir()
	name := filepath.Join(directory, "token")
	if err := os.WriteFile(name, []byte("qualification-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := loadSecret(name)
	if err != nil || token != "qualification-token" {
		t.Fatalf("token=%q err=%v", token, err)
	}
	if err := os.Chmod(name, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSecret(name); err == nil {
		t.Fatal("world-readable adapter token was accepted")
	}
	if err := os.Chmod(name, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("token with spaces"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSecret(name); err == nil {
		t.Fatal("adapter token containing whitespace was accepted")
	}
}

func TestBuildHTTPClientRejectsInvalidPrivateCA(t *testing.T) {
	name := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(name, []byte("not a certificate\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, _, err := buildHTTPClient(name); err == nil {
		t.Fatal("invalid private CA bundle was accepted")
	}
	client, trustDigest, err := buildHTTPClient("")
	if err != nil || client.Transport == nil || len(trustDigest) != 64 {
		t.Fatalf("system trust client failed: %v", err)
	}
}

func TestProductionQualificationRequiresIsolatedMTLSInputs(t *testing.T) {
	if _, _, _, _, _, err := loadSpeechTransports(speechTransportFlags{}, false); err == nil {
		t.Fatal("production qualification accepted missing workload identities")
	}
	if _, _, _, _, _, err := loadSpeechTransports(speechTransportFlags{
		sttBearerTokenFile: "/stt-token",
	}, false); err == nil {
		t.Fatal("production qualification accepted partial workload identity inputs")
	}
}

func TestDevelopmentQualificationRetainsExplicitLegacyHarness(t *testing.T) {
	name := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(name, []byte("development-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sttToken, ttsToken, sttClient, ttsClient, trust, err := loadSpeechTransports(
		speechTransportFlags{legacyBearerTokenFile: name}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer sttClient.CloseIdleConnections()
	if sttToken != "development-token" || ttsToken != sttToken ||
		sttClient != ttsClient || len(trust) != 64 {
		t.Fatalf("unexpected development transport: stt=%q tts=%q trust=%q", sttToken, ttsToken, trust)
	}
}
