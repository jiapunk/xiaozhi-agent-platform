package pushqualification

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadLiveConfigBuildsAPNsRotationWithoutEmbeddingTargets(t *testing.T) {
	directory := t.TempDir()
	writeAPNsKey := func(name string) string {
		t.Helper()
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalPKCS8PrivateKey(key)
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
			Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	current := writeAPNsKey("current.p8")
	next := writeAPNsKey("next.p8")
	targetPath := filepath.Join(directory, "target")
	if err := os.WriteFile(targetPath, []byte(strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	document := map[string]any{
		"schema": 1, "qualification_id": "m69-live-1",
		"environment": "staging", "acknowledge_live_provider_calls": true,
		"providers": []map[string]any{{
			"platform": "apns-development", "application_id": "com.example.product",
			"team_id": "TEAM12ABCD", "current_credential_id": "ABC123DEFG",
			"current_credential_file": current, "next_credential_id": "XYZ987WQRS",
			"next_credential_file": next, "valid_target_file": targetPath,
		}},
	}
	payload, _ := json.Marshal(document)
	configPath := filepath.Join(directory, "qualification.json")
	if err := os.WriteFile(configPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadLiveConfig(configPath, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if config.DevelopmentOnly || config.QualificationID != "m69-live-1" ||
		len(config.Candidates) != 1 || config.Candidates[0].ValidTarget == "" ||
		config.ConfigSHA256 == "" {
		t.Fatalf("config=%+v", config)
	}
	document["acknowledge_live_provider_calls"] = false
	payload, _ = json.Marshal(document)
	if err := os.WriteFile(configPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLiveConfig(configPath, 2*time.Second); err == nil {
		t.Fatal("unacknowledged live provider calls accepted")
	}

	document["acknowledge_live_provider_calls"] = true
	payload, _ = json.Marshal(document)
	duplicateField := strings.Replace(string(payload), `"schema":1`,
		`"schema":1,"schema":1`, 1)
	if err := os.WriteFile(configPath, []byte(duplicateField), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLiveConfig(configPath, 2*time.Second); err == nil {
		t.Fatal("duplicate qualification config JSON field accepted")
	}

	document["environment"] = "production"
	payload, _ = json.Marshal(document)
	if err := os.WriteFile(configPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLiveConfig(configPath, 2*time.Second); err == nil {
		t.Fatal("production receipt accepted APNs development endpoint")
	}
}
