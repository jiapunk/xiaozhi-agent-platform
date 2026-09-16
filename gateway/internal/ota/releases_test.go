package ota

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testRegistry(t *testing.T, enabled bool, basisPoints int,
	notBefore, expiresAt int64) *Registry {
	t.Helper()
	directory := t.TempDir()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	if err := os.WriteFile(filepath.Join(directory, "release-public.pem"),
		publicPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := manifestDocument{
		Schema: 2, ReleaseID: "box3-development-0015",
		Project: "xiaozhi_agent_platform", Board: "esp32s3-box3",
		Channel: "development", Version: "0.15.0-dev",
		ReleaseSequence: 15, SecureVersion: 2,
		ImageURL:                 "https://updates.example.com/firmware/box3/0015.bin",
		ImageSize:                1364256,
		ImageSHA256:              strings.Repeat("a", 64),
		ResetQualificationSHA256: strings.Repeat("b", 64),
		NotBefore:                notBefore, ExpiresAt: expiresAt,
		SigningKeyID:       "release-key-2026",
		SignatureAlgorithm: "ECDSA_P256_SHA256",
	}
	digest := sha256.Sum256(canonicalManifest(manifest))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	manifest.SignatureB64URL = base64.RawURLEncoding.EncodeToString(signature)
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"),
		manifestBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	document := registryDocument{
		Version: 1,
		SigningKeys: []signingKeyEntry{{
			KeyID: "release-key-2026", PublicKeyFile: "release-public.pem",
		}},
		Releases: []releaseEntry{{
			ManifestFile: "manifest.json", Enabled: enabled,
			RolloutBasisPoints: basisPoints, RetryAfterSeconds: 900,
		}},
	}
	registryBytes, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(directory, "releases.json")
	if err := os.WriteFile(registryPath, registryBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	registry, err := LoadRegistry(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestSignedRegistrySelectsOnlyNewEligibleRelease(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	registry := testRegistry(t, true, 10000,
		now.Add(-time.Hour).Unix(), now.Add(time.Hour).Unix())
	rolloutKey := []byte("rollout-key-0123456789abcdef0123456789")
	release, status, retry := registry.Select("device-1", "esp32s3-box3",
		"development", 14, now, rolloutKey)
	if status != OfferAvailable || release.ReleaseSequence != 15 ||
		release.ReleaseID != "box3-development-0015" || retry != 900 ||
		len(release.Manifest) == 0 {
		t.Fatalf("unexpected offer: status=%s release=%#v retry=%d",
			status, release, retry)
	}
	lookedUp, found := registry.Lookup("box3-development-0015")
	if !found || lookedUp.Project != "xiaozhi_agent_platform" ||
		lookedUp.SigningKeyID != "release-key-2026" ||
		lookedUp.ResetQualificationSHA256 != strings.Repeat("b", 64) ||
		len(lookedUp.Manifest) == 0 {
		t.Fatalf("lookup returned unexpected release: %#v found=%v", lookedUp, found)
	}
	lookedUp.Manifest[0] ^= 0xff
	again, found := registry.Lookup("box3-development-0015")
	if !found || again.Manifest[0] == lookedUp.Manifest[0] {
		t.Fatal("lookup did not return a defensive manifest copy")
	}
	_, status, _ = registry.Select("device-1", "esp32s3-box3",
		"development", 15, now, rolloutKey)
	if status != OfferUpToDate {
		t.Fatalf("got %s, want up_to_date", status)
	}
	_, status, _ = registry.Select("device-1", "esp32s3-n32r16",
		"development", 14, now, rolloutKey)
	if status != OfferDeferred {
		t.Fatalf("wrong board got %s", status)
	}
}

func TestRegistryContainedPathPolicy(t *testing.T) {
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(root, "inside.pem")
	if err := os.WriteFile(inside, []byte("inside"), 0o444); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveContainedFile(root, "inside.pem")
	if err != nil || resolved != inside {
		t.Fatalf("contained path rejected: path=%q error=%v", resolved, err)
	}
	outsideRoot := t.TempDir()
	outside := filepath.Join(outsideRoot, "outside.pem")
	if err := os.WriteFile(outside, []byte("outside"), 0o444); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "escape.pem")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"../outside.pem", outside, "sub/../inside.pem", "escape.pem", "",
	} {
		if _, err := resolveContainedFile(root, name); err == nil {
			t.Fatalf("unsafe path %q was accepted", name)
		}
	}
}

func TestDisabledExpiredAndZeroCohortAreDeferred(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	key := []byte("rollout-key-0123456789abcdef0123456789")
	for name, registry := range map[string]*Registry{
		"disabled": testRegistry(t, false, 10000,
			now.Add(-time.Hour).Unix(), now.Add(time.Hour).Unix()),
		"expired": testRegistry(t, true, 10000,
			now.Add(-2*time.Hour).Unix(), now.Add(-time.Hour).Unix()),
		"zero-cohort": testRegistry(t, true, 0,
			now.Add(-time.Hour).Unix(), now.Add(time.Hour).Unix()),
	} {
		t.Run(name, func(t *testing.T) {
			_, status, _ := registry.Select("device-1", "esp32s3-box3",
				"development", 14, now, key)
			if status != OfferDeferred {
				t.Fatalf("got %s", status)
			}
		})
	}
}

func TestRegistryRejectsTamperedAndDuplicateManifest(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	registry := testRegistry(t, true, 10000,
		now.Add(-time.Hour).Unix(), now.Add(time.Hour).Unix())
	if len(registry.releases) != 1 {
		t.Fatal("test setup did not load one release")
	}
	manifest := registry.releases[0].Manifest
	var document manifestDocument
	if err := json.Unmarshal(manifest, &document); err != nil {
		t.Fatal(err)
	}
	document.ImageSize++
	tampered, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	key := make(map[string]*ecdsa.PublicKey)
	if _, err := verifyManifest(tampered, key); err == nil {
		t.Fatal("tampered manifest was accepted")
	}
	duplicate := append([]byte(`{"schema":2,"schema":2}`), '\n')
	if err := rejectDuplicateJSONNames(duplicate); err == nil {
		t.Fatal("duplicate JSON name was accepted")
	}
}

func TestDeterministicCohortIsStableAndReleaseSeparated(t *testing.T) {
	key := []byte("rollout-key-0123456789abcdef0123456789")
	first := inCohort(key, "device-1", "release-15", 5000)
	for range 100 {
		if inCohort(key, "device-1", "release-15", 5000) != first {
			t.Fatal("cohort assignment changed")
		}
	}
	if inCohort(key, "device-1", "release-15", 0) {
		t.Fatal("zero basis-point cohort accepted a device")
	}
	if !inCohort(key, "device-1", "release-15", 10000) {
		t.Fatal("full cohort rejected a device")
	}
}
