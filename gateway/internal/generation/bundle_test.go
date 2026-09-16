package generation

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadBundleGenerationBindsExactReceiptAndReady(t *testing.T) {
	root := t.TempDir()
	receipt := []byte(`{"schema":2,"generation_id":"release-15-g0001","generation_sequence":1}` + "\n")
	digest := sha256.Sum256(receipt)
	if err := os.WriteFile(filepath.Join(root, "deployment-receipt.json"),
		receipt, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "READY"), []byte(
		hex.EncodeToString(digest[:])+"\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	identity, err := LoadBundleGeneration(root)
	if err != nil || identity.ID != "release-15-g0001" || identity.Sequence != 1 ||
		identity.ReceiptSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("identity=%#v err=%v", identity, err)
	}
	if err := os.Chmod(filepath.Join(root, "READY"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "READY"),
		[]byte(strings.Repeat("0", 64)+"\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBundleGeneration(root); err == nil {
		t.Fatal("wrong READY receipt hash was accepted")
	}
}

func TestRequireBundleFileRejectsAliasAndSymlink(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "control")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	expected := filepath.Join(directory, "ota-release-registry.json")
	if err := os.WriteFile(expected, []byte("{}\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if value, err := RequireBundleFile(root, expected,
		"control/ota-release-registry.json"); err != nil || value != expected {
		t.Fatalf("exact bundle file rejected: %s %v", value, err)
	}
	alias := filepath.Join(root, "alias.json")
	if err := os.Symlink(expected, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := RequireBundleFile(root, alias,
		"control/ota-release-registry.json"); err == nil {
		t.Fatal("bundle alias was accepted")
	}
}

func TestRuntimeBundleArtifactsAreReceiptBound(t *testing.T) {
	root := t.TempDir()
	control := filepath.Join(root, "control")
	origin := filepath.Join(root, "origin")
	if err := os.Mkdir(control, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(origin, 0o755); err != nil {
		t.Fatal(err)
	}
	registry := []byte("registry\n")
	manifest := []byte("manifest\n")
	publicKey := []byte("public-key\n")
	catalog := []byte("catalog\n")
	digestText := func(value []byte) string {
		digest := sha256.Sum256(value)
		return hex.EncodeToString(digest[:])
	}
	receipt := []byte(`{"schema":2,"generation_id":"release-15-g0001","generation_sequence":1,` +
		`"control_registry_sha256":"` + digestText(registry) + `",` +
		`"manifest_sha256":"` + digestText(manifest) + `",` +
		`"public_key_sha256":"` + digestText(publicKey) + `",` +
		`"origin_catalog_sha256":"` + digestText(catalog) + `"}` + "\n")
	write := func(name string, value []byte) {
		if err := os.WriteFile(name, value, 0o444); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "deployment-receipt.json"), receipt)
	receiptDigest := sha256.Sum256(receipt)
	write(filepath.Join(root, "READY"), []byte(hex.EncodeToString(receiptDigest[:])+"\n"))
	write(filepath.Join(control, "ota-release-registry.json"), registry)
	write(filepath.Join(control, "release-manifest.json"), manifest)
	write(filepath.Join(control, "release-public.pem"), publicKey)
	write(filepath.Join(origin, "firmware-origin-catalog.json"), catalog)
	if err := VerifyControlBundle(root,
		filepath.Join(control, "ota-release-registry.json")); err != nil {
		t.Fatal(err)
	}
	if err := VerifyOriginBundle(root,
		filepath.Join(origin, "firmware-origin-catalog.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(control, "ota-release-registry.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(control, "ota-release-registry.json"),
		[]byte("altered\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := VerifyControlBundle(root,
		filepath.Join(control, "ota-release-registry.json")); err == nil {
		t.Fatal("runtime registry drift was accepted")
	}
}
