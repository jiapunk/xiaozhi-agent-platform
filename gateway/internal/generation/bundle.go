package generation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func RequireBundleFile(root, configured, relative string) (string, error) {
	rootAbsolute, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	configuredAbsolute, err := filepath.Abs(configured)
	if err != nil {
		return "", err
	}
	expected := filepath.Join(rootAbsolute, filepath.FromSlash(relative))
	if configuredAbsolute != expected {
		return "", fmt.Errorf("service file must be the exact generation bundle %s", relative)
	}
	info, err := os.Lstat(expected)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm()&0o222 != 0 {
		return "", fmt.Errorf("generation bundle %s is unavailable", relative)
	}
	return expected, nil
}

func VerifyControlBundle(root, configuredRegistry string) error {
	checks := []bundleArtifactCheck{
		{configuredRegistry, "control/ota-release-registry.json",
			"control_registry_sha256", 1024 * 1024},
		{filepath.Join(root, "control", "release-manifest.json"),
			"control/release-manifest.json", "manifest_sha256", 8192},
		{filepath.Join(root, "control", "release-public.pem"),
			"control/release-public.pem", "public_key_sha256", 4096},
	}
	return verifyBundleArtifacts(root, checks)
}

func VerifyOriginBundle(root, configuredCatalog string) error {
	return verifyBundleArtifacts(root, []bundleArtifactCheck{
		{configuredCatalog, "origin/firmware-origin-catalog.json",
			"origin_catalog_sha256", 1024 * 1024},
	})
}

type bundleArtifactCheck struct {
	configured string
	relative   string
	field      string
	maximum    int64
}

func verifyBundleArtifacts(root string, checks []bundleArtifactCheck) error {
	receiptPath, err := RequireBundleFile(root,
		filepath.Join(root, "deployment-receipt.json"), "deployment-receipt.json")
	if err != nil {
		return err
	}
	payload, err := readBoundedRegular(receiptPath, 8192)
	if err != nil {
		return err
	}
	var receipt map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&receipt); err != nil || ensureJSONEOF(decoder) != nil {
		return fmt.Errorf("generation bundle receipt is invalid")
	}
	for _, check := range checks {
		var expected string
		raw, found := receipt[check.field]
		if !found || json.Unmarshal(raw, &expected) != nil || !validSHA256(expected) {
			return fmt.Errorf("generation receipt %s is invalid", check.field)
		}
		name, err := RequireBundleFile(root, check.configured, check.relative)
		if err != nil {
			return err
		}
		actual, err := digestBoundedRegular(name, check.maximum)
		if err != nil || actual != expected {
			return fmt.Errorf("generation bundle %s digest is invalid", check.relative)
		}
	}
	return nil
}

func digestBoundedRegular(name string, maximum int64) (string, error) {
	info, err := os.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Size() < 1 || info.Size() > maximum {
		return "", fmt.Errorf("generation bundle file is outside bounds")
	}
	file, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(file, maximum+1))
	if err != nil || written != info.Size() {
		return "", fmt.Errorf("generation bundle file changed while hashing")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// LoadBundleGeneration binds a replica to the exact immutable receipt mounted
// beside its registry/catalog. Full signature and lineage validation remains a
// publisher/bootstrap gate; online replicas need only prove exact receipt hash.
func LoadBundleGeneration(root string) (Generation, error) {
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return Generation{}, fmt.Errorf("generation bundle root is unavailable")
	}
	receiptPath, err := RequireBundleFile(root,
		filepath.Join(root, "deployment-receipt.json"), "deployment-receipt.json")
	if err != nil {
		return Generation{}, err
	}
	payload, err := readBoundedRegular(receiptPath, 8192)
	if err != nil {
		return Generation{}, fmt.Errorf("read generation bundle receipt: %w", err)
	}
	digest := sha256.Sum256(payload)
	digestText := hex.EncodeToString(digest[:])
	readyPath, err := RequireBundleFile(root, filepath.Join(root, "READY"), "READY")
	if err != nil {
		return Generation{}, err
	}
	ready, err := readBoundedRegular(readyPath, 128)
	if err != nil || string(ready) != digestText+"\n" {
		return Generation{}, fmt.Errorf("generation bundle READY marker is invalid")
	}
	var discriminator struct {
		Schema int `json:"schema"`
	}
	if err := json.Unmarshal(payload, &discriminator); err != nil {
		return Generation{}, fmt.Errorf("decode generation bundle receipt: %w", err)
	}
	switch discriminator.Schema {
	case 1:
		return Generation{ID: "staging", Sequence: 0,
			ReceiptSHA256: digestText}, nil
	case 2:
		var receipt struct {
			Schema             int    `json:"schema"`
			GenerationID       string `json:"generation_id"`
			GenerationSequence uint32 `json:"generation_sequence"`
		}
		if err := json.Unmarshal(payload, &receipt); err != nil ||
			receipt.Schema != 2 || !validGeneration(Generation{
			ID: receipt.GenerationID, Sequence: receipt.GenerationSequence,
			ReceiptSHA256: digestText,
		}) || receipt.GenerationSequence == 0 {
			return Generation{}, fmt.Errorf("rollout generation receipt is invalid")
		}
		return Generation{ID: receipt.GenerationID,
			Sequence: receipt.GenerationSequence, ReceiptSHA256: digestText}, nil
	default:
		return Generation{}, fmt.Errorf("generation bundle receipt schema is unsupported")
	}
}
