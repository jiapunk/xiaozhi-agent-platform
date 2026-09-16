package deploymentbundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/firmwareorigin"
	productota "xiaozhi-agent-platform/gateway/internal/ota"
)

const (
	maximumReceiptBytes = 8192
	maximumConfigBytes  = 1024 * 1024
)

var receiptFields = map[string]struct{}{
	"schema": {}, "release_id": {}, "signing_key_id": {}, "project": {},
	"board": {}, "channel": {}, "version": {}, "release_sequence": {},
	"secure_version": {}, "image_authority": {}, "image_url_path": {},
	"image_size": {}, "image_sha256": {}, "manifest_sha256": {},
	"public_key_sha256": {}, "sdkconfig_sha256": {},
	"control_registry_sha256": {}, "origin_catalog_sha256": {},
	"rollout_enabled": {}, "rollout_basis_points": {},
	"retry_after_seconds": {},
}

type Receipt struct {
	Schema                int    `json:"schema"`
	ReleaseID             string `json:"release_id"`
	SigningKeyID          string `json:"signing_key_id"`
	Project               string `json:"project"`
	Board                 string `json:"board"`
	Channel               string `json:"channel"`
	Version               string `json:"version"`
	ReleaseSequence       uint32 `json:"release_sequence"`
	SecureVersion         uint32 `json:"secure_version"`
	ImageAuthority        string `json:"image_authority"`
	ImageURLPath          string `json:"image_url_path"`
	ImageSize             int64  `json:"image_size"`
	ImageSHA256           string `json:"image_sha256"`
	ManifestSHA256        string `json:"manifest_sha256"`
	PublicKeySHA256       string `json:"public_key_sha256"`
	SDKConfigSHA256       string `json:"sdkconfig_sha256"`
	ControlRegistrySHA256 string `json:"control_registry_sha256"`
	OriginCatalogSHA256   string `json:"origin_catalog_sha256"`
	RolloutEnabled        bool   `json:"rollout_enabled"`
	RolloutBasisPoints    int    `json:"rollout_basis_points"`
	RetryAfterSeconds     int    `json:"retry_after_seconds"`
}

func Validate(root, expectedAuthority string) (Receipt, error) {
	if root == "" || !firmwareorigin.ValidAuthority(expectedAuthority) {
		return Receipt{}, fmt.Errorf("deployment bundle root/authority is invalid")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return Receipt{}, fmt.Errorf("deployment bundle root is unavailable")
	}
	receiptPath := filepath.Join(root, "deployment-receipt.json")
	receiptBytes, err := readBoundedFile(receiptPath, maximumReceiptBytes)
	if err != nil {
		return Receipt{}, fmt.Errorf("read deployment receipt: %w", err)
	}
	if err := rejectDuplicateJSONNames(receiptBytes); err != nil {
		return Receipt{}, fmt.Errorf("deployment receipt JSON: %w", err)
	}
	if err := requireExactJSONFields(receiptBytes, receiptFields); err != nil {
		return Receipt{}, fmt.Errorf("deployment receipt fields: %w", err)
	}
	var receipt Receipt
	if err := decodeStrict(receiptBytes, &receipt); err != nil {
		return Receipt{}, fmt.Errorf("decode deployment receipt: %w", err)
	}
	if err := validateReceipt(receipt, expectedAuthority); err != nil {
		return Receipt{}, err
	}
	receiptDigest := sha256.Sum256(receiptBytes)
	readyBytes, err := readBoundedFile(filepath.Join(root, "READY"), 128)
	if err != nil || string(readyBytes) != hex.EncodeToString(receiptDigest[:])+"\n" {
		return Receipt{}, fmt.Errorf("deployment bundle READY marker is invalid")
	}

	controlRoot := filepath.Join(root, "control")
	originRoot := filepath.Join(root, "origin")
	manifestPath := filepath.Join(controlRoot, "release-manifest.json")
	publicKeyPath := filepath.Join(controlRoot, "release-public.pem")
	registryPath := filepath.Join(controlRoot, "ota-release-registry.json")
	catalogPath := filepath.Join(originRoot, "firmware-origin-catalog.json")
	sdkconfigPath := filepath.Join(root, "evidence", "sdkconfig")
	for name, check := range map[string]struct {
		path    string
		maximum int64
		expect  string
	}{
		"manifest":         {manifestPath, 8192, receipt.ManifestSHA256},
		"public key":       {publicKeyPath, 4096, receipt.PublicKeySHA256},
		"sdkconfig":        {sdkconfigPath, maximumConfigBytes, receipt.SDKConfigSHA256},
		"control registry": {registryPath, maximumConfigBytes, receipt.ControlRegistrySHA256},
		"origin catalog":   {catalogPath, maximumConfigBytes, receipt.OriginCatalogSHA256},
	} {
		actual, err := digestBoundedFile(check.path, check.maximum)
		if err != nil || actual != check.expect {
			return Receipt{}, fmt.Errorf("deployment bundle %s digest is invalid", name)
		}
	}

	registry, err := productota.LoadRegistry(registryPath)
	if err != nil {
		return Receipt{}, fmt.Errorf("load bundled control registry: %w", err)
	}
	release, found := registry.Lookup(receipt.ReleaseID)
	if !found {
		return Receipt{}, fmt.Errorf("bundled release is missing")
	}
	if release.Project != receipt.Project || release.Board != receipt.Board ||
		release.Channel != receipt.Channel || release.Version != receipt.Version ||
		release.ReleaseSequence != receipt.ReleaseSequence ||
		release.SecureVersion != receipt.SecureVersion ||
		release.SigningKeyID != receipt.SigningKeyID ||
		release.ImageURL != "https://"+expectedAuthority+receipt.ImageURLPath ||
		release.ImageSize != receipt.ImageSize ||
		release.ImageSHA256 != receipt.ImageSHA256 || release.Enabled ||
		release.RolloutBasisPoints != 0 ||
		release.RetryAfterSeconds != uint32(receipt.RetryAfterSeconds) {
		return Receipt{}, fmt.Errorf("bundled control release does not match receipt")
	}
	manifestDigest := sha256.Sum256(release.Manifest)
	if hex.EncodeToString(manifestDigest[:]) != receipt.ManifestSHA256 {
		return Receipt{}, fmt.Errorf("bundled control manifest does not match receipt")
	}

	catalog, err := firmwareorigin.LoadCatalog(catalogPath)
	if err != nil {
		return Receipt{}, fmt.Errorf("load bundled origin catalog: %w", err)
	}
	object, found := catalog.Lookup(receipt.ImageURLPath)
	if !found || object.ReleaseID != receipt.ReleaseID ||
		object.ImageSHA256 != receipt.ImageSHA256 ||
		object.ImageSize != receipt.ImageSize {
		return Receipt{}, fmt.Errorf("bundled origin object does not match receipt")
	}
	if err := catalog.Ready(); err != nil {
		return Receipt{}, fmt.Errorf("bundled origin is not ready: %w", err)
	}
	if err := validateExactReadOnlyTree(root, receipt.ImageURLPath); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func validateReceipt(receipt Receipt, expectedAuthority string) error {
	if receipt.Schema != 1 || !auth.ValidIdentifier(receipt.ReleaseID, 64) ||
		!auth.ValidIdentifier(receipt.SigningKeyID, 64) ||
		!auth.ValidIdentifier(receipt.Project, 32) ||
		!auth.ValidIdentifier(receipt.Board, 32) ||
		!auth.ValidIdentifier(receipt.Channel, 32) || receipt.Version == "" ||
		receipt.ReleaseSequence == 0 || receipt.ImageAuthority != expectedAuthority ||
		!validURLPath(receipt.ImageURLPath) || receipt.ImageSize < 1024 ||
		!validSHA256(receipt.ImageSHA256) ||
		!validSHA256(receipt.ManifestSHA256) ||
		!validSHA256(receipt.PublicKeySHA256) ||
		!validSHA256(receipt.SDKConfigSHA256) ||
		!validSHA256(receipt.ControlRegistrySHA256) ||
		!validSHA256(receipt.OriginCatalogSHA256) || receipt.RolloutEnabled ||
		receipt.RolloutBasisPoints != 0 || receipt.RetryAfterSeconds < 60 ||
		receipt.RetryAfterSeconds > 86400 {
		return fmt.Errorf("deployment receipt fields are invalid")
	}
	return nil
}

func validateExactReadOnlyTree(root, urlPath string) error {
	imageRelative := filepath.ToSlash(filepath.Join(
		"origin", "objects", filepath.FromSlash(strings.TrimPrefix(urlPath, "/"))))
	expectedFiles := map[string]struct{}{
		"READY": {}, "deployment-receipt.json": {},
		"control/release-public.pem":          {},
		"control/release-manifest.json":       {},
		"control/ota-release-registry.json":   {},
		"origin/firmware-origin-catalog.json": {},
		"evidence/sdkconfig":                  {}, imageRelative: {},
	}
	expectedDirectories := map[string]struct{}{}
	for name := range expectedFiles {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			expectedDirectories[parent] = struct{}{}
		}
	}
	err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o222 != 0 {
			return fmt.Errorf("deployment bundle tree is not immutable")
		}
		if name == root {
			return nil
		}
		relative, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if entry.IsDir() {
			if _, exists := expectedDirectories[relative]; !exists {
				return fmt.Errorf("deployment bundle contains an unexpected directory")
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("deployment bundle contains a non-regular object")
		}
		if _, exists := expectedFiles[relative]; !exists {
			return fmt.Errorf("deployment bundle contains an unexpected file")
		}
		delete(expectedFiles, relative)
		return nil
	})
	if err != nil {
		return err
	}
	if len(expectedFiles) != 0 {
		return fmt.Errorf("deployment bundle file layout is incomplete")
	}
	return nil
}

func validURLPath(value string) bool {
	if len(value) < 2 || len(value) > 512 || value[0] != '/' ||
		path.Clean(value) != value || strings.HasSuffix(value, "/") ||
		strings.Contains(value, "//") || strings.ContainsAny(value, "%\\?#") ||
		!strings.HasSuffix(value, ".bin") {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '/' ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func digestBoundedFile(name string, maximum int64) (string, error) {
	payload, err := readBoundedFile(name, maximum)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func readBoundedFile(name string, maximum int64) ([]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("file is not regular")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 || int64(len(payload)) > maximum {
		return nil, fmt.Errorf("file size is outside range")
	}
	return payload, nil
}

func decodeStrict(payload []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("JSON has trailing data")
	}
	return nil
}

func requireExactJSONFields(payload []byte, expected map[string]struct{}) error {
	var document map[string]json.RawMessage
	if err := decodeStrict(payload, &document); err != nil {
		return err
	}
	if len(document) != len(expected) {
		return fmt.Errorf("field set does not match schema")
	}
	for name := range expected {
		if _, exists := document[name]; !exists {
			return fmt.Errorf("required field %q is missing", name)
		}
	}
	return nil
}

func rejectDuplicateJSONNames(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				nameToken, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := nameToken.(string)
				if !ok {
					return fmt.Errorf("object name is not a string")
				}
				if _, exists := seen[name]; exists {
					return fmt.Errorf("duplicate JSON name %q", name)
				}
				seen[name] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return fmt.Errorf("object is not closed")
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return fmt.Errorf("array is not closed")
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("JSON has trailing data")
	}
	return nil
}
