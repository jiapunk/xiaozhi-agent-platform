package ota

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const (
	maximumRegistryBytes  = 1024 * 1024
	maximumManifestBytes  = 8192
	maximumPublicKeyBytes = 4096
	maximumReleases       = 64
	maximumSigningKeys    = 2
	maximumValidity       = 30 * 24 * time.Hour
)

type signingKeyEntry struct {
	KeyID         string `json:"key_id"`
	PublicKeyFile string `json:"public_key_file"`
}

type releaseEntry struct {
	ManifestFile       string `json:"manifest_file"`
	Enabled            bool   `json:"enabled"`
	RolloutBasisPoints int    `json:"rollout_basis_points"`
	RetryAfterSeconds  int    `json:"retry_after_seconds"`
}

type registryDocument struct {
	Version     int               `json:"version"`
	SigningKeys []signingKeyEntry `json:"signing_keys"`
	Releases    []releaseEntry    `json:"releases"`
}

type manifestDocument struct {
	Schema                   int    `json:"schema"`
	ReleaseID                string `json:"release_id"`
	Project                  string `json:"project"`
	Board                    string `json:"board"`
	Channel                  string `json:"channel"`
	Version                  string `json:"version"`
	ReleaseSequence          uint32 `json:"release_sequence"`
	SecureVersion            uint32 `json:"secure_version"`
	ImageURL                 string `json:"image_url"`
	ImageSize                int64  `json:"image_size"`
	ImageSHA256              string `json:"image_sha256"`
	ResetQualificationSHA256 string `json:"reset_qualification_sha256"`
	NotBefore                int64  `json:"not_before"`
	ExpiresAt                int64  `json:"expires_at"`
	SigningKeyID             string `json:"signing_key_id"`
	SignatureAlgorithm       string `json:"signature_algorithm"`
	SignatureB64URL          string `json:"signature_b64url"`
}

type Release struct {
	ReleaseID                string
	Project                  string
	Board                    string
	Channel                  string
	Version                  string
	ReleaseSequence          uint32
	SecureVersion            uint32
	ImageURL                 string
	ImageSize                int64
	ImageSHA256              string
	ResetQualificationSHA256 string
	NotBefore                int64
	ExpiresAt                int64
	SigningKeyID             string
	Manifest                 []byte
	Enabled                  bool
	RolloutBasisPoints       int
	RetryAfterSeconds        uint32
}

type Registry struct {
	releases []Release
}

type OfferStatus string

const (
	OfferAvailable OfferStatus = "available"
	OfferUpToDate  OfferStatus = "up_to_date"
	OfferDeferred  OfferStatus = "deferred"
)

func LoadRegistry(path string) (*Registry, error) {
	if path == "" {
		return nil, fmt.Errorf("OTA release registry path is required")
	}
	payload, err := readBoundedFile(path, maximumRegistryBytes)
	if err != nil {
		return nil, fmt.Errorf("read OTA release registry: %w", err)
	}
	if err := rejectDuplicateJSONNames(payload); err != nil {
		return nil, fmt.Errorf("OTA release registry JSON: %w", err)
	}
	var document registryDocument
	if err := decodeStrict(payload, &document); err != nil {
		return nil, fmt.Errorf("decode OTA release registry: %w", err)
	}
	if document.Version != 1 || len(document.SigningKeys) == 0 ||
		len(document.SigningKeys) > maximumSigningKeys ||
		len(document.Releases) == 0 || len(document.Releases) > maximumReleases {
		return nil, fmt.Errorf("OTA release registry version/count is invalid")
	}

	root, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("resolve OTA release registry root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve OTA release registry root: %w", err)
	}
	keys := make(map[string]*ecdsa.PublicKey, len(document.SigningKeys))
	for _, entry := range document.SigningKeys {
		if !auth.ValidIdentifier(entry.KeyID, 64) || entry.PublicKeyFile == "" {
			return nil, fmt.Errorf("OTA release signing key entry is invalid")
		}
		if _, exists := keys[entry.KeyID]; exists {
			return nil, fmt.Errorf("OTA release signing key ID is duplicated")
		}
		keyPath, err := resolveContainedFile(root, entry.PublicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("resolve OTA release public key %q: %w",
				entry.KeyID, err)
		}
		key, err := loadPublicKey(keyPath)
		if err != nil {
			return nil, fmt.Errorf("load OTA release public key %q: %w", entry.KeyID, err)
		}
		keys[entry.KeyID] = key
	}

	releases := make([]Release, 0, len(document.Releases))
	seenID := make(map[string]struct{}, len(document.Releases))
	seenSequence := make(map[string]struct{}, len(document.Releases))
	for _, entry := range document.Releases {
		if entry.ManifestFile == "" || entry.RolloutBasisPoints < 0 ||
			entry.RolloutBasisPoints > 10000 || entry.RetryAfterSeconds < 60 ||
			entry.RetryAfterSeconds > 86400 {
			return nil, fmt.Errorf("OTA release rollout entry is invalid")
		}
		manifestPath, err := resolveContainedFile(root, entry.ManifestFile)
		if err != nil {
			return nil, fmt.Errorf("resolve OTA release manifest: %w", err)
		}
		manifestBytes, err := readBoundedFile(manifestPath, maximumManifestBytes)
		if err != nil {
			return nil, fmt.Errorf("read OTA release manifest: %w", err)
		}
		manifest, err := verifyManifest(manifestBytes, keys)
		if err != nil {
			return nil, fmt.Errorf("verify OTA release manifest: %w", err)
		}
		if _, exists := seenID[manifest.ReleaseID]; exists {
			return nil, fmt.Errorf("OTA release ID is duplicated")
		}
		sequenceKey := manifest.Board + "\n" + manifest.Channel + "\n" +
			strconv.FormatUint(uint64(manifest.ReleaseSequence), 10)
		if _, exists := seenSequence[sequenceKey]; exists {
			return nil, fmt.Errorf("OTA board/channel sequence is duplicated")
		}
		seenID[manifest.ReleaseID] = struct{}{}
		seenSequence[sequenceKey] = struct{}{}
		releases = append(releases, Release{
			ReleaseID: manifest.ReleaseID, Project: manifest.Project,
			Board:   manifest.Board,
			Channel: manifest.Channel, Version: manifest.Version,
			ReleaseSequence: manifest.ReleaseSequence,
			SecureVersion:   manifest.SecureVersion, ImageURL: manifest.ImageURL,
			ImageSize: manifest.ImageSize, ImageSHA256: manifest.ImageSHA256,
			ResetQualificationSHA256: manifest.ResetQualificationSHA256,
			NotBefore:                manifest.NotBefore, ExpiresAt: manifest.ExpiresAt,
			SigningKeyID: manifest.SigningKeyID,
			Manifest:     append([]byte(nil), manifestBytes...), Enabled: entry.Enabled,
			RolloutBasisPoints: entry.RolloutBasisPoints,
			RetryAfterSeconds:  uint32(entry.RetryAfterSeconds),
		})
	}
	sort.Slice(releases, func(left, right int) bool {
		if releases[left].Board != releases[right].Board {
			return releases[left].Board < releases[right].Board
		}
		if releases[left].Channel != releases[right].Channel {
			return releases[left].Channel < releases[right].Channel
		}
		return releases[left].ReleaseSequence > releases[right].ReleaseSequence
	})
	return &Registry{releases: releases}, nil
}

func (registry *Registry) Lookup(releaseID string) (Release, bool) {
	if registry == nil || !auth.ValidIdentifier(releaseID, 64) {
		return Release{}, false
	}
	for index := range registry.releases {
		if registry.releases[index].ReleaseID == releaseID {
			release := registry.releases[index]
			release.Manifest = append([]byte(nil), release.Manifest...)
			return release, true
		}
	}
	return Release{}, false
}

func (registry *Registry) Select(deviceID, board, channel string,
	currentSequence uint32, now time.Time, rolloutKey []byte) (
	Release, OfferStatus, uint32) {
	if registry == nil || !auth.ValidIdentifier(deviceID, 64) ||
		!auth.ValidIdentifier(board, 32) || !auth.ValidIdentifier(channel, 32) ||
		currentSequence == 0 || len(rolloutKey) < 32 {
		return Release{}, OfferDeferred, 3600
	}
	var candidate *Release
	for index := range registry.releases {
		release := &registry.releases[index]
		if release.Board == board && release.Channel == channel {
			candidate = release
			break
		}
	}
	if candidate == nil {
		return Release{}, OfferDeferred, 3600
	}
	if currentSequence >= candidate.ReleaseSequence {
		return Release{}, OfferUpToDate, candidate.RetryAfterSeconds
	}
	unix := now.UTC().Unix()
	if !candidate.Enabled || candidate.RolloutBasisPoints == 0 ||
		unix < candidate.NotBefore || unix > candidate.ExpiresAt ||
		!inCohort(rolloutKey, deviceID, candidate.ReleaseID,
			candidate.RolloutBasisPoints) {
		return Release{}, OfferDeferred, candidate.RetryAfterSeconds
	}
	selected := *candidate
	selected.Manifest = append([]byte(nil), candidate.Manifest...)
	return selected, OfferAvailable, candidate.RetryAfterSeconds
}

func inCohort(key []byte, deviceID, releaseID string, basisPoints int) bool {
	if basisPoints >= 10000 {
		return true
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("xiaozhi-ota-rollout-v1\n"))
	_, _ = mac.Write([]byte(releaseID))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write([]byte(deviceID))
	sum := mac.Sum(nil)
	bucket := binary.BigEndian.Uint32(sum[:4]) % 10000
	return int(bucket) < basisPoints
}

func verifyManifest(payload []byte,
	keys map[string]*ecdsa.PublicKey) (manifestDocument, error) {
	if err := rejectDuplicateJSONNames(payload); err != nil {
		return manifestDocument{}, err
	}
	var manifest manifestDocument
	if err := decodeStrict(payload, &manifest); err != nil {
		return manifestDocument{}, err
	}
	if manifest.Schema != 2 || !auth.ValidIdentifier(manifest.ReleaseID, 64) ||
		!auth.ValidIdentifier(manifest.Project, 32) ||
		!auth.ValidIdentifier(manifest.Board, 32) ||
		!auth.ValidIdentifier(manifest.Channel, 32) ||
		!validVersion(manifest.Version) || manifest.ReleaseSequence == 0 ||
		manifest.ReleaseSequence > uint32(^uint32(0)>>1) ||
		manifest.ImageSize < 1024 || manifest.ImageSize > int64(^uint32(0)>>1) ||
		!validSHA256(manifest.ImageSHA256) ||
		!validSHA256(manifest.ResetQualificationSHA256) ||
		manifest.NotBefore < 1609459200 || manifest.ExpiresAt > 4102444800 ||
		manifest.ExpiresAt <= manifest.NotBefore ||
		time.Duration(manifest.ExpiresAt-manifest.NotBefore)*time.Second > maximumValidity ||
		!auth.ValidIdentifier(manifest.SigningKeyID, 64) ||
		manifest.SignatureAlgorithm != "ECDSA_P256_SHA256" ||
		!validImageURL(manifest.ImageURL) {
		return manifestDocument{}, fmt.Errorf("manifest fields are invalid")
	}
	key := keys[manifest.SigningKeyID]
	if key == nil {
		return manifestDocument{}, fmt.Errorf("manifest signing key ID is unknown")
	}
	signature, err := base64.RawURLEncoding.DecodeString(manifest.SignatureB64URL)
	digest := sha256.Sum256(canonicalManifest(manifest))
	if err != nil || len(signature) < 8 || len(signature) > 80 ||
		base64.RawURLEncoding.EncodeToString(signature) != manifest.SignatureB64URL ||
		!ecdsa.VerifyASN1(key, digest[:], signature) {
		return manifestDocument{}, fmt.Errorf("manifest signature is invalid")
	}
	return manifest, nil
}

func canonicalManifest(manifest manifestDocument) []byte {
	return []byte("xiaozhi-product-ota-v2\n" +
		"board=" + manifest.Board + "\n" +
		"channel=" + manifest.Channel + "\n" +
		"expires_at=" + strconv.FormatInt(manifest.ExpiresAt, 10) + "\n" +
		"image_sha256=" + manifest.ImageSHA256 + "\n" +
		"image_size=" + strconv.FormatInt(manifest.ImageSize, 10) + "\n" +
		"image_url=" + manifest.ImageURL + "\n" +
		"not_before=" + strconv.FormatInt(manifest.NotBefore, 10) + "\n" +
		"project=" + manifest.Project + "\n" +
		"release_id=" + manifest.ReleaseID + "\n" +
		"release_sequence=" + strconv.FormatUint(uint64(manifest.ReleaseSequence), 10) + "\n" +
		"reset_qualification_sha256=" + manifest.ResetQualificationSHA256 + "\n" +
		"schema=" + strconv.Itoa(manifest.Schema) + "\n" +
		"secure_version=" + strconv.FormatUint(uint64(manifest.SecureVersion), 10) + "\n" +
		"signature_algorithm=" + manifest.SignatureAlgorithm + "\n" +
		"signing_key_id=" + manifest.SigningKeyID + "\n" +
		"version=" + manifest.Version + "\n")
}

func validImageURL(value string) bool {
	if len(value) > 512 || !strings.HasPrefix(value, "https://") ||
		strings.Contains(value, "\\") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Path == "" || parsed.Path == "/" || strings.Count(parsed.Host, ":") > 1 {
		return false
	}
	host, portText, hasPort := strings.Cut(parsed.Host, ":")
	if !validDNSName(host) {
		return false
	}
	if hasPort {
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return false
		}
	}
	for _, char := range value {
		if char <= 0x20 || char >= 0x7f {
			return false
		}
	}
	return true
}

func validDNSName(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' ||
			label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
				(char >= '0' && char <= '9') || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validVersion(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '.' || char == '+' ||
			char == '-' || char == '_' {
			continue
		}
		return false
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func loadPublicKey(path string) (*ecdsa.PublicKey, error) {
	payload, err := readBoundedFile(path, maximumPublicKeyBytes)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(payload)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("public key must be one PKIX PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("public key must be ECDSA P-256")
	}
	return key, nil
}

func readBoundedFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 || int64(len(payload)) > maximum {
		return nil, fmt.Errorf("file size is outside range")
	}
	return payload, nil
}

func resolveContainedFile(root, name string) (string, error) {
	if filepath.IsAbs(name) || strings.Contains(name, "\\") || len(name) > 4096 {
		return "", fmt.Errorf("path must be a bounded relative path")
	}
	clean := filepath.Clean(name)
	if clean == "." || clean == ".." || clean != name ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes registry root")
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(root, clean))
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(root, resolved)
	if err != nil || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path symlink escapes registry root")
	}
	return resolved, nil
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
