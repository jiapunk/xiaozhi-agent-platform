// Package ocirelease independently validates daemonless OCI release bundles.
package ocirelease

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	ociImageIndex    = "application/vnd.oci.image.index.v1+json"
	ociImageManifest = "application/vnd.oci.image.manifest.v1+json"
	ociImageConfig   = "application/vnd.oci.image.config.v1+json"
	ociLayerGzip     = "application/vnd.oci.image.layer.v1.tar+gzip"
	ociEmptyConfig   = "application/vnd.oci.empty.v1+json"
	spdxMediaType    = "application/spdx+json"
	intotoMediaType  = "application/vnd.in-toto+json"
	statementType    = "https://in-toto.io/Statement/v1"
	provenanceType   = "https://slsa.dev/provenance/v1"
	buildType        = "https://xiaozhi-agent.local/buildtypes/daemonless-oci/v3"
	builderID        = "https://xiaozhi-agent.local/builders/daemonless-oci/v3"
	maxJSON          = 8 << 20
	maxBlob          = 128 << 20
	maxKey           = 4096
	minEpoch         = 946684800
	maxEpoch         = 4102444800
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)
	versionPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	shaPattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	digestPattern     = regexp.MustCompile(`^sha256:([0-9a-f]{64})$`)
	supportedServices = map[string]bool{
		"gateway": true, "controlplane": true, "agentproxy": true,
		"firmwareorigin": true, "generationcoordinator": true,
		"accountauthorization": true, "factorytimeauthority": true,
	}
	supportedServiceOrder = []string{
		"gateway", "controlplane", "agentproxy", "firmwareorigin",
		"generationcoordinator", "accountauthorization", "factorytimeauthority",
	}
	signatureDomain = []byte("XIAOZHI-AGENT-OCI-RELEASE-V3\x00")
)

// Options are external trust-policy inputs, never taken from the bundle.
type Options struct {
	TrustedPublicKey  string
	SigningKeyID      string
	ExpectedReleaseID string
	RequireReadOnly   bool
}

// Receipt is the authenticated top-level release receipt.
type Receipt struct {
	Schema             int             `json:"schema"`
	ReleaseID          string          `json:"release_id"`
	Version            string          `json:"version"`
	SourceDateEpoch    int64           `json:"source_date_epoch"`
	SourceInputsSHA256 string          `json:"source_inputs_sha256"`
	CABundleSHA256     string          `json:"ca_bundle_sha256"`
	GoExecutableSHA256 string          `json:"go_executable_sha256"`
	GoVersion          string          `json:"go_version"`
	SigningKeyID       string          `json:"signing_key_id"`
	SignatureAlgorithm string          `json:"signature_algorithm"`
	Signature          string          `json:"signature_b64url"`
	Services           []ServiceRecord `json:"services"`
}

type ServiceRecord struct {
	Name                     string           `json:"name"`
	OCIIndexSHA256           string           `json:"oci_index_sha256"`
	OCIIndexSize             int64            `json:"oci_index_size"`
	ImageIndexDigest         string           `json:"image_index_digest"`
	ImageIndexSize           int64            `json:"image_index_size"`
	SBOMManifestDigest       string           `json:"sbom_manifest_digest"`
	SBOMManifestSize         int64            `json:"sbom_manifest_size"`
	ProvenanceManifestDigest string           `json:"provenance_manifest_digest"`
	ProvenanceManifestSize   int64            `json:"provenance_manifest_size"`
	Platforms                []PlatformRecord `json:"platforms"`
}

type PlatformRecord struct {
	Architecture        string `json:"architecture"`
	BinarySHA256        string `json:"binary_sha256"`
	BinarySize          int64  `json:"binary_size"`
	ImageManifestDigest string `json:"image_manifest_digest"`
	ImageManifestSize   int64  `json:"image_manifest_size"`
}

type descriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	Platform     *platform         `json:"platform,omitempty"`
}

type platform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

type indexDocument struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Manifests     []descriptor      `json:"manifests"`
	Annotations   map[string]string `json:"annotations"`
}

type manifestDocument struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	ArtifactType  string       `json:"artifactType,omitempty"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
	Subject       *descriptor  `json:"subject,omitempty"`
}

type imageConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Created      string `json:"created"`
	Config       struct {
		Entrypoint []string `json:"Entrypoint"`
		Env        []string `json:"Env"`
		StopSignal string   `json:"StopSignal"`
		User       string   `json:"User"`
		WorkingDir string   `json:"WorkingDir"`
	} `json:"config"`
	RootFS struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
	History []struct {
		Comment   string `json:"comment"`
		Created   string `json:"created"`
		CreatedBy string `json:"created_by"`
	} `json:"history"`
}

// Validate verifies signature, exact file layout, OCI graph, static layers,
// SBOM, and provenance. It returns only after every service passes.
func Validate(root string, options Options) (Receipt, error) {
	var receipt Receipt
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return receipt, errors.New("release bundle must be a non-symlink directory")
	}
	if !identifierPattern.MatchString(options.SigningKeyID) {
		return receipt, errors.New("expected signing key ID has invalid format")
	}
	receiptData, err := readRegular(filepath.Join(root, "release-receipt.json"), maxJSON)
	if err != nil {
		return receipt, fmt.Errorf("release receipt: %w", err)
	}
	receiptValue, err := parseStrict(receiptData)
	if err != nil {
		return receipt, fmt.Errorf("release receipt: %w", err)
	}
	if !bytes.Equal(prettyJSON(receiptValue), receiptData) {
		return receipt, errors.New("release receipt is not canonical JSON")
	}
	receiptMap, ok := receiptValue.(map[string]any)
	if !ok || !exactFields(receiptMap,
		"ca_bundle_sha256", "go_executable_sha256", "go_version", "release_id", "schema", "services",
		"signature_algorithm", "signature_b64url", "signing_key_id", "source_date_epoch",
		"source_inputs_sha256", "version") {
		return receipt, errors.New("release receipt fields do not match schema")
	}
	if err := decodeExact(receiptData, &receipt); err != nil {
		return receipt, fmt.Errorf("release receipt schema: %w", err)
	}
	if err := validateReceiptFields(receipt, options); err != nil {
		return receipt, err
	}
	publicKey, err := loadPublicKey(options.TrustedPublicKey)
	if err != nil {
		return receipt, err
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(receipt.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != receipt.Signature {
		return receipt, errors.New("release signature is not canonical base64url")
	}
	delete(receiptMap, "signature_b64url")
	payload := append(append([]byte{}, signatureDomain...), compactJSON(receiptMap)...)
	if !ed25519.Verify(publicKey, payload, signature) {
		return receipt, errors.New("release receipt signature is invalid")
	}
	ready, err := readRegular(filepath.Join(root, "READY"), 128)
	if err != nil || string(ready) != hashHex(receiptData)+"\n" {
		return receipt, errors.New("release READY marker is invalid")
	}
	sourceData, err := readRegular(filepath.Join(root, "source-inputs.json"), maxJSON)
	if err != nil || hashHex(sourceData) != receipt.SourceInputsSHA256 {
		return receipt, errors.New("source inputs do not match release receipt")
	}
	if err := validateSourceInputs(sourceData, receipt); err != nil {
		return receipt, err
	}
	expected := map[string]bool{
		"READY": true, "release-receipt.json": true, "source-inputs.json": true,
	}
	seenServices := map[string]bool{}
	for index, service := range receipt.Services {
		if service.Name != supportedServiceOrder[index] {
			return receipt, errors.New("release service ordering is not canonical")
		}
		if seenServices[service.Name] {
			return receipt, errors.New("release service records are duplicated")
		}
		seenServices[service.Name] = true
		files, validationErr := validateService(root, service, receipt)
		if validationErr != nil {
			return receipt, fmt.Errorf("service %s: %w", service.Name, validationErr)
		}
		for name := range files {
			expected[name] = true
		}
	}
	actual, err := inspectTree(root, options.RequireReadOnly)
	if err != nil {
		return receipt, err
	}
	if !reflect.DeepEqual(actual, expected) {
		return receipt, errors.New("release bundle file layout is not exact")
	}
	return receipt, nil
}

func validateReceiptFields(receipt Receipt, options Options) error {
	if receipt.Schema != 3 || !identifierPattern.MatchString(receipt.ReleaseID) ||
		!versionPattern.MatchString(receipt.Version) || receipt.SourceDateEpoch < minEpoch ||
		receipt.SourceDateEpoch > maxEpoch || !shaPattern.MatchString(receipt.SourceInputsSHA256) ||
		!shaPattern.MatchString(receipt.CABundleSHA256) ||
		!shaPattern.MatchString(receipt.GoExecutableSHA256) || receipt.GoVersion != "go1.26.5" ||
		!identifierPattern.MatchString(receipt.SigningKeyID) ||
		receipt.SigningKeyID != options.SigningKeyID || receipt.SignatureAlgorithm != "Ed25519" {
		return errors.New("release receipt violates trust policy")
	}
	if options.ExpectedReleaseID != "" && receipt.ReleaseID != options.ExpectedReleaseID {
		return errors.New("release ID does not match expectation")
	}
	if len(receipt.Services) != len(supportedServiceOrder) {
		return errors.New("release must contain the exact seven-service set")
	}
	return nil
}

func validateSourceInputs(data []byte, receipt Receipt) error {
	value, err := parseStrict(data)
	if err != nil || !bytes.Equal(prettyJSON(value), data) {
		return errors.New("source inputs are not canonical JSON")
	}
	root, ok := value.(map[string]any)
	if !ok || !exactFields(root, "algorithm", "inputs", "schema") ||
		root["algorithm"] != "sha256" || numberText(root["schema"]) != "1" {
		return errors.New("source input manifest is invalid")
	}
	inputs, ok := root["inputs"].([]any)
	if !ok || len(inputs) < 1 || len(inputs) > 4096 {
		return errors.New("source input count is outside range")
	}
	previous := ""
	goInputFound := false
	for _, raw := range inputs {
		entry, ok := raw.(map[string]any)
		if !ok || !(exactFields(entry, "name", "sha256", "size") ||
			exactFields(entry, "name", "sha256", "size", "version")) {
			return errors.New("source input fields are invalid")
		}
		name, ok := entry["name"].(string)
		sha, shaOK := entry["sha256"].(string)
		size, sizeOK := integer(entry["size"])
		if !ok || name == "" || len(name) > 512 || name <= previous || !shaOK ||
			!shaPattern.MatchString(sha) || !sizeOK || size < 1 || size > maxBlob {
			return errors.New("source input entry is invalid or not uniquely sorted")
		}
		if name == "toolchain:go-executable" {
			version, versionOK := entry["version"].(string)
			if !versionOK || version != receipt.GoVersion || sha != receipt.GoExecutableSHA256 {
				return errors.New("Go executable source input does not match release receipt")
			}
			goInputFound = true
		}
		previous = name
	}
	if !goInputFound {
		return errors.New("Go executable source input is missing")
	}
	return nil
}

func validateService(root string, record ServiceRecord, receipt Receipt) (map[string]bool, error) {
	expected := map[string]bool{}
	if !supportedServices[record.Name] || !shaPattern.MatchString(record.OCIIndexSHA256) ||
		!validDigest(record.ImageIndexDigest) || !validDigest(record.SBOMManifestDigest) ||
		!validDigest(record.ProvenanceManifestDigest) || record.OCIIndexSize < 1 ||
		record.OCIIndexSize > maxJSON || record.ImageIndexSize < 1 ||
		record.SBOMManifestSize < 1 || record.ProvenanceManifestSize < 1 {
		return nil, errors.New("service receipt fields are invalid")
	}
	layout := filepath.Join(root, "services", record.Name)
	info, err := os.Lstat(layout)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("OCI layout must be a non-symlink directory")
	}
	prefix := path.Join("services", record.Name)
	expected[path.Join(prefix, "oci-layout")] = true
	expected[path.Join(prefix, "index.json")] = true
	layoutData, err := readRegular(filepath.Join(layout, "oci-layout"), 1024)
	if err != nil || string(layoutData) != "{\n  \"imageLayoutVersion\": \"1.0.0\"\n}\n" {
		return nil, errors.New("oci-layout is invalid")
	}
	indexData, err := readRegular(filepath.Join(layout, "index.json"), maxJSON)
	if err != nil || int64(len(indexData)) != record.OCIIndexSize ||
		hashHex(indexData) != record.OCIIndexSHA256 {
		return nil, errors.New("OCI root index does not match receipt")
	}
	indexValue, err := parseStrict(indexData)
	if err != nil || !bytes.Equal(prettyJSON(indexValue), indexData) {
		return nil, errors.New("OCI root index is not canonical JSON")
	}
	var rootIndex indexDocument
	if err := decodeExact(indexData, &rootIndex); err != nil || rootIndex.SchemaVersion != 2 ||
		rootIndex.MediaType != ociImageIndex || len(rootIndex.Manifests) != 3 {
		return nil, errors.New("OCI root index structure is invalid")
	}
	imageDescriptor := rootIndex.Manifests[0]
	if imageDescriptor.MediaType != ociImageIndex || imageDescriptor.Digest != record.ImageIndexDigest ||
		imageDescriptor.Size != record.ImageIndexSize || imageDescriptor.Platform != nil ||
		imageDescriptor.ArtifactType != "" || len(imageDescriptor.Annotations) != 2 {
		return nil, errors.New("OCI image index descriptor does not match receipt")
	}
	referenced := map[string]bool{}
	imageData, err := readBlob(layout, imageDescriptor, ociImageIndex, referenced)
	if err != nil {
		return nil, fmt.Errorf("image index: %w", err)
	}
	if !bytes.Equal(compactParsed(imageData), imageData) {
		return nil, errors.New("OCI image index is not canonical compact JSON")
	}
	var imageIndex indexDocument
	if err := decodeExact(imageData, &imageIndex); err != nil || imageIndex.SchemaVersion != 2 ||
		imageIndex.MediaType != ociImageIndex || len(imageIndex.Manifests) != 2 ||
		len(record.Platforms) != 2 {
		return nil, errors.New("OCI image index structure is invalid")
	}
	for index, architecture := range []string{"amd64", "arm64"} {
		platformRecord := record.Platforms[index]
		descriptor := imageIndex.Manifests[index]
		if platformRecord.Architecture != architecture || !shaPattern.MatchString(platformRecord.BinarySHA256) ||
			platformRecord.BinarySize < 1 || platformRecord.BinarySize > 64<<20 ||
			descriptor.Platform == nil || descriptor.Platform.Architecture != architecture ||
			descriptor.Platform.OS != "linux" || descriptor.MediaType != ociImageManifest ||
			descriptor.Digest != platformRecord.ImageManifestDigest ||
			descriptor.Size != platformRecord.ImageManifestSize {
			return nil, errors.New("OCI platform descriptor does not match receipt")
		}
		if err := validatePlatform(layout, descriptor, platformRecord, receipt, referenced); err != nil {
			return nil, fmt.Errorf("linux/%s: %w", architecture, err)
		}
	}
	sbomDescriptor, provenanceDescriptor := rootIndex.Manifests[1], rootIndex.Manifests[2]
	if sbomDescriptor.MediaType != ociImageManifest || sbomDescriptor.ArtifactType != spdxMediaType ||
		sbomDescriptor.Digest != record.SBOMManifestDigest || sbomDescriptor.Size != record.SBOMManifestSize ||
		provenanceDescriptor.MediaType != ociImageManifest ||
		provenanceDescriptor.ArtifactType != intotoMediaType ||
		provenanceDescriptor.Digest != record.ProvenanceManifestDigest ||
		provenanceDescriptor.Size != record.ProvenanceManifestSize {
		return nil, errors.New("OCI artifact descriptors do not match receipt")
	}
	spdx, err := validateArtifact(layout, sbomDescriptor, imageDescriptor, spdxMediaType, referenced)
	if err != nil {
		return nil, fmt.Errorf("SPDX SBOM: %w", err)
	}
	provenance, err := validateArtifact(
		layout, provenanceDescriptor, imageDescriptor, intotoMediaType, referenced)
	if err != nil {
		return nil, fmt.Errorf("provenance: %w", err)
	}
	if err := validateSPDX(spdx, imageDescriptor.Digest, receipt); err != nil {
		return nil, err
	}
	if err := validateProvenance(provenance, record.Name, imageDescriptor.Digest, receipt); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(layout, "blobs", "sha256"))
	if err != nil {
		return nil, errors.New("cannot enumerate OCI blobs")
	}
	actualBlobs := map[string]bool{}
	for _, entry := range entries {
		info, infoErr := entry.Info()
		if infoErr != nil || !info.Mode().IsRegular() || entry.Type()&os.ModeSymlink != 0 ||
			!shaPattern.MatchString(entry.Name()) {
			return nil, errors.New("OCI blob directory contains an invalid object")
		}
		actualBlobs[entry.Name()] = true
	}
	if !reflect.DeepEqual(actualBlobs, referenced) {
		return nil, errors.New("OCI layout contains missing or orphaned blobs")
	}
	for digest := range referenced {
		expected[path.Join(prefix, "blobs", "sha256", digest)] = true
	}
	return expected, nil
}

func validatePlatform(
	layout string,
	descriptor descriptor,
	record PlatformRecord,
	receipt Receipt,
	referenced map[string]bool,
) error {
	manifestData, err := readBlob(layout, descriptor, ociImageManifest, referenced)
	if err != nil || !bytes.Equal(compactParsed(manifestData), manifestData) {
		return errors.New("platform manifest is invalid or noncanonical")
	}
	var manifest manifestDocument
	if err := decodeExact(manifestData, &manifest); err != nil || manifest.SchemaVersion != 2 ||
		manifest.MediaType != ociImageManifest || manifest.ArtifactType != "" ||
		manifest.Subject != nil || len(manifest.Layers) != 1 {
		return errors.New("platform manifest structure is invalid")
	}
	configData, err := readBlob(layout, manifest.Config, ociImageConfig, referenced)
	if err != nil || !bytes.Equal(compactParsed(configData), configData) {
		return errors.New("platform config is invalid or noncanonical")
	}
	var config imageConfig
	if err := decodeExact(configData, &config); err != nil {
		return errors.New("platform config fields are invalid")
	}
	created := time.Unix(receipt.SourceDateEpoch, 0).UTC().Format(time.RFC3339)
	if config.Architecture != record.Architecture || config.OS != "linux" ||
		config.Created != created || !reflect.DeepEqual(config.Config.Entrypoint, []string{"/service"}) ||
		!reflect.DeepEqual(config.Config.Env, []string{"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"}) ||
		config.Config.StopSignal != "SIGTERM" || config.Config.User != "65532:65532" ||
		config.Config.WorkingDir != "/" || len(config.History) != 1 ||
		config.History[0].Created != created || config.History[0].CreatedBy !=
		"xiaozhi-agent-daemonless-oci-builder/2" || config.History[0].Comment !=
		"reproducible daemonless OCI builder" {
		return errors.New("platform config violates static image policy")
	}
	layerData, err := readBlob(layout, manifest.Layers[0], ociLayerGzip, referenced)
	if err != nil {
		return err
	}
	diffID, err := validateLayer(layerData, record, receipt)
	if err != nil {
		return err
	}
	if config.RootFS.Type != "layers" || !reflect.DeepEqual(config.RootFS.DiffIDs, []string{diffID}) {
		return errors.New("platform rootfs diff ID is invalid")
	}
	return nil
}

func validateLayer(data []byte, record PlatformRecord, receipt Receipt) (string, error) {
	if len(data) < 10 || !bytes.Equal(data[:4], []byte{0x1f, 0x8b, 0x08, 0x00}) ||
		!bytes.Equal(data[8:10], []byte{0x02, 0xff}) ||
		int64(binary.LittleEndian.Uint32(data[4:8])) != receipt.SourceDateEpoch {
		return "", errors.New("OCI layer gzip timestamp or header is invalid")
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", errors.New("OCI layer gzip is invalid")
	}
	uncompressed, err := io.ReadAll(io.LimitReader(reader, maxBlob+1))
	closeErr := reader.Close()
	if err != nil || closeErr != nil || len(uncompressed) > maxBlob {
		return "", errors.New("OCI layer uncompressed size is invalid")
	}
	type metadata struct {
		typeflag byte
		mode     int64
		uid      int
		gid      int
	}
	expected := map[string]metadata{
		"etc": {tar.TypeDir, 0555, 0, 0}, "etc/ssl": {tar.TypeDir, 0555, 0, 0},
		"etc/ssl/certs": {tar.TypeDir, 0555, 0, 0}, "licenses": {tar.TypeDir, 0555, 0, 0},
		"service":                              {tar.TypeReg, 0555, 65532, 65532},
		"etc/ssl/certs/ca-certificates.crt":    {tar.TypeReg, 0444, 0, 0},
		"licenses/coder-websocket-LICENSE.txt": {tar.TypeReg, 0444, 0, 0},
		"licenses/THIRD_PARTY_NOTICES.md":      {tar.TypeReg, 0444, 0, 0},
	}
	seen := map[string]bool{}
	tarReader := tar.NewReader(bytes.NewReader(uncompressed))
	for {
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return "", errors.New("OCI layer tar is invalid")
		}
		logicalName := header.Name
		if header.Typeflag == tar.TypeDir {
			if !strings.HasSuffix(logicalName, "/") {
				return "", errors.New("OCI layer directory lacks a canonical trailing slash")
			}
			logicalName = strings.TrimSuffix(logicalName, "/")
		} else if strings.HasSuffix(logicalName, "/") {
			return "", errors.New("OCI layer regular file has a trailing slash")
		}
		wanted, exists := expected[logicalName]
		if !exists || seen[logicalName] || path.IsAbs(logicalName) ||
			path.Clean(logicalName) != logicalName || strings.Contains(logicalName, "\\") ||
			header.Format != tar.FormatUSTAR || header.Typeflag != wanted.typeflag ||
			header.Mode != wanted.mode || header.Uid != wanted.uid || header.Gid != wanted.gid ||
			header.ModTime.Unix() != receipt.SourceDateEpoch || header.Uname != "" || header.Gname != "" {
			return "", fmt.Errorf(
				"OCI layer contains an unsafe path or non-reproducible metadata: name=%q format=%v type=%d mode=%04o uid=%d gid=%d mtime=%d uname=%q gname=%q",
				header.Name, header.Format, header.Typeflag, header.Mode, header.Uid, header.Gid,
				header.ModTime.Unix(), header.Uname, header.Gname,
			)
		}
		seen[logicalName] = true
		if header.Typeflag != tar.TypeReg {
			continue
		}
		payload, readErr := io.ReadAll(io.LimitReader(tarReader, maxBlob+1))
		if readErr != nil || int64(len(payload)) != header.Size || len(payload) > maxBlob {
			return "", errors.New("OCI layer file size is invalid")
		}
		switch logicalName {
		case "service":
			if int64(len(payload)) != record.BinarySize || hashHex(payload) != record.BinarySHA256 ||
				!staticELF(payload, record.Architecture) {
				return "", errors.New("OCI service binary violates static ELF policy")
			}
		case "etc/ssl/certs/ca-certificates.crt":
			if hashHex(payload) != receipt.CABundleSHA256 ||
				!bytes.Contains(payload, []byte("-----BEGIN CERTIFICATE-----")) {
				return "", errors.New("OCI CA bundle does not match receipt")
			}
		}
	}
	if len(seen) != len(expected) {
		return "", errors.New("OCI layer file layout is incomplete")
	}
	return "sha256:" + hashHex(uncompressed), nil
}

func validateArtifact(
	layout string,
	descriptor descriptor,
	subject descriptor,
	artifactType string,
	referenced map[string]bool,
) (map[string]any, error) {
	manifestData, err := readBlob(layout, descriptor, ociImageManifest, referenced)
	if err != nil || !bytes.Equal(compactParsed(manifestData), manifestData) {
		return nil, errors.New("artifact manifest is invalid or noncanonical")
	}
	var manifest manifestDocument
	if err := decodeExact(manifestData, &manifest); err != nil || manifest.SchemaVersion != 2 ||
		manifest.MediaType != ociImageManifest || manifest.ArtifactType != artifactType ||
		manifest.Subject == nil || !reflect.DeepEqual(*manifest.Subject, subject) ||
		len(manifest.Layers) != 1 {
		return nil, errors.New("artifact is not attached to the image index")
	}
	empty, err := readBlob(layout, manifest.Config, ociEmptyConfig, referenced)
	if err != nil || string(empty) != "{}" || manifest.Config.Annotations != nil ||
		manifest.Config.Platform != nil || manifest.Config.ArtifactType != "" {
		return nil, errors.New("artifact empty config is invalid")
	}
	payload, err := readBlob(layout, manifest.Layers[0], artifactType, referenced)
	if err != nil || !bytes.Equal(compactParsed(payload), payload) {
		return nil, errors.New("artifact payload is invalid or noncanonical")
	}
	value, err := parseStrict(payload)
	if err != nil {
		return nil, err
	}
	document, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("artifact payload must be a JSON object")
	}
	return document, nil
}

func validateSPDX(document map[string]any, imageDigest string,
	receipt Receipt) error {
	if document["spdxVersion"] != "SPDX-2.3" || document["SPDXID"] != "SPDXRef-DOCUMENT" ||
		document["dataLicense"] != "CC0-1.0" {
		return errors.New("SPDX document identity is invalid")
	}
	describes, ok := document["documentDescribes"].([]any)
	if !ok || len(describes) != 1 || describes[0] != "SPDXRef-Package-Service" {
		return errors.New("SPDX document does not describe the service")
	}
	creation, ok := document["creationInfo"].(map[string]any)
	creators, creatorsOK := creation["creators"].([]any)
	created, createdOK := creation["created"].(string)
	if !ok || !creatorsOK || len(creators) != 1 ||
		creators[0] != "Tool: xiaozhi-agent-daemonless-oci-builder/2" ||
		!createdOK || created != time.Unix(receipt.SourceDateEpoch, 0).UTC().Format(time.RFC3339) {
		return errors.New("SPDX creation identity is invalid")
	}
	packages, ok := document["packages"].([]any)
	if !ok || len(packages) != 4 {
		return errors.New("SPDX package inventory is incomplete")
	}
	for _, raw := range packages {
		item, itemOK := raw.(map[string]any)
		if !itemOK || item["filesAnalyzed"] != false {
			return errors.New("SPDX package overclaims file analysis")
		}
	}
	service := packages[0].(map[string]any)
	checksums, ok := service["checksums"].([]any)
	if !ok || len(checksums) != 1 {
		return errors.New("SPDX service checksum is missing")
	}
	checksum, ok := checksums[0].(map[string]any)
	if !ok || checksum["algorithm"] != "SHA256" || checksum["checksumValue"] !=
		strings.TrimPrefix(imageDigest, "sha256:") {
		return errors.New("SPDX service package is not bound to image index")
	}
	return nil
}

func validateProvenance(
	document map[string]any, service, imageDigest string, receipt Receipt,
) error {
	if document["_type"] != statementType || document["predicateType"] != provenanceType {
		return errors.New("provenance statement type is invalid")
	}
	subjects, ok := document["subject"].([]any)
	if !ok || len(subjects) != 1 {
		return errors.New("provenance must have exactly one subject")
	}
	subject, ok := subjects[0].(map[string]any)
	digests, digestOK := subject["digest"].(map[string]any)
	if !ok || !digestOK || subject["name"] != "xiaozhi-agent/"+service ||
		digests["sha256"] != strings.TrimPrefix(imageDigest, "sha256:") {
		return errors.New("provenance subject is not bound to image index")
	}
	predicate, ok := document["predicate"].(map[string]any)
	if !ok {
		return errors.New("provenance predicate is invalid")
	}
	definition, ok := predicate["buildDefinition"].(map[string]any)
	details, detailsOK := predicate["runDetails"].(map[string]any)
	if !ok || !detailsOK || definition["buildType"] != buildType {
		return errors.New("provenance build definition is invalid")
	}
	builder, ok := details["builder"].(map[string]any)
	builderVersion, versionOK := builder["version"].(map[string]any)
	if !ok || builder["id"] != builderID || !versionOK ||
		builderVersion["oci-release"] != "2" {
		return errors.New("provenance builder identity is invalid")
	}
	dependencies, ok := definition["resolvedDependencies"].([]any)
	if !ok {
		return errors.New("provenance dependencies are invalid")
	}
	wanted := map[string]string{
		"file:source-inputs.json":  receipt.SourceInputsSHA256,
		"file:ca-certificates.crt": receipt.CABundleSHA256,
		"file:go-executable":       receipt.GoExecutableSHA256,
	}
	for _, raw := range dependencies {
		dependency, dependencyOK := raw.(map[string]any)
		if !dependencyOK {
			continue
		}
		uri, _ := dependency["uri"].(string)
		digest, _ := dependency["digest"].(map[string]any)
		if expected, exists := wanted[uri]; exists && digest["sha256"] == expected {
			delete(wanted, uri)
		}
	}
	if len(wanted) != 0 {
		return errors.New("provenance dependencies do not match release receipt")
	}
	return nil
}

func readBlob(layout string, descriptor descriptor, mediaType string, referenced map[string]bool) ([]byte, error) {
	match := digestPattern.FindStringSubmatch(descriptor.Digest)
	if descriptor.MediaType != mediaType || len(match) != 2 || descriptor.Size < 0 ||
		descriptor.Size > maxBlob {
		return nil, errors.New("blob descriptor is invalid")
	}
	data, err := readRegular(filepath.Join(layout, "blobs", "sha256", match[1]), maxBlob)
	if err != nil || int64(len(data)) != descriptor.Size || hashHex(data) != match[1] {
		return nil, errors.New("blob does not match descriptor")
	}
	referenced[match[1]] = true
	return data, nil
}

func inspectTree(root string, readOnly bool) (map[string]bool, error) {
	actual := map[string]bool{}
	err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == root {
			if readOnly {
				info, err := entry.Info()
				if err != nil || info.Mode().Perm()&0222 != 0 {
					return errors.New("release bundle root must be read-only")
				}
			}
			return nil
		}
		info, err := os.Lstat(name)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("release bundle contains a symlink")
		}
		if readOnly && info.Mode().Perm()&0222 != 0 {
			return errors.New("release bundle tree must be read-only")
		}
		if info.Mode().IsRegular() {
			relative, err := filepath.Rel(root, name)
			if err != nil {
				return err
			}
			actual[filepath.ToSlash(relative)] = true
		} else if !info.IsDir() {
			return errors.New("release bundle contains a non-regular object")
		}
		return nil
	})
	return actual, err
}

func readRegular(name string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() < 1 || info.Size() > maximum {
		return nil, errors.New("file is unavailable, empty, too large, or non-regular")
	}
	data, err := os.ReadFile(name)
	if err != nil || int64(len(data)) != info.Size() {
		return nil, errors.New("file could not be read atomically")
	}
	return data, nil
}

func loadPublicKey(name string) (ed25519.PublicKey, error) {
	data, err := readRegular(name, maxKey)
	if err != nil {
		return nil, errors.New("trusted release public key is unavailable")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("trusted release public key PEM is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("trusted release public key must be Ed25519")
	}
	return key, nil
}

func staticELF(data []byte, architecture string) bool {
	if len(data) < 64 || !bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) ||
		(data[4] != 1 && data[4] != 2) || (data[5] != 1 && data[5] != 2) {
		return false
	}
	var order binary.ByteOrder = binary.LittleEndian
	if data[5] == 2 {
		order = binary.BigEndian
	}
	wanted := uint16(62)
	if architecture == "arm64" {
		wanted = 183
	} else if architecture != "amd64" {
		return false
	}
	if order.Uint16(data[18:20]) != wanted {
		return false
	}
	var offset uint64
	var entrySize, count uint16
	if data[4] == 2 {
		offset = order.Uint64(data[32:40])
		entrySize, count = order.Uint16(data[54:56]), order.Uint16(data[56:58])
	} else {
		offset = uint64(order.Uint32(data[28:32]))
		entrySize, count = order.Uint16(data[42:44]), order.Uint16(data[44:46])
	}
	tableSize := uint64(entrySize) * uint64(count)
	if count > 256 || entrySize < 4 || offset > uint64(len(data)) ||
		tableSize > uint64(len(data))-offset {
		return false
	}
	for index := uint16(0); index < count; index++ {
		position := offset + uint64(entrySize)*uint64(index)
		if order.Uint32(data[position:position+4]) == 3 {
			return false
		}
	}
	return true
}

func parseStrict(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := decodeValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("JSON contains trailing data")
	}
	return value, nil
}

func decodeValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := map[string]any{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("JSON object key is not a string")
			}
			if _, exists := object[key]; exists {
				return nil, errors.New("JSON object contains duplicate fields")
			}
			value, err := decodeValue(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
			return nil, errors.New("JSON object is not terminated")
		}
		return object, nil
	case '[':
		array := []any{}
		for decoder.More() {
			value, err := decodeValue(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if closing, err := decoder.Token(); err != nil || closing != json.Delim(']') {
			return nil, errors.New("JSON array is not terminated")
		}
		return array, nil
	default:
		return nil, errors.New("unexpected JSON delimiter")
	}
}

func decodeExact(data []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}

func compactParsed(data []byte) []byte {
	value, err := parseStrict(data)
	if err != nil {
		return nil
	}
	return compactJSON(value)
}

func compactJSON(value any) []byte {
	data, _ := json.Marshal(value)
	return data
}

func prettyJSON(value any) []byte {
	data, _ := json.MarshalIndent(value, "", "  ")
	return append(data, '\n')
}

func exactFields(value map[string]any, fields ...string) bool {
	if len(value) != len(fields) {
		return false
	}
	for _, field := range fields {
		if _, ok := value[field]; !ok {
			return false
		}
	}
	return true
}

func integer(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	integer, err := number.Int64()
	return integer, err == nil
}

func numberText(value any) string {
	if number, ok := value.(json.Number); ok {
		return number.String()
	}
	return ""
}

func validDigest(value string) bool { return digestPattern.MatchString(value) }

func hashHex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// SortedFiles is used only by tests and operational diagnostics.
func SortedFiles(files map[string]bool) []string {
	result := make([]string, 0, len(files))
	for name := range files {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}
