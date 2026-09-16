package deploymentbundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/firmwareorigin"
	productota "xiaozhi-agent-platform/gateway/internal/ota"
)

const maximumApprovalWindow = int64(24 * 60 * 60)

var (
	rolloutReceiptFields = fieldSet(
		"schema", "generation_id", "generation_sequence",
		"parent_generation_id", "parent_generation_sequence",
		"parent_receipt_sha256", "promotion_action",
		"approval_keyring_sha256", "rollout_request_sha256",
		"approval_evidence", "promoted_at", "release_id", "signing_key_id",
		"project", "board", "channel", "version", "release_sequence",
		"secure_version", "image_authority", "image_url_path", "image_size",
		"image_sha256", "manifest_sha256", "public_key_sha256",
		"sdkconfig_sha256", "control_registry_sha256", "origin_catalog_sha256",
		"rollout_enabled", "rollout_basis_points", "retry_after_seconds")
	rolloutRequestFields = fieldSet(
		"schema", "generation_id", "generation_sequence",
		"parent_generation_id", "parent_generation_sequence",
		"parent_receipt_sha256", "parent_rollout_enabled",
		"parent_rollout_basis_points", "release_id", "release_sequence",
		"image_sha256", "promotion_action", "rollout_enabled",
		"rollout_basis_points", "retry_after_seconds", "created_at", "expires_at",
		"approval_keyring_sha256")
	rolloutApprovalFields = fieldSet(
		"schema", "request_sha256", "approver_id", "approval_key_id",
		"decision", "signed_at", "signature_algorithm", "signature_b64url")
	approvalEvidenceFields = fieldSet(
		"approver_id", "approval_key_id", "approval_sha256")
	approverKeyringFields = fieldSet("version", "approvers")
	approverEntryFields   = fieldSet(
		"approver_id", "approval_key_id", "public_key_file", "enabled")
)

type ApprovalEvidence struct {
	ApproverID     string `json:"approver_id"`
	ApprovalKeyID  string `json:"approval_key_id"`
	ApprovalSHA256 string `json:"approval_sha256"`
}

type RolloutReceipt struct {
	Schema                   int                `json:"schema"`
	GenerationID             string             `json:"generation_id"`
	GenerationSequence       uint32             `json:"generation_sequence"`
	ParentGenerationID       string             `json:"parent_generation_id"`
	ParentGenerationSequence uint32             `json:"parent_generation_sequence"`
	ParentReceiptSHA256      string             `json:"parent_receipt_sha256"`
	PromotionAction          string             `json:"promotion_action"`
	ApprovalKeyringSHA256    string             `json:"approval_keyring_sha256"`
	RolloutRequestSHA256     string             `json:"rollout_request_sha256"`
	ApprovalEvidence         []ApprovalEvidence `json:"approval_evidence"`
	PromotedAt               int64              `json:"promoted_at"`
	ReleaseID                string             `json:"release_id"`
	SigningKeyID             string             `json:"signing_key_id"`
	Project                  string             `json:"project"`
	Board                    string             `json:"board"`
	Channel                  string             `json:"channel"`
	Version                  string             `json:"version"`
	ReleaseSequence          uint32             `json:"release_sequence"`
	SecureVersion            uint32             `json:"secure_version"`
	ImageAuthority           string             `json:"image_authority"`
	ImageURLPath             string             `json:"image_url_path"`
	ImageSize                int64              `json:"image_size"`
	ImageSHA256              string             `json:"image_sha256"`
	ManifestSHA256           string             `json:"manifest_sha256"`
	PublicKeySHA256          string             `json:"public_key_sha256"`
	SDKConfigSHA256          string             `json:"sdkconfig_sha256"`
	ControlRegistrySHA256    string             `json:"control_registry_sha256"`
	OriginCatalogSHA256      string             `json:"origin_catalog_sha256"`
	RolloutEnabled           bool               `json:"rollout_enabled"`
	RolloutBasisPoints       int                `json:"rollout_basis_points"`
	RetryAfterSeconds        int                `json:"retry_after_seconds"`
}

type rolloutRequest struct {
	Schema                   int    `json:"schema"`
	GenerationID             string `json:"generation_id"`
	GenerationSequence       uint32 `json:"generation_sequence"`
	ParentGenerationID       string `json:"parent_generation_id"`
	ParentGenerationSequence uint32 `json:"parent_generation_sequence"`
	ParentReceiptSHA256      string `json:"parent_receipt_sha256"`
	ParentRolloutEnabled     bool   `json:"parent_rollout_enabled"`
	ParentRolloutBasisPoints int    `json:"parent_rollout_basis_points"`
	ReleaseID                string `json:"release_id"`
	ReleaseSequence          uint32 `json:"release_sequence"`
	ImageSHA256              string `json:"image_sha256"`
	PromotionAction          string `json:"promotion_action"`
	RolloutEnabled           bool   `json:"rollout_enabled"`
	RolloutBasisPoints       int    `json:"rollout_basis_points"`
	RetryAfterSeconds        int    `json:"retry_after_seconds"`
	CreatedAt                int64  `json:"created_at"`
	ExpiresAt                int64  `json:"expires_at"`
	ApprovalKeyringSHA256    string `json:"approval_keyring_sha256"`
}

type rolloutApproval struct {
	Schema             int    `json:"schema"`
	RequestSHA256      string `json:"request_sha256"`
	ApproverID         string `json:"approver_id"`
	ApprovalKeyID      string `json:"approval_key_id"`
	Decision           string `json:"decision"`
	SignedAt           int64  `json:"signed_at"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	SignatureB64URL    string `json:"signature_b64url"`
}

type approverEntry struct {
	ApproverID    string `json:"approver_id"`
	ApprovalKeyID string `json:"approval_key_id"`
	PublicKeyFile string `json:"public_key_file"`
	Enabled       bool   `json:"enabled"`
}

type approverKeyringDocument struct {
	Version   int             `json:"version"`
	Approvers []approverEntry `json:"approvers"`
}

type trustedApprover struct {
	approverID string
	keyID      string
	key        ed25519.PublicKey
	enabled    bool
}

type trustedApproverKeyring struct {
	byKeyID map[string]trustedApprover
	digest  string
}

type parentRolloutState struct {
	generationID       string
	generationSequence uint32
	releaseID          string
	releaseSequence    uint32
	imageSHA256        string
	rolloutEnabled     bool
	rolloutBasisPoints int
	retryAfterSeconds  int
}

func ValidateRollout(root, parentRoot, expectedAuthority,
	approverKeyringPath string) (RolloutReceipt, error) {
	if root == "" || parentRoot == "" || approverKeyringPath == "" ||
		!firmwareorigin.ValidAuthority(expectedAuthority) {
		return RolloutReceipt{}, fmt.Errorf("rollout bundle inputs are invalid")
	}
	if err := requireReadOnlyDirectory(root); err != nil {
		return RolloutReceipt{}, err
	}
	parentState, parentReceiptBytes, err := loadParentState(
		parentRoot, expectedAuthority)
	if err != nil {
		return RolloutReceipt{}, fmt.Errorf("validate parent bundle: %w", err)
	}
	receiptPath := filepath.Join(root, "deployment-receipt.json")
	receiptBytes, err := readBoundedFile(receiptPath, maximumReceiptBytes)
	if err != nil {
		return RolloutReceipt{}, fmt.Errorf("read rollout receipt: %w", err)
	}
	var receipt RolloutReceipt
	if err := decodeExactObject(receiptBytes, rolloutReceiptFields, &receipt); err != nil {
		return RolloutReceipt{}, fmt.Errorf("decode rollout receipt: %w", err)
	}
	if err := validateRolloutReceiptShape(receipt, expectedAuthority); err != nil {
		return RolloutReceipt{}, err
	}
	receiptDigest := sha256.Sum256(receiptBytes)
	ready, err := readBoundedFile(filepath.Join(root, "READY"), 128)
	if err != nil || string(ready) != hex.EncodeToString(receiptDigest[:])+"\n" {
		return RolloutReceipt{}, fmt.Errorf("rollout READY marker is invalid")
	}

	requestPath := filepath.Join(root, "promotion", "rollout-request.json")
	requestBytes, err := readBoundedFile(requestPath, maximumReceiptBytes)
	if err != nil {
		return RolloutReceipt{}, fmt.Errorf("read rollout request: %w", err)
	}
	var request rolloutRequest
	if err := decodeExactObject(requestBytes, rolloutRequestFields, &request); err != nil {
		return RolloutReceipt{}, fmt.Errorf("decode rollout request: %w", err)
	}
	if err := validateRolloutRequest(request); err != nil {
		return RolloutReceipt{}, err
	}
	keyring, err := loadApproverKeyring(approverKeyringPath)
	if err != nil {
		return RolloutReceipt{}, fmt.Errorf("load rollout approver keyring: %w", err)
	}
	if request.ApprovalKeyringSHA256 != keyring.digest ||
		receipt.ApprovalKeyringSHA256 != keyring.digest {
		return RolloutReceipt{}, fmt.Errorf("rollout does not bind trusted approver keyring")
	}
	requestDigest := sha256.Sum256(requestBytes)
	requestHash := hex.EncodeToString(requestDigest[:])
	if receipt.RolloutRequestSHA256 != requestHash {
		return RolloutReceipt{}, fmt.Errorf("rollout receipt request digest is invalid")
	}
	approvals := make([]rolloutApproval, 0, 2)
	approvalBytes := make([][]byte, 0, 2)
	seenApprovers := make(map[string]struct{}, 2)
	seenKeys := make(map[string]struct{}, 2)
	for index := 1; index <= 2; index++ {
		payload, err := readBoundedFile(filepath.Join(root, "promotion",
			"approval-"+strconv.Itoa(index)+".json"), maximumReceiptBytes)
		if err != nil {
			return RolloutReceipt{}, fmt.Errorf("read rollout approval: %w", err)
		}
		var approval rolloutApproval
		if err := decodeExactObject(payload, rolloutApprovalFields, &approval); err != nil {
			return RolloutReceipt{}, fmt.Errorf("decode rollout approval: %w", err)
		}
		if err := verifyRolloutApproval(approval, request, requestHash, keyring,
			seenApprovers, seenKeys); err != nil {
			return RolloutReceipt{}, err
		}
		approvals = append(approvals, approval)
		approvalBytes = append(approvalBytes, payload)
	}
	if approvals[0].ApproverID >= approvals[1].ApproverID {
		return RolloutReceipt{}, fmt.Errorf("rollout approvals are not uniquely sorted")
	}
	if receipt.PromotedAt < approvals[0].SignedAt ||
		receipt.PromotedAt < approvals[1].SignedAt ||
		receipt.PromotedAt < request.CreatedAt || receipt.PromotedAt > request.ExpiresAt {
		return RolloutReceipt{}, fmt.Errorf("rollout promoted_at is outside approval window")
	}
	if err := compareRequestParent(request, parentState, parentReceiptBytes); err != nil {
		return RolloutReceipt{}, err
	}
	if err := compareRequestReceipt(request, receipt); err != nil {
		return RolloutReceipt{}, err
	}
	if len(receipt.ApprovalEvidence) != 2 {
		return RolloutReceipt{}, fmt.Errorf("rollout receipt approval count is invalid")
	}
	for index := range receipt.ApprovalEvidence {
		evidence := receipt.ApprovalEvidence[index]
		approval := approvals[index]
		digest := sha256.Sum256(approvalBytes[index])
		if evidence.ApproverID != approval.ApproverID ||
			evidence.ApprovalKeyID != approval.ApprovalKeyID ||
			evidence.ApprovalSHA256 != hex.EncodeToString(digest[:]) {
			return RolloutReceipt{}, fmt.Errorf("rollout approval evidence is invalid")
		}
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
			return RolloutReceipt{}, fmt.Errorf("rollout %s digest is invalid", name)
		}
	}
	registry, err := productota.LoadRegistry(registryPath)
	if err != nil {
		return RolloutReceipt{}, fmt.Errorf("load rollout control registry: %w", err)
	}
	release, found := registry.Lookup(receipt.ReleaseID)
	if !found || release.Project != receipt.Project || release.Board != receipt.Board ||
		release.Channel != receipt.Channel || release.Version != receipt.Version ||
		release.ReleaseSequence != receipt.ReleaseSequence ||
		release.SecureVersion != receipt.SecureVersion ||
		release.SigningKeyID != receipt.SigningKeyID ||
		release.ImageURL != "https://"+expectedAuthority+receipt.ImageURLPath ||
		release.ImageSize != receipt.ImageSize || release.ImageSHA256 != receipt.ImageSHA256 ||
		release.Enabled != receipt.RolloutEnabled ||
		release.RolloutBasisPoints != receipt.RolloutBasisPoints ||
		release.RetryAfterSeconds != uint32(receipt.RetryAfterSeconds) {
		return RolloutReceipt{}, fmt.Errorf("rollout control release does not match receipt")
	}
	if request.CreatedAt < release.NotBefore || request.ExpiresAt > release.ExpiresAt {
		return RolloutReceipt{}, fmt.Errorf(
			"rollout approval window is outside manifest validity")
	}
	manifestDigest := sha256.Sum256(release.Manifest)
	if hex.EncodeToString(manifestDigest[:]) != receipt.ManifestSHA256 {
		return RolloutReceipt{}, fmt.Errorf("rollout manifest does not match receipt")
	}
	catalog, err := firmwareorigin.LoadCatalog(catalogPath)
	if err != nil {
		return RolloutReceipt{}, fmt.Errorf("load rollout origin catalog: %w", err)
	}
	object, found := catalog.Lookup(receipt.ImageURLPath)
	if !found || object.ReleaseID != receipt.ReleaseID ||
		object.ImageSHA256 != receipt.ImageSHA256 || object.ImageSize != receipt.ImageSize {
		return RolloutReceipt{}, fmt.Errorf("rollout origin object does not match receipt")
	}
	if err := catalog.Ready(); err != nil {
		return RolloutReceipt{}, fmt.Errorf("rollout origin is not ready: %w", err)
	}
	if err := validateRolloutReadOnlyTree(root, receipt.ImageURLPath); err != nil {
		return RolloutReceipt{}, err
	}
	return receipt, nil
}

func ValidateRolloutChain(root string, parentRoots, approverKeyringPaths []string,
	expectedAuthority string) (RolloutReceipt, error) {
	if root == "" || len(parentRoots) == 0 || len(approverKeyringPaths) == 0 {
		return RolloutReceipt{}, fmt.Errorf("rollout lineage inputs are incomplete")
	}
	keyrings := make(map[string]string, len(approverKeyringPaths))
	for _, name := range approverKeyringPaths {
		keyring, err := loadApproverKeyring(name)
		if err != nil {
			return RolloutReceipt{}, fmt.Errorf("load rollout lineage keyring: %w", err)
		}
		if prior, exists := keyrings[keyring.digest]; exists && prior != name {
			return RolloutReceipt{}, fmt.Errorf("rollout lineage keyring digest is duplicated")
		}
		keyrings[keyring.digest] = name
	}
	current := root
	var first RolloutReceipt
	seenGenerations := make(map[string]struct{}, len(parentRoots))
	for index, parent := range parentRoots {
		payload, err := readBoundedFile(
			filepath.Join(current, "deployment-receipt.json"), maximumReceiptBytes)
		if err != nil {
			return RolloutReceipt{}, fmt.Errorf("read rollout lineage receipt: %w", err)
		}
		var receipt RolloutReceipt
		if err := decodeExactObject(payload, rolloutReceiptFields, &receipt); err != nil ||
			receipt.Schema != 2 {
			return RolloutReceipt{}, fmt.Errorf("rollout lineage contains an extra parent")
		}
		if _, exists := seenGenerations[receipt.GenerationID]; exists {
			return RolloutReceipt{}, fmt.Errorf("rollout lineage generation ID is duplicated")
		}
		seenGenerations[receipt.GenerationID] = struct{}{}
		keyringPath := keyrings[receipt.ApprovalKeyringSHA256]
		if keyringPath == "" {
			return RolloutReceipt{}, fmt.Errorf("rollout lineage keyring snapshot is missing")
		}
		validated, err := ValidateRollout(
			current, parent, expectedAuthority, keyringPath)
		if err != nil {
			return RolloutReceipt{}, fmt.Errorf("validate rollout lineage generation: %w", err)
		}
		if index == 0 {
			first = validated
		}
		current = parent
	}
	if _, err := Validate(current, expectedAuthority); err != nil {
		return RolloutReceipt{}, fmt.Errorf(
			"rollout lineage does not terminate at valid staging: %w", err)
	}
	return first, nil
}

func fieldSet(names ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(names))
	for _, name := range names {
		result[name] = struct{}{}
	}
	return result
}

func decodeExactObject(payload []byte, fields map[string]struct{}, output any) error {
	if err := rejectDuplicateJSONNames(payload); err != nil {
		return err
	}
	if err := requireExactJSONFields(payload, fields); err != nil {
		return err
	}
	return decodeStrict(payload, output)
}

func validateRolloutReceiptShape(receipt RolloutReceipt, authority string) error {
	if receipt.Schema != 2 || !auth.ValidIdentifier(receipt.GenerationID, 64) ||
		!auth.ValidIdentifier(receipt.ParentGenerationID, 64) ||
		receipt.GenerationSequence == 0 ||
		receipt.GenerationSequence != receipt.ParentGenerationSequence+1 ||
		receipt.GenerationID == receipt.ParentGenerationID ||
		!validSHA256(receipt.ParentReceiptSHA256) ||
		!validPromotionAction(receipt.PromotionAction) ||
		!validSHA256(receipt.ApprovalKeyringSHA256) ||
		!validSHA256(receipt.RolloutRequestSHA256) ||
		receipt.PromotedAt < 1609459200 || receipt.PromotedAt > 4102444800 ||
		!auth.ValidIdentifier(receipt.ReleaseID, 64) ||
		!auth.ValidIdentifier(receipt.SigningKeyID, 64) ||
		!auth.ValidIdentifier(receipt.Project, 32) ||
		!auth.ValidIdentifier(receipt.Board, 32) ||
		!auth.ValidIdentifier(receipt.Channel, 32) || receipt.Version == "" ||
		receipt.ReleaseSequence == 0 || receipt.ImageAuthority != authority ||
		!validURLPath(receipt.ImageURLPath) || receipt.ImageSize < 1024 ||
		!validSHA256(receipt.ImageSHA256) || !validSHA256(receipt.ManifestSHA256) ||
		!validSHA256(receipt.PublicKeySHA256) || !validSHA256(receipt.SDKConfigSHA256) ||
		!validSHA256(receipt.ControlRegistrySHA256) ||
		!validSHA256(receipt.OriginCatalogSHA256) ||
		receipt.RolloutEnabled != (receipt.RolloutBasisPoints > 0) ||
		receipt.RolloutBasisPoints < 0 || receipt.RolloutBasisPoints > 10000 ||
		receipt.RetryAfterSeconds < 60 || receipt.RetryAfterSeconds > 86400 ||
		len(receipt.ApprovalEvidence) != 2 {
		return fmt.Errorf("rollout receipt fields are invalid")
	}
	prior := ""
	for _, evidence := range receipt.ApprovalEvidence {
		if !auth.ValidIdentifier(evidence.ApproverID, 64) ||
			!auth.ValidIdentifier(evidence.ApprovalKeyID, 64) ||
			!validSHA256(evidence.ApprovalSHA256) || evidence.ApproverID <= prior {
			return fmt.Errorf("rollout approval evidence fields are invalid")
		}
		prior = evidence.ApproverID
	}
	return nil
}

func validateRolloutRequest(request rolloutRequest) error {
	if request.Schema != 1 || !auth.ValidIdentifier(request.GenerationID, 64) ||
		!auth.ValidIdentifier(request.ParentGenerationID, 64) ||
		request.GenerationSequence == 0 ||
		request.GenerationSequence != request.ParentGenerationSequence+1 ||
		request.GenerationID == request.ParentGenerationID ||
		!validSHA256(request.ParentReceiptSHA256) ||
		request.ParentRolloutEnabled != (request.ParentRolloutBasisPoints > 0) ||
		request.ParentRolloutBasisPoints < 0 || request.ParentRolloutBasisPoints > 10000 ||
		!auth.ValidIdentifier(request.ReleaseID, 64) || request.ReleaseSequence == 0 ||
		!validSHA256(request.ImageSHA256) || !validPromotionAction(request.PromotionAction) ||
		request.RolloutEnabled != (request.RolloutBasisPoints > 0) ||
		request.RolloutBasisPoints < 0 || request.RolloutBasisPoints > 10000 ||
		request.RetryAfterSeconds < 60 || request.RetryAfterSeconds > 86400 ||
		request.CreatedAt < 1609459200 || request.ExpiresAt > 4102444800 ||
		request.ExpiresAt <= request.CreatedAt ||
		request.ExpiresAt-request.CreatedAt > maximumApprovalWindow ||
		!validSHA256(request.ApprovalKeyringSHA256) {
		return fmt.Errorf("rollout request fields are invalid")
	}
	switch request.PromotionAction {
	case "EXPAND":
		if !request.RolloutEnabled ||
			request.RolloutBasisPoints <= request.ParentRolloutBasisPoints ||
			(!request.ParentRolloutEnabled && request.ParentGenerationSequence != 0) {
			return fmt.Errorf("rollout EXPAND transition is invalid")
		}
	case "EMERGENCY_STOP":
		if !request.ParentRolloutEnabled || request.RolloutEnabled ||
			request.RolloutBasisPoints != 0 {
			return fmt.Errorf("rollout EMERGENCY_STOP transition is invalid")
		}
	case "RESUME":
		if request.ParentRolloutEnabled || request.ParentGenerationSequence == 0 ||
			!request.RolloutEnabled {
			return fmt.Errorf("rollout RESUME transition is invalid")
		}
	}
	return nil
}

func validPromotionAction(value string) bool {
	return value == "EXPAND" || value == "EMERGENCY_STOP" || value == "RESUME"
}

func loadApproverKeyring(name string) (trustedApproverKeyring, error) {
	payload, err := readBoundedFile(name, maximumConfigBytes)
	if err != nil {
		return trustedApproverKeyring{}, err
	}
	var document approverKeyringDocument
	if err := decodeExactObject(payload, approverKeyringFields, &document); err != nil {
		return trustedApproverKeyring{}, err
	}
	if document.Version != 1 || len(document.Approvers) < 2 || len(document.Approvers) > 32 {
		return trustedApproverKeyring{}, fmt.Errorf("approver keyring version/count is invalid")
	}
	root, err := filepath.Abs(filepath.Dir(name))
	if err != nil {
		return trustedApproverKeyring{}, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return trustedApproverKeyring{}, err
	}
	result := trustedApproverKeyring{byKeyID: make(map[string]trustedApprover)}
	seenApprovers := make(map[string]struct{})
	seenPublicKeys := make(map[string]struct{})
	for index, entry := range document.Approvers {
		raw := nestedArrayObject(payload, "approvers", index)
		if raw == nil || !hasExactRawFields(raw, approverEntryFields) ||
			!auth.ValidIdentifier(entry.ApproverID, 64) ||
			!auth.ValidIdentifier(entry.ApprovalKeyID, 64) || entry.PublicKeyFile == "" {
			return trustedApproverKeyring{}, fmt.Errorf("approver keyring entry is invalid")
		}
		if _, exists := seenApprovers[entry.ApproverID]; exists {
			return trustedApproverKeyring{}, fmt.Errorf("approver ID is duplicated")
		}
		if _, exists := result.byKeyID[entry.ApprovalKeyID]; exists {
			return trustedApproverKeyring{}, fmt.Errorf("approval key ID is duplicated")
		}
		keyPath, err := resolveContainedRolloutFile(root, entry.PublicKeyFile)
		if err != nil {
			return trustedApproverKeyring{}, err
		}
		keyPayload, err := readBoundedFile(keyPath, 4096)
		if err != nil {
			return trustedApproverKeyring{}, err
		}
		block, rest := pem.Decode(keyPayload)
		if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
			return trustedApproverKeyring{}, fmt.Errorf("approval key must be one PKIX PEM block")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		key, ok := parsed.(ed25519.PublicKey)
		if err != nil || !ok || len(key) != ed25519.PublicKeySize {
			return trustedApproverKeyring{}, fmt.Errorf("approval key must be Ed25519")
		}
		keyFingerprint := string(key)
		if _, exists := seenPublicKeys[keyFingerprint]; exists {
			return trustedApproverKeyring{}, fmt.Errorf("approval public keys are duplicated")
		}
		seenApprovers[entry.ApproverID] = struct{}{}
		seenPublicKeys[keyFingerprint] = struct{}{}
		result.byKeyID[entry.ApprovalKeyID] = trustedApprover{
			approverID: entry.ApproverID, keyID: entry.ApprovalKeyID,
			key: append(ed25519.PublicKey(nil), key...), enabled: entry.Enabled,
		}
	}
	digest := sha256.Sum256(payload)
	result.digest = hex.EncodeToString(digest[:])
	return result, nil
}

func verifyRolloutApproval(approval rolloutApproval, request rolloutRequest,
	requestHash string, keyring trustedApproverKeyring,
	seenApprovers, seenKeys map[string]struct{}) error {
	if approval.Schema != 1 || approval.RequestSHA256 != requestHash ||
		!auth.ValidIdentifier(approval.ApproverID, 64) ||
		!auth.ValidIdentifier(approval.ApprovalKeyID, 64) ||
		approval.Decision != "APPROVE" || approval.SignatureAlgorithm != "Ed25519" ||
		approval.SignedAt < request.CreatedAt || approval.SignedAt > request.ExpiresAt {
		return fmt.Errorf("rollout approval fields are invalid")
	}
	trusted, exists := keyring.byKeyID[approval.ApprovalKeyID]
	if !exists || !trusted.enabled || trusted.approverID != approval.ApproverID {
		return fmt.Errorf("rollout approval signer is not trusted and enabled")
	}
	if _, exists := seenApprovers[approval.ApproverID]; exists {
		return fmt.Errorf("rollout approvers must be distinct")
	}
	if _, exists := seenKeys[approval.ApprovalKeyID]; exists {
		return fmt.Errorf("rollout approval keys must be distinct")
	}
	signature, err := base64.RawURLEncoding.DecodeString(approval.SignatureB64URL)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != approval.SignatureB64URL ||
		!ed25519.Verify(trusted.key, rolloutApprovalPayload(approval), signature) {
		return fmt.Errorf("rollout approval signature is invalid")
	}
	seenApprovers[approval.ApproverID] = struct{}{}
	seenKeys[approval.ApprovalKeyID] = struct{}{}
	return nil
}

func rolloutApprovalPayload(approval rolloutApproval) []byte {
	return []byte("xiaozhi-ota-rollout-approval-v1\n" +
		"approval_key_id=" + approval.ApprovalKeyID + "\n" +
		"approver_id=" + approval.ApproverID + "\n" +
		"decision=" + approval.Decision + "\n" +
		"request_sha256=" + approval.RequestSHA256 + "\n" +
		"schema=" + strconv.Itoa(approval.Schema) + "\n" +
		"signature_algorithm=" + approval.SignatureAlgorithm + "\n" +
		"signed_at=" + strconv.FormatInt(approval.SignedAt, 10) + "\n")
}

func loadParentState(root, authority string) (parentRolloutState, []byte, error) {
	payload, err := readBoundedFile(filepath.Join(root, "deployment-receipt.json"),
		maximumReceiptBytes)
	if err != nil {
		return parentRolloutState{}, nil, err
	}
	var discriminator struct {
		Schema int `json:"schema"`
	}
	if err := json.Unmarshal(payload, &discriminator); err != nil {
		return parentRolloutState{}, nil, err
	}
	if discriminator.Schema == 1 {
		receipt, err := Validate(root, authority)
		if err != nil {
			return parentRolloutState{}, nil, err
		}
		return parentRolloutState{
			generationID: "staging", releaseID: receipt.ReleaseID,
			releaseSequence: receipt.ReleaseSequence, imageSHA256: receipt.ImageSHA256,
			rolloutEnabled:     receipt.RolloutEnabled,
			rolloutBasisPoints: receipt.RolloutBasisPoints,
			retryAfterSeconds:  receipt.RetryAfterSeconds,
		}, payload, nil
	}
	if discriminator.Schema != 2 {
		return parentRolloutState{}, nil, fmt.Errorf("parent receipt schema is unsupported")
	}
	var receipt RolloutReceipt
	if err := decodeExactObject(payload, rolloutReceiptFields, &receipt); err != nil {
		return parentRolloutState{}, nil, err
	}
	if err := validateRolloutReceiptShape(receipt, authority); err != nil {
		return parentRolloutState{}, nil, err
	}
	digest := sha256.Sum256(payload)
	ready, err := readBoundedFile(filepath.Join(root, "READY"), 128)
	if err != nil || string(ready) != hex.EncodeToString(digest[:])+"\n" {
		return parentRolloutState{}, nil, fmt.Errorf("parent rollout READY marker is invalid")
	}
	return parentRolloutState{
		generationID:       receipt.GenerationID,
		generationSequence: receipt.GenerationSequence,
		releaseID:          receipt.ReleaseID, releaseSequence: receipt.ReleaseSequence,
		imageSHA256: receipt.ImageSHA256, rolloutEnabled: receipt.RolloutEnabled,
		rolloutBasisPoints: receipt.RolloutBasisPoints,
		retryAfterSeconds:  receipt.RetryAfterSeconds,
	}, payload, nil
}

func compareRequestParent(request rolloutRequest, parent parentRolloutState,
	parentReceipt []byte) error {
	digest := sha256.Sum256(parentReceipt)
	if request.ParentGenerationID != parent.generationID ||
		request.ParentGenerationSequence != parent.generationSequence ||
		request.GenerationSequence != parent.generationSequence+1 ||
		request.ParentReceiptSHA256 != hex.EncodeToString(digest[:]) ||
		request.ParentRolloutEnabled != parent.rolloutEnabled ||
		request.ParentRolloutBasisPoints != parent.rolloutBasisPoints ||
		request.ReleaseID != parent.releaseID ||
		request.ReleaseSequence != parent.releaseSequence ||
		request.ImageSHA256 != parent.imageSHA256 ||
		request.RetryAfterSeconds != parent.retryAfterSeconds {
		return fmt.Errorf("rollout request does not match parent bundle")
	}
	return nil
}

func compareRequestReceipt(request rolloutRequest, receipt RolloutReceipt) error {
	if receipt.GenerationID != request.GenerationID ||
		receipt.GenerationSequence != request.GenerationSequence ||
		receipt.ParentGenerationID != request.ParentGenerationID ||
		receipt.ParentGenerationSequence != request.ParentGenerationSequence ||
		receipt.ParentReceiptSHA256 != request.ParentReceiptSHA256 ||
		receipt.PromotionAction != request.PromotionAction ||
		receipt.ApprovalKeyringSHA256 != request.ApprovalKeyringSHA256 ||
		receipt.ReleaseID != request.ReleaseID ||
		receipt.ReleaseSequence != request.ReleaseSequence ||
		receipt.ImageSHA256 != request.ImageSHA256 ||
		receipt.RolloutEnabled != request.RolloutEnabled ||
		receipt.RolloutBasisPoints != request.RolloutBasisPoints ||
		receipt.RetryAfterSeconds != request.RetryAfterSeconds {
		return fmt.Errorf("rollout receipt does not match approved request")
	}
	return nil
}

func resolveContainedRolloutFile(root, name string) (string, error) {
	if filepath.IsAbs(name) || strings.Contains(name, "\\") || name == "" || len(name) > 4096 {
		return "", fmt.Errorf("approval key path must be bounded and relative")
	}
	clean := filepath.Clean(name)
	if clean == "." || clean == ".." || clean != name ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("approval key path escapes keyring root")
	}
	joined := filepath.Join(root, clean)
	info, err := os.Lstat(joined)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("approval key path must be a regular non-symlink file")
	}
	resolved, err := filepath.EvalSymlinks(joined)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(root, resolved)
	if err != nil || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("approval key symlink escapes keyring root")
	}
	return resolved, nil
}

func requireReadOnlyDirectory(root string) error {
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("rollout bundle root is unavailable")
	}
	return nil
}

func validateRolloutReadOnlyTree(root, urlPath string) error {
	imageRelative := filepath.ToSlash(filepath.Join(
		"origin", "objects", filepath.FromSlash(strings.TrimPrefix(urlPath, "/"))))
	expectedFiles := fieldSet(
		"READY", "deployment-receipt.json", "control/release-public.pem",
		"control/release-manifest.json", "control/ota-release-registry.json",
		"origin/firmware-origin-catalog.json", "evidence/sdkconfig",
		"promotion/rollout-request.json", "promotion/approval-1.json",
		"promotion/approval-2.json", imageRelative)
	expectedDirectories := make(map[string]struct{})
	for name := range expectedFiles {
		for parent := filepath.ToSlash(filepath.Dir(name)); parent != "."; parent = filepath.ToSlash(filepath.Dir(parent)) {
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
			return fmt.Errorf("rollout bundle tree is not immutable")
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
				return fmt.Errorf("rollout bundle has an unexpected directory")
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("rollout bundle contains a non-regular object")
		}
		if _, exists := expectedFiles[relative]; !exists {
			return fmt.Errorf("rollout bundle has an unexpected file")
		}
		delete(expectedFiles, relative)
		return nil
	})
	if err != nil {
		return err
	}
	if len(expectedFiles) != 0 {
		return fmt.Errorf("rollout bundle file layout is incomplete")
	}
	return nil
}

func nestedArrayObject(payload []byte, name string, index int) map[string]json.RawMessage {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(payload, &root); err != nil {
		return nil
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(root[name], &entries); err != nil || index >= len(entries) {
		return nil
	}
	return entries[index]
}

func hasExactRawFields(document map[string]json.RawMessage,
	expected map[string]struct{}) bool {
	if len(document) != len(expected) {
		return false
	}
	for name := range expected {
		if _, exists := document[name]; !exists {
			return false
		}
	}
	return true
}
