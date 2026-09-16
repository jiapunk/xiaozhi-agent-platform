package deploymentbundle

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReceiptRequiresExactFieldSet(t *testing.T) {
	document := make(map[string]any, len(receiptFields))
	for name := range receiptFields {
		document[name] = nil
	}
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireExactJSONFields(payload, receiptFields); err != nil {
		t.Fatalf("exact field set rejected: %v", err)
	}
	delete(document, "secure_version")
	payload, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireExactJSONFields(payload, receiptFields); err == nil {
		t.Fatal("missing zero-valued field was accepted")
	}
	document["secure_version"] = nil
	document["unknown"] = nil
	payload, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireExactJSONFields(payload, receiptFields); err == nil {
		t.Fatal("unknown field was accepted")
	}
}

func TestReceiptPolicyIsFailClosedAndPathSafe(t *testing.T) {
	digest := strings.Repeat("a", 64)
	receipt := Receipt{
		Schema: 1, ReleaseID: "release-17", SigningKeyID: "release-key-2026",
		Project: "xiaozhi_agent_platform", Board: "esp32s3-box3",
		Channel: "stable", Version: "0.17.0", ReleaseSequence: 17,
		ImageAuthority: "updates.example.com",
		ImageURLPath:   "/firmware/box3/17/image.bin",
		ImageSize:      4096, ImageSHA256: digest, ManifestSHA256: digest,
		PublicKeySHA256: digest, SDKConfigSHA256: digest,
		ControlRegistrySHA256: digest, OriginCatalogSHA256: digest,
		RetryAfterSeconds: 900,
	}
	if err := validateReceipt(receipt, "updates.example.com"); err != nil {
		t.Fatalf("valid fail-closed receipt rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Receipt){
		"enabled": func(value *Receipt) { value.RolloutEnabled = true },
		"cohort":  func(value *Receipt) { value.RolloutBasisPoints = 1 },
		"encoded": func(value *Receipt) { value.ImageURLPath = "/firmware/%2e.bin" },
		"escape":  func(value *Receipt) { value.ImageURLPath = "/firmware/../x.bin" },
		"authority": func(value *Receipt) {
			value.ImageAuthority = "other.example.com"
		},
	} {
		t.Run(name, func(t *testing.T) {
			altered := receipt
			mutate(&altered)
			if err := validateReceipt(altered, "updates.example.com"); err == nil {
				t.Fatal("unsafe receipt was accepted")
			}
		})
	}
}

func TestReceiptDuplicateJSONNameIsRejected(t *testing.T) {
	if err := rejectDuplicateJSONNames([]byte(`{"schema":1,"schema":1}`)); err == nil {
		t.Fatal("duplicate receipt field was accepted")
	}
}
