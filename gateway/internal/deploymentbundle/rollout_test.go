package deploymentbundle

import (
	"encoding/json"
	"strings"
	"testing"
)

func validTestRolloutRequest() rolloutRequest {
	return rolloutRequest{
		Schema: 1, GenerationID: "stable-18-g1", GenerationSequence: 1,
		ParentGenerationID: "staging", ParentGenerationSequence: 0,
		ParentReceiptSHA256: strings.Repeat("a", 64),
		ReleaseID:           "box3-stable-18", ReleaseSequence: 18,
		ImageSHA256: strings.Repeat("b", 64), PromotionAction: "EXPAND",
		RolloutEnabled: true, RolloutBasisPoints: 100, RetryAfterSeconds: 900,
		CreatedAt: 1_786_276_800, ExpiresAt: 1_786_280_400,
		ApprovalKeyringSHA256: strings.Repeat("c", 64),
	}
}

func TestRolloutRequestTransitionPolicy(t *testing.T) {
	request := validTestRolloutRequest()
	if err := validateRolloutRequest(request); err != nil {
		t.Fatalf("valid initial expansion rejected: %v", err)
	}
	cases := map[string]func(*rolloutRequest){
		"same-generation": func(value *rolloutRequest) {
			value.GenerationID = value.ParentGenerationID
		},
		"sequence-gap": func(value *rolloutRequest) {
			value.GenerationSequence = 2
		},
		"zero-expand": func(value *rolloutRequest) {
			value.RolloutBasisPoints = 0
		},
		"nonmonotonic": func(value *rolloutRequest) {
			value.ParentRolloutEnabled = true
			value.ParentRolloutBasisPoints = 100
			value.RolloutBasisPoints = 50
		},
		"stop-inactive": func(value *rolloutRequest) {
			value.PromotionAction = "EMERGENCY_STOP"
			value.RolloutEnabled = false
			value.RolloutBasisPoints = 0
		},
		"resume-staging": func(value *rolloutRequest) {
			value.PromotionAction = "RESUME"
		},
		"long-window": func(value *rolloutRequest) {
			value.ExpiresAt = value.CreatedAt + maximumApprovalWindow + 1
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			altered := request
			mutate(&altered)
			if err := validateRolloutRequest(altered); err == nil {
				t.Fatal("unsafe rollout transition was accepted")
			}
		})
	}
}

func TestRolloutReceiptRequiresEveryField(t *testing.T) {
	document := make(map[string]any, len(rolloutReceiptFields))
	for name := range rolloutReceiptFields {
		document[name] = nil
	}
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireExactJSONFields(payload, rolloutReceiptFields); err != nil {
		t.Fatalf("exact rollout receipt field set rejected: %v", err)
	}
	delete(document, "rollout_enabled")
	payload, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireExactJSONFields(payload, rolloutReceiptFields); err == nil {
		t.Fatal("missing false-valued rollout field was accepted")
	}
}

func TestRolloutApprovalPayloadDomainIsExact(t *testing.T) {
	approval := rolloutApproval{
		Schema: 1, RequestSHA256: strings.Repeat("a", 64),
		ApproverID: "operator-1", ApprovalKeyID: "rollout-key-1",
		Decision: "APPROVE", SignedAt: 1_786_276_810,
		SignatureAlgorithm: "Ed25519",
	}
	expected := "xiaozhi-ota-rollout-approval-v1\n" +
		"approval_key_id=rollout-key-1\n" +
		"approver_id=operator-1\n" +
		"decision=APPROVE\n" +
		"request_sha256=" + strings.Repeat("a", 64) + "\n" +
		"schema=1\n" +
		"signature_algorithm=Ed25519\n" +
		"signed_at=1786276810\n"
	if string(rolloutApprovalPayload(approval)) != expected {
		t.Fatal("approval signature domain changed")
	}
}
