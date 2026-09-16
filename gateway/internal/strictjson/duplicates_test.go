package strictjson

import "testing"

func TestRejectDuplicateFieldsAtEveryDepth(t *testing.T) {
	for _, valid := range []string{
		`{"a":1,"nested":{"a":2},"items":[{"a":3}]}`,
		`[true,false,null,"value",1.5]`,
	} {
		if err := RejectDuplicateFields([]byte(valid)); err != nil {
			t.Fatalf("valid JSON rejected: %v", err)
		}
	}
	for _, invalid := range []string{
		`{"a":1,"a":2}`,
		`{"nested":{"a":1,"a":2}}`,
		`[{"a":1,"a":2}]`,
		`{} {}`,
		`{"a":`,
	} {
		if err := RejectDuplicateFields([]byte(invalid)); err == nil {
			t.Fatalf("invalid JSON accepted: %s", invalid)
		}
	}
}
