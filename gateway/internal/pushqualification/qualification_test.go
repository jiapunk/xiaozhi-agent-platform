package pushqualification

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
	"xiaozhi-agent-platform/gateway/internal/pushdelivery"
)

type providerFixture struct {
	valid string
	calls int
}

func (provider *providerFixture) Send(ctx context.Context,
	target string) (pushdelivery.DeliveryResult, error) {
	provider.calls++
	if ctx.Err() != nil {
		return pushdelivery.DeliveryRetry, pushdelivery.ErrUnavailable
	}
	if target == provider.valid {
		return pushdelivery.DeliveryAccepted, nil
	}
	return pushdelivery.DeliveryInvalidInstallation, nil
}

func TestRunnerProbesRotationInvalidationAndCancellationWithoutSecrets(t *testing.T) {
	validTarget := "fcm-staging-token:abcdefghijklmnopqrstuvwxyz0123456789"
	current := &providerFixture{valid: validTarget}
	next := &providerFixture{valid: validTarget}
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	runner := &Runner{random: bytes.NewReader(make([]byte, 32)),
		now: func() time.Time {
			result := now
			now = now.Add(10 * time.Millisecond)
			return result
		}}
	receipt, err := runner.Run(context.Background(), RunConfig{
		QualificationID: "m69-fixture-1", Environment: "staging",
		ConfigSHA256:    stringsOfZeroSHA256,
		ToolSHA256:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		DevelopmentOnly: true,
		Candidates: []Candidate{{Platform: accountauth.PushPlatformFCM,
			ApplicationID: "product-123", CurrentCredentialID: "current-key-123",
			NextCredentialID: "next-key-456", Current: current, Next: next,
			ValidTarget: validTarget}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Result != FixtureResult || !receipt.DevelopmentOnly ||
		!receipt.SecretFree || receipt.ProductionReady ||
		len(receipt.Providers) != 1 || current.calls != 2 || next.calls != 2 {
		t.Fatalf("receipt=%+v current=%d next=%d", receipt,
			current.calls, next.calls)
	}
	provider := receipt.Providers[0]
	if !provider.CurrentAccepted || !provider.NextAccepted ||
		!provider.InvalidTargetClassified || !provider.CanceledRequestRetried {
		t.Fatalf("provider evidence=%+v", provider)
	}
	payload, _ := canonicalReceipt(receipt)
	if bytes.Contains(payload, []byte(validTarget)) ||
		bytes.Contains(payload, []byte("m69-invalid")) {
		t.Fatal("provider target escaped into receipt")
	}
}

func TestRunnerFailsWithoutProducingPartialPass(t *testing.T) {
	validTarget := "fcm-staging-token:abcdefghijklmnopqrstuvwxyz0123456789"
	failed := &providerFixture{valid: "different-target"}
	runner := NewRunner()
	_, err := runner.Run(context.Background(), RunConfig{
		QualificationID: "m69-fixture-2", Environment: "staging",
		ConfigSHA256:    stringsOfZeroSHA256,
		ToolSHA256:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		DevelopmentOnly: true,
		Candidates: []Candidate{{Platform: accountauth.PushPlatformFCM,
			ApplicationID: "product-123", CurrentCredentialID: "current-key-123",
			NextCredentialID: "next-key-456", Current: failed, Next: failed,
			ValidTarget: validTarget}},
	})
	if err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("failed provider err=%v", err)
	}
}
