package usagebudget

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testPricing() Pricing {
	return Pricing{
		ProfileID:                     "provider-contract-1",
		InputMicrousdPerMillionToken:  1_000_000,
		OutputMicrousdPerMillionToken: 1_000_000,
		DailyBudgetMicrousd:           30,
		InputTokenOverhead:            8,
		ReservationTTL:                time.Minute,
	}
}

func TestMemoryLedgerReservesSettlesAndEnforcesAggregateBudget(t *testing.T) {
	ledger, err := NewMemoryLedger(testPricing(), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	first, err := ledger.Reserve(ctx, "owned-scope-a", 10, 10)
	if err != nil || first.ReservedMicrousd != 20 {
		t.Fatalf("reserve: %#v err=%v", first, err)
	}
	settled, err := ledger.Settle(ctx, first,
		Usage{InputTokens: 5, OutputTokens: 2, TotalTokens: 7})
	if err != nil || settled.CostMicrousd != 7 {
		t.Fatalf("settle: %#v err=%v", settled, err)
	}
	second, err := ledger.Reserve(ctx, "owned-scope-a", 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Reserve(ctx, "owned-scope-a", 2, 2); !errors.Is(err,
		ErrBudgetExceeded) {
		t.Fatalf("aggregate budget accepted: %v", err)
	}
	if _, err := ledger.MarkUncertain(ctx, second); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Reserve(ctx, "owned-scope-b", 10, 10); err != nil {
		t.Fatalf("isolated subject rejected: %v", err)
	}
}

func TestMemoryLedgerRejectsUsageBeyondReservationAndExpiresConservatively(t *testing.T) {
	ledger, err := NewMemoryLedger(testPricing(), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	ledger.now = func() time.Time { return now }
	reservation, err := ledger.Reserve(context.Background(), "owned-scope", 5, 5)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Settle(context.Background(), reservation,
		Usage{InputTokens: 6, OutputTokens: 1, TotalTokens: 7}); !errors.Is(err, ErrUsageExceeded) {
		t.Fatalf("oversized usage: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := ledger.Reserve(context.Background(), "owned-scope", 11, 10); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("expired reservation was refunded: %v", err)
	}
}

func TestDigestKeyLoaderRejectsSymlinkPermissionsAndNoncanonicalData(t *testing.T) {
	root := t.TempDir()
	valid := filepath.Join(root, "valid.key")
	encoded := base64.RawURLEncoding.EncodeToString(
		[]byte("0123456789abcdef0123456789abcdef"))
	if err := os.WriteFile(valid, []byte(encoded+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if key, err := LoadDigestKey(valid); err != nil || len(key) != 32 {
		t.Fatalf("valid key rejected: length=%d err=%v", len(key), err)
	}
	link := filepath.Join(root, "link.key")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDigestKey(link); err == nil {
		t.Fatal("symlink key accepted")
	}
	if err := os.Chmod(valid, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDigestKey(valid); err == nil {
		t.Fatal("world-readable key accepted")
	}
	noncanonical := filepath.Join(root, "padded.key")
	if err := os.WriteFile(noncanonical, []byte(encoded+"=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDigestKey(noncanonical); err == nil {
		t.Fatal("padded key accepted")
	}
}

func TestPricingAndUsageValidationAreBounded(t *testing.T) {
	pricing := testPricing()
	if pricing.Validate() != nil {
		t.Fatal("valid pricing rejected")
	}
	pricing.ProfileID = "unsafe profile"
	if pricing.Validate() == nil {
		t.Fatal("unsafe profile accepted")
	}
	for _, usage := range []Usage{
		{InputTokens: 0, OutputTokens: 1, TotalTokens: 1},
		{InputTokens: 1, OutputTokens: 0, TotalTokens: 1},
		{InputTokens: 2, OutputTokens: 1, TotalTokens: 2},
		{InputTokens: MaximumTokenBound, OutputTokens: 1,
			TotalTokens: MaximumTokenBound + 1},
	} {
		if usage.Validate() == nil {
			t.Fatalf("invalid usage accepted: %#v", usage)
		}
	}
}
