package speechbudget

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
	return Pricing{ProfileID: "speech-provider-contract-1",
		STTMicrousdPerMillionAudioMS:       1_000_000,
		TTSMicrousdPerMillionCharacters:    1_000_000,
		TTSMicrousdPerMillionOutputAudioMS: 2_000_000,
		DailyBudgetMicrousd:                30_000,
		STTReservationChunkAudioMS:         6_000,
		TTSMaxOutputAudioMS:                10_000,
		ReservationTTL:                     time.Minute}
}

func TestMemoryLedgerAggregatesSpeechDimensionsAndBudget(t *testing.T) {
	ledger, err := NewMemoryLedger(testPricing(),
		[]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	stt, err := ledger.Reserve(ctx, "owned-scope-a", STTUsage(6_000))
	if err != nil || stt.ReservedMicrousd != 6_000 {
		t.Fatalf("STT reserve: %#v err=%v", stt, err)
	}
	settled, err := ledger.Settle(ctx, stt, STTUsage(3_000))
	if err != nil || settled.CostMicrousd != 3_000 {
		t.Fatalf("STT settle: %#v err=%v", settled, err)
	}
	tts, err := ledger.Reserve(ctx, "owned-scope-a", TTSUsage(2_000, 10_000))
	if err != nil || tts.ReservedMicrousd != 22_000 {
		t.Fatalf("TTS reserve: %#v err=%v", tts, err)
	}
	if _, err := ledger.Reserve(ctx, "owned-scope-a", STTUsage(6_000)); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("cross-mode daily budget accepted: %v", err)
	}
	if cost, err := ledger.MarkUncertain(ctx, tts); err != nil || cost != 22_000 {
		t.Fatalf("uncertain TTS: cost=%d err=%v", cost, err)
	}
	if _, err := ledger.Reserve(ctx, "owned-scope-b", STTUsage(6_000)); err != nil {
		t.Fatalf("isolated subject rejected: %v", err)
	}
}

func TestMemoryLedgerRejectsModeMismatchAndExpiresConservatively(t *testing.T) {
	ledger, err := NewMemoryLedger(testPricing(),
		[]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	ledger.now = func() time.Time { return now }
	reservation, err := ledger.Reserve(context.Background(), "owned-scope",
		STTUsage(6_000))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Settle(context.Background(), reservation,
		TTSUsage(1, 0)); !errors.Is(err, ErrUsageExceeded) {
		t.Fatalf("cross-mode settlement accepted: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := ledger.Reserve(context.Background(), "owned-scope",
		TTSUsage(5_000, 10_000)); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("expired reservation was refunded: %v", err)
	}
}

func TestPricingSupportsCharacterAudioOrHybridTTS(t *testing.T) {
	for _, rates := range [][2]int64{{1, 0}, {0, 1}, {1, 1}} {
		pricing := testPricing()
		pricing.TTSMicrousdPerMillionCharacters = rates[0]
		pricing.TTSMicrousdPerMillionOutputAudioMS = rates[1]
		if pricing.Validate() != nil {
			t.Fatalf("valid TTS rates rejected: %v", rates)
		}
	}
	pricing := testPricing()
	pricing.TTSMicrousdPerMillionCharacters = 0
	pricing.TTSMicrousdPerMillionOutputAudioMS = 0
	if pricing.Validate() == nil {
		t.Fatal("unpriced TTS accepted")
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
