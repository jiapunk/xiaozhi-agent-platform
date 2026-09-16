package gateway

import (
	"context"
	"errors"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/speechbudget"
)

func speechMeterPricing() speechbudget.Pricing {
	return speechbudget.Pricing{
		ProfileID:                          "speech-provider-contract-1",
		STTMicrousdPerMillionAudioMS:       1_000_000,
		TTSMicrousdPerMillionCharacters:    1_000_000,
		TTSMicrousdPerMillionOutputAudioMS: 1_000_000,
		DailyBudgetMicrousd:                1_000_000,
		STTReservationChunkAudioMS:         1_000,
		TTSMaxOutputAudioMS:                2_000,
		ReservationTTL:                     time.Minute,
	}
}

func testSpeechLedger(t *testing.T,
	pricing speechbudget.Pricing) speechbudget.Ledger {
	t.Helper()
	ledger, err := speechbudget.NewMemoryLedger(pricing,
		[]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	return ledger
}

func TestSTTMeterReservesBeforeSendAndSettlesExactAudio(t *testing.T) {
	pricing := speechMeterPricing()
	metrics := &Metrics{}
	meter := newSTTUsageMeter(testSpeechLedger(t, pricing), pricing,
		"owned-scope", metrics)
	sends := 0
	for range 10 {
		if err := meter.HandleAudio(context.Background(), 100, func() error {
			sends++
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	meter.Close()
	if sends != 10 || metrics.speechSettledReservations.Load() != 1 ||
		metrics.speechSTTAudioMS.Load() != 1_000 ||
		metrics.speechCommittedMicrousd.Load() != 1_000 {
		t.Fatalf("sends=%d settled=%d audio=%d cost=%d", sends,
			metrics.speechSettledReservations.Load(),
			metrics.speechSTTAudioMS.Load(),
			metrics.speechCommittedMicrousd.Load())
	}
}

func TestSTTMeterRejectsBeforeProviderAndMarksWriteFailureUncertain(t *testing.T) {
	pricing := speechMeterPricing()
	pricing.DailyBudgetMicrousd = 999
	metrics := &Metrics{}
	meter := newSTTUsageMeter(testSpeechLedger(t, pricing), pricing,
		"owned-scope", metrics)
	contacted := false
	err := meter.HandleAudio(context.Background(), 100, func() error {
		contacted = true
		return nil
	})
	if !errors.Is(err, speechbudget.ErrBudgetExceeded) || contacted ||
		metrics.speechBudgetRejected.Load() != 1 {
		t.Fatalf("err=%v contacted=%v rejected=%d", err, contacted,
			metrics.speechBudgetRejected.Load())
	}

	pricing.DailyBudgetMicrousd = 10_000
	metrics = &Metrics{}
	meter = newSTTUsageMeter(testSpeechLedger(t, pricing), pricing,
		"owned-scope", metrics)
	providerFailure := errors.New("upstream write ambiguous")
	if err := meter.HandleAudio(context.Background(), 100,
		func() error { return providerFailure }); !errors.Is(err, providerFailure) {
		t.Fatalf("write failure=%v", err)
	}
	if metrics.speechUncertainReservations.Load() != 1 ||
		metrics.speechUncertainMicrousd.Load() != 1_000 {
		t.Fatalf("uncertain=%d cost=%d",
			metrics.speechUncertainReservations.Load(),
			metrics.speechUncertainMicrousd.Load())
	}
}

func TestTTSBudgetSupportsExactSettlementAndConservativeFailure(t *testing.T) {
	pricing := speechMeterPricing()
	server := &Server{config: Config{SpeechPricing: pricing,
		SpeechUsageLedger: testSpeechLedger(t, pricing)}}
	reservation, err := server.reserveTTS(context.Background(),
		"owned-scope", 100)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.settleTTS(context.Background(), reservation, 100, 1_000); err != nil {
		t.Fatal(err)
	}
	if server.metrics.speechTTSCharacters.Load() != 100 ||
		server.metrics.speechTTSOutputAudioMS.Load() != 1_000 ||
		server.metrics.speechCommittedMicrousd.Load() != 1_100 {
		t.Fatalf("characters=%d audio=%d cost=%d",
			server.metrics.speechTTSCharacters.Load(),
			server.metrics.speechTTSOutputAudioMS.Load(),
			server.metrics.speechCommittedMicrousd.Load())
	}
	second, err := server.reserveTTS(context.Background(), "owned-scope", 100)
	if err != nil {
		t.Fatal(err)
	}
	server.uncertainTTS(context.Background(), second)
	if server.metrics.speechUncertainReservations.Load() != 1 ||
		server.metrics.speechUncertainMicrousd.Load() != 2_100 {
		t.Fatalf("uncertain=%d cost=%d",
			server.metrics.speechUncertainReservations.Load(),
			server.metrics.speechUncertainMicrousd.Load())
	}
}
