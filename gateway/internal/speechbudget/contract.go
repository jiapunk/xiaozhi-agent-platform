package speechbudget

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	SchemaVersion         = 1
	SchemaContract        = "xz-speech-usage-budget-v1-20260811"
	MaximumUnitBound      = int64(86_400_000)
	MaximumRate           = int64(1_000_000_000_000)
	MaximumBudget         = int64(1_000_000_000_000_000)
	MinimumSTTChunkMS     = int64(1_000)
	MaximumSTTChunkMS     = int64(60_000)
	MinimumTTSOutputMS    = int64(1_000)
	MaximumTTSOutputMS    = int64(600_000)
	MinimumReservationTTL = 60 * time.Second
)

var (
	ErrInvalid         = errors.New("invalid speech usage budget request")
	ErrUnavailable     = errors.New("speech usage budget unavailable")
	ErrBudgetExceeded  = errors.New("speech daily usage budget exceeded")
	ErrReservationLost = errors.New("speech usage reservation lost")
	ErrUsageExceeded   = errors.New("speech provider usage exceeded reservation")
	profilePattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)
)

type Pricing struct {
	ProfileID                          string
	STTMicrousdPerMillionAudioMS       int64
	TTSMicrousdPerMillionCharacters    int64
	TTSMicrousdPerMillionOutputAudioMS int64
	DailyBudgetMicrousd                int64
	STTReservationChunkAudioMS         int64
	TTSMaxOutputAudioMS                int64
	ReservationTTL                     time.Duration
}

func (pricing Pricing) Validate() error {
	if !profilePattern.MatchString(pricing.ProfileID) ||
		pricing.STTMicrousdPerMillionAudioMS < 1 ||
		pricing.STTMicrousdPerMillionAudioMS > MaximumRate ||
		pricing.TTSMicrousdPerMillionCharacters < 0 ||
		pricing.TTSMicrousdPerMillionCharacters > MaximumRate ||
		pricing.TTSMicrousdPerMillionOutputAudioMS < 0 ||
		pricing.TTSMicrousdPerMillionOutputAudioMS > MaximumRate ||
		(pricing.TTSMicrousdPerMillionCharacters == 0 &&
			pricing.TTSMicrousdPerMillionOutputAudioMS == 0) ||
		pricing.DailyBudgetMicrousd < 1 ||
		pricing.DailyBudgetMicrousd > MaximumBudget ||
		pricing.STTReservationChunkAudioMS < MinimumSTTChunkMS ||
		pricing.STTReservationChunkAudioMS > MaximumSTTChunkMS ||
		pricing.TTSMaxOutputAudioMS < MinimumTTSOutputMS ||
		pricing.TTSMaxOutputAudioMS > MaximumTTSOutputMS ||
		pricing.ReservationTTL < MinimumReservationTTL ||
		pricing.ReservationTTL > 10*time.Minute {
		return ErrInvalid
	}
	return nil
}

type Usage struct {
	STTAudioMS       int64
	TTSCharacters    int64
	TTSOutputAudioMS int64
}

func STTUsage(audioMS int64) Usage { return Usage{STTAudioMS: audioMS} }

func TTSUsage(characters, outputAudioMS int64) Usage {
	return Usage{TTSCharacters: characters, TTSOutputAudioMS: outputAudioMS}
}

func (usage Usage) Validate() error {
	stt := usage.STTAudioMS > 0 && usage.TTSCharacters == 0 &&
		usage.TTSOutputAudioMS == 0
	tts := usage.STTAudioMS == 0 && usage.TTSCharacters > 0 &&
		usage.TTSOutputAudioMS >= 0
	if (!stt && !tts) || usage.STTAudioMS > MaximumUnitBound ||
		usage.TTSCharacters > MaximumUnitBound ||
		usage.TTSOutputAudioMS > MaximumUnitBound {
		return ErrInvalid
	}
	return nil
}

type Reservation struct {
	ID               [16]byte
	Limit            Usage
	ReservedMicrousd int64
}

type Settlement struct {
	CostMicrousd int64
}

type Ledger interface {
	VerifySchema(context.Context) error
	Reserve(context.Context, string, Usage) (Reservation, error)
	Settle(context.Context, Reservation, Usage) (Settlement, error)
	MarkUncertain(context.Context, Reservation) (int64, error)
	Release(context.Context, Reservation) error
}

func usageCost(pricing Pricing, usage Usage) (int64, error) {
	if usage.Validate() != nil {
		return 0, ErrInvalid
	}
	values := []struct {
		units int64
		rate  int64
	}{
		{usage.STTAudioMS, pricing.STTMicrousdPerMillionAudioMS},
		{usage.TTSCharacters, pricing.TTSMicrousdPerMillionCharacters},
		{usage.TTSOutputAudioMS, pricing.TTSMicrousdPerMillionOutputAudioMS},
	}
	var total int64
	for _, value := range values {
		cost, err := unitCost(value.units, value.rate)
		if err != nil || total > MaximumBudget-cost {
			return 0, ErrInvalid
		}
		total += cost
	}
	if total < 1 {
		return 0, ErrInvalid
	}
	return total, nil
}

func unitCost(units, rate int64) (int64, error) {
	if units < 0 || units > MaximumUnitBound || rate < 0 || rate > MaximumRate {
		return 0, ErrInvalid
	}
	if units == 0 || rate == 0 {
		return 0, nil
	}
	const million = int64(1_000_000)
	const maximumInt64 = int64(^uint64(0) >> 1)
	whole := (units / million) * rate
	remainder := units % million
	if remainder != 0 {
		if remainder > (maximumInt64-(million-1))/rate {
			return 0, ErrInvalid
		}
		whole += (remainder*rate + million - 1) / million
	}
	if whole < 0 || whole > MaximumBudget {
		return 0, ErrInvalid
	}
	return whole, nil
}

func usageWithin(usage, limit Usage) bool {
	if usage.Validate() != nil || limit.Validate() != nil {
		return false
	}
	return usage.STTAudioMS <= limit.STTAudioMS &&
		usage.TTSCharacters <= limit.TTSCharacters &&
		usage.TTSOutputAudioMS <= limit.TTSOutputAudioMS &&
		(usage.STTAudioMS > 0) == (limit.STTAudioMS > 0)
}

func validReservation(reservation Reservation) bool {
	zero := true
	for _, value := range reservation.ID {
		zero = zero && value == 0
	}
	return !zero && reservation.Limit.Validate() == nil &&
		reservation.ReservedMicrousd > 0
}

func unavailable(action string, err error) error {
	if err == nil {
		return ErrUnavailable
	}
	return fmt.Errorf("%w: %s", ErrUnavailable, action)
}
