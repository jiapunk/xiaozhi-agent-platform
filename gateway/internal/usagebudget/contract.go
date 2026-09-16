package usagebudget

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	SchemaVersion     = 1
	SchemaContract    = "xz-agent-usage-budget-v1-20260811"
	MaximumTokenBound = int64(2_000_000)
	MaximumRate       = int64(1_000_000_000_000)
	MaximumBudget     = int64(1_000_000_000_000_000)
)

var (
	ErrInvalid         = errors.New("invalid Agent usage budget request")
	ErrUnavailable     = errors.New("Agent usage budget unavailable")
	ErrBudgetExceeded  = errors.New("Agent daily usage budget exceeded")
	ErrReservationLost = errors.New("Agent usage reservation lost")
	ErrUsageExceeded   = errors.New("Agent provider usage exceeded reservation")
	profilePattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)
)

type Pricing struct {
	ProfileID                     string
	InputMicrousdPerMillionToken  int64
	OutputMicrousdPerMillionToken int64
	DailyBudgetMicrousd           int64
	InputTokenOverhead            int64
	ReservationTTL                time.Duration
}

func (pricing Pricing) Validate() error {
	if !profilePattern.MatchString(pricing.ProfileID) ||
		pricing.InputMicrousdPerMillionToken < 1 ||
		pricing.InputMicrousdPerMillionToken > MaximumRate ||
		pricing.OutputMicrousdPerMillionToken < 1 ||
		pricing.OutputMicrousdPerMillionToken > MaximumRate ||
		pricing.DailyBudgetMicrousd < 1 ||
		pricing.DailyBudgetMicrousd > MaximumBudget ||
		pricing.InputTokenOverhead < 0 ||
		pricing.InputTokenOverhead > 65_536 ||
		pricing.ReservationTTL < 30*time.Second ||
		pricing.ReservationTTL > 10*time.Minute {
		return ErrInvalid
	}
	return nil
}

type Reservation struct {
	ID               [16]byte
	ReservedMicrousd int64
	InputTokenLimit  int64
	OutputTokenLimit int64
}

type Usage struct {
	InputTokens  int64
	OutputTokens int64
	TotalTokens  int64
}

func (usage Usage) Validate() error {
	if usage.InputTokens < 1 || usage.InputTokens > MaximumTokenBound ||
		usage.OutputTokens < 1 || usage.OutputTokens > MaximumTokenBound ||
		usage.TotalTokens != usage.InputTokens+usage.OutputTokens ||
		usage.TotalTokens > MaximumTokenBound {
		return ErrInvalid
	}
	return nil
}

type Settlement struct {
	CostMicrousd int64
}

type Ledger interface {
	VerifySchema(context.Context) error
	Reserve(context.Context, string, int64, int64) (Reservation, error)
	Settle(context.Context, Reservation, Usage) (Settlement, error)
	MarkUncertain(context.Context, Reservation) (int64, error)
	Release(context.Context, Reservation) error
}

func reservationCost(pricing Pricing, inputTokens, outputTokens int64) (int64, error) {
	input, err := tokenCost(inputTokens, pricing.InputMicrousdPerMillionToken)
	if err != nil {
		return 0, err
	}
	output, err := tokenCost(outputTokens, pricing.OutputMicrousdPerMillionToken)
	if err != nil || input > MaximumBudget-output {
		return 0, ErrInvalid
	}
	return input + output, nil
}

func tokenCost(tokens, rate int64) (int64, error) {
	if tokens < 0 || tokens > MaximumTokenBound || rate < 1 || rate > MaximumRate {
		return 0, ErrInvalid
	}
	const million = int64(1_000_000)
	const maximumInt64 = int64(^uint64(0) >> 1)
	whole := (tokens / million) * rate
	remainder := tokens % million
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

func validReservation(reservation Reservation) bool {
	zero := true
	for _, value := range reservation.ID {
		zero = zero && value == 0
	}
	return !zero
}

func unavailable(action string, err error) error {
	if err == nil {
		return ErrUnavailable
	}
	return fmt.Errorf("%w: %s", ErrUnavailable, action)
}
