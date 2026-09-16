package usagebudget

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sync"
	"time"
)

const subjectDigestDomain = "xiaozhi-agent-usage-subject-v1\x00"

type MemoryLedger struct {
	mu           sync.Mutex
	pricing      Pricing
	digestKey    []byte
	random       io.Reader
	now          func() time.Time
	daily        map[string]*memoryDaily
	reservations map[[16]byte]memoryReservation
}

type memoryDaily struct {
	CommittedMicrousd int64
	UncertainMicrousd int64
	ReservedMicrousd  int64
	InputTokens       int64
	OutputTokens      int64
	SettledRequests   int64
	UncertainRequests int64
}

type memoryReservation struct {
	day         string
	subject     string
	profile     string
	inputLimit  int64
	outputLimit int64
	reserved    int64
	expiresAt   time.Time
}

func NewMemoryLedger(pricing Pricing, digestKey []byte) (*MemoryLedger, error) {
	if pricing.Validate() != nil || len(digestKey) != 32 {
		return nil, ErrInvalid
	}
	return &MemoryLedger{pricing: pricing, digestKey: append([]byte(nil), digestKey...),
		random: rand.Reader, now: time.Now, daily: make(map[string]*memoryDaily),
		reservations: make(map[[16]byte]memoryReservation)}, nil
}

func (ledger *MemoryLedger) VerifySchema(ctx context.Context) error {
	if ledger == nil || ctx == nil {
		return ErrUnavailable
	}
	return nil
}

func (ledger *MemoryLedger) Reserve(ctx context.Context, subject string,
	inputLimit, outputLimit int64) (Reservation, error) {
	if ledger == nil || ctx == nil || ctx.Err() != nil || subject == "" ||
		inputLimit < 1 || inputLimit > MaximumTokenBound || outputLimit < 1 ||
		outputLimit > MaximumTokenBound {
		return Reservation{}, ErrInvalid
	}
	cost, err := reservationCost(ledger.pricing, inputLimit, outputLimit)
	if err != nil || cost < 1 {
		return Reservation{}, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	now := ledger.now().UTC()
	ledger.reconcileExpired(now)
	day := now.Format("2006-01-02")
	subjectKey := ledger.subjectKey(subject)
	dailyKey := day + ":" + subjectKey
	daily := ledger.daily[dailyKey]
	if daily == nil {
		daily = &memoryDaily{}
		ledger.daily[dailyKey] = daily
	}
	if daily.CommittedMicrousd+daily.UncertainMicrousd+
		daily.ReservedMicrousd > ledger.pricing.DailyBudgetMicrousd-cost {
		return Reservation{}, ErrBudgetExceeded
	}
	reservation := Reservation{ReservedMicrousd: cost,
		InputTokenLimit: inputLimit, OutputTokenLimit: outputLimit}
	if _, err := io.ReadFull(ledger.random, reservation.ID[:]); err != nil {
		return Reservation{}, unavailable("generate usage reservation", err)
	}
	if _, exists := ledger.reservations[reservation.ID]; exists {
		return Reservation{}, unavailable("generate unique usage reservation", nil)
	}
	ledger.reservations[reservation.ID] = memoryReservation{
		day: day, subject: subjectKey, profile: ledger.pricing.ProfileID,
		inputLimit: inputLimit, outputLimit: outputLimit, reserved: cost,
		expiresAt: now.Add(ledger.pricing.ReservationTTL),
	}
	daily.ReservedMicrousd += cost
	return reservation, nil
}

func (ledger *MemoryLedger) Settle(ctx context.Context, reservation Reservation,
	usage Usage) (Settlement, error) {
	if ledger == nil || ctx == nil || ctx.Err() != nil ||
		!validReservation(reservation) || usage.Validate() != nil {
		return Settlement{}, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	stored, found := ledger.reservations[reservation.ID]
	if !found {
		return Settlement{}, ErrReservationLost
	}
	if usage.InputTokens > stored.inputLimit || usage.OutputTokens > stored.outputLimit {
		return Settlement{}, ErrUsageExceeded
	}
	cost, err := reservationCost(ledger.pricing, usage.InputTokens,
		usage.OutputTokens)
	if err != nil || cost > stored.reserved {
		return Settlement{}, ErrUsageExceeded
	}
	daily := ledger.daily[stored.day+":"+stored.subject]
	if daily == nil || daily.ReservedMicrousd < stored.reserved {
		return Settlement{}, ErrUnavailable
	}
	daily.ReservedMicrousd -= stored.reserved
	daily.CommittedMicrousd += cost
	daily.InputTokens += usage.InputTokens
	daily.OutputTokens += usage.OutputTokens
	daily.SettledRequests++
	delete(ledger.reservations, reservation.ID)
	return Settlement{CostMicrousd: cost}, nil
}

func (ledger *MemoryLedger) MarkUncertain(ctx context.Context,
	reservation Reservation) (int64, error) {
	if ledger == nil || ctx == nil || ctx.Err() != nil || !validReservation(reservation) {
		return 0, ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	stored, found := ledger.reservations[reservation.ID]
	if !found {
		return 0, ErrReservationLost
	}
	daily := ledger.daily[stored.day+":"+stored.subject]
	if daily == nil || daily.ReservedMicrousd < stored.reserved {
		return 0, ErrUnavailable
	}
	daily.ReservedMicrousd -= stored.reserved
	daily.UncertainMicrousd += stored.reserved
	daily.UncertainRequests++
	delete(ledger.reservations, reservation.ID)
	return stored.reserved, nil
}

func (ledger *MemoryLedger) Release(ctx context.Context,
	reservation Reservation) error {
	if ledger == nil || ctx == nil || ctx.Err() != nil || !validReservation(reservation) {
		return ErrInvalid
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	stored, found := ledger.reservations[reservation.ID]
	if !found {
		return ErrReservationLost
	}
	daily := ledger.daily[stored.day+":"+stored.subject]
	if daily == nil || daily.ReservedMicrousd < stored.reserved {
		return ErrUnavailable
	}
	daily.ReservedMicrousd -= stored.reserved
	delete(ledger.reservations, reservation.ID)
	return nil
}

func (ledger *MemoryLedger) reconcileExpired(now time.Time) {
	for id, reservation := range ledger.reservations {
		if reservation.expiresAt.After(now) {
			continue
		}
		daily := ledger.daily[reservation.day+":"+reservation.subject]
		if daily != nil && daily.ReservedMicrousd >= reservation.reserved {
			daily.ReservedMicrousd -= reservation.reserved
			daily.UncertainMicrousd += reservation.reserved
			daily.UncertainRequests++
		}
		delete(ledger.reservations, id)
	}
}

func (ledger *MemoryLedger) subjectKey(subject string) string {
	mac := hmac.New(sha256.New, ledger.digestKey)
	_, _ = mac.Write([]byte(subjectDigestDomain))
	_, _ = mac.Write([]byte(subject))
	return hex.EncodeToString(mac.Sum(nil))
}
