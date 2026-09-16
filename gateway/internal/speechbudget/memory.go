package speechbudget

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

const subjectDigestDomain = "xiaozhi-speech-usage-subject-v1\x00"

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
	committed int64
	uncertain int64
	reserved  int64
}

type memoryReservation struct {
	day       string
	subject   string
	profile   string
	limit     Usage
	reserved  int64
	expiresAt time.Time
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
	limit Usage) (Reservation, error) {
	if ledger == nil || ctx == nil || ctx.Err() != nil || subject == "" ||
		limit.Validate() != nil {
		return Reservation{}, ErrInvalid
	}
	cost, err := usageCost(ledger.pricing, limit)
	if err != nil {
		return Reservation{}, err
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
	if daily.committed+daily.uncertain+daily.reserved >
		ledger.pricing.DailyBudgetMicrousd-cost {
		return Reservation{}, ErrBudgetExceeded
	}
	reservation := Reservation{Limit: limit, ReservedMicrousd: cost}
	if _, err := io.ReadFull(ledger.random, reservation.ID[:]); err != nil {
		return Reservation{}, unavailable("generate speech reservation", err)
	}
	if _, exists := ledger.reservations[reservation.ID]; exists {
		return Reservation{}, unavailable("generate unique speech reservation", nil)
	}
	ledger.reservations[reservation.ID] = memoryReservation{day: day,
		subject: subjectKey, profile: ledger.pricing.ProfileID, limit: limit,
		reserved: cost, expiresAt: now.Add(ledger.pricing.ReservationTTL)}
	daily.reserved += cost
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
	if !usageWithin(usage, stored.limit) {
		return Settlement{}, ErrUsageExceeded
	}
	cost, err := usageCost(ledger.pricing, usage)
	if err != nil || cost > stored.reserved {
		return Settlement{}, ErrUsageExceeded
	}
	daily := ledger.daily[stored.day+":"+stored.subject]
	if daily == nil || daily.reserved < stored.reserved {
		return Settlement{}, ErrUnavailable
	}
	daily.reserved -= stored.reserved
	daily.committed += cost
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
	if daily == nil || daily.reserved < stored.reserved {
		return 0, ErrUnavailable
	}
	daily.reserved -= stored.reserved
	daily.uncertain += stored.reserved
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
	if daily == nil || daily.reserved < stored.reserved {
		return ErrUnavailable
	}
	daily.reserved -= stored.reserved
	delete(ledger.reservations, reservation.ID)
	return nil
}

func (ledger *MemoryLedger) reconcileExpired(now time.Time) {
	for id, reservation := range ledger.reservations {
		if reservation.expiresAt.After(now) {
			continue
		}
		daily := ledger.daily[reservation.day+":"+reservation.subject]
		if daily != nil && daily.reserved >= reservation.reserved {
			daily.reserved -= reservation.reserved
			daily.uncertain += reservation.reserved
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
