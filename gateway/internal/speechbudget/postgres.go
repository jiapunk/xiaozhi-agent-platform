package speechbudget

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

const maximumTransactionTries = 4

type PostgresLedger struct {
	db               *sql.DB
	pricing          Pricing
	digestKey        []byte
	operationTimeout time.Duration
	random           io.Reader
}

func NewPostgresLedger(database *sql.DB, pricing Pricing, digestKey []byte,
	operationTimeout time.Duration) (*PostgresLedger, error) {
	if database == nil || pricing.Validate() != nil || len(digestKey) != 32 ||
		operationTimeout < 100*time.Millisecond || operationTimeout > 30*time.Second {
		return nil, fmt.Errorf("invalid PostgreSQL speech usage budget configuration")
	}
	return &PostgresLedger{db: database, pricing: pricing,
		digestKey:        append([]byte(nil), digestKey...),
		operationTimeout: operationTimeout, random: rand.Reader}, nil
}

func (ledger *PostgresLedger) VerifySchema(ctx context.Context) error {
	if ledger == nil || ledger.db == nil || ctx == nil {
		return ErrUnavailable
	}
	operation, cancel := context.WithTimeout(ctx, ledger.operationTimeout)
	defer cancel()
	if err := ledger.db.PingContext(operation); err != nil {
		return unavailable("ping speech usage budget database", err)
	}
	var version int
	var contract string
	if err := ledger.db.QueryRowContext(operation, `
SELECT version, contract_id FROM xz_speech_usage_budget_schema
WHERE singleton = TRUE`).Scan(&version, &contract); err != nil {
		return unavailable("read speech usage budget schema", err)
	}
	if version != SchemaVersion || contract != SchemaContract {
		return ErrUnavailable
	}
	return nil
}

func (ledger *PostgresLedger) Reserve(ctx context.Context, subject string,
	limit Usage) (Reservation, error) {
	if ledger == nil || ledger.db == nil || ctx == nil || subject == "" ||
		limit.Validate() != nil {
		return Reservation{}, ErrInvalid
	}
	reservedCost, err := usageCost(ledger.pricing, limit)
	if err != nil {
		return Reservation{}, err
	}
	reservation := Reservation{Limit: limit, ReservedMicrousd: reservedCost}
	if _, err := io.ReadFull(ledger.random, reservation.ID[:]); err != nil {
		return Reservation{}, unavailable("generate speech reservation", err)
	}
	subjectHMAC := ledger.subjectHMAC(subject)
	err = ledger.serializable(ctx, func(operation context.Context,
		tx *sql.Tx) (error, error) {
		if err := reconcileExpired(operation, tx); err != nil {
			return nil, err
		}
		var databaseNow, usageDay time.Time
		if err := tx.QueryRowContext(operation, `
SELECT CURRENT_TIMESTAMP,
       ((CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date)`).
			Scan(&databaseNow, &usageDay); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(operation, `
INSERT INTO speech_usage_pricing_profiles
    (pricing_profile_id, stt_microusd_per_million_audio_ms,
     tts_microusd_per_million_characters,
     tts_microusd_per_million_output_audio_ms)
VALUES ($1, $2, $3, $4)
ON CONFLICT (pricing_profile_id) DO NOTHING`, ledger.pricing.ProfileID,
			ledger.pricing.STTMicrousdPerMillionAudioMS,
			ledger.pricing.TTSMicrousdPerMillionCharacters,
			ledger.pricing.TTSMicrousdPerMillionOutputAudioMS); err != nil {
			return nil, err
		}
		var sttRate, ttsCharacterRate, ttsAudioRate int64
		if err := tx.QueryRowContext(operation, `
SELECT stt_microusd_per_million_audio_ms,
       tts_microusd_per_million_characters,
       tts_microusd_per_million_output_audio_ms
FROM speech_usage_pricing_profiles
WHERE pricing_profile_id = $1 FOR UPDATE`, ledger.pricing.ProfileID).
			Scan(&sttRate, &ttsCharacterRate, &ttsAudioRate); err != nil {
			return nil, err
		}
		if sttRate != ledger.pricing.STTMicrousdPerMillionAudioMS ||
			ttsCharacterRate != ledger.pricing.TTSMicrousdPerMillionCharacters ||
			ttsAudioRate != ledger.pricing.TTSMicrousdPerMillionOutputAudioMS {
			return ErrInvalid, nil
		}
		if _, err := tx.ExecContext(operation, `
INSERT INTO speech_usage_budget_daily (usage_day, subject_hmac)
VALUES ($1, $2)
ON CONFLICT (usage_day, subject_hmac) DO NOTHING`, usageDay, subjectHMAC); err != nil {
			return nil, err
		}
		var committed, uncertain, alreadyReserved int64
		if err := tx.QueryRowContext(operation, `
SELECT committed_cost_microusd, uncertain_cost_microusd,
       reserved_cost_microusd
FROM speech_usage_budget_daily
WHERE usage_day = $1 AND subject_hmac = $2 FOR UPDATE`, usageDay, subjectHMAC).
			Scan(&committed, &uncertain, &alreadyReserved); err != nil {
			return nil, err
		}
		if committed+uncertain+alreadyReserved >
			ledger.pricing.DailyBudgetMicrousd-reservedCost {
			return ErrBudgetExceeded, nil
		}
		if _, err := tx.ExecContext(operation, `
INSERT INTO speech_usage_profile_daily
    (usage_day, subject_hmac, pricing_profile_id)
VALUES ($1, $2, $3)
ON CONFLICT (usage_day, subject_hmac, pricing_profile_id) DO NOTHING`,
			usageDay, subjectHMAC, ledger.pricing.ProfileID); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(operation, `
INSERT INTO speech_usage_reservations
    (reservation_id, usage_day, subject_hmac, pricing_profile_id,
     stt_audio_ms_limit, tts_characters_limit,
     tts_output_audio_ms_limit, reserved_cost_microusd,
     created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
        $9 + ($10 * INTERVAL '1 millisecond'))`, reservation.ID[:], usageDay,
			subjectHMAC, ledger.pricing.ProfileID, limit.STTAudioMS,
			limit.TTSCharacters, limit.TTSOutputAudioMS, reservedCost,
			databaseNow, ledger.pricing.ReservationTTL.Milliseconds()); err != nil {
			return nil, err
		}
		result, err := tx.ExecContext(operation, `
UPDATE speech_usage_budget_daily
SET reserved_cost_microusd = reserved_cost_microusd + $3,
    updated_at = $4
WHERE usage_day = $1 AND subject_hmac = $2`, usageDay, subjectHMAC,
			reservedCost, databaseNow)
		if err != nil {
			return nil, err
		}
		if err := exactlyOne(result); err != nil {
			return nil, err
		}
		return nil, nil
	})
	if err != nil {
		return Reservation{}, err
	}
	return reservation, nil
}

func (ledger *PostgresLedger) Settle(ctx context.Context,
	reservation Reservation, usage Usage) (Settlement, error) {
	if ledger == nil || ledger.db == nil || ctx == nil ||
		!validReservation(reservation) || usage.Validate() != nil {
		return Settlement{}, ErrInvalid
	}
	var settledCost int64
	err := ledger.serializable(ctx, func(operation context.Context,
		tx *sql.Tx) (error, error) {
		stored, err := lockReservation(operation, tx, reservation.ID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrReservationLost, nil
			}
			return nil, err
		}
		if !usageWithin(usage, stored.limit) {
			return ErrUsageExceeded, nil
		}
		pricing, err := loadStoredPricing(operation, tx, stored.profileID)
		if err != nil {
			return nil, err
		}
		cost, err := usageCost(pricing, usage)
		if err != nil || cost > stored.reservedCost {
			return ErrUsageExceeded, nil
		}
		if err := updateSettlement(operation, tx, stored, usage, cost); err != nil {
			return nil, err
		}
		settledCost = cost
		return nil, nil
	})
	if err != nil {
		return Settlement{}, err
	}
	return Settlement{CostMicrousd: settledCost}, nil
}

func (ledger *PostgresLedger) MarkUncertain(ctx context.Context,
	reservation Reservation) (int64, error) {
	if ledger == nil || ledger.db == nil || ctx == nil ||
		!validReservation(reservation) {
		return 0, ErrInvalid
	}
	var uncertainCost int64
	err := ledger.serializable(ctx, func(operation context.Context,
		tx *sql.Tx) (error, error) {
		stored, err := lockReservation(operation, tx, reservation.ID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrReservationLost, nil
			}
			return nil, err
		}
		if err := updateUncertain(operation, tx, stored); err != nil {
			return nil, err
		}
		uncertainCost = stored.reservedCost
		return nil, nil
	})
	return uncertainCost, err
}

func (ledger *PostgresLedger) Release(ctx context.Context,
	reservation Reservation) error {
	if ledger == nil || ledger.db == nil || ctx == nil ||
		!validReservation(reservation) {
		return ErrInvalid
	}
	return ledger.serializable(ctx, func(operation context.Context,
		tx *sql.Tx) (error, error) {
		stored, err := lockReservation(operation, tx, reservation.ID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrReservationLost, nil
			}
			return nil, err
		}
		if err := updateReserved(operation, tx, stored, 0); err != nil {
			return nil, err
		}
		return nil, nil
	})
}

type storedReservation struct {
	id           [16]byte
	usageDay     time.Time
	subjectHMAC  []byte
	profileID    string
	limit        Usage
	reservedCost int64
}

func lockReservation(ctx context.Context, tx *sql.Tx,
	id [16]byte) (storedReservation, error) {
	stored := storedReservation{id: id}
	err := tx.QueryRowContext(ctx, `
SELECT r.usage_day, r.subject_hmac, r.pricing_profile_id,
       r.stt_audio_ms_limit, r.tts_characters_limit,
       r.tts_output_audio_ms_limit, r.reserved_cost_microusd
FROM speech_usage_reservations r
JOIN speech_usage_budget_daily d
  ON d.usage_day = r.usage_day AND d.subject_hmac = r.subject_hmac
WHERE r.reservation_id = $1
FOR UPDATE OF d, r`, id[:]).Scan(&stored.usageDay, &stored.subjectHMAC,
		&stored.profileID, &stored.limit.STTAudioMS, &stored.limit.TTSCharacters,
		&stored.limit.TTSOutputAudioMS, &stored.reservedCost)
	return stored, err
}

func loadStoredPricing(ctx context.Context, tx *sql.Tx,
	profileID string) (Pricing, error) {
	pricing := Pricing{ProfileID: profileID, DailyBudgetMicrousd: MaximumBudget,
		STTReservationChunkAudioMS: MinimumSTTChunkMS,
		TTSMaxOutputAudioMS:        MinimumTTSOutputMS,
		ReservationTTL:             30 * time.Second}
	err := tx.QueryRowContext(ctx, `
SELECT stt_microusd_per_million_audio_ms,
       tts_microusd_per_million_characters,
       tts_microusd_per_million_output_audio_ms
FROM speech_usage_pricing_profiles WHERE pricing_profile_id = $1`, profileID).
		Scan(&pricing.STTMicrousdPerMillionAudioMS,
			&pricing.TTSMicrousdPerMillionCharacters,
			&pricing.TTSMicrousdPerMillionOutputAudioMS)
	return pricing, err
}

func updateSettlement(ctx context.Context, tx *sql.Tx, stored storedReservation,
	usage Usage, cost int64) error {
	result, err := tx.ExecContext(ctx, `
UPDATE speech_usage_budget_daily
SET reserved_cost_microusd = reserved_cost_microusd - $3,
    committed_cost_microusd = committed_cost_microusd + $4,
    settled_reservations = settled_reservations + 1,
    updated_at = CURRENT_TIMESTAMP
WHERE usage_day = $1 AND subject_hmac = $2`, stored.usageDay,
		stored.subjectHMAC, stored.reservedCost, cost)
	if err != nil {
		return err
	}
	if err := exactlyOne(result); err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, `
UPDATE speech_usage_profile_daily
SET committed_stt_audio_ms = committed_stt_audio_ms + $4,
    committed_tts_characters = committed_tts_characters + $5,
    committed_tts_output_audio_ms = committed_tts_output_audio_ms + $6,
    committed_cost_microusd = committed_cost_microusd + $7,
    settled_reservations = settled_reservations + 1,
    updated_at = CURRENT_TIMESTAMP
WHERE usage_day = $1 AND subject_hmac = $2 AND pricing_profile_id = $3`,
		stored.usageDay, stored.subjectHMAC, stored.profileID, usage.STTAudioMS,
		usage.TTSCharacters, usage.TTSOutputAudioMS, cost)
	if err != nil {
		return err
	}
	if err := exactlyOne(result); err != nil {
		return err
	}
	return deleteReservation(ctx, tx, stored.id)
}

func updateUncertain(ctx context.Context, tx *sql.Tx,
	stored storedReservation) error {
	result, err := tx.ExecContext(ctx, `
UPDATE speech_usage_budget_daily
SET reserved_cost_microusd = reserved_cost_microusd - $3,
    uncertain_cost_microusd = uncertain_cost_microusd + $3,
    uncertain_reservations = uncertain_reservations + 1,
    updated_at = CURRENT_TIMESTAMP
WHERE usage_day = $1 AND subject_hmac = $2`, stored.usageDay,
		stored.subjectHMAC, stored.reservedCost)
	if err != nil {
		return err
	}
	if err := exactlyOne(result); err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, `
UPDATE speech_usage_profile_daily
SET uncertain_cost_microusd = uncertain_cost_microusd + $4,
    uncertain_reservations = uncertain_reservations + 1,
    updated_at = CURRENT_TIMESTAMP
WHERE usage_day = $1 AND subject_hmac = $2 AND pricing_profile_id = $3`,
		stored.usageDay, stored.subjectHMAC, stored.profileID, stored.reservedCost)
	if err != nil {
		return err
	}
	if err := exactlyOne(result); err != nil {
		return err
	}
	return deleteReservation(ctx, tx, stored.id)
}

func updateReserved(ctx context.Context, tx *sql.Tx,
	stored storedReservation, replacement int64) error {
	if replacement < 0 || replacement > stored.reservedCost {
		return ErrInvalid
	}
	result, err := tx.ExecContext(ctx, `
UPDATE speech_usage_budget_daily
SET reserved_cost_microusd = reserved_cost_microusd - $3 + $4,
    updated_at = CURRENT_TIMESTAMP
WHERE usage_day = $1 AND subject_hmac = $2`, stored.usageDay,
		stored.subjectHMAC, stored.reservedCost, replacement)
	if err != nil {
		return err
	}
	if err := exactlyOne(result); err != nil {
		return err
	}
	return deleteReservation(ctx, tx, stored.id)
}

func deleteReservation(ctx context.Context, tx *sql.Tx, id [16]byte) error {
	result, err := tx.ExecContext(ctx,
		`DELETE FROM speech_usage_reservations WHERE reservation_id = $1`, id[:])
	if err != nil {
		return err
	}
	return exactlyOne(result)
}

func exactlyOne(result sql.Result) error {
	if result == nil {
		return fmt.Errorf("missing speech usage SQL result")
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return fmt.Errorf("unexpected speech usage affected row count")
	}
	return nil
}

// reconcileExpired converts bounded abandoned reservations to uncertain spend;
// a process crash or database outage can never silently refund provider work.
func reconcileExpired(ctx context.Context, tx *sql.Tx) error {
	row := tx.QueryRowContext(ctx, `
WITH candidates AS (
    SELECT reservation_id
    FROM speech_usage_reservations
    WHERE expires_at <= CURRENT_TIMESTAMP
    ORDER BY expires_at, reservation_id
    LIMIT 1024
    FOR UPDATE SKIP LOCKED
), expired AS (
    DELETE FROM speech_usage_reservations r
    USING candidates c
    WHERE r.reservation_id = c.reservation_id
    RETURNING r.usage_day, r.subject_hmac, r.pricing_profile_id,
              r.reserved_cost_microusd
), budget_totals AS (
    SELECT usage_day, subject_hmac, sum(reserved_cost_microusd) AS cost,
           count(*) AS reservations
    FROM expired GROUP BY usage_day, subject_hmac
), updated_budgets AS (
    UPDATE speech_usage_budget_daily d
    SET reserved_cost_microusd = d.reserved_cost_microusd - e.cost,
        uncertain_cost_microusd = d.uncertain_cost_microusd + e.cost,
        uncertain_reservations = d.uncertain_reservations + e.reservations,
        updated_at = CURRENT_TIMESTAMP
    FROM budget_totals e
    WHERE d.usage_day = e.usage_day AND d.subject_hmac = e.subject_hmac
    RETURNING 1
), profile_totals AS (
    SELECT usage_day, subject_hmac, pricing_profile_id,
           sum(reserved_cost_microusd) AS cost, count(*) AS reservations
    FROM expired GROUP BY usage_day, subject_hmac, pricing_profile_id
), updated_profiles AS (
    UPDATE speech_usage_profile_daily d
    SET uncertain_cost_microusd = d.uncertain_cost_microusd + e.cost,
        uncertain_reservations = d.uncertain_reservations + e.reservations,
        updated_at = CURRENT_TIMESTAMP
    FROM profile_totals e
    WHERE d.usage_day = e.usage_day AND d.subject_hmac = e.subject_hmac
      AND d.pricing_profile_id = e.pricing_profile_id
    RETURNING 1
)
SELECT (SELECT count(*) FROM expired),
       (SELECT count(*) FROM budget_totals),
       (SELECT count(*) FROM updated_budgets),
       (SELECT count(*) FROM profile_totals),
       (SELECT count(*) FROM updated_profiles)`)
	var reconciled, budgetGroups, updatedBudgets, profileGroups, updatedProfiles int64
	if err := row.Scan(&reconciled, &budgetGroups, &updatedBudgets,
		&profileGroups, &updatedProfiles); err != nil {
		return err
	}
	if reconciled > 0 && (budgetGroups != updatedBudgets ||
		profileGroups != updatedProfiles) {
		return fmt.Errorf("speech usage expiry reconciliation was incomplete")
	}
	return nil
}

type transactionAction func(context.Context, *sql.Tx) (business error, failure error)

func (ledger *PostgresLedger) serializable(ctx context.Context,
	action transactionAction) error {
	if ledger == nil || ledger.db == nil || ctx == nil || action == nil {
		return ErrInvalid
	}
	operation, cancel := context.WithTimeout(ctx, ledger.operationTimeout)
	defer cancel()
	var last error
	for attempt := 0; attempt < maximumTransactionTries; attempt++ {
		tx, err := ledger.db.BeginTx(operation,
			&sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			last = err
			if retryable(err) {
				continue
			}
			return unavailable("begin speech usage transaction", err)
		}
		business, failure := action(operation, tx)
		if failure != nil {
			_ = tx.Rollback()
			last = failure
			if retryable(failure) {
				continue
			}
			return unavailable("execute speech usage transaction", failure)
		}
		if err := tx.Commit(); err != nil {
			last = err
			if retryable(err) {
				continue
			}
			return unavailable("commit speech usage transaction", err)
		}
		return business
	}
	return unavailable("retry speech usage transaction", last)
}

func (ledger *PostgresLedger) subjectHMAC(subject string) []byte {
	mac := hmac.New(sha256.New, ledger.digestKey)
	_, _ = mac.Write([]byte(subjectDigestDomain))
	_, _ = mac.Write([]byte(subject))
	return mac.Sum(nil)
}

func retryable(err error) bool {
	var postgres *pgconn.PgError
	return errors.As(err, &postgres) &&
		(postgres.Code == "40001" || postgres.Code == "40P01")
}
