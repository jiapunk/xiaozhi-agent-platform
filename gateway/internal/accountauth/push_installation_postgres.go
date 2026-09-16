package accountauth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"time"
)

var _ PushInstallationStore = (*PostgresStore)(nil)

func (store *PostgresStore) UpsertPushInstallation(ctx context.Context,
	session Session, registration PushInstallationRegistration) (PushInstallation, error) {
	if store == nil || ctx == nil || !ValidSession(session) ||
		!ValidPushInstallationRegistration(registration) {
		return PushInstallation{}, ErrInvalid
	}
	return runPostgresTransaction(store, ctx, func(ctx context.Context,
		tx *sql.Tx) (PushInstallation, error) {
		account, found, err := selectAccount(ctx, tx, session.Principal)
		if err != nil {
			return PushInstallation{}, err
		}
		if !found {
			return PushInstallation{}, ErrNotFound
		}
		if account.Status != AccountActive {
			return PushInstallation{}, ErrSuspended
		}
		if account.Revision != session.AccountRevision {
			return PushInstallation{}, ErrStaleSession
		}
		now, err := postgresTime(ctx, tx)
		if err != nil {
			return PushInstallation{}, err
		}
		if _, err := tx.ExecContext(ctx, `
DELETE FROM companion_push_installations
WHERE tenant_id = $1 AND subject = $2
  AND (account_revision <> $3 OR valid_until <= $4)`,
			session.Principal.TenantID, session.Principal.Subject,
			account.Revision, now); err != nil {
			return PushInstallation{}, err
		}
		var existing bool
		if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1 FROM companion_push_installations
    WHERE tenant_id = $1 AND subject = $2 AND installation_id = $3
)`, session.Principal.TenantID, session.Principal.Subject,
			registration.InstallationID).Scan(&existing); err != nil {
			return PushInstallation{}, err
		}
		if !existing {
			var count int
			if err := tx.QueryRowContext(ctx, `
SELECT count(*) FROM companion_push_installations
WHERE tenant_id = $1 AND subject = $2 AND account_revision = $3`,
				session.Principal.TenantID, session.Principal.Subject,
				account.Revision).Scan(&count); err != nil {
				return PushInstallation{}, err
			}
			if count >= MaximumPushInstallationsPerAccount {
				return PushInstallation{}, ErrCapacity
			}
		}
		validUntil := now.Add(MaximumPushInstallationLifetime)
		installation := PushInstallation{
			InstallationID:  registration.InstallationID,
			Principal:       session.Principal,
			AccountRevision: account.Revision,
			Platform:        registration.Platform,
			Token:           cloneProtectedPushToken(registration.Token),
			RefreshedAt:     now,
			ValidUntil:      validUntil,
		}
		var digest []byte
		err = tx.QueryRowContext(ctx, `
INSERT INTO companion_push_installations
    (tenant_id, subject, installation_id, account_revision, platform,
     token_ciphertext, token_key_id, token_digest, registered_at,
     refreshed_at, valid_until)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, $10)
ON CONFLICT (tenant_id, subject, installation_id) DO UPDATE SET
    account_revision = EXCLUDED.account_revision,
    platform = EXCLUDED.platform,
    token_ciphertext = EXCLUDED.token_ciphertext,
    token_key_id = EXCLUDED.token_key_id,
    token_digest = EXCLUDED.token_digest,
    refreshed_at = EXCLUDED.refreshed_at,
    valid_until = EXCLUDED.valid_until
RETURNING registered_at, refreshed_at, valid_until, token_digest`,
			session.Principal.TenantID, session.Principal.Subject,
			registration.InstallationID, account.Revision, registration.Platform,
			registration.Token.Ciphertext, registration.Token.KeyID,
			registration.Token.Digest[:], now, validUntil).
			Scan(&installation.RegisteredAt, &installation.RefreshedAt,
				&installation.ValidUntil, &digest)
		if err != nil {
			return PushInstallation{}, err
		}
		if len(digest) != len(installation.Token.Digest) ||
			subtle.ConstantTimeCompare(digest, installation.Token.Digest[:]) != 1 {
			return PushInstallation{}, ErrUnavailable
		}
		installation.RegisteredAt = installation.RegisteredAt.UTC()
		installation.RefreshedAt = installation.RefreshedAt.UTC()
		installation.ValidUntil = installation.ValidUntil.UTC()
		return installation, nil
	})
}

func (store *PostgresStore) RemovePushInstallation(ctx context.Context,
	session Session, installationID string) error {
	if store == nil || ctx == nil || !ValidSession(session) ||
		!ValidPushInstallationID(installationID) {
		return ErrInvalid
	}
	_, err := runPostgresTransaction(store, ctx, func(ctx context.Context,
		tx *sql.Tx) (bool, error) {
		account, found, err := selectAccount(ctx, tx, session.Principal)
		if err != nil {
			return false, err
		}
		if !found {
			return false, ErrNotFound
		}
		if account.Status != AccountActive {
			return false, ErrSuspended
		}
		if account.Revision != session.AccountRevision {
			return false, ErrStaleSession
		}
		_, err = tx.ExecContext(ctx, `
DELETE FROM companion_push_installations
WHERE tenant_id = $1 AND subject = $2 AND installation_id = $3
  AND account_revision = $4`, session.Principal.TenantID,
			session.Principal.Subject, installationID, account.Revision)
		return err == nil, err
	})
	return err
}

func (store *PostgresStore) ActivePushInstallations(ctx context.Context,
	principal Principal) ([]PushInstallation, error) {
	if store == nil || ctx == nil || !ValidPrincipal(principal) {
		return nil, ErrInvalid
	}
	return runPostgresTransaction(store, ctx, func(ctx context.Context,
		tx *sql.Tx) ([]PushInstallation, error) {
		account, found, err := selectAccount(ctx, tx, principal)
		if err != nil {
			return nil, err
		}
		if !found || account.Status != AccountActive {
			return nil, nil
		}
		now, err := postgresTime(ctx, tx)
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `
DELETE FROM companion_push_installations
WHERE tenant_id = $1 AND subject = $2
  AND (account_revision <> $3 OR valid_until <= $4)`,
			principal.TenantID, principal.Subject, account.Revision, now); err != nil {
			return nil, err
		}
		rows, err := tx.QueryContext(ctx, `
SELECT installation_id, platform, token_ciphertext, token_key_id,
       token_digest, registered_at, refreshed_at, valid_until
FROM companion_push_installations
WHERE tenant_id = $1 AND subject = $2 AND account_revision = $3
  AND valid_until > $4
ORDER BY installation_id`, principal.TenantID, principal.Subject,
			account.Revision, now)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		installations := make([]PushInstallation, 0,
			MaximumPushInstallationsPerAccount)
		for rows.Next() {
			installation := PushInstallation{Principal: principal,
				AccountRevision: account.Revision}
			var digest []byte
			if err := rows.Scan(&installation.InstallationID,
				&installation.Platform, &installation.Token.Ciphertext,
				&installation.Token.KeyID, &digest, &installation.RegisteredAt,
				&installation.RefreshedAt, &installation.ValidUntil); err != nil {
				return nil, err
			}
			if len(digest) != len(installation.Token.Digest) {
				return nil, ErrUnavailable
			}
			copy(installation.Token.Digest[:], digest)
			installation.RegisteredAt = installation.RegisteredAt.UTC()
			installation.RefreshedAt = installation.RefreshedAt.UTC()
			installation.ValidUntil = installation.ValidUntil.UTC()
			if !validPushInstallation(installation, now) {
				return nil, ErrUnavailable
			}
			installations = append(installations, installation)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return installations, nil
	})
}

func (store *PostgresStore) InvalidatePushInstallation(ctx context.Context,
	principal Principal, installationID string, digest [32]byte) error {
	if store == nil || ctx == nil || !ValidPrincipal(principal) ||
		!ValidPushInstallationID(installationID) {
		return ErrInvalid
	}
	_, err := runPostgresTransaction(store, ctx, func(ctx context.Context,
		tx *sql.Tx) (bool, error) {
		account, found, err := selectAccount(ctx, tx, principal)
		if err != nil {
			return false, err
		}
		if !found {
			return false, ErrNotFound
		}
		result, err := tx.ExecContext(ctx, `
DELETE FROM companion_push_installations
WHERE tenant_id = $1 AND subject = $2 AND installation_id = $3
  AND account_revision = $4 AND token_digest = $5`,
			principal.TenantID, principal.Subject, installationID,
			account.Revision, digest[:])
		if err != nil {
			return false, err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return false, err
		}
		if changed != 1 {
			return false, ErrNotFound
		}
		return true, nil
	})
	return err
}

func validPushInstallation(installation PushInstallation, now time.Time) bool {
	return ValidPushInstallationID(installation.InstallationID) &&
		ValidPrincipal(installation.Principal) &&
		ValidAccountRevision(installation.AccountRevision) &&
		ValidPushPlatform(installation.Platform) &&
		ValidProtectedPushToken(installation.Token) &&
		!installation.RegisteredAt.IsZero() &&
		!installation.RefreshedAt.Before(installation.RegisteredAt) &&
		installation.ValidUntil.After(installation.RefreshedAt) &&
		installation.ValidUntil.Sub(installation.RefreshedAt) <= MaximumPushInstallationLifetime &&
		installation.ValidUntil.After(now)
}
