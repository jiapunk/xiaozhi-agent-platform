BEGIN;

CREATE TABLE xz_action_consent_wake_schema (
    singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version integer NOT NULL CHECK (version = 1),
    contract_id varchar(64) NOT NULL
        CHECK (contract_id = 'xz-action-consent-wake-db-v1-20260810'),
    applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO xz_action_consent_wake_schema (singleton, version, contract_id)
VALUES (TRUE, 1, 'xz-action-consent-wake-db-v1-20260810');

CREATE TABLE action_consent_wake_outbox (
    challenge_id varchar(22) PRIMARY KEY
        REFERENCES action_consent_challenges (challenge_id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    available_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    attempts integer NOT NULL DEFAULT 0
        CHECK (attempts BETWEEN 0 AND 100000),
    claimed_by varchar(64)
        CHECK (claimed_by IS NULL OR
               claimed_by ~ '^[A-Za-z0-9:_.-]{1,64}$'),
    lease_until timestamptz,
    CHECK (expires_at > created_at),
    CHECK (expires_at <= created_at + INTERVAL '30 seconds'),
    CHECK (available_at >= created_at),
    CHECK ((claimed_by IS NULL) = (lease_until IS NULL))
);

CREATE INDEX action_consent_wake_available_idx
    ON action_consent_wake_outbox (available_at, expires_at, challenge_id);

COMMIT;
