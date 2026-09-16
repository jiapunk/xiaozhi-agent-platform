BEGIN;

CREATE TABLE xz_action_consent_schema (
    singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version integer NOT NULL CHECK (version = 1),
    contract_id varchar(64) NOT NULL
        CHECK (contract_id = 'xz-action-consent-db-v1-20260810'),
    applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO xz_action_consent_schema (singleton, version, contract_id)
VALUES (TRUE, 1, 'xz-action-consent-db-v1-20260810');

CREATE TABLE action_consent_challenges (
    challenge_id varchar(22) PRIMARY KEY
        CHECK (challenge_id ~ '^[A-Za-z0-9_-]{22}$'),
    device_id varchar(64) NOT NULL REFERENCES device_owners (device_id),
    tenant_id varchar(128) NOT NULL
        CHECK (tenant_id ~ '^[A-Za-z0-9:_.-]{1,128}$'),
    owner_id varchar(128) NOT NULL
        CHECK (owner_id ~ '^[A-Za-z0-9:_.-]{1,128}$'),
    owner_revision bigint NOT NULL
        CHECK (owner_revision BETWEEN 1 AND 4294967295),
    session_id varchar(64) NOT NULL
        CHECK (session_id ~ '^[A-Za-z0-9:_.-]{1,64}$'),
    request_id bigint NOT NULL CHECK (request_id BETWEEN 1 AND 4294967295),
    capability varchar(32) NOT NULL
        CHECK (capability = 'device.set_indicator'),
    indicator_on boolean NOT NULL,
    decision varchar(8) CHECK (decision IN ('approve', 'deny')),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    decided_at timestamptz,
    consumed_at timestamptz,
    CHECK (expires_at > created_at),
    CHECK (expires_at <= created_at + INTERVAL '30 seconds'),
    CHECK ((decision IS NULL) = (decided_at IS NULL)),
    CHECK (consumed_at IS NULL OR decision IS NOT NULL),
    UNIQUE (device_id, session_id, request_id)
);

CREATE INDEX action_consent_live_idx
    ON action_consent_challenges (expires_at)
    WHERE consumed_at IS NULL;
CREATE INDEX action_consent_device_idx
    ON action_consent_challenges (device_id, challenge_id);

COMMIT;

