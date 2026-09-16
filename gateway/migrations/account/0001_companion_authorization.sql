BEGIN;

CREATE TABLE xz_companion_authorization_schema (
    singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version integer NOT NULL CHECK (version = 1),
    contract_id varchar(64) NOT NULL
        CHECK (contract_id = 'xz-companion-auth-db-v1-20260810'),
    applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO xz_companion_authorization_schema
    (singleton, version, contract_id)
VALUES (TRUE, 1, 'xz-companion-auth-db-v1-20260810');

CREATE TABLE companion_accounts (
    tenant_id varchar(128) NOT NULL
        CHECK (tenant_id ~ '^[A-Za-z0-9:_.-]{1,128}$'),
    subject varchar(128) NOT NULL
        CHECK (subject ~ '^[A-Za-z0-9:_.-]{1,128}$'),
    revision bigint NOT NULL
        CHECK (revision BETWEEN 1 AND 4294967295),
    status varchar(10) NOT NULL CHECK (status IN ('active', 'suspended')),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, subject),
    CHECK (updated_at >= created_at)
);

CREATE TABLE companion_tokens (
    token_id varchar(128) PRIMARY KEY
        CHECK (token_id ~ '^[A-Za-z0-9:_.-]{1,128}$'),
    tenant_id varchar(128) NOT NULL,
    subject varchar(128) NOT NULL,
    account_revision bigint NOT NULL
        CHECK (account_revision BETWEEN 1 AND 4294967295),
    action varchar(32) NOT NULL CHECK (action IN (
        'device:claim', 'device:release', 'device:action-consent')),
    device_id varchar(64) NOT NULL,
    issued_at_unix bigint NOT NULL CHECK (issued_at_unix > 0),
    expires_at_unix bigint NOT NULL CHECK (
        expires_at_unix - issued_at_unix BETWEEN 60 AND 3600),
    created_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revocation_reason varchar(24) CHECK (revocation_reason IN (
        'account_logout', 'account_suspended', 'token_revoked')),
    FOREIGN KEY (tenant_id, subject)
        REFERENCES companion_accounts (tenant_id, subject),
    CHECK (
        (action = 'device:claim' AND device_id = '') OR
        (action IN ('device:release', 'device:action-consent') AND
         device_id ~ '^[A-Za-z0-9:_.-]{1,64}$')
    ),
    CHECK ((revoked_at IS NULL) = (revocation_reason IS NULL)),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX companion_tokens_account_idx
    ON companion_tokens (tenant_id, subject, account_revision);
CREATE INDEX companion_tokens_expiry_idx
    ON companion_tokens (expires_at_unix);

COMMIT;
