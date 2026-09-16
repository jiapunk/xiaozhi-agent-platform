BEGIN;

CREATE TABLE xz_companion_push_schema (
    singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version integer NOT NULL CHECK (version = 1),
    contract_id varchar(64) NOT NULL
        CHECK (contract_id = 'xz-companion-push-db-v1-20260810'),
    applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO xz_companion_push_schema (singleton, version, contract_id)
VALUES (TRUE, 1, 'xz-companion-push-db-v1-20260810');

CREATE TABLE companion_push_installations (
    tenant_id varchar(128) NOT NULL,
    subject varchar(128) NOT NULL,
    installation_id varchar(22) NOT NULL
        CHECK (installation_id ~ '^[A-Za-z0-9_-]{22}$'),
    account_revision bigint NOT NULL
        CHECK (account_revision BETWEEN 1 AND 4294967295),
    platform varchar(20) NOT NULL CHECK (platform IN (
        'apns-production', 'apns-development', 'fcm')),
    token_ciphertext bytea NOT NULL
        CHECK (octet_length(token_ciphertext) BETWEEN 32 AND 8192),
    token_key_id varchar(64) NOT NULL
        CHECK (token_key_id ~ '^[A-Za-z0-9:_.-]{1,64}$'),
    token_digest bytea NOT NULL CHECK (octet_length(token_digest) = 32),
    registered_at timestamptz NOT NULL,
    refreshed_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, subject, installation_id),
    UNIQUE (platform, token_digest),
    FOREIGN KEY (tenant_id, subject)
        REFERENCES companion_accounts (tenant_id, subject),
    CHECK (refreshed_at >= registered_at),
    CHECK (valid_until > refreshed_at),
    CHECK (valid_until <= refreshed_at + INTERVAL '840 hours')
);

CREATE INDEX companion_push_installations_account_idx
    ON companion_push_installations
       (tenant_id, subject, account_revision, valid_until);

COMMIT;
