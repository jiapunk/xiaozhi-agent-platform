BEGIN;

CREATE TABLE xz_ownership_schema (
    singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version integer NOT NULL CHECK (version = 3),
    contract_id varchar(64) NOT NULL
        CHECK (contract_id = 'xz-owner-v3-20260809-lifecycle'),
    applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO xz_ownership_schema (singleton, version, contract_id)
VALUES (TRUE, 3, 'xz-owner-v3-20260809-lifecycle');

CREATE TABLE ownership_app_nonces (
    tenant_id varchar(128) NOT NULL
        CHECK (tenant_id ~ '^[A-Za-z0-9:_.-]{1,128}$'),
    owner_id varchar(128) NOT NULL
        CHECK (owner_id ~ '^[A-Za-z0-9:_.-]{1,128}$'),
    app_nonce varchar(22) NOT NULL
        CHECK (app_nonce ~ '^[A-Za-z0-9_-]{22}$'),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, owner_id, app_nonce)
);

CREATE INDEX ownership_app_nonces_expiry_idx
    ON ownership_app_nonces (expires_at);

CREATE TABLE ownership_claims (
    request_id varchar(22) PRIMARY KEY
        CHECK (request_id ~ '^[A-Za-z0-9_-]{22}$'),
    tenant_id varchar(128) NOT NULL
        CHECK (tenant_id ~ '^[A-Za-z0-9:_.-]{1,128}$'),
    owner_id varchar(128) NOT NULL
        CHECK (owner_id ~ '^[A-Za-z0-9:_.-]{1,128}$'),
    device_id varchar(64) NOT NULL
        CHECK (device_id ~ '^[A-Za-z0-9:_.-]{1,64}$'),
    claim_digest bytea NOT NULL UNIQUE
        CHECK (octet_length(claim_digest) = 32),
    status varchar(8) NOT NULL CHECK (status IN ('pending', 'bound')),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    CHECK (expires_at > created_at)
);

CREATE INDEX ownership_claims_expiry_idx
    ON ownership_claims (expires_at);
CREATE INDEX ownership_claims_device_idx
    ON ownership_claims (device_id);

CREATE TABLE device_owners (
    device_id varchar(64) PRIMARY KEY
        CHECK (device_id ~ '^[A-Za-z0-9:_.-]{1,64}$'),
    tenant_id varchar(128) NOT NULL
        CHECK (tenant_id ~ '^[A-Za-z0-9:_.-]{1,128}$'),
    owner_id varchar(128) NOT NULL
        CHECK (owner_id ~ '^[A-Za-z0-9:_.-]{1,128}$'),
    binding_id varchar(22) NOT NULL UNIQUE
        CHECK (binding_id ~ '^[A-Za-z0-9_-]{22}$'),
    binding_revision bigint NOT NULL
        CHECK (binding_revision BETWEEN 1 AND 4294967295),
    status varchar(8) NOT NULL CHECK (status IN ('active', 'released')),
    bound_at timestamptz NOT NULL
);

CREATE TABLE device_ownership_events (
    event_id varchar(22) PRIMARY KEY
        CHECK (event_id ~ '^[A-Za-z0-9_-]{22}$'),
    event_type varchar(16) NOT NULL CHECK (event_type IN ('bind', 'release')),
    device_id varchar(64) NOT NULL REFERENCES device_owners (device_id),
    tenant_id varchar(128) NOT NULL,
    owner_id varchar(128) NOT NULL,
    binding_id varchar(22) NOT NULL
        CHECK (binding_id ~ '^[A-Za-z0-9_-]{22}$'),
    binding_revision bigint NOT NULL
        CHECK (binding_revision BETWEEN 1 AND 4294967295),
    request_id varchar(22)
        CHECK (request_id ~ '^[A-Za-z0-9_-]{22}$'),
    occurred_at timestamptz NOT NULL,
    UNIQUE (device_id, binding_revision)
);

COMMIT;
