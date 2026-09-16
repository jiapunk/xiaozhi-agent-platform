BEGIN;

CREATE TABLE xz_service_entitlement_schema (
    singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version integer NOT NULL CHECK (version = 1),
    contract_id varchar(64) NOT NULL
        CHECK (contract_id = 'xz-service-entitlement-db-v1-20260811'),
    applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO xz_service_entitlement_schema
    (singleton, version, contract_id)
VALUES (TRUE, 1, 'xz-service-entitlement-db-v1-20260811');

CREATE TABLE service_entitlement_events (
    source_event_id varchar(128) PRIMARY KEY
        CHECK (source_event_id ~ '^[A-Za-z0-9:_.-]{1,128}$'),
    tenant_id varchar(128) NOT NULL,
    subject varchar(128) NOT NULL,
    previous_revision bigint NOT NULL
        CHECK (previous_revision BETWEEN 0 AND 4294967294),
    revision bigint NOT NULL
        CHECK (revision BETWEEN 1 AND 4294967295),
    update_digest bytea NOT NULL CHECK (octet_length(update_digest) = 32),
    plan_id varchar(64) NOT NULL
        CHECK (plan_id ~ '^[A-Za-z0-9:_.-]{1,64}$'),
    state varchar(10) NOT NULL CHECK (state IN (
        'active', 'grace', 'suspended', 'ended')),
    voice_enabled boolean NOT NULL,
    agent_enabled boolean NOT NULL,
    access_until timestamptz NOT NULL,
    applied_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, subject)
        REFERENCES companion_accounts (tenant_id, subject),
    UNIQUE (tenant_id, subject, revision),
    CHECK (revision = previous_revision + 1),
    CHECK (
        (state IN ('active', 'grace') AND
         (voice_enabled OR agent_enabled)) OR
        (state IN ('suspended', 'ended') AND
         NOT voice_enabled AND NOT agent_enabled)
    )
);

CREATE TABLE service_entitlements (
    tenant_id varchar(128) NOT NULL,
    subject varchar(128) NOT NULL,
    revision bigint NOT NULL
        CHECK (revision BETWEEN 1 AND 4294967295),
    plan_id varchar(64) NOT NULL
        CHECK (plan_id ~ '^[A-Za-z0-9:_.-]{1,64}$'),
    state varchar(10) NOT NULL CHECK (state IN (
        'active', 'grace', 'suspended', 'ended')),
    voice_enabled boolean NOT NULL,
    agent_enabled boolean NOT NULL,
    access_until timestamptz NOT NULL,
    source_event_id varchar(128) NOT NULL UNIQUE
        REFERENCES service_entitlement_events (source_event_id),
    applied_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, subject),
    FOREIGN KEY (tenant_id, subject)
        REFERENCES companion_accounts (tenant_id, subject),
    CHECK (updated_at >= applied_at),
    CHECK (
        (state IN ('active', 'grace') AND
         (voice_enabled OR agent_enabled)) OR
        (state IN ('suspended', 'ended') AND
         NOT voice_enabled AND NOT agent_enabled)
    )
);

CREATE INDEX service_entitlements_access_idx
    ON service_entitlements (state, access_until);
CREATE INDEX service_entitlement_events_account_idx
    ON service_entitlement_events (tenant_id, subject, revision);

COMMIT;
