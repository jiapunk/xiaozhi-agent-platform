BEGIN;

CREATE TABLE xz_agent_usage_budget_schema (
    singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version integer NOT NULL CHECK (version = 1),
    contract_id varchar(64) NOT NULL
        CHECK (contract_id = 'xz-agent-usage-budget-v1-20260811'),
    applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO xz_agent_usage_budget_schema
    (singleton, version, contract_id)
VALUES (TRUE, 1, 'xz-agent-usage-budget-v1-20260811');

-- A profile ID is immutable once observed. Reusing a profile ID with new rates
-- is rejected by the serving adapter rather than silently corrupting cost data.
CREATE TABLE agent_usage_pricing_profiles (
    pricing_profile_id varchar(64) PRIMARY KEY
        CHECK (pricing_profile_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$'),
    input_microusd_per_million_tokens bigint NOT NULL
        CHECK (input_microusd_per_million_tokens BETWEEN 1 AND 1000000000000),
    output_microusd_per_million_tokens bigint NOT NULL
        CHECK (output_microusd_per_million_tokens BETWEEN 1 AND 1000000000000),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- This row is the budget enforcement aggregate across every pricing profile.
-- subject_hmac is a purpose-specific HMAC and cannot be joined to other digest
-- tables. No product identifier, prompt, output, URL, or provider payload exists.
CREATE TABLE agent_usage_budget_daily (
    usage_day date NOT NULL,
    subject_hmac bytea NOT NULL CHECK (octet_length(subject_hmac) = 32),
    committed_cost_microusd bigint NOT NULL DEFAULT 0
        CHECK (committed_cost_microusd BETWEEN 0 AND 1000000000000000),
    uncertain_cost_microusd bigint NOT NULL DEFAULT 0
        CHECK (uncertain_cost_microusd BETWEEN 0 AND 1000000000000000),
    reserved_cost_microusd bigint NOT NULL DEFAULT 0
        CHECK (reserved_cost_microusd BETWEEN 0 AND 1000000000000000),
    settled_requests bigint NOT NULL DEFAULT 0 CHECK (settled_requests >= 0),
    uncertain_requests bigint NOT NULL DEFAULT 0 CHECK (uncertain_requests >= 0),
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (usage_day, subject_hmac)
);

-- This subordinate aggregate preserves token and cost attribution by immutable
-- pricing profile while the table above prevents profile rotation from resetting
-- the daily subject budget.
CREATE TABLE agent_usage_profile_daily (
    usage_day date NOT NULL,
    subject_hmac bytea NOT NULL CHECK (octet_length(subject_hmac) = 32),
    pricing_profile_id varchar(64) NOT NULL REFERENCES agent_usage_pricing_profiles,
    committed_input_tokens bigint NOT NULL DEFAULT 0 CHECK (committed_input_tokens >= 0),
    committed_output_tokens bigint NOT NULL DEFAULT 0 CHECK (committed_output_tokens >= 0),
    committed_cost_microusd bigint NOT NULL DEFAULT 0
        CHECK (committed_cost_microusd BETWEEN 0 AND 1000000000000000),
    uncertain_cost_microusd bigint NOT NULL DEFAULT 0
        CHECK (uncertain_cost_microusd BETWEEN 0 AND 1000000000000000),
    settled_requests bigint NOT NULL DEFAULT 0 CHECK (settled_requests >= 0),
    uncertain_requests bigint NOT NULL DEFAULT 0 CHECK (uncertain_requests >= 0),
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (usage_day, subject_hmac, pricing_profile_id),
    FOREIGN KEY (usage_day, subject_hmac)
        REFERENCES agent_usage_budget_daily (usage_day, subject_hmac)
);

CREATE TABLE agent_usage_reservations (
    reservation_id bytea PRIMARY KEY CHECK (octet_length(reservation_id) = 16),
    usage_day date NOT NULL,
    subject_hmac bytea NOT NULL CHECK (octet_length(subject_hmac) = 32),
    pricing_profile_id varchar(64) NOT NULL REFERENCES agent_usage_pricing_profiles,
    input_token_limit bigint NOT NULL CHECK (input_token_limit BETWEEN 1 AND 2000000),
    output_token_limit bigint NOT NULL CHECK (output_token_limit BETWEEN 1 AND 2000000),
    reserved_cost_microusd bigint NOT NULL
        CHECK (reserved_cost_microusd BETWEEN 1 AND 1000000000000000),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamptz NOT NULL,
    FOREIGN KEY (usage_day, subject_hmac)
        REFERENCES agent_usage_budget_daily (usage_day, subject_hmac),
    FOREIGN KEY (usage_day, subject_hmac, pricing_profile_id)
        REFERENCES agent_usage_profile_daily
            (usage_day, subject_hmac, pricing_profile_id)
);

CREATE INDEX agent_usage_reservation_expiry_idx
    ON agent_usage_reservations (expires_at);
CREATE INDEX agent_usage_reservation_subject_idx
    ON agent_usage_reservations (subject_hmac, expires_at);

COMMIT;
