BEGIN;

CREATE TABLE xz_runtime_coordination_schema (
    singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version integer NOT NULL CHECK (version = 1),
    contract_id varchar(64) NOT NULL
        CHECK (contract_id = 'xz-runtime-coordination-v1-20260810'),
    applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO xz_runtime_coordination_schema
    (singleton, version, contract_id)
VALUES (TRUE, 1, 'xz-runtime-coordination-v1-20260810');

-- One row serializes the bounded global Agent inflight decision. It contains no
-- product identity and is never used as a mutable configuration source.
CREATE TABLE runtime_coordination_guard (
    singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO runtime_coordination_guard (singleton) VALUES (TRUE);

CREATE TABLE runtime_coordination_proof_nonces (
    proof_scope smallint NOT NULL CHECK (proof_scope BETWEEN 1 AND 6),
    subject_sha256 bytea NOT NULL CHECK (octet_length(subject_sha256) = 32),
    nonce_sha256 bytea NOT NULL CHECK (octet_length(nonce_sha256) = 32),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (proof_scope, subject_sha256, nonce_sha256)
);

CREATE INDEX runtime_coordination_proof_nonce_expiry_idx
    ON runtime_coordination_proof_nonces (expires_at);

CREATE TABLE runtime_coordination_proof_limits (
    proof_scope smallint NOT NULL CHECK (proof_scope BETWEEN 1 AND 6),
    subject_sha256 bytea NOT NULL CHECK (octet_length(subject_sha256) = 32),
    last_accepted_at timestamptz,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (proof_scope, subject_sha256)
);

CREATE INDEX runtime_coordination_proof_limit_expiry_idx
    ON runtime_coordination_proof_limits (expires_at);

CREATE TABLE runtime_coordination_voice_tokens (
    subject_sha256 bytea NOT NULL CHECK (octet_length(subject_sha256) = 32),
    token_sha256 bytea NOT NULL CHECK (octet_length(token_sha256) = 32),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (subject_sha256, token_sha256)
);

CREATE INDEX runtime_coordination_voice_token_expiry_idx
    ON runtime_coordination_voice_tokens (expires_at);

-- kind 1 is a voice WebSocket owner; kind 2 is an Agent request permit.
-- lease_id fencing prevents an expired owner from deleting a successor lease.
CREATE TABLE runtime_coordination_leases (
    lease_kind smallint NOT NULL CHECK (lease_kind IN (1, 2)),
    subject_sha256 bytea NOT NULL CHECK (octet_length(subject_sha256) = 32),
    lease_id bytea NOT NULL CHECK (octet_length(lease_id) = 16),
    holder_id varchar(64) NOT NULL
        CHECK (holder_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$'),
    acquired_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    renewed_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (lease_kind, subject_sha256)
);

CREATE UNIQUE INDEX runtime_coordination_lease_id_idx
    ON runtime_coordination_leases (lease_id);

CREATE INDEX runtime_coordination_lease_expiry_idx
    ON runtime_coordination_leases (lease_kind, expires_at);

CREATE TABLE runtime_coordination_agent_limits (
    subject_sha256 bytea PRIMARY KEY CHECK (octet_length(subject_sha256) = 32),
    window_started_at timestamptz NOT NULL,
    accepted_requests integer NOT NULL CHECK (accepted_requests BETWEEN 0 AND 600),
    expires_at timestamptz NOT NULL
);

CREATE INDEX runtime_coordination_agent_limit_expiry_idx
    ON runtime_coordination_agent_limits (expires_at);

COMMIT;
