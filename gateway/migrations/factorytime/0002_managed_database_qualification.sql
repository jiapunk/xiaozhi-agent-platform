BEGIN;

CREATE TABLE xz_managed_database_qualification_schema (
    singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version integer NOT NULL CHECK (version = 1),
    contract_id varchar(64) NOT NULL
        CHECK (contract_id = 'xz-managed-db-qualification-v1-20260810'),
    applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO xz_managed_database_qualification_schema
    (singleton, version, contract_id)
VALUES (TRUE, 1, 'xz-managed-db-qualification-v1-20260810');

CREATE TABLE managed_database_qualification_events (
    qualification_id varchar(64) NOT NULL
        CHECK (qualification_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$'),
    run_nonce bytea NOT NULL CHECK (octet_length(run_nonce) = 16),
    event_sequence bigint NOT NULL
        CHECK (event_sequence BETWEEN 1 AND 100000),
    phase varchar(20) NOT NULL CHECK (phase IN (
        'pre', 'restore-marker', 'restore-exclusion', 'heartbeat', 'post')),
    payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256) = 32),
    committed_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (qualification_id, run_nonce, event_sequence)
);

CREATE UNIQUE INDEX managed_database_qualification_singleton_phase_idx
    ON managed_database_qualification_events
       (qualification_id, run_nonce, phase)
    WHERE phase IN ('pre', 'restore-marker', 'restore-exclusion', 'post');

CREATE INDEX managed_database_qualification_time_idx
    ON managed_database_qualification_events
       (qualification_id, run_nonce, committed_at, event_sequence);

CREATE FUNCTION reject_managed_database_qualification_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'managed database qualification events are append-only'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER managed_database_qualification_events_append_only
BEFORE UPDATE OR DELETE ON managed_database_qualification_events
FOR EACH ROW
EXECUTE FUNCTION reject_managed_database_qualification_event_mutation();

COMMIT;
