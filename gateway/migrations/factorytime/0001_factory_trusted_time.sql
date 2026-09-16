BEGIN;

CREATE TABLE xz_factory_time_schema (
    singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version integer NOT NULL CHECK (version = 1),
    contract_id varchar(64) NOT NULL
        CHECK (contract_id = 'xz-factory-time-db-v1-20260810'),
    applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO xz_factory_time_schema (singleton, version, contract_id)
VALUES (TRUE, 1, 'xz-factory-time-db-v1-20260810');

CREATE TABLE factory_time_stations (
    station_id varchar(128) PRIMARY KEY
        CHECK (station_id ~ '^[A-Za-z0-9:_.-]{1,128}$'),
    fixture_id varchar(128) NOT NULL
        CHECK (fixture_id ~ '^[A-Za-z0-9:_.-]{1,128}$'),
    fixture_version varchar(128) NOT NULL
        CHECK (fixture_version ~ '^[A-Za-z0-9:_.-]{1,128}$'),
    client_certificate_sha256 bytea NOT NULL
        CHECK (octet_length(client_certificate_sha256) = 32),
    enabled boolean NOT NULL DEFAULT FALSE,
    enrolled_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (updated_at >= enrolled_at)
);

CREATE UNIQUE INDEX factory_time_station_certificate_idx
    ON factory_time_stations (client_certificate_sha256);

CREATE TABLE factory_trusted_time_requests (
    request_sha256 bytea PRIMARY KEY CHECK (octet_length(request_sha256) = 32),
    request_id varchar(128) NOT NULL UNIQUE
        CHECK (request_id ~ '^[A-Za-z0-9:_.-]{1,128}$'),
    nonce_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(nonce_sha256) = 32),
    station_id varchar(128) NOT NULL REFERENCES factory_time_stations (station_id),
    fixture_id varchar(128) NOT NULL,
    fixture_version varchar(128) NOT NULL,
    client_certificate_sha256 bytea NOT NULL
        CHECK (octet_length(client_certificate_sha256) = 32),
    policy_sha256 bytea NOT NULL CHECK (octet_length(policy_sha256) = 32),
    policy_id varchar(128) NOT NULL,
    ledger_id varchar(128) NOT NULL,
    plan_sha256 bytea NOT NULL CHECK (octet_length(plan_sha256) = 32),
    plan_id varchar(128) NOT NULL,
	authorization_issued_at timestamptz NOT NULL,
	authorization_expires_at timestamptz NOT NULL,
    attempt_id varchar(128) NOT NULL,
    device_id varchar(15) NOT NULL CHECK (device_id ~ '^xz-[0-9a-f]{12}$'),
    base_mac varchar(17) NOT NULL
        CHECK (base_mac ~ '^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$'),
	authority_key_id varchar(128) NOT NULL
		CHECK (authority_key_id ~ '^[A-Za-z0-9:_.-]{1,128}$'),
    observed_at timestamptz NOT NULL,
    receipt_expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CHECK (authorization_issued_at < authorization_expires_at),
	CHECK (observed_at BETWEEN authorization_issued_at AND authorization_expires_at),
    CHECK (receipt_expires_at > observed_at),
    CHECK (receipt_expires_at <= observed_at + INTERVAL '10 seconds')
);

CREATE INDEX factory_trusted_time_station_observed_idx
    ON factory_trusted_time_requests (station_id, observed_at DESC);
CREATE INDEX factory_trusted_time_attempt_idx
    ON factory_trusted_time_requests (attempt_id, observed_at DESC);

COMMIT;
