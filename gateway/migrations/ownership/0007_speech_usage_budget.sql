BEGIN;

CREATE TABLE xz_speech_usage_budget_schema (
    singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version integer NOT NULL CHECK (version = 1),
    contract_id varchar(64) NOT NULL
        CHECK (contract_id = 'xz-speech-usage-budget-v1-20260811'),
    applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO xz_speech_usage_budget_schema
    (singleton, version, contract_id)
VALUES (TRUE, 1, 'xz-speech-usage-budget-v1-20260811');

-- Profile IDs are immutable once observed. Zero is allowed only for a TTS
-- dimension that the signed upstream billing contract does not use.
CREATE TABLE speech_usage_pricing_profiles (
    pricing_profile_id varchar(64) PRIMARY KEY
        CHECK (pricing_profile_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$'),
    stt_microusd_per_million_audio_ms bigint NOT NULL
        CHECK (stt_microusd_per_million_audio_ms BETWEEN 1 AND 1000000000000),
    tts_microusd_per_million_characters bigint NOT NULL
        CHECK (tts_microusd_per_million_characters BETWEEN 0 AND 1000000000000),
    tts_microusd_per_million_output_audio_ms bigint NOT NULL
        CHECK (tts_microusd_per_million_output_audio_ms BETWEEN 0 AND 1000000000000),
    CHECK (tts_microusd_per_million_characters > 0 OR
           tts_microusd_per_million_output_audio_ms > 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- This aggregate enforces one UTC-day budget across STT, TTS and every pricing
-- profile. subject_hmac uses a speech-only HMAC domain/key; no raw product,
-- account, transcript, request text, audio, URL or provider payload is stored.
CREATE TABLE speech_usage_budget_daily (
    usage_day date NOT NULL,
    subject_hmac bytea NOT NULL CHECK (octet_length(subject_hmac) = 32),
    committed_cost_microusd bigint NOT NULL DEFAULT 0
        CHECK (committed_cost_microusd BETWEEN 0 AND 1000000000000000),
    uncertain_cost_microusd bigint NOT NULL DEFAULT 0
        CHECK (uncertain_cost_microusd BETWEEN 0 AND 1000000000000000),
    reserved_cost_microusd bigint NOT NULL DEFAULT 0
        CHECK (reserved_cost_microusd BETWEEN 0 AND 1000000000000000),
    settled_reservations bigint NOT NULL DEFAULT 0 CHECK (settled_reservations >= 0),
    uncertain_reservations bigint NOT NULL DEFAULT 0 CHECK (uncertain_reservations >= 0),
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (usage_day, subject_hmac)
);

CREATE TABLE speech_usage_profile_daily (
    usage_day date NOT NULL,
    subject_hmac bytea NOT NULL CHECK (octet_length(subject_hmac) = 32),
    pricing_profile_id varchar(64) NOT NULL REFERENCES speech_usage_pricing_profiles,
    committed_stt_audio_ms bigint NOT NULL DEFAULT 0 CHECK (committed_stt_audio_ms >= 0),
    committed_tts_characters bigint NOT NULL DEFAULT 0 CHECK (committed_tts_characters >= 0),
    committed_tts_output_audio_ms bigint NOT NULL DEFAULT 0
        CHECK (committed_tts_output_audio_ms >= 0),
    committed_cost_microusd bigint NOT NULL DEFAULT 0
        CHECK (committed_cost_microusd BETWEEN 0 AND 1000000000000000),
    uncertain_cost_microusd bigint NOT NULL DEFAULT 0
        CHECK (uncertain_cost_microusd BETWEEN 0 AND 1000000000000000),
    settled_reservations bigint NOT NULL DEFAULT 0 CHECK (settled_reservations >= 0),
    uncertain_reservations bigint NOT NULL DEFAULT 0 CHECK (uncertain_reservations >= 0),
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (usage_day, subject_hmac, pricing_profile_id),
    FOREIGN KEY (usage_day, subject_hmac)
        REFERENCES speech_usage_budget_daily (usage_day, subject_hmac)
);

CREATE TABLE speech_usage_reservations (
    reservation_id bytea PRIMARY KEY CHECK (octet_length(reservation_id) = 16),
    usage_day date NOT NULL,
    subject_hmac bytea NOT NULL CHECK (octet_length(subject_hmac) = 32),
    pricing_profile_id varchar(64) NOT NULL REFERENCES speech_usage_pricing_profiles,
    stt_audio_ms_limit bigint NOT NULL
        CHECK (stt_audio_ms_limit BETWEEN 0 AND 86400000),
    tts_characters_limit bigint NOT NULL
        CHECK (tts_characters_limit BETWEEN 0 AND 86400000),
    tts_output_audio_ms_limit bigint NOT NULL
        CHECK (tts_output_audio_ms_limit BETWEEN 0 AND 86400000),
    CHECK ((stt_audio_ms_limit > 0 AND tts_characters_limit = 0 AND
            tts_output_audio_ms_limit = 0) OR
           (stt_audio_ms_limit = 0 AND tts_characters_limit > 0)),
    reserved_cost_microusd bigint NOT NULL
        CHECK (reserved_cost_microusd BETWEEN 1 AND 1000000000000000),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamptz NOT NULL,
    FOREIGN KEY (usage_day, subject_hmac)
        REFERENCES speech_usage_budget_daily (usage_day, subject_hmac),
    FOREIGN KEY (usage_day, subject_hmac, pricing_profile_id)
        REFERENCES speech_usage_profile_daily
            (usage_day, subject_hmac, pricing_profile_id)
);

CREATE INDEX speech_usage_reservation_expiry_idx
    ON speech_usage_reservations (expires_at);
CREATE INDEX speech_usage_reservation_subject_idx
    ON speech_usage_reservations (subject_hmac, expires_at);

COMMIT;
