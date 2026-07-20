-- Phase 12: custom permission profiles — named capability sets assignable to
-- users as an alternative to the four built-in roles. capabilities is a
-- comma-separated list of stable capability names (see internal/auth).
CREATE TABLE IF NOT EXISTS profiles (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    capabilities TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
