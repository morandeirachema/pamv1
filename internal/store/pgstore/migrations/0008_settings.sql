-- Phase 12: persisted configuration overrides for identity backends, SSO, and
-- operational policy. Values for secret settings (bind passwords, client
-- secrets) are stored vault-encrypted (secret = TRUE).
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    secret     BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
