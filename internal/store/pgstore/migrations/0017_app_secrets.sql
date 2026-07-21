-- Phase 24 (Tier-4): application-secrets API — Conjur-style secret delivery to
-- non-agent applications.

-- Application identity keys: bearer keys (only the SHA-256 hash is stored) that
-- let an application retrieve the specific secrets it has been granted. owner is
-- the accountable human/team recorded in the audit trail.
CREATE TABLE IF NOT EXISTS app_keys (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    owner      TEXT NOT NULL DEFAULT '',
    token_hash TEXT NOT NULL UNIQUE,
    disabled   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-app secret grants (default-deny): an app may fetch a credential's secret
-- only if it has an explicit grant. Both foreign keys cascade, so revoking an app
-- or deleting a credential removes the corresponding grants.
CREATE TABLE IF NOT EXISTS app_secret_grants (
    id            BIGSERIAL PRIMARY KEY,
    app_id        BIGINT NOT NULL REFERENCES app_keys(id) ON DELETE CASCADE,
    credential_id BIGINT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (app_id, credential_id)
);

CREATE INDEX IF NOT EXISTS app_secret_grants_app_idx ON app_secret_grants(app_id);
