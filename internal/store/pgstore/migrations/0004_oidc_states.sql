-- Phase 10 follow-on (HA): shared OIDC login PKCE/nonce state so the auth-code
-- callback can be handled by any replica.

CREATE TABLE IF NOT EXISTS oidc_states (
    state      TEXT PRIMARY KEY,
    verifier   TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS oidc_states_expiry_idx ON oidc_states (expires_at);
