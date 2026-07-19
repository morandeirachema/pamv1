-- Phase 7 follow-on: exclusive, time-boxed credential checkout/check-in leases.

CREATE TABLE IF NOT EXISTS checkouts (
    id             BIGSERIAL PRIMARY KEY,
    credential_id  BIGINT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    target_id      BIGINT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    holder         TEXT NOT NULL,
    reason         TEXT NOT NULL DEFAULT '',
    checked_out_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL,
    returned_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS checkouts_active_idx
    ON checkouts (credential_id) WHERE returned_at IS NULL;
