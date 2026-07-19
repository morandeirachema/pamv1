-- Phase 8 (OT): per-target approval gate + the 4-eyes access-request workflow.

ALTER TABLE targets
    ADD COLUMN IF NOT EXISTS require_approval BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS access_requests (
    id         BIGSERIAL PRIMARY KEY,
    requester  TEXT NOT NULL,
    target_id  BIGINT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    reason     TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | denied
    approver   TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS access_requests_lookup_idx
    ON access_requests (requester, target_id, status);
