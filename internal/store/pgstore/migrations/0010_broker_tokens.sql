-- Phase 13: single-use resume tokens for approval-parked broker tool calls.
--
-- When a tool call is parked for human approval the broker mints an opaque
-- token; only its SHA-256 hash (jti) is stored. The agent presents the token to
-- resume and collect the post-approval result exactly once — consumption is an
-- atomic UPDATE guarded on used_at IS NULL AND expires_at > now(), so a replayed
-- token can never collect a result twice.
CREATE TABLE IF NOT EXISTS broker_tokens (
    jti        TEXT PRIMARY KEY,
    call_id    TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS broker_tokens_expires_idx ON broker_tokens (expires_at);
