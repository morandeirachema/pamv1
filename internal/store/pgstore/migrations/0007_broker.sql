-- Phase 13: AI-agent access broker.

-- Agent identity keys: bearer keys (only the SHA-256 hash is stored) that let an
-- AI agent request brokered tool calls, never a credential. owner is the
-- accountable human/service recorded in the agent's audit entries.
CREATE TABLE IF NOT EXISTS agent_keys (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    owner      TEXT NOT NULL DEFAULT '',
    token_hash TEXT NOT NULL UNIQUE,
    disabled   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Broker audit: a tamper-evident, keyed-HMAC hash-chained log kept separate from
-- the general audit_events trail. Each row's hmac covers the previous row's hmac
-- (prev_hash), so any edit or truncation breaks the chain. The broker is the sole
-- writer, so rows chain in id order.
CREATE TABLE IF NOT EXISTS broker_audit_events (
    id           BIGSERIAL PRIMARY KEY,
    ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor        TEXT NOT NULL,
    on_behalf_of TEXT NOT NULL DEFAULT '',
    actor_chain  TEXT NOT NULL DEFAULT '',
    action       TEXT NOT NULL,
    detail       TEXT NOT NULL DEFAULT '',
    scope        TEXT NOT NULL DEFAULT '',
    prev_hash    BYTEA NOT NULL,
    hmac         BYTEA NOT NULL
);
