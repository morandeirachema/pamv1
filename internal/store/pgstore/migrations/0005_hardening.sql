-- Hardening: make credential-checkout exclusivity atomic, index audit exports,
-- and drop indexes made redundant by UNIQUE constraints.

-- Exactly one ACTIVE (unreturned) checkout per credential. CreateCheckout
-- auto-closes expired-but-unreturned leases before inserting, so an expired
-- lease does not block a new one; concurrent inserts race on this index instead
-- of the old check-then-insert, which could grant two holders the same secret.
DROP INDEX IF EXISTS checkouts_active_idx;
CREATE UNIQUE INDEX IF NOT EXISTS checkouts_one_active_idx
    ON checkouts (credential_id) WHERE returned_at IS NULL;

-- ExportAudit filters by a ts range over an append-only table that grows without
-- bound; the only prior index was on (action).
CREATE INDEX IF NOT EXISTS audit_events_ts_idx ON audit_events (ts);

-- users.token_hash and sessions.token_hash are already UNIQUE (a unique btree);
-- the extra non-unique indexes are redundant maintenance cost.
DROP INDEX IF EXISTS users_token_hash_idx;
DROP INDEX IF EXISTS sessions_token_hash_idx;
