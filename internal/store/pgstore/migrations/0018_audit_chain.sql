-- Optional tamper-evident hash chain over the primary audit trail. The columns
-- are nullable and additive: existing rows and deployments are unaffected, and
-- they stay NULL unless an audit HMAC key is configured (PAM_AUDIT_HMAC_KEY),
-- which activates chaining for subsequently appended events.
--   hmac      = HMAC-SHA256(key, prev_hash || canonical(actor, action, detail))
--   prev_hash = the previous row's hmac (the chain link)
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS prev_hash BYTEA;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS hmac BYTEA;
