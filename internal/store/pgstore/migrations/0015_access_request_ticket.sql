-- ITSM / ticketing gate (Phase 20): an access request may carry a change or
-- incident ticket reference, validated (regex and/or a webhook) before the
-- request is created and recorded in the audit trail.
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS ticket TEXT NOT NULL DEFAULT '';
