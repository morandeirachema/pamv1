-- Richer approval workflows (Phase 21): multi-tier approval chains and scheduled
-- access windows on access requests.
--   required_approvals: how many distinct approvers must approve (default 1).
--   approved_by:        comma-joined set of approvers so far.
--   not_before:         an approved request only becomes active from this time
--                       (a scheduled maintenance window); NULL = active on approval.
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS required_approvals INT NOT NULL DEFAULT 1;
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS approved_by TEXT NOT NULL DEFAULT '';
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS not_before TIMESTAMPTZ;
