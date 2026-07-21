-- Safes (Phase 17): named containers that group targets and delegate who may
-- access them. A safe member may connect to every target placed in the safe —
-- an authorization path alongside per-target grants — and a can_manage member
-- is a delegated safe administrator. Deleting a safe unassigns its targets
-- (ON DELETE SET NULL) rather than deleting them.

CREATE TABLE IF NOT EXISTS safes (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safe_members (
    id           BIGSERIAL PRIMARY KEY,
    safe_id      BIGINT NOT NULL REFERENCES safes(id) ON DELETE CASCADE,
    subject_type TEXT NOT NULL,
    subject      TEXT NOT NULL,
    can_manage   BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (safe_id, subject_type, subject)
);

CREATE INDEX IF NOT EXISTS safe_members_safe_idx ON safe_members (safe_id);

ALTER TABLE targets ADD COLUMN IF NOT EXISTS safe_id BIGINT REFERENCES safes(id) ON DELETE SET NULL;
