-- Access certification / attestation campaigns (Phase 19): a point-in-time
-- review of who has access to what. A campaign snapshots the current access
-- grants (target grants + safe members) as items; a reviewer certifies or
-- revokes each. Deleting a campaign cascades its items.

CREATE TABLE IF NOT EXISTS campaigns (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    due_at     TIMESTAMPTZ,
    status     TEXT NOT NULL DEFAULT 'open',
    closed_at  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS campaign_items (
    id           BIGSERIAL PRIMARY KEY,
    campaign_id  BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,
    ref_id       BIGINT NOT NULL,
    subject_type TEXT NOT NULL,
    subject      TEXT NOT NULL,
    detail       TEXT NOT NULL DEFAULT '',
    decision     TEXT NOT NULL DEFAULT 'pending',
    decided_by   TEXT NOT NULL DEFAULT '',
    decided_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS campaign_items_campaign_idx ON campaign_items (campaign_id);
