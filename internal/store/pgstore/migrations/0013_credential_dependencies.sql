-- Dependent accounts (Phase 17): declare the consumers of a credential (Windows
-- Services, Scheduled Tasks, IIS App Pools that log on with the account). When
-- the credential is rotated, pamv1 updates each consumer over WinRM so the
-- rotation does not break production. Deleting the credential cascades.

CREATE TABLE IF NOT EXISTS credential_dependencies (
    id            BIGSERIAL PRIMARY KEY,
    credential_id BIGINT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL,
    host          TEXT NOT NULL,
    port          INT  NOT NULL DEFAULT 5985,
    name          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS credential_dependencies_cred_idx ON credential_dependencies (credential_id);
