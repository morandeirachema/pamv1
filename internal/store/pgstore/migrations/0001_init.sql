CREATE TABLE IF NOT EXISTS targets (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    host       TEXT NOT NULL,
    port       INT  NOT NULL DEFAULT 22,
    os_type    TEXT NOT NULL,
    protocol   TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS credentials (
    id          BIGSERIAL PRIMARY KEY,
    target_id   BIGINT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    username    TEXT NOT NULL,
    secret_type TEXT NOT NULL DEFAULT 'password',
    secret_enc  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS credentials_target_idx ON credentials (target_id);

CREATE TABLE IF NOT EXISTS target_grants (
    id           BIGSERIAL PRIMARY KEY,
    target_id    BIGINT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    subject_type TEXT NOT NULL,
    subject      TEXT NOT NULL,
    UNIQUE (target_id, subject_type, subject)
);

CREATE INDEX IF NOT EXISTS target_grants_target_idx ON target_grants (target_id);

CREATE TABLE IF NOT EXISTS audit_events (
    id     BIGSERIAL PRIMARY KEY,
    ts     TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS audit_events_action_idx ON audit_events (action);

CREATE TABLE IF NOT EXISTS users (
    id         BIGSERIAL PRIMARY KEY,
    username   TEXT NOT NULL UNIQUE,
    role       TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS users_token_hash_idx ON users (token_hash);

CREATE TABLE IF NOT EXISTS sessions (
    id         BIGSERIAL PRIMARY KEY,
    username   TEXT NOT NULL,
    role       TEXT NOT NULL,
    scope      TEXT NOT NULL DEFAULT '',
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_token_hash_idx ON sessions (token_hash);

CREATE TABLE IF NOT EXISTS mfa_enrollments (
    username   TEXT PRIMARY KEY,
    secret_enc TEXT NOT NULL,
    confirmed  BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    username  TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    PRIMARY KEY (username, code_hash)
);
