-- Track the last-used TOTP time-step per user so a code cannot be replayed
-- within the validation skew window.
ALTER TABLE mfa_enrollments ADD COLUMN IF NOT EXISTS last_totp_step BIGINT NOT NULL DEFAULT 0;
