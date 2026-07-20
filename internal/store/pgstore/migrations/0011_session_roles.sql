-- Multi-group directory logins: persist the full set of matched roles so the
-- resolved principal gets the UNION of their capabilities and role-grants (a
-- user in both the "users" and "auditors" groups keeps `connect`, not just the
-- highest role). Empty for a single-role login.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS roles TEXT NOT NULL DEFAULT '';
