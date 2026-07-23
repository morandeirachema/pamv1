# pamv1 — Backup & Restore Runbook

> **Living document.** Update when the data model or deployment changes. See the
> [change log](#change-log).
>
> Last updated: 2026-07-23 · Reflects: Phases 0–24 + the 2026-07 hardening pass.

> ⚠️ **Alpha · for learning purposes.** pamv1 has not been security-audited and is
> not production-ready.

pamv1 has **two** things to protect, and they must be backed up **separately** —
backing them up together defeats the encryption:

1. **The database** — targets, encrypted credentials, users, sessions, MFA
   enrollments, audit trail. Secrets here are ciphertext.
2. **The vault key** — `PAM_MASTER_KEY` (local KEK) or the KMS key material
   (`vault-transit`). Without it, a database backup is unrecoverable *by design*.

> ⚠️ Keep the key backup in a **different** location/custodian from the database
> backup (e.g. the DB backup in object storage, the key in a secrets manager /
> sealed envelope). Anyone holding both can decrypt every secret.

Also back up, if used (these are **keys** → hold them under separate-custodian
handling like the vault key):

- the **audit-chain keys** `PAM_AUDIT_HMAC_KEY` and `PAM_AUDIT_SIGN_SEED` —
  without the HMAC key you cannot verify the audit chain after a restore, and the
  archived `GET /api/audit/head` ed25519 checkpoints are your only tail-truncation
  anchor;
- the **SSH proxy host key** (`PAM_SSH_HOST_KEY`) and the **ZSP SSH-CA key**
  (`PAM_SSH_CA_KEY`), if configured;
- session recordings (`PAM_RECORDING_DIR`, including the `.chain` head that anchors
  the [recording hash chain](ARCHITECTURE-LOW-LEVEL.md)).

## Back up the database

```bash
# Consistent logical backup, compressed (custom format)
pg_dump --format=custom --no-owner "$PAM_DATABASE_URL" > pamv1-$(date +%F).dump

# Encrypt the dump before it leaves the host (age, gpg, or your KMS)
age -r <recipient> pamv1-*.dump > pamv1-*.dump.age && rm pamv1-*.dump
```

Store the dump in your backup system with retention that satisfies your audit
requirements (NIS2 retention — see [audit retention & SIEM forwarding](NIS2-COMPLIANCE.md#3-audit-retention--siem-forwarding)).

## Back up the vault key

- **Local KEK:** copy `PAM_MASTER_KEY` into your secrets manager (Vault, AWS
  Secrets Manager, 1Password) or a sealed envelope under dual control. Record the
  key version/date. Test recovery periodically.
- **vault-transit KEK:** nothing to export — Vault holds the key. Ensure **Vault
  itself** is backed up (its storage + unseal keys / recovery keys).

## Restore

```bash
# 1. Provision an empty PostgreSQL database and restore the dump
age -d -i <identity> pamv1-*.dump.age | pg_restore --no-owner --dbname "$PAM_DATABASE_URL"

# 2. Provide the SAME vault key the backup was encrypted under
export PAM_MASTER_KEY=<the-backed-up-key>          # or point vault-transit at the same key

# 3. Start pam-server; the schema is applied idempotently on boot
./pam-server
```

Verify by revealing/decrypting one credential (or opening a proxy session) — if
the key matches, it works; if not, the vault key is wrong.

## Key-loss scenarios

- **Lost the vault key, have the DB:** the vaulted secrets are **unrecoverable**.
  Re-onboard credentials (rotate them on the targets and re-vault). This is the
  intended failure mode — the DB alone is useless.
- **Lost the DB, have the key:** restore from the last DB backup; secrets decrypt
  normally.
- **Compromise suspected:** rotate the vault key (`pam-server -rotate-kek`, see the
  [Admin Guide](ADMIN-GUIDE.md#rotating-the-vault-key)), rotate exposed target
  credentials, and review the audit trail (including any `break-glass` rows).

## Hardened PostgreSQL (production)

- Require TLS: `sslmode=verify-full` in `PAM_DATABASE_URL` with a pinned CA.
- Enforce `scram-sha-256` (the bundled compose already does).
- Use a **least-privilege** DB role for pam-server (DML on its tables; not a
  superuser).
- Enable **[pgAudit](https://www.pgaudit.org/)** for database-side audit logging
  (needs an image that bundles the extension; the demo `postgres:17-alpine` does not).
- Managed HA with point-in-time recovery **ships** in `deploy/k8s/postgres-cnpg.yaml`
  (a 3-instance [CloudNativePG](https://cloudnative-pg.io/) cluster with automatic
  failover). Uncomment the `backup.barmanObjectStore` block and point it at object
  storage to enable continuous backup + PITR.

## Change log

| Date | Change |
|---|---|
| 2026-07-23 | Aligned with the doc set (standard header, change log); added the audit-chain keys and ZSP SSH-CA key to the backup inventory; corrected the CloudNativePG PITR note (ships in `deploy/k8s/postgres-cnpg.yaml`); fixed the NIS2 retention cross-link |
| 2026-07-19 | Initial backup & restore runbook (Phase 5): separate DB and vault-key backup, restore procedure, key-loss scenarios, hardened Postgres |
