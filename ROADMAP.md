# pamv1 Roadmap

Guiding principle: **fully functional at every step**. Each phase ships something that runs end-to-end, passes tests, and deploys via IaC. Phases build on each other but stay independently releasable.

Status: ✅ done · 🚧 in progress · ⬜ planned

---

## Phase 0 — Project foundation ✅

- [x] Public open-source repo ([github.com/morandeirachema/pamv1](https://github.com/morandeirachema/pamv1)), Apache-2.0 license
- [x] Go module, standard layout (`cmd/`, `internal/`), CI on GitHub Actions (fmt, vet, build, race tests, Docker build)

## Phase 1 — Core: vault, inventory, audit, portal ✅

- [x] **Hardened vault**: AES-256-GCM, random nonce per secret, AAD binding to owning target, versioned token format (`v1:`) ready for key rotation
- [x] **Target inventory**: Linux/Windows machines (ssh / winrm / rdp) via REST API
- [x] **Credential store**: secrets encrypted before touching the DB; JSON encoder can never leak them; audited `reveal` as the temporary escape hatch
- [x] **Audit trail**: append-only events for every sensitive action
- [x] **Break-glass v1**: sealed emergency key (only its SHA-256 in config), loud `break-glass` actor, every use audited + logged
- [x] **Portal**: AS/400 / 5250-style terminal UI (Sign On, Work-with screens, F-keys) — deliberately austere so admins feel the gravity of the system
- [x] **Storage**: PostgreSQL (pgx) with embedded idempotent schema; in-memory store for tests/demo
- [x] **Deploy as IaC**: Dockerfile (distroless, non-root), docker-compose with hardened Postgres (scram-sha-256), K8s manifests (restricted PSS), Terraform module

## Phase 2 — Session proxy with JIT credential injection (Linux/SSH) 🚧

The flagship: users connect *through* pamv1, never holding the credential.

- [x] SSH gateway (`golang.org/x/crypto/ssh`): user opens `ssh user@target@pam-proxy`, proxy authenticates the user, pulls the credential from the vault and injects it **just-in-time** into the upstream connection
- [x] Session recording (asciicast v2) stored with a SHA-256 written to the audit trail (tamper evidence)
- [x] Per-session audit events (start, record, end, denied, error)
- [ ] Policy engine / per-target authorization (currently any valid API key can reach any target)
- [ ] Live session listing and kill-switch in portal/API
- [ ] Hash-chain the recordings (not just per-file hash)
- [ ] Disable `reveal` by policy once proxy path is the norm (reveal becomes break-glass-only)

## Phase 3 — Identity & access control 🚧

### 3a — RBAC with four profiles ✅

- [x] Four roles — **admin**, **user**, **auditor**, **approver** — with an authoritative role→capability matrix (`internal/auth`)
- [x] Per-user access tokens (stored as SHA-256 only), minted by an admin via `POST /api/users`
- [x] Enforcement in the REST API (per-route capability) and the SSH proxy (`CapConnect`); every denial audited (`authz.denied` / `session.denied`)
- [x] Audit now attributes real usernames; portal tolerates per-role 403s
- [ ] `approver`'s approval endpoints (access-request workflow) — arrives with the OT/approval phase

### 3b — Active Directory connector 🚧

- [x] LDAP/LDAPS bind against AD ([go-ldap](https://github.com/go-ldap/ldap)): service-account search + user bind to verify the password
- [x] AD groups → the four pamv1 roles (highest privilege wins), via `PAM_LDAP_GROUP_*`
- [x] Portal Sign On with AD username + password; short-lived **session tokens** (`POST /api/login`, `POST /api/logout`) that work in the portal and the SSH proxy
- [x] **MFA: TOTP** (RFC 6238) enrollment + verification (`internal/mfa`), secret stored vault-encrypted, enforced on `/api/login`; self-service `/api/mfa/*` (NIS2 Art. 21(2)(j))
- [x] **Microsoft Entra ID (Azure AD)** login: OAuth2 (ROPC) against the tenant, Entra app roles / groups → the four roles; composable with LDAP via a chain authenticator; sovereign-cloud authority host
- [ ] Entra OIDC auth-code flow + JWKS signature validation (production hardening over ROPC)
- [ ] Optional Kerberos bind
- [ ] Enforce-MFA-for-all policy + recovery codes (currently per-user opt-in)
- [x] Local emergency admin kept for AD-down scenarios (bootstrap key + break-glass)

## Phase 4 — Windows targets ⬜

- [ ] WinRM command execution with JIT credentials
- [ ] RDP access via gateway (Guacamole-style flow or RD Gateway integration), recorded
- [ ] AD-joined target support: use domain service accounts from the vault

## Phase 5 — Hardening: database, vault, transport ⬜

- [x] **Envelope encryption** with a pluggable KEK: per-secret data keys wrapped by a Key Encryption Key; `local` KEK (dev/test) + **HashiCorp Vault Transit** KEK (production, KEK never leaves the KMS)
- [ ] More KEK providers on the same interface: AWS KMS, PKCS#11 HSM
- [ ] Vault key rotation (re-encrypt job; rotate the KEK / re-wrap data keys)
- [ ] Postgres TLS (verify-full), scram-sha-256 enforced, least-privilege DB role, [pgAudit](https://www.pgaudit.org/)
- [ ] Versioned migrations (tern/goose) replacing startup schema
- [ ] HTTPS with managed certs; strict headers; rate limiting on auth endpoints
- [ ] Backup/restore runbook with encrypted backups

## Phase 6 — Break-glass v2 ⬜

- [ ] M-of-N quorum unseal (Shamir secret sharing) for emergency access
- [ ] Auto-expiring break-glass sessions + forced credential rotation after use
- [ ] Real-time alerting (webhook/email/syslog) on any break-glass event
- [ ] Documented offline procedure (sealed envelopes, dual control, periodic drills)

## Phase 7 — Credential lifecycle ⬜

- [ ] Automatic rotation after each proxied session and on schedule
- [ ] Rotation connectors: Linux (SSH `chpasswd`/key replacement), AD (LDAPS password change), Windows local (WinRM)
- [ ] Credential checkout/check-in with max lease time
- [ ] Discovery: scan AD/OU or IP ranges to onboard targets
- [ ] **Account reconciliation (out-of-sync detection & remediation):**
  - [ ] Credential reconciliation — verify each vaulted secret still authenticates to its target; flag out-of-band changes and remediate per policy (rotate to a PAM-managed secret, or re-vault the current one)
  - [ ] Identity reconciliation — sync against AD/Entra: revoke pamv1 access for disabled/deleted directory users; surface orphaned/rogue accounts on targets not managed by the vault
  - [ ] Reconciliation report + optional auto-remediation, scheduled and on-demand, fully audited

## Phase 8 — OT adaptation ⬜

Designed for industrial environments ([IEC 62443](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards), Purdue model):

- [ ] Deployment pattern for the industrial DMZ (level 3.5): proxy is the *only* path from IT to OT cells
- [ ] Air-gap/offline mode: no external calls, local time-boxed vendor access workflow
- [ ] Protocol allowlisting per cell; read-only observer sessions for engineers
- [ ] Session approval workflow (maintenance windows, 4-eyes principle)
- [ ] Serial/jump-host connectors for legacy equipment

## Phase 9 — NIS2 compliance pack ⬜

Mapping to [Directive (EU) 2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555/oj) Art. 21:

- [ ] Control matrix doc: pamv1 feature ↔ NIS2 measure (access control, cryptography, MFA, logging)
- [ ] Incident reporting hooks: export audit slices for the 24h early-warning / 72h notification duties (Art. 23)
- [ ] Configurable audit retention + tamper-evident log export (syslog/SIEM forwarding)
- [ ] Risk-management documentation templates for operators of essential/important entities

## Phase 10 — Scale & operations ⬜

- [ ] HA: stateless multi-replica server; Postgres HA via [CloudNativePG](https://cloudnative-pg.io/)
- [ ] Helm chart; Terraform modules for cloud-managed Postgres
- [ ] Observability: Prometheus metrics, structured logs, health/readiness split
- [ ] Supply chain: SBOM, signed releases (cosign), pinned digests, SLSA provenance
