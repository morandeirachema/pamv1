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

## Phase 2 — Session proxy with JIT credential injection (Linux/SSH) ✅

The flagship: users connect *through* pamv1, never holding the credential.

- [x] SSH gateway (`golang.org/x/crypto/ssh`): user opens `ssh user@target@pam-proxy`, proxy authenticates the user, pulls the credential from the vault and injects it **just-in-time** into the upstream connection
- [x] Session recording (asciicast v2) stored with a SHA-256 written to the audit trail (tamper evidence)
- [x] Per-session audit events (start, record, end, denied, error)
- [x] **Per-target authorization** (`target_grants`): a target with grants only admits matching users/roles (admins always; ungranted targets stay open); enforced in the proxy, WinRM and RDP; managed via `/api/targets/{id}/grants`
- [x] **Live session listing and kill-switch** (`internal/session`): `GET /api/sessions` (auditor+) lists active proxy/RDP sessions; `DELETE /api/sessions/{id}` (admin) terminates one
- [x] **Hash-chain the recordings**: each recording's chain hash = SHA-256(prev-chain-hash ‖ file-hash), head persisted; recorded in the `session.record` audit (`chain:`)
- [x] Disable `reveal` by policy (`PAM_REVEAL_DISABLED`): reveal becomes break-glass-only, forcing the recorded proxy path

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
- [x] **Enforce-MFA policy** (`PAM_MFA_REQUIRED`) with enrollment-only sessions, and **single-use recovery codes**
- [x] **OIDC Authorization Code flow + PKCE + JWKS signature validation** (`internal/oidc`): browser SSO (`/api/auth/oidc/{start,callback}`), IdP-side MFA/Conditional Access, ID-token verified (RS256, iss/aud/nonce/exp), discovery
- [ ] Optional Kerberos bind
- [ ] OIDC pending-state shared store for multi-replica HA
- [x] Local emergency admin kept for AD-down scenarios (bootstrap key + break-glass)

## Phase 4 — Windows targets 🚧

- [x] **WinRM command execution with JIT credentials** (`internal/winrm`): `POST /api/targets/{id}/winrm` decrypts the target's credential only at run time, executes over WinRM, records the transcript (SHA-256 in the audit), returns stdout/stderr/exit — the caller never sees the secret
- [x] AD-joined target support: uses domain service accounts stored in the vault (the credential username may be `DOMAIN\\user` or UPN)
- [x] **NTLM WinRM auth** (`PAM_WINRM_AUTH=ntlm`) — NTLMv2 transport, which AD-joined hosts usually require
- [x] **RDP brokering via Apache Guacamole `guacd`** (`internal/guacd` + `GET /api/targets/{id}/rdp` WebSocket tunnel): the credential is injected just-in-time into the guacd handshake — it reaches guacd, never the browser (`PAM_GUACD_ADDR`)
- [ ] Browser RDP viewer: bundle guacamole-common-js and add a portal display (server-side tunnel is done and tested)
- [x] guacd server-side session recording for RDP (`PAM_GUACD_RECORDING_PATH`; recording name in the `rdp.connect` audit)
- [ ] Kerberos WinRM auth
- [ ] Interactive WinRM/PowerShell shell through the SSH proxy (beyond one-shot commands)

## Phase 5 — Hardening: database, vault, transport ✅

- [x] **Envelope encryption** with a pluggable KEK: per-secret data keys wrapped by a Key Encryption Key; `local` KEK (dev/test) + **HashiCorp Vault Transit** KEK (production, KEK never leaves the KMS)
- [x] **Vault key rotation** (`pam-server -rotate-kek`, `internal/maint`): re-encrypts all credentials + MFA secrets from `PAM_MASTER_KEY` to `PAM_NEW_MASTER_KEY`, preserving AAD
- [x] Hardened Postgres guidance: scram-sha-256 enforced (compose), TLS `verify-full` + least-privilege role + [pgAudit](https://www.pgaudit.org/) documented
- [x] **Versioned migrations** (embedded, `schema_migrations` table, ordered `migrations/*.sql` applied in a transaction) replacing the ad-hoc startup schema
- [x] **Native HTTPS** (`PAM_TLS_CERT`/`PAM_TLS_KEY`, TLS 1.2+), **security headers** (nosniff, frame-deny, referrer, HSTS), **rate limiting** on auth endpoints (`PAM_AUTH_RATE_LIMIT`)
- [x] **Backup/restore runbook** with encrypted backups ([docs](docs/BACKUP-AND-RESTORE.md))
- [x] **AWS KMS KEK** (`aws-kms` provider): the data key is wrapped/unwrapped by KMS (`PAM_KEK_AWS_KEY_ID`/`PAM_KEK_AWS_REGION`); the CMK never leaves KMS
- [ ] _(optional extension, interface ready)_ PKCS#11 HSM KEK provider

## Phase 6 — Break-glass v2 ✅

- [x] **M-of-N quorum unseal** ([Shamir secret sharing](internal/shamir), `pam-server -split-key`, `POST /api/breakglass/unseal`): custodians submit shares; when M reconstruct the key (verified against its hash) a session is issued
- [x] **Auto-expiring break-glass sessions** (short-TTL session, `PAM_BREAK_GLASS_TTL_MIN`, scope `breakglass` → admin + loud audit)
- [x] **Real-time alerting** (`internal/alert` webhook, `PAM_ALERT_WEBHOOK`) on every break-glass **access** and **unseal**
- [x] Documented offline procedure (sealed shares, dual control) — see the [Admin Guide](docs/ADMIN-GUIDE.md)
- [ ] Forced credential rotation after break-glass use (needs the rotation connectors from Phase 7)
- [ ] Additional alert channels (email/syslog) on the same `Notifier` interface

## Phase 7 — Credential lifecycle ✅

- [x] **Rotation connectors** ([`internal/rotate`](internal/rotate)): Linux over SSH (`chpasswd` via stdin — no shell injection), Windows over WinRM (`net user`). Strong password generation from a shell-safe alphabet with guaranteed complexity categories
- [x] **On-demand rotation**: `POST /api/credentials/{id}/rotate` generates a fresh secret, sets it on the target, then re-vaults it and stamps `rotated_at` — the new secret is never returned (proxy injects it JIT)
- [x] **Scheduled rotation**: background lifecycle worker (`PAM_ROTATE_INTERVAL_MIN`) rotates password credentials older than `PAM_ROTATE_MAX_AGE_HOURS`
- [x] **Account reconciliation (out-of-sync detection & remediation):**
  - [x] Credential reconciliation — `POST /api/credentials/{id}/reconcile` verifies the vaulted secret still authenticates to the target (SSH handshake / WinRM probe); drift is flagged and, with `?remediate=true`, remediated by rotating to a PAM-managed secret
  - [x] Reconciliation scan — `GET /api/reconcile` reports drift across all credentials (read-only, safe to schedule), fully audited (`credential.reconcile`, `credential.rotate`, `credential.remediate`)
- [ ] Credential checkout/check-in with max lease time (follow-on)
- [ ] AD/LDAPS password-change connector + identity reconciliation (revoke access for disabled directory users; surface orphaned accounts) — needs the AD write path (follow-on)
- [ ] Discovery: scan AD/OU or IP ranges to onboard targets (follow-on)
- [ ] Forced rotation immediately after each proxied session ends (follow-on; ties the proxy back into the rotation orchestrator)

## Phase 8 — OT adaptation ✅

Designed for industrial environments ([IEC 62443](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards), Purdue model) — see the [OT Deployment Guide](docs/OT-DEPLOYMENT.md):

- [x] **Session approval workflow (4-eyes)**: `POST /api/access-requests` → approver (a *different* principal, `CapApprove`) approves/denies; `access_requests` table; enforced on **every** connect path (SSH proxy, WinRM, RDP); break-glass bypasses; approvals/denials audited + alerted. Per-target (`require_approval`) or global (`PAM_REQUIRE_APPROVAL`), time-boxed (`PAM_APPROVAL_WINDOW_MIN`)
- [x] **Air-gap/offline mode** (`PAM_OT_AIRGAP`): disables all outbound calls (alert webhooks); alerts still hit the audit trail + local logs
- [x] Deployment pattern for the industrial DMZ (level 3.5) documented (Purdue diagram, firewall guidance, IEC 62443 control mapping)
- [ ] Protocol allowlisting per cell; read-only observer sessions for engineers (follow-on)
- [ ] Serial/jump-host connectors for legacy equipment (follow-on)

## Phase 9 — NIS2 compliance pack ✅

Mapping to [Directive (EU) 2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555/oj) — see the [NIS2 Compliance Pack](docs/NIS2-COMPLIANCE.md):

- [x] **Control matrix doc**: full Art. 21(2)(a–j) measure ↔ pamv1 feature mapping
- [x] **Incident reporting export** (Art. 23): `GET /api/audit/export` returns a scoped audit slice (`since`/`until`/`actor`/`action`, JSON or CSV) with a **SHA-256 tamper-evidence digest** (body field + `X-PAM-Export-SHA256` header); the export is itself audited
- [x] **Audit retention + SIEM forwarding** guidance (append-only trail in Postgres; JSON logs + audit events to stdout for a collector; real-time alert webhook)
- [x] **Risk-management documentation template** for essential/important entities

## Phase 10 — Scale & operations ✅

- [x] **Observability**: Prometheus `/metrics` (`internal/metrics`, dependency-free exposition — request counts by status, audit volume, break-glass use, rotations, active-sessions gauge), structured JSON logs, **health/readiness split** (`/healthz` liveness + `/readyz` store-reachability readiness, `store.Ping`)
- [x] **Helm chart** (`deploy/helm/pamv1`): deployment/service/secret/ingress/ServiceMonitor, configurable replicas, PVC or emptyDir, hardened pod security context
- [x] **Signed releases** (`.github/workflows/release.yml`): build + push by digest on a version tag, **SBOM** (SPDX) generation + attestation, **cosign** keyless image signing, GitHub Release
- [ ] HA: fully stateless multi-replica (shared store for OIDC PKCE / break-glass unseal / rate-limit state — currently per-replica in-memory); Postgres HA via [CloudNativePG](https://cloudnative-pg.io/) (follow-on)
- [ ] Terraform modules for cloud-managed Postgres; SLSA provenance (follow-on)
