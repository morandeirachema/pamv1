# pamv1 Roadmap

Guiding principle: **fully functional at every step**. Each phase ships something that runs end-to-end, passes tests, and deploys via IaC. Phases build on each other but stay independently releasable.

Status: ✅ done · 🚧 in progress · ⬜ planned

**Phases 0–20 are shipped** — through the CyberArk/Wallix-style console, the AI-agent
access broker (MCP + SPIFFE), SOPS-encrypted secrets, the four **Tier-1
competitive-coverage gaps** closed (a PostgreSQL session proxy, supervised sessions
with command control, safes, dependent-account propagation), optional CyberArk Conjur
secret sourcing, and the **Tier-2** access-governance gaps landing (certification
campaigns, an ITSM/ticketing gate) — see their sections below. Beyond those,
a few items genuinely require external infrastructure to build and verify
honestly, so they are left as documented follow-ons rather than faked:

- **Optional Kerberos bind** (Phase 3b) — needs a KDC.
- **Browser RDP viewer** (Phase 4) — needs the vendored guacamole-common-js renderer + a real browser/guacd/RDP host (the server-side tunnel is done and tested).
- **Kerberos WinRM auth** (Phase 4) — needs a KDC + an AD-joined host.
- **Serial (RS-232 / terminal-server) connectors** (Phase 8) — needs serial hardware.

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

## Phase 3 — Identity & access control ✅

### 3a — RBAC with four profiles ✅

- [x] Four roles — **admin**, **user**, **auditor**, **approver** — with an authoritative role→capability matrix (`internal/auth`)
- [x] Per-user access tokens (stored as SHA-256 only), minted by an admin via `POST /api/users`
- [x] Enforcement in the REST API (per-route capability) and the SSH proxy (`CapConnect`); every denial audited (`authz.denied` / `session.denied`)
- [x] Audit now attributes real usernames; portal tolerates per-role 403s
- [x] `approver`'s approval endpoints (access-request workflow) — **shipped in Phase 8** (`/api/access-requests`, 4-eyes)

### 3b — Active Directory connector 🚧

- [x] LDAP/LDAPS bind against AD ([go-ldap](https://github.com/go-ldap/ldap)): service-account search + user bind to verify the password
- [x] AD groups → the four pamv1 roles, via `PAM_LDAP_GROUP_*`; a user in several mapped groups carries **all** of them (`Principal.Roles`) and is granted the **union** of their capabilities — not just the single highest role — persisted across a session as `sessions.roles` (same for Entra app-roles/groups)
- [x] Portal Sign On with AD username + password; short-lived **session tokens** (`POST /api/login`, `POST /api/logout`) that work in the portal and the SSH proxy
- [x] **MFA: TOTP** (RFC 6238) enrollment + verification (`internal/mfa`), secret stored vault-encrypted, enforced on `/api/login`; self-service `/api/mfa/*` (NIS2 Art. 21(2)(j))
- [x] **Microsoft Entra ID (Azure AD)** login: OAuth2 (ROPC) against the tenant, Entra app roles / groups → the four roles; composable with LDAP via a chain authenticator; sovereign-cloud authority host
- [x] **Enforce-MFA policy** (`PAM_MFA_REQUIRED`) with enrollment-only sessions, and **single-use recovery codes**
- [x] **OIDC Authorization Code flow + PKCE + JWKS signature validation** (`internal/oidc`): browser SSO (`/api/auth/oidc/{start,callback}`), IdP-side MFA/Conditional Access, ID-token verified (RS256, iss/aud/nonce/exp), discovery
- [ ] Optional Kerberos bind (needs a KDC to test)
- [x] Entra ROPC **id_token JWKS signature validation** — requests `openid`, validates the id_token's RS256 signature against the tenant JWKS (`oidc.VerifyRS256`) + audience + expiry before trusting role/group claims
- [x] OIDC pending-state shared store for multi-replica HA — **shipped in Phase 10** (`store.PutOIDCState`/`TakeOIDCState`, migration `0004`)
- [x] Local emergency admin kept for AD-down scenarios (bootstrap key + break-glass)

## Phase 4 — Windows targets ✅

- [x] **WinRM command execution with JIT credentials** (`internal/winrm`): `POST /api/targets/{id}/winrm` decrypts the target's credential only at run time, executes over WinRM, records the transcript (SHA-256 in the audit), returns stdout/stderr/exit — the caller never sees the secret
- [x] AD-joined target support: uses domain service accounts stored in the vault (the credential username may be `DOMAIN\\user` or UPN)
- [x] **NTLM WinRM auth** (`PAM_WINRM_AUTH=ntlm`) — NTLMv2 transport, which AD-joined hosts usually require
- [x] **RDP brokering via Apache Guacamole `guacd`** (`internal/guacd` + `GET /api/targets/{id}/rdp` WebSocket tunnel): the credential is injected just-in-time into the guacd handshake — it reaches guacd, never the browser (`PAM_GUACD_ADDR`)
- [ ] Browser RDP viewer: bundle guacamole-common-js and add a portal display (server-side tunnel is done and tested) — **infra-bound**: needs the vendored JS renderer plus a real browser + guacd + RDP host to verify end to end
- [x] guacd server-side session recording for RDP (`PAM_GUACD_RECORDING_PATH`; recording name in the `rdp.connect` audit)
- [ ] Kerberos WinRM auth — **infra-bound**: needs a KDC + an AD-joined Windows host to verify
- [x] **Interactive WinRM shell through the SSH proxy** (`PAM_PROXY_WINRM`): `ssh <cred>@<winrm-target>@pam` opens a command loop — each line runs as a WinRM command (JIT credential), output streams back and is recorded. (A command loop, not a stateful PowerShell — working directory/variables don't persist across lines; a WinRS streaming shell is a follow-on needing a real host to verify.)

## Phase 5 — Hardening: database, vault, transport ✅

- [x] **Envelope encryption** with a pluggable KEK: per-secret data keys wrapped by a Key Encryption Key; `local` KEK (dev/test) + **HashiCorp Vault Transit** KEK (production, KEK never leaves the KMS)
- [x] **Vault key rotation** (`pam-server -rotate-kek`, `internal/maint`): re-encrypts all credentials + MFA secrets from `PAM_MASTER_KEY` to `PAM_NEW_MASTER_KEY`, preserving AAD
- [x] Hardened Postgres guidance: scram-sha-256 enforced (compose), TLS `verify-full` + least-privilege role + [pgAudit](https://www.pgaudit.org/) documented
- [x] **Versioned migrations** (embedded, `schema_migrations` table, ordered `migrations/*.sql` applied in a transaction) replacing the ad-hoc startup schema
- [x] **Native HTTPS** (`PAM_TLS_CERT`/`PAM_TLS_KEY`, TLS 1.2+), **security headers** (nosniff, frame-deny, referrer, HSTS), **rate limiting** on auth endpoints (`PAM_AUTH_RATE_LIMIT`)
- [x] **Backup/restore runbook** with encrypted backups ([docs](docs/BACKUP-AND-RESTORE.md))
- [x] **Upstream SSH host-key pinning** (`PAM_SSH_KNOWN_HOSTS`, [known_hosts](https://pkg.go.dev/golang.org/x/crypto/ssh/knownhosts)): the JIT proxy and the rotation connector verify target host keys instead of trusting any; unconfigured falls back to trust-any with a loud warning
- [x] **AWS KMS KEK** (`aws-kms` provider): the data key is wrapped/unwrapped by KMS (`PAM_KEK_AWS_KEY_ID`/`PAM_KEK_AWS_REGION`); the CMK never leaves KMS
- [x] _(optional extension)_ **PKCS#11 HSM KEK provider** — `vault/pkcs11.go` behind the `pkcs11` build tag (cgo), `Dockerfile.pkcs11`, `PAM_KEK_PKCS11_*`; the AES wrapping key stays in the HSM. Verified against SoftHSM2 in CI; the default static image is unchanged (a stub returns "not built in")

## Phase 6 — Break-glass v2 ✅

- [x] **M-of-N quorum unseal** ([Shamir secret sharing](internal/shamir), `pam-server -split-key`, `POST /api/breakglass/unseal`): custodians submit shares; when M reconstruct the key (verified against its hash) a session is issued
- [x] **Auto-expiring break-glass sessions** (short-TTL session, `PAM_BREAK_GLASS_TTL_MIN`, scope `breakglass` → admin + loud audit)
- [x] **Real-time alerting** (`internal/alert` webhook, `PAM_ALERT_WEBHOOK`) on every break-glass **access** and **unseal**
- [x] Documented offline procedure (sealed shares, dual control) — see the [Admin Guide](docs/ADMIN-GUIDE.md)
- [x] Forced credential rotation after break-glass use — a break-glass session that connects through the proxy triggers `PAM_ROTATE_AFTER_SESSION` on session end (a reveal-path break-glass rotation is a smaller follow-on)
- [x] **Additional alert channels (email + syslog)** on the same `Notifier` interface (`alert.Syslog`, `alert.Email`, `alert.Multi` fan-out; `PAM_ALERT_SYSLOG` / `PAM_ALERT_EMAIL_*`)

## Phase 7 — Credential lifecycle ✅

- [x] **Rotation connectors** ([`internal/rotate`](internal/rotate)): Linux over SSH (`chpasswd` via stdin — no shell injection), Windows over WinRM (`net user`). Strong password generation from a shell-safe alphabet with guaranteed complexity categories. **`ssh_key` rotation**: generates a fresh ed25519 keypair and replaces the account's `authorized_keys` (old key stops working)
- [x] **On-demand rotation**: `POST /api/credentials/{id}/rotate` generates a fresh secret, sets it on the target, then re-vaults it and stamps `rotated_at` — the new secret is never returned (proxy injects it JIT)
- [x] **Scheduled rotation**: background lifecycle worker (`PAM_ROTATE_INTERVAL_MIN`) rotates password credentials older than `PAM_ROTATE_MAX_AGE_HOURS`
- [x] **Account reconciliation (out-of-sync detection & remediation):**
  - [x] Credential reconciliation — `POST /api/credentials/{id}/reconcile` verifies the vaulted secret still authenticates to the target (SSH handshake / WinRM probe); drift is flagged and, with `?remediate=true`, remediated by rotating to a PAM-managed secret
  - [x] Reconciliation scan — `GET /api/reconcile` reports drift across all credentials (read-only, safe to schedule), fully audited (`credential.reconcile`, `credential.rotate`, `credential.remediate`)
- [x] **Credential checkout/check-in with lease** — `POST /api/credentials/{id}/checkout` grants an exclusive, time-boxed lease (`PAM_CHECKOUT_TTL_MIN`) and returns the secret; `/checkin` ends it and **rotates** the credential so the seen password is invalidated. Enforced single-holder; honors the reveal-disabled policy
- [x] **Discovery** — `POST /api/discovery/scan` probes hosts for reachable management ports (SSH/WinRM/RDP) and can auto-onboard new targets (`internal/discovery`, reachability only — no credentials used)
- [x] **Identity reconciliation**: `POST /api/identity/reconcile[?dry_run=true]` checks every local user against the directory (`auth.DirectorySource.UserStatus`), **revokes disabled directory users** (`user.revoked`) and surfaces absent local-only accounts as `not_in_directory` (never revoked on uncertainty)
- [x] **AD/LDAPS password-change primitive** (`LDAPAuthenticator.ChangePassword` — Modify `unicodePwd`, UTF-16LE/quoted; unit-tested). *(Wiring it into a full AD-account rotation flow and real-DC interop is a follow-on.)*
- [x] **Forced rotation after each proxied SSH session ends** (`PAM_ROTATE_AFTER_SESSION`): the proxy's `OnSessionEnd` hook calls `Server.RotateCredentialByID`, so a secret used in one session can't be reused in the next (covers break-glass proxied sessions too)

## Phase 8 — OT adaptation ✅

Designed for industrial environments ([IEC 62443](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards), Purdue model) — see the [OT Deployment Guide](docs/OT-DEPLOYMENT.md):

- [x] **Session approval workflow (4-eyes)**: `POST /api/access-requests` → approver (a *different* principal, `CapApprove`) approves/denies; `access_requests` table; enforced on **every** connect path (SSH proxy, WinRM, RDP); break-glass bypasses; approvals/denials audited + alerted. Per-target (`require_approval`) or global (`PAM_REQUIRE_APPROVAL`), time-boxed (`PAM_APPROVAL_WINDOW_MIN`)
- [x] **Air-gap/offline mode** (`PAM_OT_AIRGAP`): disables all outbound calls (alert webhooks); alerts still hit the audit trail + local logs
- [x] Deployment pattern for the industrial DMZ (level 3.5) documented (Purdue diagram, firewall guidance, IEC 62443 control mapping)
- [x] **Protocol allowlisting** (`PAM_ALLOWED_PROTOCOLS`): restrict which target protocols may be created/connected (e.g. forbid RDP in an OT zone); enforced at create-target and on every connect path (API + proxy)
- [x] **Read-only observer sessions**: `ssh <cred>@<target>+observe@pam` opens a view-only session — output streams and is recorded, but operator keystrokes are dropped and exec/subsystem requests are refused (`mode:observer` in the audit)
- [x] **Jump-host / bastion connector** (`PAM_SSH_JUMP_*`): reach SSH targets only accessible via an SSH bastion — the proxy tunnels a `direct-tcpip` channel through the jump host (public-key auth, per-dial bastion connection)
- [ ] Serial connectors (RS-232 / terminal servers) for legacy equipment — needs serial hardware (follow-on)

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
- [x] **HA — OIDC login state shared** via the store (migration `0004`, `store.PutOIDCState`/`TakeOIDCState`), so the auth-code callback can land on any replica. The auth rate-limiter stays best-effort per-replica; break-glass quorum-unseal keeps its shares in memory **by design** (persisting key shares to the DB would weaken the offline-shares guarantee — use a sticky session or a single replica for the unseal flow)
- [x] **Postgres HA** via [CloudNativePG](https://cloudnative-pg.io/): a 3-instance `Cluster` manifest (`deploy/k8s/postgres-cnpg.yaml`, automatic failover, scram-sha-256, optional PITR)
- [x] **Terraform module for cloud-managed Postgres** (`deploy/terraform/cloud-postgres/` — AWS RDS example: multi-AZ, encrypted, `force_ssl`)
- [x] **SLSA build provenance** attested on release (`actions/attest-build-provenance` in `release.yml`, pushed to the registry alongside the cosign signature + SBOM)

## Phase 11 — Management console ✅

The AS/400 5250 green-terminal portal grows from 3 screens into a full
management console covering every backend capability (CyberArk/Wallix-grade
*coverage*, IBM 5250 *look*). Still one `//go:embed`'d page, vanilla JS,
nonce-CSP, no build step — the retro aesthetic is a deliberate constraint, not a
limitation.

- [x] **Role-aware menu** — `GET /api/me` returns the caller's identity + the stable capability names its role holds; the main menu shows only the options the role may use (panels still tolerate a 403 as a backstop)
- [x] **Targets** — subfile with delete + *work-with-grants*, `require_approval` on add; **target grants** screen (list/add/delete role- or user-scoped access)
- [x] **Credentials** — reveal (audited), **check-out** (leased secret + expiry), rotate, reconcile, delete
- [x] **Check-out / check-in** — active exclusive leases; check-in rotates the secret
- [x] **Active sessions** — live monitor (auto-refresh) of proxied SSH/WinRM/RDP sessions with a kill switch
- [x] **Access requests** — 4-eyes: approvers see pending requests and approve/deny; connect-capable users file requests
- [x] **Users & roles** — mint one-time tokens, delete, run directory reconciliation
- [x] **MFA self-service** — enroll (secret + otpauth), confirm, recovery codes, disable
- [x] **Discovery** — scan hosts for reachable SSH/WinRM/RDP and optionally onboard as targets
- [x] **Reconciliation report** — read-only drift scan across all credentials
- [x] **Audit trail** — client-side filter + tamper-evident CSV export (SHA-256)
- [x] **Break-glass unseal** — submit an M-of-N quorum share; on quorum an audited, auto-expiring admin session is issued

## Phase 12 — Configuration subsystem & custom profiles ✅

Make identity backends, policies, and permission profiles configurable from the
console — the CyberArk/Wallix administration surface — using a **hybrid** model
that respects the project's IaC-first roots.

- [x] **Hybrid config model**: directory bindings (LDAP/AD, **Kerberos**), SSO (Entra/OIDC), and policies become editable settings **persisted in the DB** and applied on save; the authenticator chain is rebuilt from stored config — *shipped*: the DB-persisted, vault-encrypted settings store + `GET/PUT/DELETE /api/config` overlaid onto the env config, **plus hot-swap without a restart** (an atomic `runtimeConf` snapshot rebuilt by a `Reconfigure` closure, with rollback on a rejected change; bootstrap/transport/listeners stay env-only and restart-bound)
- [x] **Networking/TLS stays IaC**: a read-only effective-config + backend-health screen (`GET /api/config/effective`) plus a generator (`GET /api/config/iac?format=env|helm|terraform`) that exports the console-set overrides back to IaC, secrets rendered as secret-store placeholders (never plaintext); listeners/ports/TLS stay env-only
- [x] **Custom permission profiles**: named capability sets assignable to users (a configurable RBAC engine), with the current 4 roles as built-in defaults; assignment surfaced in *Work with users & profiles* — *shipped*: `profiles` table (migration `0009`), `POST/GET /api/profiles` + `DELETE /api/profiles/{id}`, `auth.Principal.Can` resolving a capability set (built-in roles unchanged), `createUser` accepting a profile name, and the console role/profile picker now loading custom profiles live
- [x] Console screens (5250 style) to manage profiles (menu 12), identity/SSO/policy configuration (menu 13), and effective config + backend health with IaC export (menu 14); Kerberos *config* is expressible via the generic `PAM_*` override editor even though live Kerberos auth needs a KDC to exercise (see the infra-bound list above)

## Phase 13 — AI-agent access broker ✅

PAM for AI agents (ports [`morandeirachema/pam-research`](https://github.com/morandeirachema/pam-research)): an agent holds only an identity key; a policy engine decides `allow / require_approval / deny` on a tool call **and its arguments**; approved actions execute **server-side** with a just-in-time credential; the agent receives only the result. "Trust the chokepoint, not the agent." Opt-in via `PAM_BROKER_POLICY_FILE`; brokers pamv1's own operations with JIT vault injection.

- [x] **Policy engine** (`internal/policy`): YAML rules (`eq`/`not`/`in`/`not_in`), first-match-wins, implicit deny, scope templating, fail-loud loader
- [x] **Agent identity** (`internal/agentid`): static bearer keys (`agent_keys`, SHA-256 hash lookup), `RoleAgent` + `CapCallTool`
- [x] **Tool registry + JIT execution**: `winrm_exec` over the refactored `execWinRM` — decrypts just-in-time, returns only the result (proven: the runner gets the vaulted secret, the response leaks nothing)
- [x] **Verifiable audit chain** (`internal/auditchain`): keyed-HMAC per-event hash chain (`broker_audit_events`) + `/v1/audit/verify` + ed25519-signed head checkpoint for truncation detection
- [x] **REST surface**: `POST /v1/tool-calls`, `GET /v1/tool-calls/{id}`, `POST /v1/agents`, `GET /v1/audit[/verify|/head]`; HTTP-200-with-status error model
- [x] **Approval + resume + short-lived single-use tokens + more tools**: the `require_approval` effect parks a call, an approver decides via `GET /v1/approvals` + `POST /v1/approvals/{id}/decision`, execute-on-approve injects JIT (the human decision satisfies the target four-eyes gate), and the agent collects the result once with a single-use `broker_tokens` JTI (`POST /v1/tool-calls/{id}/resume`); per-agent rate limits + argument-size caps. Tools: `winrm_exec`, `ssh_exec`, `list_targets`, `list_credentials`, `rotate_credential`, and `reveal_credential` (default-deny)
- [x] **MCP server** (`internal/mcp`): hand-rolled JSON-RPC 2.0 at `POST /mcp` (`initialize`, `tools/list`, `tools/call`, `ping`, `broker/resume`) behind the same agent auth and sharing the one `broker.ProcessCall`/`Resume` loop — proven at parity with REST (same policy, JIT injection, single-use resume, audit)
- [x] **SPIFFE JWT-SVID + RFC 8693 delegation**: `agentid.SVIDVerifier` validates JWT-SVIDs against a file trust-domain JWKS (RS256/ES256/EdDSA), enforcing SPIFFE subject + audience + expiry (fail-closed), with nested `act` claims capped by `PAM_BROKER_MAX_DELEGATION_DEPTH`; a `MultiVerifier` accepts SVIDs alongside static keys (reuses the `internal/oidc` JWT/JWKS approach, no new dependency)
- [x] **Post-review hardening**: a parked `require_approval` call is **re-validated at decision time** (`broker.WithRevalidator`) — an agent key revoked/disabled, or an SVID expired, since parking is refused rather than executed on approval; broker-audit append is serialized across processes under a **Postgres advisory lock** (`AppendBrokerAuditLinked`, the migration-lock idiom) so a rolling-deploy pod overlap or an HA replica can't fork the keyed-HMAC chain; numeric policy arguments match in plain decimal (no `1e+07` mismatch)
- Deferred (documented): SPIRE workload attestation, RFC 8693 token-**exchange** minting, MCP SSE/elicitation, KEK-wrapping the audit keys

## Phase 14 — SOPS-encrypted secrets ✅

Keep the Kubernetes secret manifest **in the IaC repo** without leaking it: encrypt the
values with [SOPS](https://github.com/getsops/sops) + [age](https://age-encryption.org/) so
`kind`/`metadata`/keys stay reviewable while `PAM_MASTER_KEY`, `PAM_API_KEY` and the database
URL are sealed to a key only operators (or a KMS/HSM) hold.

- [x] **SOPS creation rules** (`.sops.yaml`): `encrypted_regex` seals only `data`/`stringData` values of any `deploy/k8s/sops/secrets*.yaml`; age recipient (KMS/PGP recipients documented for cloud/multi-custodian setups)
- [x] **Reproducible encrypted example**: `deploy/k8s/sops/secrets.sops.example.yaml` is a real SOPS-sealed Secret decryptable with a committed **throwaway demo key** (`age-example.key`, loudly marked demo-only) so the whole flow can be run and studied
- [x] **Deploy flow**: `apply.sh` streams `sops --decrypt | kubectl apply -f -` (plaintext never touches disk); `.gitignore` blocks real keys and non-example sealed files; docs cover Flux / Argo / helm-secrets GitOps
- [x] **CI gate**: a `sops` job installs sops+age and runs `verify.sh` — proving the example is encrypted (no accidental plaintext commit) and round-trips
- Deferred (documented): cloud-KMS recipients wired into the Helm chart, a Flux `Kustomization` example, and sealing the CloudNativePG app-secret

## Phase 15 — Database session proxy (PostgreSQL) ✅

Extend the JIT chokepoint to **databases** — the first of the [Tier-1 competitive-coverage gaps](README.md#coverage-vs-commercial-pam-cyberark-wallix-) (matching [Teleport](https://goteleport.com/docs/enroll-resources/database-access/) / [StrongDM](https://www.strongdm.com/) / CyberArk DPA). An operator points `psql` at pamv1; the proxy authenticates them, injects the vaulted DB credential just-in-time, and brokers the wire protocol — auditing every SQL statement. The operator never sees the database password. Opt-in via `PAM_DB_ADDR`.

- [x] **PostgreSQL wire-protocol proxy** (`internal/proxy/dbproxy.go`, on `PAM_DB_ADDR`, default off): speaks the frontend/backend protocol via `pgproto3` (already vendored with pgx). Operator connects `psql "host=pam port=5433 user=<dbcred>@<target> dbname=<db>"` with their PAM key as the password; login parsing reuses the SSH proxy's `creduser@target` convention
- [x] **Same authorization gates as the SSH proxy** (decrypt only after every gate): `CapConnect`, per-target grants (`CanConnectTarget`), the protocol allowlist, and the 4-eyes/OT approval gate — then JIT `vault.Decrypt` and injection
- [x] **Upstream authentication with the vaulted secret**: trust, cleartext, MD5, and **SCRAM-SHA-256** (RFC 5802, stdlib `crypto/hmac`·`sha256` + `x/crypto/pbkdf2`), plus best-effort upstream TLS (`sslmode=prefer` style) — so it reaches self-hosted **and** managed/SCRAM Postgres. Optional operator-leg TLS when `PAM_TLS_CERT/KEY` are set
- [x] **Per-statement query audit + recording**: every `Query`/`Parse` becomes a `db.query` audit event and a line in the session recording (asciicast, SHA-256 hash-chained like SSH/WinRM); live in the session registry (list + kill) as protocol `postgres`; post-session rotation honored
- [x] **End-to-end JIT proof**: an in-process fake PostgreSQL upstream that accepts **only** the vaulted secret — a passing test proves the operator's PAM key was swapped for the vault secret and the SQL was audited; a bad-key operator is refused before any upstream contact
- Deferred (documented): MySQL/MSSQL/Oracle connectors (same pattern, new wire protocols), CA-pinned upstream TLS, and result-row redaction policies

## Phase 16 — Live session monitoring + command control ✅

Turn the existing recording + kill-switch into **supervised** sessions — the third [Tier-1 competitive-coverage gap](README.md#coverage-vs-commercial-pam-cyberark-wallix-) (matching CyberArk PSM / Wallix live monitoring + command filtering).

- [x] **Live session monitoring**: a `session.Hub` fans out every recorded output byte, keyed by session id; `GET /api/sessions/{id}/stream` (`CapReadAudit`) streams it as **Server-Sent Events** so a supervisor watches an SSH or PostgreSQL session as it happens. Non-blocking fan-out (a slow watcher drops frames, never stalls the session); the watch is audited (`session.monitor`)
- [x] **Command control**: a `CommandGuard` (regex denylist from `PAM_COMMAND_DENY_FILE`, one pattern per line) blocks a dangerous command **before it reaches the target** on every path where a discrete command is visible — SSH `exec` (the request is refused, never forwarded), each WinRM command-loop line, and each PostgreSQL `Query`/`Parse` (a simple query is refused but the session stays usable; an extended-protocol statement fails closed). Blocks are audited `command.blocked` with the matched pattern
- [x] **Shared writer plumbing**: the proxy tees session output to the hub via `teeLive`; the DB relay serializes all client-facing writes under one mutex (pgproto3 is not concurrency-safe), proven race-free under `-race`
- [x] **Tests**: the guard (match / comment-skip / fail-loud / nil no-op), the hub (pub-sub, cancel, slow-watcher drop), a blocked SSH exec and a blocked SQL statement (neither reaches the upstream), a live SQL frame observed over the hub, and the SSE endpoint (200 + frame for an auditor, 403 without `CapReadAudit`)
- Deferred (documented): interactive-shell command filtering (a raw PTY stream is not parsed — use observer sessions or restrict shell access), WinRM live streaming, and an in-portal 5250 viewer for the live stream

## Phase 17 — Safes & dependent-account propagation ✅

The last two [Tier-1 competitive-coverage gaps](README.md#coverage-vs-commercial-pam-cyberark-wallix-): CyberArk's Safe-centric authorization model, and safe rotation of service accounts.

**Safes / vault containers (delegated access):**

- [x] **Safe model** (migration `0012`: `safes`, `safe_members`, `targets.safe_id`): a named container groups targets and delegates who may access them. A **safe member may connect to every target in the safe** — an authorization path alongside per-target grants
- [x] **Effective grants**: `store.EffectiveTargetGrants(targetID)` = direct grants ∪ safe-member-derived grants; every connect gate (SSH proxy, DB proxy, RDP, the two broker-tool checks, `gateCredentialAccess`) now honors it, so placing a target in a safe restricts it to the safe's members. `auth.SubjectMatches` factored out of `CanConnectTarget` and reused
- [x] **Delegated administration**: `POST/GET /api/safes`, `DELETE /api/safes/{id}`, `GET/POST /api/safes/{id}/members`, `DELETE /api/safes/{id}/members/{mid}`, `PUT /api/targets/{id}/safe`. Member management is gated by `canManageSafe` — a global target manager **or** a `can_manage` member of that safe (so safe ownership can be delegated). Audit `safe.create`/`safe.delete`/`safe.member.{add,remove}`/`target.safe_set`
- [x] **Tests**: store contract (CRUD, conflict, `EffectiveTargetGrants`, cascade-unassign on delete), an end-to-end proxy test (a non-member is denied a target in a safe; adding the member's role grants the connection), and delegated-management authz

**Dependent-account propagation (safe service-account rotation):**

- [x] **Declared consumers** (migration `0013`: `credential_dependencies`): a credential lists the **Windows Services / Scheduled Tasks / IIS App Pools** that log on with it (`POST/GET /api/credentials/{id}/dependencies`, `DELETE …/{did}`)
- [x] **Propagation on rotation**: after `rotateCredential` sets and re-vaults the new secret, `propagateDependencies` updates each consumer over WinRM (`sc.exe config` / `schtasks /Change /RP` / `appcmd set apppool …password`) with the new secret — so auto-rotating a service account no longer breaks the services that use it. A propagation failure never fails the (already-persisted) rotation; each consumer is audited `credential.dependency_updated`/`credential.dependency_failed` (the secret is injected into the WinRM command but never audited or recorded)
- [x] **Tests**: store contract (CRUD, default WinRM port, missing-credential `ErrNotFound`, cascade on credential delete) and an end-to-end rotation test (the fake WinRM receives the `sc.exe config` for the service with the new secret; the audit carries the update without the secret)
- Deferred (documented): a per-consumer management/reconcile credential (propagation currently connects as the rotated account), a Safe-scoped policy/workflow layer (per-safe approval, dual control), and an in-portal 5250 safe-management screen

## Phase 18 — Conjur secret sourcing (alternative to SOPS) ✅

Let pamv1 source its **own** bootstrap secrets from [CyberArk Conjur](https://www.conjur.org/) at runtime — the runtime-broker counterpart to the SOPS GitOps sealing (Phase 14). **Both ship; SOPS stays the zero-dependency default**, Conjur is opt-in (`PAM_CONJUR_URL`). This is the same philosophy pamv1 already applies to its KEK (Vault-Transit / AWS-KMS / PKCS#11) — externalize the root of trust — now applied to the secret *values*.

- [x] **Hand-rolled Conjur client** (`internal/conjur`, no new dependency — the two REST endpoints pamv1 needs, like the MCP/SPIFFE hand-rolls): authenticate + read secret, over TLS with an optional CA bundle
- [x] **Two authenticators**: `authn-api-key` (host login + API key) and **`authn-jwt`** — the pod presents a Kubernetes projected service-account token, so **no bootstrap secret lives in Git at all** (reuses the JWT posture from `oidc`/`agentid`)
- [x] **Startup sourcing** (`conjur.SourceEnv`, before `config.Load`): fills any **empty** bootstrap `PAM_*` secret (master key, API key, DB URL, break-glass hash, broker keys) from `PAM_CONJUR_POLICY_PREFIX/<name>`. An explicit env value **wins**; a variable missing in Conjur (404) is skipped; a configured-but-unreachable Conjur is **fail-loud** (never starts with empty secrets)
- [x] **IaC**: `deploy/k8s/conjur/` — a Conjur policy (`policy.yaml`), a pam-server Deployment with the authn-jwt projected-token volume (`deployment.yaml`), and a README covering the SOPS-vs-Conjur trade-offs
- [x] **Tests**: an in-process fake Conjur (authenticate → retrieve, 404-as-not-found, auth-failure fail-loud) plus `SourceEnv` behavior (fills empty, env wins, disabled no-op, `PAM_SECRETS_PROVIDER=conjur` without a URL fails loud)
- Deferred (documented): runtime secret **refresh** without a restart (sourcing is one-shot at boot, like SOPS at apply), a per-variable override map, and pushing pamv1's *managed* secrets **out** to Conjur (Secrets-Hub-style sync — a Tier-4 gap)

## Phase 19 — Access certification / attestation campaigns ✅

The first [Tier-2 competitive-coverage gap](README.md#coverage-vs-commercial-pam-cyberark-wallix-) (access-governance depth): the periodic "recertify or revoke who has access to what" review that SOX / ISO 27001 / NIS2 Art. 21(2) expect, and that CyberArk/SailPoint-style IGA provides.

- [x] **Campaign snapshot**: `POST /api/campaigns` captures the *current* access grants — every target grant and every safe member — as reviewable **campaign items** (migration `0014`: `campaigns`, `campaign_items`). A campaign is a point-in-time attestation record
- [x] **Certify or revoke, with teeth**: `POST /api/campaigns/{id}/items/{iid}/decision {certify|revoke}` — a **revoke actually deletes the underlying grant** (`DeleteTargetGrant`/`DeleteSafeMember`; a grant already gone is a no-op, since the goal state is "no access"), certify records the attestation. `POST …/close` closes the campaign (further decisions refused). Every decision is audited
- [x] **Governance-scoped authz**: management (`create`/`decide`/`close`) needs `CapManageUsers`; reading a campaign + its items needs `CapReadAudit` — so an auditor can review the evidence without being able to change access. No new capability added to the matrix
- [x] **Audit vocabulary**: `certification.campaign_created` · `certification.item_certified` · `certification.item_revoked` · `certification.campaign_closed`
- [x] **Tests**: store contract (CRUD, decide, close, missing-campaign `ErrNotFound`) and an end-to-end API test (a campaign snapshots a grant + a safe member; revoke deletes the grant, certify retains the member, a closed campaign returns 409; auditor can read, a plain user cannot manage)
- Deferred (documented): scheduled/recurring campaigns, scoped campaigns (per-safe or per-owner), reviewer assignment + reminders, and a 5250 console review screen

## Phase 20 — ITSM / ticketing gate ✅

The second [Tier-2 competitive-coverage gap](README.md#coverage-vs-commercial-pam-cyberark-wallix-): "no privileged access without an approved change ticket" — the ServiceNow/Jira integration compliance teams expect, hung on the existing 4-eyes access-request engine.

- [x] **Ticket validator** (`internal/ticket`, no new dependency): two optional, composable checks — a **regex format** (`PAM_TICKET_PATTERN`, e.g. a ServiceNow/Jira number) and a **webhook** (`PAM_TICKET_VALIDATE_URL`) the ITSM system answers `2xx` for a valid, approved ticket (`POST {"ticket":"<id>"}`). A nil validator accepts any ticket (disabled)
- [x] **Gate on access requests**: `POST /api/access-requests` accepts a `ticket`; when `PAM_REQUIRE_TICKET` is set it is mandatory (422 otherwise), a configured validator must pass (422 + `access.ticket_rejected` audit on failure), and the ticket is **stamped into the request and the audit trail** (`store.AccessRequest.Ticket`, migration `0015`)
- [x] **Tests**: a `ticket` unit test (disabled / bad-pattern / format reject) and an end-to-end API test with a fake ITSM webhook (missing → 422, bad format → 422, webhook-rejected → 422, an approved ticket → 201 and recorded)
- Deferred (documented): a first-class ServiceNow/Jira connector (this ships the generic webhook + regex hook), and gating the connect path directly on a live ticket lookup (today the ticket is validated at request time)
