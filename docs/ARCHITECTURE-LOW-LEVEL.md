# pamv1 — Low-Level Architecture (living document)

> **Living document.** Update this whenever code structure, packages, schemas,
> wire formats, env vars or algorithms change. This is the engineer's map of
> the codebase; the conceptual view lives in
> [ARCHITECTURE-HIGH-LEVEL.md](ARCHITECTURE-HIGH-LEVEL.md).
>
> Last updated: 2026-07-21 · Reflects: **Phases 0–24 shipped** — through the 5250 management console (11), the configuration subsystem + custom-profile RBAC + hot-swap (12), the AI-agent access broker (13), SOPS-encrypted secrets (14), the PostgreSQL database session proxy (15), live session monitoring + command control (16), safes + dependent-account propagation (17), optional CyberArk Conjur secret sourcing (18), access certification campaigns (19), an ITSM/ticketing gate (20), richer approval workflows (21), Zero Standing Privilege via ephemeral SSH certificates (22), privileged threat analytics (23), and a Conjur-style application-secrets API for non-agent apps (24) — plus a keyboard-first console and the security/correctness hardening passes and code-generated diagrams. Items that need external infrastructure or a paid account to build/verify honestly are catalogued in [EXTERNAL-INFRA-GAPS.md](EXTERNAL-INFRA-GAPS.md). See the [ROADMAP](../ROADMAP.md) for authoritative per-phase status. Commit the doc update with the code change.

## 1. Language, layout, dependencies

- **Go** (module `github.com/morandeirachema/pamv1`, `go 1.26`).
- Standard layout: `cmd/` entrypoints, `internal/` non-exported packages.
- Direct deps: [`jackc/pgx/v5`](https://github.com/jackc/pgx) (Postgres), [`golang.org/x/crypto/ssh`](https://pkg.go.dev/golang.org/x/crypto/ssh) (proxy). Standard library otherwise.

```
cmd/pam-server/main.go        # wiring, flags (-genkey, -hashkey), lifecycle
internal/
  config/      # env (PAM_*) -> Config
  logging/     # slog setup (json/text, level) + per-service loggers
  vault/       # AES-256-GCM encrypt/decrypt, key gen
  sshca/       # Zero Standing Privilege SSH certificate authority (mints short-lived user certs)
  analytics/   # privileged threat analytics — behavioral risk scoring over the audit trail
  mfa/         # TOTP (RFC 6238) generate/validate + otpauth URI
  winrm/       # WinRM command Runner (Windows targets) + real client (basic/NTLM)
  guacd/       # Apache Guacamole protocol client (RDP handshake + JIT injection)
  oidc/        # OIDC Authorization Code + PKCE, RS256 JWKS validation
  maint/       # offline maintenance (vault KEK rotation)
  rotate/      # credential rotation/verify connectors (SSH chpasswd, ssh_key, WinRM)
  discovery/   # TCP port scan → onboard targets (ssh/winrm/rdp)
  metrics/     # dependency-free Prometheus /metrics
  session/     # live-session registry (list + kill), shared proxy↔api
  shamir/      # Shamir secret sharing (GF(2^8)) for break-glass quorum
  alert/       # real-time alert delivery (webhook, syslog, email), break-glass events
  auth/        # roles, capabilities, Principal, Resolver (RBAC), LDAP/Entra/OIDC
  store/       # Store interface + domain types + CredentialAAD
    memstore/  # in-memory impl (tests, demo)
    pgstore/   # PostgreSQL impl + embedded versioned migrations
  api/         # REST handlers, authz middleware, user administration
  proxy/       # SSH gateway, JIT injection, session recording, host key
  web/         # embedded AS/400 portal (static/index.html)
```

## 2. Package contracts

### 2.1 `vault`

**Envelope encryption** (the KMS/PAM-vendor pattern). Each secret is sealed with
a fresh random **data key** (AES-256-GCM, 12-byte nonce, `aad` authenticated),
and that data key is **wrapped by a KEK** (Key Encryption Key). Token format is
versioned: `"v2:" + base64url( uint16(len(wrappedDEK)) || wrappedDEK || nonce ||
ciphertext )`. `Encrypt(ctx, plaintext, aad)` / `Decrypt(ctx, token, aad)` are
context-aware because a KMS KEK makes network calls; data keys are zeroed after use.

The **KEK is pluggable** (`KEK` interface, `NewKEK(KEKOptions)`):

- `LocalKEK` — AES-256-GCM key from `PAM_MASTER_KEY` (base64). **Dev/test only** —
  the key sits in an env var.
- `TransitKEK` — HashiCorp [Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit)
  over HTTPS (`transit.go`); the KEK never leaves Vault, wrap/unwrap round-trip
  the data key. **Production / vendor-aligned.**
- `AWSKMSKEK` — AWS KMS (`awskms.go`): the data key is Encrypt/Decrypt'd by KMS,
  so the CMK never leaves KMS. **Production.** The `kmsAPI` client is an interface
  (tests inject a fake).
- `PKCS11KEK` — on-prem **HSM** via a PKCS#11 module (`pkcs11.go`, build tag
  `pkcs11`): an AES key inside the token wraps/unwraps the data key
  (`CKM_AES_CBC_PAD`); the KEK never leaves the HSM. Needs cgo + a dynamic loader,
  so it is **excluded from the default static/distroless build** — a `pkcs11_stub.go`
  (`!pkcs11`) returns a clear "not built in" error. Verified against SoftHSM2 in CI.

`GenerateMasterKey()` → 32 random bytes, urlsafe-base64 (seeds the local KEK).
Selected by `PAM_KEK_PROVIDER` (`local` | `vault-transit` | `aws-kms` | `pkcs11`).

### 2.2 `store`

Interface `Store` with `memstore` and `pgstore` implementations. Domain types:
`Target`, `Credential` (field `SecretEnc` is `json:"-"` — **never serialized**),
`AuditEvent`. Sentinel errors `ErrNotFound`, `ErrConflict`.
`CredentialAAD(targetID, credID) = "target:<id>/cred:<id>"` — shared by `api` and `proxy` so vault
AAD matches on both encrypt and decrypt paths.

Schema is applied by an embedded **migration runner** (`pgstore/migrate.go`):
ordered `migrations/*.sql` files run once each in a transaction, tracked in a
`schema_migrations` table. `0001_init.sql` is the idempotent baseline (safe on a
pre-migrations database); later changes are new numbered files (through
`0011_session_roles.sql`), applied under a `pg_advisory_lock` so concurrent replicas
don't race. Tables: `targets`, `credentials` (FK `ON DELETE CASCADE`),
`target_grants`, `audit_events`, `users`, `sessions`, `mfa_enrollments`,
`mfa_recovery_codes`, `access_requests`, `checkouts` (partial UNIQUE index — one
active lease per credential), `oidc_states`, `agent_keys`, `broker_audit_events`
(the hash-chained agent-broker audit log), `settings` (config overrides).

### 2.3 `auth` *(Phase 3a)*

RBAC. Four `Role`s — `admin`, `user`, `auditor`, `approver` — each granted a set
of `Capability` values by the authoritative `roleCaps` matrix (`Role.Can(cap)`).
`Principal{Name, Role, BreakGlass}` is the authenticated identity.

`Resolver.Resolve(ctx, key)` maps a presented key to a Principal, trying in
order: the bootstrap admin key (`PAM_API_KEY`) → `admin`; the break-glass key →
`admin` with `BreakGlass=true`; a per-user token (`store.GetUserByTokenHash`);
then a **login session token** (`store.GetSessionByTokenHash`, non-expired).
Shared by `api` and `proxy` so both enforce the same identities and roles.
`auth` imports `store` (no cycle).

**Password identity sources** (`Authenticator` interface, Phase 3b): verify
username+password and return a Principal whose role comes from the directory.
Pluggable and composable via `NewChain` (try each, first success wins):

- `LDAPAuthenticator` (`ldap.go`) — on-prem AD: binds a service account, searches
  the user under `BaseDN`, reads `memberOf`, re-binds as the user to verify the
  password, maps groups → roles (`MatchedRoles` — a user in several mapped groups
  keeps **all** of them, carried on `Principal.Roles`, and `Can` evaluates the
  **union** of their capabilities). The LDAP connection is behind an `ldapConn`
  interface so tests inject a fake; real dial uses LDAPS.
- `EntraAuthenticator` (`entra.go`) — Microsoft Entra ID (Azure AD): OAuth2 ROPC
  grant to the tenant token endpoint (over TLS, back-channel), requesting `openid`
  so Entra returns an **id_token**. It **validates the id_token's RS256 signature
  against the tenant JWKS** (`oidc.VerifyRS256`, plus audience + expiry) before
  reading `roles` (app roles) / `groups` claims and mapping to a role.
  `AuthorityHost` supports sovereign clouds; the endpoints are overridable in
  tests. Note: ROPC still skips IdP-side Conditional Access/MFA (use pamv1's TOTP;
  prefer the OIDC auth-code flow for production).

`POST /api/login` runs the configured authenticator, enforces TOTP if enrolled,
and issues a session token (see `api`). `HighestRole` is the shared claim→role
mapper used by LDAP, Entra and OIDC.

**OIDC login** (`internal/oidc`, Phase 3b hardening): the production-grade
browser flow. `GET /api/auth/oidc/start` generates PKCE + state + nonce and
persists them via `store.PutOIDCState` (shared, so any replica can complete the
login — HA), then redirects to the IdP. `GET /api/auth/oidc/callback`
atomically takes the state (`store.TakeOIDCState`, single-use), exchanges the
code, and **verifies the ID token's RS256 signature against the IdP JWKS** plus
issuer/audience/nonce/exp, maps roles/groups → role, issues a session, and
redirects to the portal with the token in the URL fragment. Unlike ROPC, the IdP
performs the login (so its Conditional Access / MFA apply); pamv1 does not layer
its own TOTP on OIDC.

Capability grants: admin = all; user = `CapReadInventory`+`CapConnect`; auditor =
`CapReadInventory`+`CapReadAudit`; approver = auditor + `CapApprove` (approval
endpoints arrive with the OT/approval phase).

### 2.4 `api`

- Router: Go 1.22+ `http.ServeMux` pattern methods (`GET /api/targets/{id}` …).
- `authz(cap, handler)` middleware: resolves the `X-API-Key` into a Principal via
  `auth.Resolver`, emits the loud `breakglass.access` audit if applicable, then
  enforces `Principal.Role.Can(cap)` (403 + `authz.denied` audit otherwise). The
  Principal goes in the request context; `actorFrom` reads its name for audit.
- Each route declares its required capability (e.g. `POST /api/targets` needs
  `CapManageTargets`, `GET /api/audit` needs `CapReadAudit`).
- User administration (`CapManageUsers`): `POST /api/users` mints a token and
  returns it **once**; only the SHA-256 is stored. `GET`/`DELETE /api/users`.
- **Break-glass quorum** (`breakglass_handlers.go`, Phase 6): `POST
  /api/breakglass/unseal` (public, rate-limited) collects Shamir shares in an
  in-memory `unsealState`; when `PAM_BREAK_GLASS_THRESHOLD` shares reconstruct a
  key whose SHA-256 matches `PAM_BREAK_GLASS_KEY_HASH`, it issues a short-lived
  session (`SessionScopeBreakGlass` → admin + `BreakGlass=true`, auto-expiring).
  Every break-glass use fires an `alert.Notifier` (webhook). Shares are produced
  offline by `pam-server -split-key`; the server holds none.
- Login (`authn` optional): `POST /api/login` (public) verifies username+password
  via the configured `Authenticator`, then — if the user has a **confirmed TOTP
  enrollment** — requires a valid `otp` (401 `mfa_required` if missing), and
  issues a session token (12h TTL, stored as SHA-256) with the role from the
  directory; `POST /api/logout` revokes it. Returns 503 when no authenticator is
  configured.
- MFA (`internal/mfa`, self-service, authenticated): `POST /api/mfa/enroll`
  generates a TOTP secret (returned once, plus an `otpauth://` URI), stored
  **vault-encrypted** (AAD `mfa:<user>`), unconfirmed; `POST /api/mfa/verify`
  confirms it with a code; `POST /api/mfa/recovery-codes` issues 10 single-use
  backup codes (hashes stored); `GET /api/mfa` status; `DELETE /api/mfa` disables.
  A login OTP accepts a TOTP code **or** a recovery code (consumed on use).
- **Enforce-MFA policy** (`Options.MFARequired`, `PAM_MFA_REQUIRED`): when a user
  with no confirmed MFA logs in, they get an **enrollment-only session**
  (`store.Session.Scope="enroll"` → `Principal.EnrollOnly`) that only the MFA
  endpoints accept — `authz` and the proxy reject it (403 / `session.denied`)
  until enrollment is confirmed and the user re-logs in with a full session.
- Handlers validate input (os_type ∈ {linux,windows}, protocol ∈ {ssh,winrm,rdp}),
  translate store errors to HTTP codes, and append audit events.
- `reveal` (needs `CapRevealSecret`, admin only) decrypts on demand and is audited.
- **WinRM** (`POST /api/targets/{id}/winrm`, needs `CapConnect`): the Windows
  counterpart to the SSH proxy. Resolves the target (must be `protocol=winrm`),
  decrypts its credential **just-in-time**, runs the command via `winrm.Runner`,
  writes a transcript to `RecordingDir` with its SHA-256 in the audit, and
  returns stdout/stderr/exit — the secret is never returned. `winrm.Runner` is an
  interface (tests inject a fake); `winrm.Client` wraps masterzen/winrm over HTTPS
  with basic or NTLMv2 auth (`PAM_WINRM_AUTH`).
- **RDP** (`GET /api/targets/{id}/rdp`, WebSocket, needs `CapConnect`): brokers RDP
  through Apache Guacamole. Authorizes via a `token` query param (browsers can't
  set WS headers), resolves the `protocol=rdp` target, decrypts the credential
  **just-in-time**, and `guacd.Connect` performs the Guacamole handshake injecting
  the credential (`internal/guacd`) — it reaches guacd, never the browser. Then it
  bridges the WebSocket ↔ guacd stream. Enabled by `PAM_GUACD_ADDR`; audited
  `rdp.connect`/`rdp.end`. The browser viewer (guacamole-common-js) is the last mile.

- **Credential lifecycle** (`lifecycle_handlers.go` + `internal/rotate`, Phase 7,
  needs `CapManageCredentials`): rotation and reconciliation run over the same
  secure protocols as the proxy.
  - `POST /api/credentials/{id}/rotate`: generates a strong password
    (`rotate.GeneratePassword` — shell-safe alphabet, guaranteed complexity),
    sets it on the target via a protocol `Rotator` (SSH `chpasswd` fed on stdin;
    WinRM `net user`), then re-encrypts it into the vault and stamps `rotated_at`
    (`store.RotateCredentialSecret`). The new secret is **never returned**.
  - `POST /api/credentials/{id}/reconcile[?remediate=true]`: a `Verifier` checks
    the vaulted secret still authenticates (SSH handshake / WinRM probe). Drift is
    reported as `out_of_sync`; with `remediate=true` an out-of-band change is
    healed by rotating to a PAM-managed secret.
  - `GET /api/reconcile`: read-only drift scan over every credential (safe to
    schedule). All three audit `credential.rotate` / `credential.reconcile` /
    `credential.remediate`.
  - **Background worker** (`scheduler.go`, `RunLifecycleWorker`): on
    `PAM_ROTATE_INTERVAL_MIN` it reconciles all credentials and rotates password
    ones older than `PAM_ROTATE_MAX_AGE_HOURS` (actor `system-scheduler`).
  - `Rotator`/`Verifier` are interfaces keyed by protocol in `Options`; tests
    inject fakes, and the SSH connector is proven against an in-process SSH server.
  - **Checkout/check-in** (`store.Checkout`, migration `0003`): `POST
    /api/credentials/{id}/checkout` (needs `CapRevealSecret`) grants an exclusive
    lease (`PAM_CHECKOUT_TTL_MIN`) and returns the secret; a second holder gets
    409. `/checkin` ends the lease and rotates the credential so the seen password
    is dead. `GET /api/checkouts` lists them. Honors `PAM_REVEAL_DISABLED`.
  - **Discovery** (`internal/discovery`, `POST /api/discovery/scan`, needs
    `CapManageTargets`): TCP-probes hosts for known management ports
    (22→ssh, 5985/5986→winrm, 3389→rdp) and, with `create:true`, onboards new
    targets. Reachability only — no credentials are used.

- **Access-request approval** (`approval_handlers.go`, Phase 8 — OT 4-eyes):
  `POST /api/access-requests` (needs `CapConnect`) files a request; `GET
  /api/access-requests` + `POST /api/access-requests/{id}/{approve,deny}` (needs
  `CapApprove`) let an approver decide. The **four-eyes** rule refuses
  self-approval (approver ≠ requester); an approval is valid for
  `PAM_APPROVAL_WINDOW_MIN`. Enforcement (`enforceApproval`): when a target sets
  `require_approval` or the global `PAM_REQUIRE_APPROVAL` is on, the WinRM/RDP
  handlers and the SSH proxy require `store.HasActiveApproval` before brokering;
  **break-glass bypasses**. Decisions audit + fire the `alert.Notifier`.
- **Air-gap mode** (`Options.AirGap`, `PAM_OT_AIRGAP`): forces the alerter to
  `alert.Noop` so an isolated OT deployment makes no outbound calls.
- **Audit export** (`compliance_handlers.go`, Phase 9 — NIS2, needs
  `CapReadAudit`): `GET /api/audit/export` returns a `store.ExportAudit` slice
  filtered by `since`/`until`/`actor`/`action` as JSON or CSV, with a **SHA-256**
  over the canonical event list in the body and the `X-PAM-Export-SHA256` header
  (tamper evidence for Art. 23 incident reports). The export is audited
  (`audit.export`).
- **Observability** (Phase 10, unauthenticated like `/healthz` — restrict at the
  network): `GET /metrics` renders a dependency-free Prometheus exposition
  (`internal/metrics`: `pam_http_requests_total{status}`, `pam_audit_events_total`,
  `pam_breakglass_access_total`, `pam_auth_failures_total`,
  `pam_credential_rotations_total`, `pam_active_sessions` gauge). `GET /healthz`
  is liveness; `GET /readyz` is readiness (calls `store.Ping`, 503 if the DB is
  unreachable). All three are skipped by the access log + request counter.

### 2.5 `proxy`  *(Phase 2, RBAC in 3a)*

SSH gateway. See §3 for the wire-level flow.

- `New(store, vault, resolver, Config)` → `Proxy`; `ListenAndServe(ctx, addr)` or
  `Serve(ctx, ln)` (tests inject a `127.0.0.1:0` listener).
- **Auth** (`authenticate`): `PasswordCallback` resolves the SSH password (a PAM
  key or per-user token) into a Principal via `auth.Resolver`. The SSH *username*
  selects the target: `splitLogin` parses `creduser@target` (rightmost `@`) or
  bare `target`. Principal name/role + target stashed in `ssh.Permissions.Extensions`.
- **Authz**: after the handshake, a connection whose role lacks `CapConnect`
  (e.g. `auditor`, `approver`) is rejected with a `session.denied` audit before
  any target is resolved.
- **Gates** (in order, each denial audited): protocol allowlist
  (`PAM_ALLOWED_PROTOCOLS`), per-target grants (`CanConnectTarget`), and the
  4-eyes approval gate (`HasActiveApproval`; break-glass bypasses). Non-`ssh`
  targets branch to the WinRM loop (`serveWinRM`) when a runner is configured.
- **Resolve + JIT decrypt** (`resolveTarget` → `decryptSecret`): look up target
  by name and pick the credential (matching `creduser` or first) *without*
  decrypting, then **decrypt the secret only after every gate passes** — plaintext
  never exists for a denied session. The AAD binds the ciphertext to
  `(target, credential)` (`store.CredentialAAD`).
- **Upstream** (`dialUpstream`): `ssh.Dial` to `host:port` as the credential
  user, `ssh.Password` or `ssh.PublicKeys` (for `secret_type=ssh_key`). The
  `HostKeyCallback` verifies the target's host key against `PAM_SSH_KNOWN_HOSTS`
  (`knownhosts`); when unset it falls back to trust-any with a **startup warning**
  (`proxy.Config.UpstreamHostKey`; the rotation connector shares the callback).
- **Session** (`handleSession`): for each `session` channel, open an upstream
  session channel and bidirectionally forward: channel requests via
  `pumpRequests` (pty-req, shell, exec, window-change, exit-status), stdin,
  stdout (tee'd into the recording), stderr.
- **Recording** (`record.go`): asciicast v2 (`{header}` line + `[t,"o",data]`
  events) written to `PAM_RECORDING_DIR`, hashed with SHA-256 as it is written;
  on close the audit stores path, byte count, file hash and a **chain hash**
  (`recordChain`: `SHA-256(prev-chain ‖ file-hash)`, head persisted to `.chain`)
  so recordings are tamper-evident as a sequence, not just individually.
- **Host key** (`hostkey.go`): `PAM_SSH_HOST_KEY` PEM path (persisted, generated
  if missing) or ephemeral ed25519.
- **Also**: a `+observe` login suffix opens a read-only session (operator
  keystrokes dropped, output still streamed/recorded); `Config.Jump` reaches
  targets through an SSH bastion (`direct-tcpip`); `Config.WinRMRunner` brokers an
  interactive WinRM command loop; `Config.OnSessionEnd` fires post-session
  credential rotation; `Config.RequireRecording` refuses a session that can't be
  recorded. Shutdown is a **bounded drain**: `Serve` force-closes active
  connections on `ctx` cancel and waits for handlers, and closing audits are
  written detached from the cancelled context.

### 2.5a `sshca` *(Phase 22 — Zero Standing Privilege)*

An SSH **certificate authority** for the ZSP model: no standing secret is stored
for an account; the proxy mints a short-lived user certificate just-in-time per
session. `LoadOrCreate(PAM_SSH_CA_KEY)` persists an ed25519 CA key (generated on
first use, like the host key). `IssueUser(principal, ttl, keyID)` generates a
**fresh ephemeral keypair** (used for one dial, then discarded), builds an
`ssh.Certificate` (`UserCert`, `ValidPrincipals=[principal]`, a serial for audit,
`ValidBefore=now+ttl`, standard interactive extensions), signs it with the CA, and
returns an `ssh.NewCertSigner`. A credential of `secret_type="ssh_ca"` stores **no
secret** (`SecretEnc` empty); the proxy's `dialUpstream` branches on it to mint a
cert instead of decrypting — a missing CA fails the session closed (`session.error`).
`GET /api/ca/ssh` (`CapReadInventory`) publishes the CA public key + a
`TrustedUserCAKeys` install hint. Audit `session.cert_issued` (serial · principal ·
valid-before · key-id — never the private key). Reconciliation reports `ssh_ca` as
`unsupported`; post-session rotation and the lifecycle worker skip it.

### 2.5b `analytics` *(Phase 23 — privileged threat analytics)*

A deterministic, explainable behavioral **risk scorer** over the audit trail (no
clock, no I/O, no opaque model in `Score`). Each actor's score is the sum of named
**signals** — `break_glass`, `command_blocked`, `auth_failure`, `off_hours`,
`decrypt_failure`, `high_velocity` — each with a configurable weight and a
per-signal cap; thresholds map the total to low/medium/high/critical. `Config`
carries the weights, thresholds, business hours (for off-hours) and the velocity
limit; `New` fills zero fields from `DefaultConfig` (a single break-glass access
alone reaches **high**). The API wires it up: `GET /api/analytics/risk`
(`CapReadAudit`, `?min_level=`/`?window_min=`) scores the recent window over
`store.ExportAudit`; `RunAnalyticsWorker` (`PAM_ANALYTICS_INTERVAL_MIN`) scores each
tick and, for a **newly elevated** high/critical actor, audits `analytics.risk_flagged`
+ alerts, and — with `PAM_ANALYTICS_AUTO_KILL` — terminates a critical actor's live
sessions (`session.Registry.KillByActor`, audit `analytics.auto_response`). A
steady state is not re-alerted; a worsening trend is (a per-actor high-water mark).

### 2.6 `web`

Single embedded `static/index.html` (`//go:embed`). 5250-style terminal UI:
Sign On, menu, "Work with…" screens, F-keys, plain JS calling the REST API with
the key/token entered at Sign On. Panels load independently and tolerate a 403,
so a non-admin role gets a working portal (panels it can't see stay empty).
Served with a strict CSP.

## 3. Proxy wire flow (per connection)

```mermaid
sequenceDiagram
    participant C as ssh client
    participant P as proxy (handleConn)
    participant V as vault
    participant S as store
    participant U as upstream sshd
    C->>P: TCP + SSH handshake
    C->>P: password = API key; user = "root@web-01"
    P->>P: authenticate() -> ext{target,cred_user}
    P->>S: resolve target + credential
    P->>V: Decrypt(SecretEnc, target:ID)  %% JIT
    V-->>P: plaintext (memory only)
    P->>U: ssh.Dial(host:port, user=root, pw=plaintext)
    P->>S: audit session.start
    loop each session channel
        C->>P: OpenChannel("session")
        P->>U: OpenChannel("session")
        C-->>U: requests + stdin (pumped)
        U-->>C: stdout/stderr (tee -> recording)
        P->>S: audit session.record (file, bytes, sha256)
    end
    C->>P: disconnect
    P->>S: audit session.end
```

Concurrency notes: one goroutine per connection (`handleConn`), one per session
channel (`handleSession`), request pumps and stdin copy run in their own
goroutines; the stdout copy runs in the foreground of `handleSession`. Teardown
is keyed on the connection lifecycle, not on stdin: the client→upstream stdin
copy only `CloseWrite`s on a stdin half-close (so a batch command's remaining
output and `exit-status` still flow back), and the upstream is fully closed by
`handleConn` when the client's channel loop ends — i.e. when the client is
actually gone — which unblocks any session still copying idle/wedged upstream
output. Before the client channel closes we `Wait` on both the upstream→client
request pump (so `exit-status` is delivered) and the client→upstream request
pump (so the `exec`/`shell` reply the client's `Session.Start` blocks on is
flushed first). `Serve`'s shutdown is bounded: on `ctx` cancel it closes the
listener **and** force-closes every tracked client connection, then waits for
handlers to return, so no handler goroutine outlives `Serve` and the drain does
not block on operators voluntarily disconnecting. `main` waits for this drain on
SIGTERM (before closing the store), and the closing audit events (`session.end`,
`session.record`) are written through `auditClosing`, which detaches from the
cancelled shutdown context so they are not dropped mid-drain.

## 4. Configuration (env `PAM_*`)

| Var | Default | Used by |
|---|---|---|
| `PAM_MASTER_KEY` | — (required for local KEK) | local KEK key (base64, dev/test); see `PAM_KEK_PROVIDER` |
| `PAM_API_KEY` | — (required) | api auth, proxy auth |
| `PAM_DATABASE_URL` | — (required); `memory` for demo | store |
| `PAM_BREAK_GLASS_KEY_HASH` | "" (disabled) | api auth |
| `PAM_CONJUR_URL` | "" (off) | Conjur secret-source appliance URL; presence enables sourcing bootstrap `PAM_*` at startup (Phase 18) |
| `PAM_CONJUR_ACCOUNT` / `_POLICY_PREFIX` | `default` / `pamv1` | Conjur account + variable-name prefix |
| `PAM_CONJUR_AUTHN_LOGIN` / `_API_KEY` | "" | Conjur authn-api-key credentials |
| `PAM_CONJUR_AUTHN_JWT_SERVICE_ID` / `_JWT_FILE` | "" | Conjur authn-jwt service id + JWT file (K8s-native) |
| `PAM_CONJUR_CACERT` | "" | PEM CA bundle for TLS to Conjur |
| `PAM_REQUIRE_TICKET` | `false` | require an ITSM ticket on access requests (Phase 20) |
| `PAM_TICKET_PATTERN` / `PAM_TICKET_VALIDATE_URL` | "" | ticket format regex / ITSM validation webhook |
| `PAM_APPROVALS_REQUIRED` | `1` | default distinct approvers per access request (Phase 21) |
| `PAM_REQUIRE_REASON` | `false` | reject an access request with no reason |
| `PAM_LISTEN_ADDR` | `:8080` | http server |
| `PAM_SSH_ADDR` | `:2222`; `off` disables | proxy |
| `PAM_DB_ADDR` | `off` | PostgreSQL session-proxy listen address (Phase 15) |
| `PAM_COMMAND_DENY_FILE` | "" (off) | regex denylist file for command control (Phase 16) |
| `PAM_ANALYTICS_INTERVAL_MIN` | `0` (worker off) | privileged-threat-analytics worker interval (Phase 23); the read-only risk endpoint stays available |
| `PAM_ANALYTICS_WINDOW_MIN` | `60` | how far back each risk-scoring pass looks |
| `PAM_ANALYTICS_AUTO_KILL` | `false` | terminate a critical-risk actor's live sessions (automated response) |
| `PAM_ANALYTICS_BUSINESS_START` / `_END` | `7` / `20` | business hours for the off-hours risk signal |
| `PAM_ANALYTICS_TIMEZONE` | "" (UTC) | IANA timezone the business hours are interpreted in (audit timestamps are UTC) |
| `PAM_APP_SECRETS_ENABLED` | `false` | enable the application-secrets API (Phase 24, Tier-4): Conjur-style secret delivery to non-agent apps |
| `PAM_SSH_HOST_KEY` | "" (ephemeral) | proxy host key |
| `PAM_SSH_CA_KEY` | "" (ZSP off) | Zero Standing Privilege SSH CA key path (Phase 22); presence enables `ssh_ca` credentials (mint short-lived certs) |
| `PAM_SSH_CERT_TTL_MIN` | `2` | validity (minutes) of a minted ZSP certificate |
| `PAM_SSH_KNOWN_HOSTS` | "" (trust-any + warn) | pin upstream target host keys (OpenSSH known_hosts) |
| `PAM_SSH_JUMP_HOST` / `_USER` / `_KEY` | — | reach SSH targets through an SSH bastion (jump host) |
| `PAM_RECORDING_DIR` | `recordings` | proxy recordings |
| `PAM_LOG_LEVEL` | `info` | logging (debug/info/warn/error) |
| `PAM_LOG_FORMAT` | `json` | logging (json/text) |
| `PAM_TLS_CERT` / `PAM_TLS_KEY` | — | native HTTPS (TLS 1.2+) when both set |
| `PAM_AUTH_RATE_LIMIT` | `20` | auth attempts / client IP / minute (0 disables) |
| `PAM_TRUSTED_PROXY_HOPS` | `0` | trusted reverse-proxy hops; picks the client IP from `X-Forwarded-For` for rate limiting (0 = use RemoteAddr) |
| `PAM_PROXY_AUTH_RATE_LIMIT` | `10` | failed-auth throttle / source IP / minute on the SSH (:2222) and DB (:5433) proxies (0 disables) |
| `PAM_REQUIRE_HTTPS` | `false` | refuse to start the API/portal without native TLS (fail-closed transport) |
| `PAM_REQUIRE_DB_CLIENT_TLS` | `false` | refuse to start the DB proxy without operator-leg TLS |
| `PAM_DB_UPSTREAM_CA` | — | PEM CA bundle to VERIFY the upstream PostgreSQL cert (fail-closed upstream TLS) |
| `PAM_DB_UPSTREAM_TLS_VERIFY` | `false` | verify the upstream PostgreSQL cert against the system roots |
| `PAM_ALLOW_WEAK_API_KEY` | `false` | override the 16-char `PAM_API_KEY` floor (demos only; ignored for `memory`) |
| `PAM_AUDIT_HMAC_KEY` | — | base64 32-byte key; enables the tamper-evident HMAC chain over the **primary** audit trail (verify via `GET /api/audit/verify`). Unset = plain audit table |
| `PAM_AUDIT_SIGN_SEED` | — | base64 32-byte ed25519 seed (needs `PAM_AUDIT_HMAC_KEY`); signs audit checkpoints served by `GET /api/audit/head` so an auditor can detect **tail truncation** |
| `PAM_REVEAL_DISABLED` | `false` | make credential reveal break-glass-only |
| `PAM_BREAK_GLASS_THRESHOLD` / `_SHARES` | `0` / `5` | quorum M / N (M≥2 enables unseal) |
| `PAM_BREAK_GLASS_TTL_MIN` | `15` | break-glass session lifetime (minutes) |
| `PAM_ALERT_WEBHOOK` | — | JSON POST target for break-glass alerts |
| `PAM_ALERT_SYSLOG` | — | syslog alert channel, `udp://host:port` or `tcp://host:port` |
| `PAM_ALERT_EMAIL_SMTP` / `_FROM` / `_TO` / `_USER` / `_PASS` | — | SMTP alert channel (comma-separated `_TO`) |
| `PAM_KEK_PROVIDER` | `local` | vault KEK: `local` \| `vault-transit` \| `aws-kms` \| `pkcs11` |
| `PAM_KEK_TRANSIT_ADDR` / `_TOKEN` / `_KEY` | — | HashiCorp Vault Transit KEK (production; `https://` required off-loopback) |
| `PAM_NEW_MASTER_KEY` / `PAM_NEW_KEK_*` | — | target KEK for the `-rotate-kek` run (any provider; `PAM_NEW_KEK_PROVIDER` etc. mirror `PAM_KEK_*`, enabling local→KMS migration) |
| `PAM_KEK_AWS_KEY_ID` / `_AWS_REGION` | — | AWS KMS KEK (`aws-kms` provider) |
| `PAM_KEK_PKCS11_MODULE` / `_PIN` / `_KEY_LABEL` / `_TOKEN_LABEL` | — | on-prem HSM KEK (`pkcs11` provider; **only in the `pkcs11`-tagged build**) |
| `PAM_LDAP_URL` | — (disabled) | AD/LDAP login; `ldaps://…` enables `/api/login` |
| `PAM_LDAP_BIND_DN` / `_BIND_PASSWORD` | — | service account for user search |
| `PAM_LDAP_BASE_DN` / `_USER_FILTER` | — / `(sAMAccountName=%s)` | search base + filter |
| `PAM_LDAP_GROUP_ADMIN` / `_USER` / `_AUDITOR` / `_APPROVER` | — | group DN → role |
| `PAM_LDAP_INSECURE_SKIP_VERIFY` | `false` | disable TLS verify (dev only) |
| `PAM_ENTRA_TENANT_ID` | — (disabled) | Entra ID login; set to enable |
| `PAM_ENTRA_CLIENT_ID` / `_CLIENT_SECRET` / `_SCOPE` / `_AUTHORITY_HOST` | — | Entra app registration |
| `PAM_ENTRA_ROLE_ADMIN` / `_USER` / `_AUDITOR` / `_APPROVER` | — | Entra app-role/group → role |
| `PAM_MFA_REQUIRED` | `false` | require a confirmed TOTP factor for password login |
| `PAM_ROTATE_INTERVAL_MIN` | `0` (off) | credential-lifecycle worker interval (minutes) |
| `PAM_ROTATE_MAX_AGE_HOURS` | `0` (report only) | auto-rotate password credentials older than this |
| `PAM_ROTATE_AFTER_SESSION` | `false` | rotate a credential as soon as a proxied session using it ends |
| `PAM_ALLOWED_PROTOCOLS` | — (all) | OT: comma-separated protocol allowlist (e.g. `ssh,winrm`) enforced at create + connect |
| `PAM_REQUIRE_APPROVAL` | `false` | OT: gate every target behind an approved access request (4-eyes) |
| `PAM_REQUIRE_RECORDING` | `false` | refuse a proxied session if its recording cannot be created (fail-closed audit) |
| `PAM_APPROVAL_WINDOW_MIN` | `60` | how long an approved access request stays valid |
| `PAM_CHECKOUT_TTL_MIN` | `30` | credential checkout lease lifetime (minutes) |
| `PAM_OT_AIRGAP` | `false` | disable all outbound calls (alert webhooks) for air-gapped sites |
| `PAM_WINRM_HTTPS` | `true` | use HTTPS (5986) for WinRM |
| `PAM_WINRM_INSECURE_SKIP_VERIFY` | `false` | skip WinRM TLS verify (dev only) |
| `PAM_WINRM_AUTH` | `basic` | `basic` or `ntlm` |
| `PAM_GUACD_ADDR` | — (RDP off) | Guacamole guacd address, e.g. `127.0.0.1:4822` |
| `PAM_GUACD_RECORDING_PATH` | — | server-side path for guacd to record RDP sessions |
| `PAM_PROXY_WINRM` | `false` | broker an interactive WinRM command loop through the SSH proxy |
| `PAM_GUACD_RDP_SECURITY` / `PAM_GUACD_IGNORE_CERT` | negotiate / `false` (verify) | RDP security mode; cert verification (opt-out for dev) |
| `PAM_OIDC_ISSUER` | — (disabled) | OIDC login; set to enable the auth-code flow |
| `PAM_OIDC_CLIENT_ID` / `_CLIENT_SECRET` / `_REDIRECT_URL` / `_SCOPES` | — | OIDC client |
| `PAM_OIDC_AUTH_URL` / `_TOKEN_URL` / `_JWKS_URL` | — (discovered) | override endpoints |
| `PAM_OIDC_ROLE_ADMIN` / `_USER` / `_AUDITOR` / `_APPROVER` | — | OIDC app-role/group → role |
| `PAM_PORTAL_URL` | `/` | OIDC callback redirect base |
| `PAM_BROKER_POLICY_FILE` | — (broker off) | AI-agent broker: YAML policy rules; set to enable the broker |
| `PAM_BROKER_AUDIT_KEY` | — | base64 32-byte HMAC key for the broker audit chain (required when the broker is on) |
| `PAM_BROKER_AUDIT_SIGN_SEED` | — | base64 32-byte ed25519 seed for signed head checkpoints (required when the broker is on) |
| `PAM_BROKER_TOKEN_TTL_MIN` | `15` | Lifetime (minutes) of a single-use approval resume token |
| `PAM_BROKER_MAX_ARG_BYTES` | `16384` | Cap on a tool call's serialized arguments; `0` disables |
| `PAM_BROKER_RATE_PER_MIN` | `0` (off) | Per-agent tool-call rate limit (calls per minute) |
| `PAM_BROKER_TRUST_DOMAIN_JWKS` | — (SVID off) | File with the SPIFFE trust-domain JWKS; set to accept JWT-SVIDs |
| `PAM_BROKER_TRUST_DOMAIN` | — | SPIFFE trust domain host (e.g. `example.org`); required with the JWKS |
| `PAM_BROKER_AUDIENCE` | — | Required SVID audience; required with the JWKS |
| `PAM_BROKER_MAX_DELEGATION_DEPTH` | `1` | RFC 8693 `act`-chain depth cap (fail-closed beyond it) |

## 4a. Logging (operational, to stdout)

`internal/logging` installs the process slog logger (`Setup`) and hands each
component a logger tagged `service=<name>` (`Component`). Distinct from the DB
**audit trail**: logs are for ops/debugging/SIEM, the audit trail is the security
record. Highlights: `api` logs one line per HTTP request (method/path/status/
actor/duration) via an access-log middleware + `statusWriter`; `proxy` logs
connection auth, session start/end, denials, upstream errors; `store` (pgstore)
logs the Postgres connect and traces each query at `debug` (SQL text + duration +
rows, **never argument values**). The vault deliberately logs nothing about
secrets. Format `json` (SIEM) or `text` (humans); collect from stdout.

## 5. Audit action vocabulary

`target.create` · `target.delete` · `credential.create` · `credential.reveal` ·
`credential.delete` · `credential.reveal_denied` · `credential.checkin_denied` · `credential.rotate_orphaned` · `grant.create` · `grant.delete` ·
`winrm.denied` · `session.kill` · `breakglass.unseal` · `user.create` · `user.delete` · `login` · `logout` ·
`credential.rotate` · `credential.rotate_started` · `credential.rotate_failed` · `credential.reconcile` · `credential.reconcile_scan` · `credential.remediate` ·
`credential.checkout` · `credential.checkin` · `credential.checkout_denied` · `credential.checkin_rotate_failed` · `credential.decrypt_failed` · `discovery.scan` ·
`access.request` · `access.approve` · `access.deny` · `access.denied` · `access.decision_denied` · `audit.export` · `identity.reconcile` · `user.revoked` ·
`mfa.enroll` · `mfa.confirm` · `mfa.disable` · `mfa.recovery_generated` ·
`mfa.recovery_used` · `winrm.run` · `winrm.error` · `ssh.exec` · `rdp.connect` · `rdp.end` ·
`rdp.error` · `authz.denied` · `login.failed` · `proxy.auth_failed` · `proxy.auth_rate_limited` · `session.revoked` · `vault.kek_rotated` · `breakglass.access` · `session.start` ·
`session.record` · `session.record_failed` · `session.end` · `session.denied` · `session.error` · `session.cert_issued` ·
`analytics.risk_flagged` · `analytics.auto_response` ·
`db.session.start` · `db.session.end` · `db.session.denied` · `db.session.error` · `db.query` ·
`command.blocked` · `session.monitor` ·
`safe.create` · `safe.delete` · `safe.member.add` · `safe.member.remove` · `target.safe_set` ·
`dependency.create` · `dependency.delete` · `credential.dependency_updated` · `credential.dependency_failed` ·
`certification.campaign_created` · `certification.item_certified` · `certification.item_revoked` · `certification.campaign_closed` ·
`access.ticket_rejected` · `access.approve_partial` ·
`app.create` · `app.revoke` · `app.grant` · `app.grant_revoked` · `app.secret_retrieved` · `app.secret_denied` ·
`agent.create` · `agent.revoke` · `broker.tool_call.requested` · `broker.tool_call.executed` · `broker.tool_call.denied` · `broker.tool_call.pending_approval` · `broker.tool_call.failed` · `broker.tool_call.resumed` · `broker.approval.granted` · `broker.approval.denied` ·
`config.update` · `config.revert` · `profile.create` · `profile.delete`. The actor is the Principal name
(`bootstrap-admin`, `break-glass`, a username, or an agent name). Agent-broker
events are also written to the separate tamper-evident `broker_audit_events` chain.

## 6. Security-relevant invariants (do not regress)

1. `Credential.SecretEnc` must never be serialized to any client (`json:"-"`).
2. All key/secret comparisons use `crypto/subtle.ConstantTimeCompare`.
3. Vault AAD on decrypt must equal AAD on encrypt (`store.CredentialAAD`).
2a. Per-target authorization: connect paths (proxy/WinRM/RDP) must pass
   `auth.CanConnectTarget(p, grants, safeScoped)` — a target with grants admits
   only matching users/roles (admins always). An **ungated** target (not in a
   safe) is open to any connect-capable principal; a **safe-scoped** target
   (`Target.SafeID` set) is default-DENY when no grant matches, so safe
   membership actually contains it. Pass `target.SafeID != nil` at every call.
3a. Envelope encryption: per-secret data keys are wrapped by the KEK and zeroed
   after use; the base64 `PAM_MASTER_KEY` (local KEK) is dev/test only —
   production uses a KMS-backed KEK.
4. Every code path that reveals or uses a secret appends an audit event, and the
   secret-delivery paths do so **fail-closed**: reveal / checkout / app-secret use
   `mustAudit`/`mustAuditAs` (HTTP 503 if the durable write fails), and both
   proxies audit `session.start` *before* decryption via `appendAuditErr` (session
   refused if it fails). Only non-secret events remain best-effort.
4a. TOTP secrets are stored vault-encrypted (AAD `mfa:<user>`), returned only
   once at enrollment, and compared in constant time (`crypto/subtle`). Recovery
   codes are stored only as SHA-256 hashes, shown once, and single-use.
5. Break-glass config holds only the SHA-256 hash, never the plaintext key.
6. Proxy plaintext secret is confined to `resolve`→`dialUpstream`; never logged.
7. User access tokens are stored only as `TokenHash` (`json:"-"`); the plaintext
   is returned once at creation and never persisted or re-derivable.
8. Every protected route/connection declares a capability; the role→capability
   matrix in `auth` is the single source of truth (don't inline role checks).

**Known, accepted limitations (documented, not defects):**

- **Session-recording UTF-8 fidelity.** `proxy.Recording.Write` records each read
  as an asciicast v2 `"o"` frame (`string(p)`), so a multi-byte rune split across
  two reads lands on a frame boundary; Go's JSON encoder emits U+FFFD for the
  partial bytes. The recording stays valid JSON and the SHA-256 still covers what
  was written — only the split rune is cosmetically off in playback. Byte-exact
  capture of arbitrary binary is out of scope for the text-oriented asciicast
  format by design.
- **Local-KEK nonce ceiling.** `LocalKEK.Wrap` uses a random 96-bit AES-GCM nonce
  per DEK wrap. [NIST SP 800-38D §8.3](https://csrc.nist.gov/pubs/sp/800/38/d/final)
  bounds a single key to ~2³² random-nonce invocations; one wrap per secret (plus
  rotations) stays far below that here, and production uses an external KEK
  (Vault-Transit / KMS / PKCS#11) as invariant 3a already requires.

## 7. Testing

- `vault`: envelope roundtrip, AAD binding, tamper detection, version rejection, distinct tokens; local KEK wrap/unwrap + tamper; KEK factory; **Transit KMS** wrap/unwrap and full envelope over a mock Vault Transit server; **PKCS#11 HSM** wrap/unwrap + full envelope against SoftHSM2 (tag `pkcs11`, CI).
- `auth`: role→capability matrix, role parsing, resolver (bootstrap/break-glass/token/**session**/unknown); **LDAP** authenticate against a fake `ldapConn`; **Entra** app-role/group login with an RS256-signed id_token (valid maps roles; a forged signature is rejected).
- `store` conformance: `storetest.RunStoreContract` exercises the whole `Store` interface (targets/creds/grants/access-requests/checkouts/audit+export/users/sessions/MFA/recovery/OIDC-state) — run by **memstore** and, in CI, against a **live PostgreSQL** (`PAM_TEST_DATABASE_URL`).
- `mfa`: RFC 6238 test vector, validate roundtrip + skew + wrong/short code, otpauth URI, secret randomness, recovery-code generation.
- `api` (WinRM): JIT injection (fake runner receives the vaulted secret), non-Windows target rejected, `CapConnect` required, transcript recorded + audited.
- `winrm`: basic and NTLM client construction (NTLM must not mutate library defaults).
- `guacd`: instruction encode (byte vs code-point length), and handshake against a mock guacd asserting the **JIT credential injection** into `connect` (+ unknown args empty).
- `api` (RDP): tunnel disabled without guacd (404), no/invalid token 401, non-connect role 403, non-rdp target 422 (pre-WebSocket checks).
- `oidc`: Exchange with a real RSA-signed token (valid), and rejects bad signature / wrong issuer / wrong audience / nonce mismatch / expired; PKCE + auth URL.
- `api` (OIDC): full flow (start redirect → callback with a signed token → session → admin role enforced), bad-state error redirect, not-configured 404.
- `auth` (Entra/chain): Entra app-role & group login, multi-group role **union** (`TestMatchedRoles`/`TestMultiGroupUnion`), bad password, no mapped role (mock token endpoint); chain resolves via a later source and rejects when none match.
- `shamir`: split/combine roundtrip (any M reconstruct), below-threshold and corrupted shares don't, validation.
- `alert`: webhook receives the event; no-op is safe.
- `api` (break-glass): quorum unseal issues a break-glass session that reads audit + fires unseal & access alerts; wrong shares 401; not-configured 404.
- `api`: full CRUD flow, auth required, secret-non-leak, cascade delete, break-glass audited, validation/conflict, **RBAC** (user/auditor/approver each allowed only their capabilities), **login session** (issue → use with role enforcement → logout revokes), login-not-configured 503, **MFA** (enroll → confirm → login requires OTP → wrong OTP rejected), **enforce-MFA** (enrollment-only session blocked from other routes → enroll → full session), **recovery codes** (login with a code, single-use).
- `proxy`: **end-to-end JIT injection** against an in-process upstream sshd that
  accepts only the vaulted password (proves the client never had it), plus wrong-key
  rejection, unknown-target denial, credential selector, recording hash match, and
  **auditor-denied connect** (RBAC gate).
- CI runs `gofmt -l`, `go vet`, `staticcheck`, `govulncheck`, `gosec`, `go build`, `go test -race`, and a Docker build.

## 8. Change log

| Date | Change |
|---|---|
| 2026-07-23 | **Signed audit checkpoints (tail-truncation detection).** The primary-audit HMAC chain catches edits/reorders/mid-deletions but not tail truncation. Added `GET /api/audit/head` (`CapReadAudit`), which returns an ed25519-signed checkpoint over `(last_id, head)` — an auditor stores it and later detects truncation, mirroring the broker chain. New `PAM_AUDIT_SIGN_SEED` (base64 32-byte ed25519 seed; requires `PAM_AUDIT_HMAC_KEY`, fail-loud). New store method `GetAuditHead`; the signing helper `auditchain.SignCheckpoint` is now shared by the broker and primary chains. 501 when unconfigured |
| 2026-07-23 | **Security hygiene: dependency refresh + gosec gate.** Bumped outdated dependencies (AWS SDK point releases, go-logr; `go mod verify` clean, govulncheck still 0 reachable). Added `gosec` as a CI gate (`-confidence high -exclude=G104,G115,G304,G306,G101` — the pervasively-deliberate/noisy rule categories); the remaining deliberate findings (protocol-mandated md5/sha1, the documented trust-any host-key defaults, the opt-in-verify TLS fallbacks, the loopback healthcheck probe, the conditionally-Secure OIDC cookie, operator-config file reads) are recorded inline with `#nosec Gxxx -- reason`. No behavior change |
| 2026-07-23 | **Tamper-evident PRIMARY audit trail (opt-in).** The keyed-HMAC chain now covers the main `audit_events` table, not just broker events. Additive migration `0018` adds nullable `prev_hash`/`hmac`; when `PAM_AUDIT_HMAC_KEY` (base64 32 bytes) is set, `AppendAudit` links each event `hmac = HMAC-SHA256(key, prev_hash ‖ canonical(actor,action,detail))` in the same transaction under an advisory lock (`pam_audc`), so editing/reordering/deleting any event is detectable. `store.EnableAuditChain`/`VerifyAuditChain` + `GET /api/audit/verify` (`CapReadAudit`, 501 when disabled). Unset = today's plain table (non-breaking). Contract + tamper tests (memstore in-package, live-Postgres via `UPDATE`) |
| 2026-07-22 | **Rate-limiter de-dup + invariants-as-tests.** Extracted the two near-identical fixed-window limiters (API auth endpoints, SSH/DB proxies, broker per-agent) into one shared `internal/ratelimit` package (`ratelimit.New`/`Limiter.Allow`, injectable clock); all three now share tested logic. Encoded security invariant §6.1/§6.7 as executable tests (`internal/store/invariants_test.go`): a reflection guard that every secret-bearing field (`Credential.SecretEnc`, the four `TokenHash`es, `MFAEnrollment.SecretEnc`/`LastTOTPStep`, `BrokerToken.JTI`, `BrokerAuditEvent.PrevHash`) is `json:"-"`, plus a behavioral marshal test that secret material never appears in JSON. No behavior change |
| 2026-07-22 | **HA leader election for the background workers.** New `store.WithLeaderLock(ctx, key, fn)` runs a periodic job only if it can take a non-blocking Postgres advisory lock (`pg_try_advisory_lock`, held on a dedicated pooled connection for the pass), so across replicas exactly one runs the credential-lifecycle (rotation/reconcile) and threat-analytics passes per tick — no more N replicas rotating the same credential or firing duplicate alerts/kills. Keys `pam_lfc`/`pam_ana` (distinct from `pam_mig`/`pam_br`). memstore always runs fn (single process). Contract test + a live-Postgres mutual-exclusion test |
| 2026-07-22 | **CI static analysis + vuln scanning.** Added `staticcheck` and `govulncheck` as CI gates (both clean at introduction). Fixed the staticcheck findings surfaced: `archgen` uses `parser.ParseFile` per file instead of the deprecated `parser.ParseDir`; the two proxy accept-loops document their deliberate `net.Error.Temporary()` use with `//lint:ignore SA1019`; the DB-proxy startup switch binds the type-switch variable (drops a redundant assertion); a test passes `context.TODO()` instead of a nil context. No behavior change |
| 2026-07-22 | **Security gap-analysis hardening pass** (see `docs/SECURITY-GAPS.md`). Authorization: `auth.CanConnectTarget` now takes `safeScoped` — a target in a safe with no matching grant is default-DENY (was open); all 5 call sites pass `target.SafeID != nil`. The DB proxy now rejects MFA enroll-only sessions (was a `PAM_MFA_REQUIRED` bypass for postgres targets) and reconstructs the full multi-group principal for the SSH grant check (`ext["roles"]`). Audit: secret-delivery is fail-closed — `mustAudit`/`mustAuditAs` (reveal/checkout/app-secret → 503) and `appendAuditErr` (both proxies audit `session.start` before decryption). Break-glass is now audited on the `authenticated` middleware (`/me`, `/logout`, `/mfa/*`). Transport: `PAM_DB_UPSTREAM_CA`/`_TLS_VERIFY` verify the upstream PostgreSQL cert fail-closed; SCRAM server-signature is verified; `PAM_REQUIRE_HTTPS`/`PAM_REQUIRE_DB_CLIENT_TLS` refuse plaintext; PostgreSQL `FunctionCall` fast-path is audited. Brute-force: `PAM_PROXY_AUTH_RATE_LIMIT` throttles SSH/DB proxy auth; `PAM_TRUSTED_PROXY_HOPS` makes the API limiter XFF-aware. Sessions: admin `GET /api/login-sessions` + `POST /api/login-sessions/revoke` (`CapManageUsers`), and identity reconcile revokes directory-disabled sessions (store gains `ListSessions`/`DeleteSessionsByUsername`). `-rotate-kek` supports any KEK provider via `PAM_NEW_KEK_*` and audits `vault.kek_rotated`; `PAM_API_KEY` has a 16-char floor (non-demo, `PAM_ALLOW_WEAK_API_KEY` override); healthcheck matches the TLS scheme. IaC: default-deny NetworkPolicy (k8s + gated Helm), pinned `:latest` images. New audit vocab `proxy.auth_rate_limited`/`session.revoked`/`vault.kek_rotated`; new env vars listed in §4. Tests added for each; `go test -race`, `vet`, `gofmt` green |
| 2026-07-22 | Repo root decluttered: the Docker/compose/env files moved to `deploy/docker/` (`Dockerfile`, `Dockerfile.pkcs11`, `docker-compose.yml`, `.env.example`; compose `build.context` still the repo root) and the SOPS config to `deploy/.sops.yaml` (regexes relative to `deploy/`; encrypt with `--config deploy/.sops.yaml`, decrypt/CI unaffected). CI/release workflows, `.dockerignore` and all docs updated. The root now holds only `go.mod`/`go.sum`, `README*`, `ROADMAP.md`, `LICENSE`, `CLAUDE.md`, `.dockerignore`, `.gitignore`. No code change |
| 2026-07-21 | Phase 24 console: a 5250 screen for the application-secrets API — menu 15 *Work with application secrets* (mint/revoke apps, one-time token) + per-app *Work with secret grants* (grant/revoke credentials), keyboard-first, tolerating the API being disabled. No new routes/schema (uses the Phase 24 API) |
| 2026-07-21 | Phase 24 (Tier-4 application-secrets API) + **keyboard-first portal**. New store types `AppKey`/`AppSecretGrant` (migration `0017`: `app_keys`, `app_secret_grants`, both FKs cascade) + store methods (`CreateAppKey`/`GetAppKeyByTokenHash`/`ListAppKeys`/`DeleteAppKey`/`GrantAppSecret`/`ListAppSecretGrants`/`DeleteAppSecretGrant`/`AppMayAccessCredential`). Opt-in via `PAM_APP_SECRETS_ENABLED`: `appAuth` resolves an application bearer key (SHA-256-hash lookup, disabled = 401), `GET /v1/app-secrets/{id}` returns a **granted** credential's secret JIT (default-deny → `app.secret_denied`/403; `ssh_ca` → 422), admin routes `POST/GET/DELETE /v1/apps[...]` (`CapManageUsers`) and grants `POST/DELETE /v1/apps/{id}/grants[...]` (`CapRevealSecret` — you can only delegate a secret you could reveal). New audit vocab `app.create`/`revoke`/`grant`/`grant_revoked`/`secret_retrieved`/`secret_denied`. **Portal keyboard-first** (`web/static/index.html`): `render()` focuses each screen's primary field (`focusPrimary`), Esc = back/cancel, ↑/↓ move between subfile option cells, a persistent `.khint` documents the shortcuts — look unchanged. Store contract + end-to-end API tests |
| 2026-07-21 | Phase 22/23 review fixes: **analytics re-alert cooldown** — the per-actor alerted-set now stores `{score, time}` and is pruned after `PAM_ANALYTICS_WINDOW_MIN`, so a sustained/recurring high-risk incident re-alerts (and re-kills) instead of being suppressed forever, and the map (keyed by attacker-controllable actor names from auth-failure events) can't grow unbounded; **off-hours timezone** — the off-hours signal is evaluated in `PAM_ANALYTICS_TIMEZONE` (default UTC) rather than the UTC audit timestamp's hour; **`?window_min=` cap** — the risk endpoint clamps the window to 7 days so one request can't score the whole audit table; **ssh_ca reveal/checkout** — reveal/checkout and the broker `ssh_exec`/`reveal_credential` tools now refuse a Zero Standing Privilege credential with a 422 instead of decrypting its empty secret (a 500 + a misleading `credential.decrypt_failed`); **ZSP cert TTL** upper-bounded at 24h so a long TTL can't silently become a standing credential. Regression tests added |
| 2026-07-21 | Phase 23 (privileged threat analytics): the second Tier-3 gap. New `internal/analytics` — a deterministic, explainable risk scorer over the audit trail (`Score` is pure: no clock/IO/model). Named signals (`break_glass`, `command_blocked`, `auth_failure`, `off_hours`, `decrypt_failure`, `high_velocity`) with configurable weights, per-signal caps and level thresholds; a single break-glass access reaches high. API `GET /api/analytics/risk` (`CapReadAudit`, `?min_level`/`?window_min`) scores the recent window via `store.ExportAudit`; `RunAnalyticsWorker` (`PAM_ANALYTICS_INTERVAL_MIN`) flags a **newly elevated** high/critical actor (`analytics.risk_flagged` + alert) and, with `PAM_ANALYTICS_AUTO_KILL`, terminates a critical actor's live sessions (new `session.Registry.KillByActor`, audit `analytics.auto_response`). A per-actor high-water mark suppresses steady-state re-alerting. New env `PAM_ANALYTICS_*`; `api.Options.Analytics/AnalyticsWindow/AnalyticsAutoKill`. Engine unit tests + API worker/endpoint tests |
| 2026-07-21 | Phase 22 (Zero Standing Privilege): the first Tier-3 gap. New `internal/sshca` — an SSH certificate authority that mints a short-lived user certificate **just-in-time** per session (fresh ephemeral keypair, one dial, then discarded) so an account has **no standing secret**. A `secret_type="ssh_ca"` credential stores nothing (`SecretEnc` empty); `proxy.dialUpstream` branches on it to mint a cert signed by the CA instead of decrypting, and fails closed (`session.error`) when no CA is configured. `PAM_SSH_CA_KEY` (persistent, generated on first use) + `PAM_SSH_CERT_TTL_MIN` (default 2m); `GET /api/ca/ssh` (`CapReadInventory`) publishes the CA public key + `TrustedUserCAKeys` install hint. Audit `session.cert_issued` (serial/principal/valid-before/key-id, never the key). Reconcile reports `ssh_ca` as `unsupported`; post-session rotation and the lifecycle worker skip it. `proxy.Config.CA/CertTTL`, `api.Options.CA`. `internal/sshca` unit tests + an end-to-end cert-only-upstream ZSP proxy test (no password auth exists) + without-CA fail-closed + credential/endpoint API tests. Infra-bound Tier-3 leftovers catalogued in `docs/EXTERNAL-INFRA-GAPS.md` |
| 2026-07-21 | Phase 21 (richer approval workflows): multi-tier chains + scheduled windows + mandatory reason on the access-request engine (migration `0016`: `required_approvals`, `approved_by`, `not_before`). **N-of-M** — `decideAccessRequest`'s approve path accumulates DISTINCT approvers into `approved_by` via the new `store.SetApprovalState`; the request stays `pending` (audit `access.approve_partial`) until `RequiredApprovals` is met, then `approved` (double-approval 409, self-approval still 403). **Scheduled window** — `not_before`/`not_after`; `HasActiveApproval` now also requires `not_before <= now`. **Mandatory reason** — `PAM_REQUIRE_REASON`. New env `PAM_APPROVALS_REQUIRED`/`PAM_REQUIRE_REASON` (via `api.Options`). Completes Tier-2. One-time access deferred (needs a consume hook in every connect gate). Store contract + end-to-end API tests |
| 2026-07-21 | Phase 20 (ITSM / ticketing gate): "no access without an approved change ticket". New `internal/ticket` (no new dependency): a `Validator` with two optional, composable checks — a regex format (`PAM_TICKET_PATTERN`) and a webhook (`PAM_TICKET_VALIDATE_URL`, `POST {"ticket":…}` → 2xx = valid). `createAccessRequest` accepts a `ticket`: mandatory when `PAM_REQUIRE_TICKET` (422 otherwise), validated when a validator is configured (422 + `access.ticket_rejected` on failure), and recorded on the request + in the `access.request` audit (`store.AccessRequest.Ticket`, migration `0015`). Wired via `api.Options.TicketValidator`/`RequireTicket`. Fake-webhook API test + a `ticket` unit test |
| 2026-07-21 | Phase 19 (access certification campaigns): the first Tier-2 gap. `POST /api/campaigns` snapshots the current access grants — every target grant + every safe member — as `campaign_items` (migration `0014`: `campaigns`, `campaign_items`). `POST /api/campaigns/{id}/items/{iid}/decision {certify\|revoke}` records the attestation; a **revoke deletes the underlying grant** (`DeleteTargetGrant`/`DeleteSafeMember`, no-op if already gone), `…/close` closes it (further decisions 409). Management is `CapManageUsers`, reading `CapReadAudit` (an auditor reviews without changing access) — no new capability. New store types `Campaign`/`CampaignItem`; audit vocab `certification.campaign_created`/`item_certified`/`item_revoked`/`campaign_closed`. Store contract + end-to-end API test |
| 2026-07-21 | Phase 18 (Conjur secret sourcing): pamv1 can source its **own** bootstrap secrets from CyberArk Conjur at startup — the runtime-broker alternative to the SOPS GitOps sealing (Phase 14), which stays the default. New `internal/conjur` (hand-rolled over two REST endpoints, **no new dependency**): `New`/`Authenticate`/`Get` with `authn-api-key` **and** `authn-jwt` (a Kubernetes projected SA token — no bootstrap secret in Git), TLS with an optional CA bundle. `conjur.SourceEnv(ctx)` runs in `main` **before `config.Load`**: when `PAM_CONJUR_URL` is set it fills any empty bootstrap `PAM_*` (`master-key`/`api-key`/`database-url`/`break-glass-key-hash`/`broker-audit-key`/`_sign-seed`) from `PAM_CONJUR_POLICY_PREFIX/<name>`; an explicit env value wins, a 404 variable is skipped, a configured-but-unreachable Conjur is fail-loud. Same philosophy as the pluggable KEK (externalize the root of trust), now for the secret values. New env `PAM_CONJUR_*`; `deploy/k8s/conjur/` (policy + authn-jwt Deployment + README). Fake-Conjur tests; no schema/wire-format/audit-vocab change |
| 2026-07-21 | Phase 17b (dependent-account propagation): a credential declares its consumers — Windows Services / Scheduled Tasks / IIS App Pools (migration `0013`: `credential_dependencies`, cascades on credential delete). After `rotateCredential` persists the new secret, `propagateDependencies` updates each consumer over WinRM (`sc.exe config` / `schtasks /Change /RP` / `appcmd …processModel.password`) with the new secret, so auto-rotating a service account doesn't break the services it runs. A propagation failure never fails the (already-persisted) rotation; each consumer is audited `credential.dependency_updated`/`credential.dependency_failed` — the secret is injected into the command but never audited or recorded. API `POST/GET /api/credentials/{id}/dependencies` + `DELETE …/{did}`; new `store.CredentialDependency`. Completes Phase 17 (all four Tier-1 competitive-coverage gaps shipped) |
| 2026-07-21 | Phase 17a (safes / vault containers): named containers group targets and delegate access (migration `0012`: `safes`, `safe_members`, `targets.safe_id`). A **safe member may connect to every target in the safe** — an authorization path alongside per-target grants — surfaced by the new `store.EffectiveTargetGrants(targetID)` = direct grants ∪ safe-member-derived grants; the six connect gates (SSH proxy, DB proxy, RDP, two broker-tool checks, `gateCredentialAccess`) now call it instead of `ListTargetGrants`. `auth.SubjectMatches` factored out of `CanConnectTarget` and reused for safe membership + delegated management. API `POST/GET /api/safes`, `DELETE /api/safes/{id}`, `GET/POST /api/safes/{id}/members`, `DELETE /api/safes/{id}/members/{mid}`, `PUT /api/targets/{id}/safe`; member management is open to inventory readers but gated by `canManageSafe` (a global target manager **or** a `can_manage` member of that safe — delegated administration). New `store.Safe`/`SafeMember`, `Target.SafeID`; audit `safe.create`/`safe.delete`/`safe.member.add`/`safe.member.remove`/`target.safe_set` |
| 2026-07-21 | Phase 16 (live monitoring + command control): supervised sessions. **Live monitoring** — a `session.Hub` (`internal/session/hub.go`) fans out recorded output keyed by session id; `GET /api/sessions/{id}/stream` (`CapReadAudit`) streams it as Server-Sent Events so a supervisor watches an SSH or PostgreSQL session live (non-blocking fan-out; audited `session.monitor`). The proxy tees output via `Proxy.teeLive`/`liveWriter`; `statusWriter` gained a delegating `Flush` so the SSE handler can push through the middleware chain. **Command control** — a `proxy.CommandGuard` (regex denylist from `PAM_COMMAND_DENY_FILE`) blocks a command before it reaches the target: SSH `exec` (`pumpRequests`' `onExec` now returns a forward/veto bool), each WinRM line (`winrmRun`), and each PostgreSQL `Query`/`Parse` (the DB relay now serializes all client-facing writes under one mutex — pgproto3 is not concurrency-safe — and refuses a simple query gracefully / an extended statement fail-closed). New audit vocab `command.blocked`, `session.monitor`. Interactive-shell filtering, WinRM live streaming, and an in-portal viewer are documented follow-ons |
| 2026-07-20 | Phase 15 (database session proxy): a second listener (`internal/proxy/dbproxy.go`, `PAM_DB_ADDR`, default off) extends the JIT chokepoint to **PostgreSQL**. Speaks the frontend/backend wire protocol via `pgproto3` (vendored with pgx); an operator runs `psql user=<dbcred>@<target>` with their PAM key as the password. Runs the **same authorization gates as the SSH proxy** — `CapConnect`, per-target grants (`CanConnectTarget`), protocol allowlist, 4-eyes approval — then decrypts JIT and authenticates upstream with the vaulted secret (trust / cleartext / MD5 / **SCRAM-SHA-256** via `x/crypto/pbkdf2`, best-effort upstream TLS; optional operator-leg TLS). Each `Query`/`Parse` is a `db.query` audit event and a recorded line (asciicast, hash-chained); sessions appear in the live registry (protocol `postgres`) with kill + post-session rotation. Target protocol `postgres` added to `validProtocol`. Shared proxy helpers (`lookupTargetCred`/`jitDecrypt`/`appendAudit`/`recoverPanicLog`) factored out of `proxy.go` so both listeners reuse the security-critical resolve/decrypt/audit path. New audit vocab `db.session.{start,end,denied,error}` + `db.query`. Proven by an in-process fake-upstream test that accepts only the vaulted secret |
| 2026-07-20 | Deferred-set follow-ups (post-review). **Multi-group role union** — a directory principal can now carry several roles (`Principal.Roles`); `Can`/`CanConnectTarget`/`CapabilityNames` evaluate the **union** of their capabilities (LDAP/Entra group→role maps that overlap no longer silently collapse to one role), persisted across a session as `sessions.roles` (migration `0011`) and re-split on resolve. **Agent revocation at approval time** — a parked `require_approval` call is re-validated before it executes (`broker.WithRevalidator`): a static agent key revoked/disabled since parking (`store.GetAgentKey` by id) or an expired SVID (`agentid.Identity.ExpiresAt`) is refused, not run. **Chain can't fork under concurrent writers** — broker-audit append is now `AppendBrokerAuditLinked`: the store reads the current head and inserts the linked event as **one atomic step under a Postgres advisory lock** (`brokerChainLockKey`; the migration-lock idiom), so an old+new pod overlapping during a rolling deploy — or HA replicas — serialize instead of forking the keyed-HMAC chain (the in-process head is now only advisory). **Policy numeric match** — a JSON-number argument (float64) stringifies in plain decimal (`10000000`, not `1e+07`), so an `eq`/`in` on a large integer can't silently never match. Each carries a regression test |
| 2026-07-20 | Whole-codebase code-review fixes (15 findings + sweep). **Authz:** `PUT/DELETE /api/config` require a built-in admin (`Principal.IsAdmin`); reveal + checkout enforce target grants + four-eyes (`gateCredentialAccess`); checkin verifies the holder; `Covers` treats a built-in admin as unconstrained. **Broker:** `Decide` redacts a `Sensitive` reveal (approver gets status, agent resumes once); `getToolCall` strips `ResumeToken`; self-approval refused; `Tool.Capability()` enforced; parked-approval TTL sweep. **KEK rotation:** re-wraps encrypted settings and preserves `last_totp_step` (`ListMFAEnrollments` now selects it); loud `credential.rotate_orphaned`. **Recording/audit:** proxy records the exec command (WinRM + SSH-exec `ssh.exec`); RDP break-glass uses `noteBreakGlass`; `proxy.auth_failed` audited; audit export digest is over the exact artifact bytes + records the filter. **Config:** `PAM_LDAP_INSECURE_SKIP_VERIFY` no longer overridable; fail-loud on negative rate limits and partial email alerting. **Robustness:** rate-limiter eviction; break-glass share-poison rejection; proxy goroutine panic barrier; migrations on the locked conn; mfa body caps; discovery honors the protocol allowlist; policy rejects a typo'd operator; memstore token/audit parity. **Vault/auth:** transit/KMS `Unwrap` key-length check; bootstrap key compared by SHA-256; LDAP names lower-cased; `capCount` sentinel. Every fix carries a regression test |
| 2026-07-20 | Phase 12/13 hardening (multi-agent gap review): **privilege-escalation guard** — `createUser`/`createProfile` now enforce `Principal.Covers` (you cannot grant a role/profile with capabilities you don't hold), so a delegated `manage_users` can't mint an admin or forge a max-cap profile. **Reveal confinement** — a `reveal_credential` result is `Sensitive`; `GET /v1/tool-calls/{id}` is now a status-only poll (never re-serves the secret) and the plaintext is not retained in the poll cache. **Resume** peeks the token and refuses to spend it while the call is still pending. **Bounded state** — `broker.parked` capped (`maxParked`, fail-closed) and a `RunBrokerTokenGC` reaper (`DeleteExpiredBrokerTokens`) sweeps spent/expired `broker_tokens`. **SVID delegation** — every RFC 8693 `act.sub` must be in the trust domain (no spoofed accountable identity). **Hot-swap torn read** — login/OIDC snapshot `s.rt()` once; config notes corrected (the SSH proxy's protocol/approval gates apply on restart, not live). Store gains `PeekBrokerToken`/`DeleteExpiredBrokerTokens` (contract-tested); pgstore integration `TRUNCATE` covers the Phase 12/13 tables |
| 2026-07-20 | Phase 14 (SOPS-encrypted secrets): [SOPS](https://github.com/getsops/sops)+[age](https://age-encryption.org/) encryption for the Kubernetes secret manifest, keeping it in the IaC repo without leaking it. Repo-root `.sops.yaml` seals only `data`/`stringData` values (`encrypted_regex`) of `deploy/k8s/sops/secrets*.yaml`; `deploy/k8s/sops/` holds a **real encrypted example** decryptable with a committed throwaway demo key, an `apply.sh` (`sops -d \| kubectl apply -f -`, plaintext never on disk), a `verify.sh`, and a README covering Flux/Argo/helm-secrets. New CI `sops` job runs `verify.sh`. `.gitignore` blocks real age keys and non-example sealed files. No Go code / schema / wire-format change |
| 2026-07-20 | Phase 13 (SPIFFE SVID + delegation, increment D): `internal/agentid` gains an `SVIDVerifier` that validates SPIFFE JWT-SVIDs against a **file** trust-domain JWKS (`PAM_BROKER_TRUST_DOMAIN_JWKS`) — RS256/ES256/EdDSA (stdlib `crypto/rsa`·`ecdsa`·`ed25519`), requiring `sub = spiffe://<PAM_BROKER_TRUST_DOMAIN>/…`, `aud = PAM_BROKER_AUDIENCE`, and a present, unexpired `exp` (all fail-closed). Nested RFC 8693 `act` claims become an `ActorChain` capped at `PAM_BROKER_MAX_DELEGATION_DEPTH`. A `MultiVerifier` composes it with the static-key verifier so `agentAuth` accepts either. Mirrors the `internal/oidc` JWT/JWKS machinery; no new crypto dependency. Deferred (documented): live SPIRE workload attestation and an RFC 8693 token-exchange minting endpoint |
| 2026-07-20 | Phase 13 (MCP server, increment C): new `internal/mcp` — a hand-rolled JSON-RPC 2.0 core (stdlib only: `Request`/`Response`/`Error`, a `Dispatcher` method table) — served at `POST /mcp` behind the same `agentAuth` as REST. Methods `initialize`, `tools/list` (from the broker registry, tool input maps rendered as JSON Schema), `tools/call`, `ping`, and `broker/resume` route through the **same `broker.ProcessCall`/`Resume`**, so an MCP tool call is policy-gated, JIT-injected, single-use-resumed, and audited identically to REST (`broker.tool_call … via:mcp`). Notifications (no id) get no response; unknown methods return `-32601`. Proven at parity with an in-process test |
| 2026-07-20 | Phase 13 (broker toolset, increment B cont.): five more agent tools alongside `winrm_exec` — `ssh_exec` (one-shot SSH command via the new `rotate.SSHConnector.Exec`; JIT credential, only output returns), `list_targets`/`list_credentials` (metadata only — no secret ever), `rotate_credential` (reuses `rotateCredential`; the new secret stays vaulted), and `reveal_credential`, the deliberate secret-returning tool shipped **default-deny** (no rule allows it unless an operator adds one) that also honors `PAM_REVEAL_DISABLED` and keeps the plaintext out of every audit record. Shared gates refactored into `authorizeAgentTarget`/`authorizeAgentCredential` (protocol allowlist + target grants + four-eyes). New audit action `ssh.exec` |
| 2026-07-20 | Phase 13 (broker approval + resume + tokens, increment B): the `require_approval` policy effect now **parks** a tool call for a human decision instead of dead-ending. The broker mints a **single-use resume token** (`broker_tokens`, migration `0010`; only its SHA-256 JTI is stored, spent by an atomic `UPDATE … RETURNING`) and alerts an approver. Operator routes `GET /v1/approvals` + `POST /v1/approvals/{id}/decision` (`CapApprove`) — on approve the broker **executes the parked call server-side** (JIT injection; the human approval satisfies the target four-eyes gate via `broker.WithApproved`), on reject it denies. The agent collects the result once via `POST /v1/tool-calls/{id}/resume` (spends the token). Per-agent **rate limit** (`PAM_BROKER_RATE_PER_MIN`) in `agentAuth` and an **argument-size cap** (`PAM_BROKER_MAX_ARG_BYTES`) in `ProcessCall`. New env `PAM_BROKER_TOKEN_TTL_MIN`; audit vocab `broker.approval.granted`/`broker.approval.denied`/`broker.tool_call.resumed` |
| 2026-07-20 | Phase 12 (console + IaC export, increment D): 5250 console screens for the CyberArk/Wallix admin surface — *Work with permission profiles* (menu 12), *System configuration* (menu 13, set/clear identity/SSO/policy overrides), and *Effective config & backend health* (menu 14) with a one-key export of the console-set overrides back to IaC. New read-only routes `GET /api/config/effective` (backend status from the live runtime snapshot) and `GET /api/config/iac?format=env\|helm\|terraform` (secrets rendered as secret-store placeholders, never plaintext). The user add-screen role picker now loads custom profiles live. No new audit vocab (both new routes are read-only) |
| 2026-07-20 | Phase 12 (configuration hot-swap): `PUT`/`DELETE /api/config` now take effect **without a restart**. The server holds the runtime-overridable settings (identity backends, SSO, operational policy) in one immutable `runtimeConf` snapshot behind an `atomic.Pointer`, read through `s.rt()`; a `Reconfigure` closure (wired by `main` from the pristine env baseline + current DB overrides) rebuilds it and `applyReconfigure` swaps it atomically. A rejected reconfigure (e.g. an unreachable directory) rolls the offending override back so it can't also break the next restart. Networking/TLS listeners stay restart-bound (env-only) |
| 2026-07-20 | Phase 12 (custom-profile RBAC): named capability sets (`profiles` table, migration `0009`) assignable to users as an alternative to the four built-in roles. `auth.Principal` gains a resolved `Caps` set + `Can`/`CapabilityNames` — built-in roles fall through the `roleCaps` matrix unchanged; the resolver resolves a non-built-in user/session role as a custom profile (`Resolver.WithProfiles`, `ParseCapabilities`). Authorization now checks `principal.Can(cap)` everywhere (api `authz`, RDP, and the SSH proxy via a `can_connect` handshake flag). Admin API `POST/GET /api/profiles` + `DELETE /api/profiles/{id}` (`CapManageUsers`); `createUser` accepts a profile name; audit `profile.create`/`profile.delete` |
| 2026-07-20 | Phase 12 (configuration subsystem, increment A): DB-persisted, editable `PAM_*` overrides for the identity backends, SSO, and operational policy. New `settings` table (migration `0008`) + `store.Setting`/`PutSetting`/`GetSetting`/`ListSettings`/`DeleteSetting`; secret settings (bind password, client secrets) are vault-encrypted (`store.ConfigAAD`). A whitelist (`config.OverridableKeys`/`ApplyOverrides`) overlays stored values onto the env-derived config at startup — bootstrap/transport keys (DB URL, master key, listen/TLS, KEK) stay environment-only. Admin API `GET/PUT /api/config` + `DELETE /api/config/{key}` (`CapManageUsers`; secrets masked); audit `config.update`/`config.revert`. Hot-swap (no restart), the custom-profile RBAC engine, and console screens land in later increments |
| 2026-07-20 | Phase 13 broker hardening (self-review fixes): agents now obey the same **approval gate** as humans (`winrm_exec` calls `enforceApproval`); a **`role:agent` target grant** is creatable (`auth.ParseGrantRole`) so targets can be scoped to agents; the broker records a tamper-evident **`broker.tool_call.requested`** event *before* executing and **fails closed** if the chain is unavailable (no more silent unaudited executions); `agentAuth` now `withPrincipal`s the agent so the `winrm.run` audit event is attributed to the agent, not "unknown"; agent keys are revocable/listable — `GET /v1/agents` + `DELETE /v1/agents/{id}` (new audit action `agent.revoke`) |
| 2026-07-20 | Phase 13 (AI-agent access broker, increment A): opt-in via `PAM_BROKER_POLICY_FILE`. New packages `internal/policy` (YAML rule engine: eq/not/in/not_in, first-match-wins, implicit deny, scope templating), `internal/agentid` (static agent-key verifier; `RoleAgent`+`CapCallTool`), `internal/auditchain` (keyed-HMAC per-event hash chain + ed25519 signed head), `internal/broker` (Tool registry + `ProcessCall`). New store types/tables `agent_keys` + `broker_audit_events` (migration `0007`). `winrm_exec` tool runs over the refactored `Server.execWinRM` (JIT decrypt → run → result; credential never returned). Routes `POST /v1/tool-calls`, `GET /v1/tool-calls/{id}`, `POST /v1/agents`, `GET /v1/audit[/verify|/head]` (HTTP-200-with-`status` error model; agent Bearer auth via `agentAuth`). New env: `PAM_BROKER_POLICY_FILE`, `PAM_BROKER_AUDIT_KEY`, `PAM_BROKER_AUDIT_SIGN_SEED`. Audit vocab: `broker.tool_call.{executed,denied,pending_approval,failed}`, `agent.create`. Approval/resume, MCP, and SPIFFE land in later increments (see ROADMAP Phase 13) |
| 2026-07-20 | Code-derived architecture diagrams: `cmd/archgen` regenerates `docs/ARCHITECTURE-DIAGRAMS.md` (Mermaid package-dependency graph from imports, domain ER model from `store` structs, REST route→capability map from the mux). Deterministic output; a CI step (`go run ./cmd/archgen && git diff --exit-code`) fails if it drifts, so the diagrams stay current on every change. Wired via `go:generate` |
| 2026-07-20 | Phase 11: management console — the 5250 portal grows into a role-aware console over every existing API. New `GET /api/me` (`authenticated`) returns the caller's identity + stable capability names (`auth.Capability.String`/`Role.Capabilities`) driving the menu. `internal/web/static/index.html` gains screens for targets+grants, credentials (reveal/check-out/rotate/reconcile), check-out/check-in, active sessions (+kill), access requests (approve/deny/file), users & roles (+directory reconcile), MFA self-service, discovery, reconciliation, audit (filter + CSV export), break-glass unseal — still one nonce-CSP `//go:embed`'d vanilla-JS page. Phase 12 (planned) adds the hybrid config subsystem + custom-profile RBAC |
| 2026-07-19 | Second audit pass (gap-finding): proxy joins upstream stderr into the recording before hashing (was a lost-write race) and rejects non-proxyable protocols before decrypt; expired checkout leases are rotated before a re-checkout reuses the secret (memstore/pgstore parity); TOTP replay guard fails **closed** on a store error; OIDC state cookie honors `X-Forwarded-Proto`; `createCredential` rollback uses a cancel-detached context; RDP kill cancels a shared context so a wedged tunnel tears down; syslog/email alert deliveries are timeout-bounded; portal is served under a per-request **nonce-based CSP** (+ `base-uri`/`form-action`/`frame-ancestors`/`object-src`), `esc()` covers `'`, `viewCred` cleared on nav; `pam-server -healthcheck` for the shell-less image; Docker (`.dockerignore`, numeric UID, HEALTHCHECK), compose (read-only rootfs, cap_drop, `/data` chown init), Helm/k8s (`secret.create=false` default + guard, numeric `runAsUser`/`fsGroup`, startupProbe, image pin, port 8080), Terraform (RDS `manage_master_user_password`, encrypted-backend requirement, var validation), and CI (GitHub Actions pinned to commit SHAs) hardening |
| 2026-07-19 | Breaking (pre-1.0): the vault token format is `v2:` with per-credential AAD (`target:%d/cred:%d`); there is no in-place migration from earlier `v1:`/per-target-AAD ciphertext or the pre-GCM PKCS#11 wrap, so a deployment carrying vaulted secrets across the change must re-enter them. Fresh deploys are unaffected. |
| 2026-07-19 | Security/correctness hardening pass (repo-wide audit): strict config parsing (fail-loud booleans/ints, TLS all-or-nothing, quorum-threshold validation); login/MFA fixes (MFA fail-closed on store error, step-up to change a confirmed factor, `login.failed` audit, target-scoped grant delete, rate-limited oidc/start); Entra tenant (`tid`) pinning, required token `exp`, LDAPS enforced; rotation robustness (`rotate_started` on all paths, detached persist, worker panic-recover + failure audit, ssh_key reconcile via key auth, non-clobbering `RotateKey`, WinRM `net user /y`, exec deadline); resumable KEK rotation + Vault-Transit HTTPS; atomic checkout exclusivity (partial UNIQUE index + expired-lease auto-close) and store parity fixes; migrations under advisory lock + `audit_events(ts)` index; guacd handshake deadline + bounded alloc; alert CR/LF sanitization; `PAM_REQUIRE_RECORDING`, stderr recorded |
| 2026-07-19 | Proxy: post-session rotation callbacks are tracked so a graceful shutdown drains them (not killed mid-rotation); `RotateCredentialByID` audits `credential.rotate_started` before the external password change so a crash leaves a trail |
| 2026-07-19 | Proxy: `Serve` retries transient `Accept` errors (e.g. fd exhaustion) with capped backoff instead of tearing the listener down permanently |
| 2026-07-19 | Proxy hardening: decrypt the JIT secret only after all authz gates; record target stderr into the asciicast (hash now covers stderr); audit `session.record_failed` and optionally refuse (`PAM_REQUIRE_RECORDING`) when a session can't be recorded |
| 2026-07-19 | Proxy: graceful shutdown flushes session audit — `main` awaits the (bounded) proxy drain on SIGTERM before closing the store, and closing audits (`session.end`/`session.record`) use `auditClosing` (detached from the cancelled ctx) so they are no longer dropped mid-drain |
| 2026-07-19 | Proxy: session teardown keyed on the connection lifecycle — stdin half-close only `CloseWrite`s (batch/piped/`ssh -n` output + `exit-status` no longer truncated), `handleConn` closes the upstream when the client is gone; client→upstream request pump joined so the `exec`/`shell` reply flushes before teardown (fixes an EOF flake); `Serve` shutdown drain bounded by force-closing active connections |
| 2026-07-19 | Phase 10: Postgres HA (CloudNativePG `Cluster`, `deploy/k8s/postgres-cnpg.yaml`), cloud-Postgres Terraform (`deploy/terraform/cloud-postgres`, AWS RDS), SLSA build-provenance attestation in `release.yml` |
| 2026-07-19 | Phase 8: SSH jump-host / bastion connector (`proxy.Config.Jump`, `PAM_SSH_JUMP_*`) — targets reached via a `direct-tcpip` tunnel through the bastion |
| 2026-07-19 | Phase 7: identity reconciliation (`POST /api/identity/reconcile`, `auth.DirectorySource.UserStatus`, revokes disabled directory users) + AD `ChangePassword` primitive (`unicodePwd`) |
| 2026-07-19 | Proxy: interactive WinRM command loop through the SSH proxy (`proxy.Config.WinRMRunner`, `PAM_PROXY_WINRM`) — each operator line runs as a WinRM command, recorded; stateless-per-line |
| 2026-07-19 | OT: read-only observer sessions (`<login>+observe` → drop operator keystrokes, refuse exec/subsystem; `session.start … mode:observer`) |
| 2026-07-19 | OT: protocol allowlist (`PAM_ALLOWED_PROTOCOLS`) enforced at create-target and every connect path (WinRM/RDP handlers + SSH proxy) |
| 2026-07-19 | Alerting: email + syslog channels (`alert.Email`/`alert.Syslog`/`alert.Multi`, `PAM_ALERT_SYSLOG`/`PAM_ALERT_EMAIL_*`) alongside the webhook |
| 2026-07-19 | Lifecycle: forced rotation after a proxied SSH session ends (`proxy.Config.OnSessionEnd` → `Server.RotateCredentialByID`, `PAM_ROTATE_AFTER_SESSION`) |
| 2026-07-19 | Lifecycle: `ssh_key` credential rotation (`rotate.GenerateSSHKey` + `SSHConnector.RotateKey` / `KeyRotator`) — generates a keypair and replaces `authorized_keys` |
| 2026-07-19 | Tests: shared store conformance suite (`internal/store/storetest.RunStoreContract`) run by memstore and, in CI, against a live PostgreSQL (`PAM_TEST_DATABASE_URL`, a `postgres` service job) — verifies the pgstore SQL/migrations |
| 2026-07-19 | Hardening: Entra ROPC now validates the id_token RS256 signature against the tenant JWKS (`oidc.VerifyRS256`) instead of reading unverified claims |
| 2026-07-19 | Hardening: RDP now verifies the server certificate by default (`PAM_GUACD_RDP_SECURITY`/`PAM_GUACD_IGNORE_CERT`) instead of hardcoding `security:any`/`ignore-cert:true` |
| 2026-07-19 | Hardening: upstream SSH host-key pinning (`PAM_SSH_KNOWN_HOSTS`, `proxy.Config.UpstreamHostKey` + rotation connector) — no longer trusts any target key |
| 2026-07-19 | PKCS#11 HSM KEK provider (`vault/pkcs11.go`, build tag `pkcs11`; stub in the default build), `Dockerfile.pkcs11`, CI job against SoftHSM2, `PAM_KEK_PKCS11_*` |
| 2026-07-19 | HA: OIDC PKCE login state moved to the store (`store.PutOIDCState`/`TakeOIDCState`, migration `0004`) so the auth-code callback works on any replica; removed the in-memory `oidcPending` |
| 2026-07-19 | Phase 7 follow-ons: credential checkout/check-in leases (`store.Checkout`, migration `0003`, auto-rotate on return) + discovery (`internal/discovery`, `POST /api/discovery/scan`); `docs/REQUIREMENTS.md` (run specs) |
| 2026-07-19 | Phase 10: scale & ops — `internal/metrics` + `GET /metrics` (Prometheus), `GET /readyz` (`store.Ping`), `deploy/helm/pamv1` chart, `release.yml` (SBOM + cosign signing) |
| 2026-07-19 | Phase 9: NIS2 pack — `GET /api/audit/export` (`compliance_handlers.go`, `store.ExportAudit`, JSON/CSV, SHA-256 tamper digest), `docs/NIS2-COMPLIANCE.md` (Art. 21 matrix + Art. 23 export) |
| 2026-07-19 | Phase 8: OT adaptation — access-request approval workflow (`approval_handlers.go`, `store.AccessRequest`, migration `0002`, 4-eyes, enforced on proxy/WinRM/RDP), air-gap mode (`PAM_OT_AIRGAP`), `docs/OT-DEPLOYMENT.md` |
| 2026-07-19 | Phase 7: credential lifecycle — `internal/rotate` (SSH/WinRM `Rotator`/`Verifier`, strong password gen), `POST /api/credentials/{id}/rotate`, `/reconcile[?remediate]`, `GET /api/reconcile`, background worker (`scheduler.go`), store `RotateCredentialSecret` |
| 2026-07-19 | Phase 6: break-glass v2 — `shamir` (M-of-N quorum), `pam-server -split-key`, `POST /api/breakglass/unseal` (auto-expiring session), `alert` webhook on break-glass access/unseal; AWS KMS KEK (`awskms.go`) |
| 2026-07-19 | Phase 5 done: embedded versioned migrations (`pgstore/migrate.go`, `schema_migrations`, `migrations/0001_init.sql`) replacing the ad-hoc startup schema |
| 2026-07-19 | Phase 2: live session registry (`internal/session`) — `GET /api/sessions` + `DELETE /api/sessions/{id}` (kill-switch); proxy + RDP register live sessions |
| 2026-07-18 | Phase 2: per-target authorization (`store.TargetGrant`, `auth.CanConnectTarget`, `/api/targets/{id}/grants`, enforced in proxy/WinRM/RDP); reveal lockdown (`PAM_REVEAL_DISABLED`) |
| 2026-07-18 | Phase 5: vault KEK rotation (`internal/maint`, `pam-server -rotate-kek`); store `UpdateCredentialSecretEnc` + `ListMFAEnrollments` |
| 2026-07-18 | Phase 5: transport hardening — native HTTPS (`PAM_TLS_*`), security-headers middleware, per-IP auth rate limiting (`middleware.go`) |
| 2026-07-18 | Phase 4: NTLM WinRM auth (`PAM_WINRM_AUTH`); `guacd` package + `GET /api/targets/{id}/rdp` WebSocket tunnel (RDP via Guacamole with JIT injection); `PAM_GUACD_ADDR` |
| 2026-07-18 | Phase 3b hardening: `oidc` package (Authorization Code + PKCE, RS256 JWKS validation, discovery); `/api/auth/oidc/{start,callback}`; portal SSO token pickup; shared `auth.HighestRole`; `PAM_OIDC_*` config |
| 2026-07-18 | Phase 4: `winrm` package + `POST /api/targets/{id}/winrm` (JIT credential injection on Windows, transcript recording, `winrm.run` audit); `PAM_WINRM_*` config |
| 2026-07-18 | Phase 3b hardening: enforce-MFA policy (`PAM_MFA_REQUIRED`, enrollment-only sessions via `Session.Scope`/`Principal.EnrollOnly`) + single-use recovery codes (`/api/mfa/recovery-codes`) |
| 2026-07-18 | Phase 3b Entra: `EntraAuthenticator` (Azure AD, OAuth2 ROPC, app-roles/groups → role); `ChainAuthenticator`; `PAM_ENTRA_*` env; LDAP + Entra composable |
| 2026-07-18 | Phase 3b MFA: `mfa` package (TOTP RFC 6238); `store.MFAEnrollment` (vault-encrypted secret); `/api/mfa/*` self-service; `/api/login` enforces confirmed TOTP; portal Sign On OTP field |
| 2026-07-18 | Phase 3b: AD/LDAP login (`ldap.go`, `Authenticator`); login sessions (`store.Session`, `/api/login` + `/api/logout`); resolver session support; portal Sign On with user+password; `PAM_LDAP_*` env |
| 2026-07-18 | Vault envelope encryption + pluggable KEK (`kek.go`, `transit.go`); `v2:` token format; ctx-aware Encrypt/Decrypt; `local` (dev/test) + `vault-transit` (production) providers; `PAM_KEK_*` env |
| 2026-07-18 | Added `logging` package (per-service slog, json/text, `PAM_LOG_LEVEL`/`PAM_LOG_FORMAT`); api access log, proxy session logs, pgstore connect + query tracer; user/admin guides |
| 2026-07-18 | Phase 3a: `auth` package (roles admin/user/auditor/approver, capabilities, Resolver); `store.User` + user CRUD; API `authz` middleware + `/api/users`; proxy `CapConnect` gate; portal tolerates 403 |
| 2026-07-18 | Added `proxy` package (SSH gateway, JIT, recording, host key); `store.CredentialAAD`; proxy env vars |
| 2026-07-17 | Initial packages: config, vault, store(+mem/pg), api, web |
