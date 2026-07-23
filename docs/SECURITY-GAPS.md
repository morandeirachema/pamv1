# pamv1 — Security Gaps (findings, fixes, and remaining work)

> 🟢 **Living document** — updated in the same change as the code, without a separate ask (see the [docs hub](README.md)).

> **Purpose.** This is a self-audit of pamv1 against the security posture expected
> of a Privileged Access Management system. It records every gap found in a
> read-only review of the codebase, whether each was **fixed**, **mitigated**, or
> **deferred** (a whole subsystem / new roadmap phase), and where the change
> lives. pamv1 is educational ("for learning purposes") — this document is part of
> that: it shows the reasoning, not just the result.
>
> Last updated: 2026-07-23 · Reflects: Phases 0–24 + the 2026-07 hardening pass.

## How the review was run

Six independent read-only passes over the ~20k-LOC tree, one per security-critical
dimension — at-rest crypto & secret leakage, authentication/RBAC/break-glass, the
session proxy (SSH + PostgreSQL), the REST API surface & audit completeness, the
tamper-evident audit chain & logging, and deployment/IaC — cross-checked against
each other. The system's central invariant held throughout: **the operator never
receives the vaulted credential** (JIT decryption happens strictly after every
authorization gate, proven against a real upstream that accepts only the vaulted
secret), AAD parity is exact across all encrypt/decrypt sites, `SecretEnc` never
serializes, and no secret is written to logs. The gaps clustered on the **trust
boundaries around** that core — upstream authentication, audit integrity, and a
few authorization edges.

## Status legend

- **Fixed** — code changed + test; the gap is closed.
- **Mitigated** — a fail-closed opt-in / hardening knob was added; the insecure
  behavior is no longer the *only* option (default kept for the demo where a hard
  change would break the quickstart).
- **Deferred** — a missing capability that is a new roadmap phase, not a bug.

---

## Tier 1 — Authorization & audit integrity (fixed)

| # | Gap | Status | Fix |
|---|-----|--------|-----|
| 1 | **Empty-safe default-allow.** A target placed in a safe with no members fell through `CanConnectTarget`'s "no grants ⇒ open" branch, so it was reachable by *any* connect-capable user — the opposite of safe containment. | **Fixed** | `CanConnectTarget` now takes a `safeScoped` flag: a safe-scoped target with no matching grant is default-DENY. All five call sites pass `target.SafeID != nil`. Tests: `auth.TestCanConnectSafeScoped`. |
| 2 | **DB proxy skipped the MFA enroll-only gate.** `PAM_MFA_REQUIRED` was bypassable for PostgreSQL targets — the SSH proxy and HTTP API rejected enroll-only sessions, the DB proxy did not. | **Fixed** | `internal/proxy/dbproxy.go` now rejects `principal.EnrollOnly` before any other gate. Test: `proxy.TestDBProxyEnrollOnlyRejected`. |
| 3 | **Fail-open auditing.** A credential reveal/checkout/app-fetch was returned even if the durable audit write failed — violating "every secret use appends an audit event." | **Fixed** | New `mustAudit`/`mustAuditAs` (API) and `appendAuditErr` (proxy) fail CLOSED: no durable audit ⇒ HTTP 503 / session refused. Applies to reveal, checkout, app-secret, and both proxies' session-start (audited *before* decryption). Test: `api.TestRevealFailsClosedWithoutAudit`. |
| 4 | **Upstream SSH host key / DB TLS unverified by default.** Both legs carry the JIT-decrypted credential; the DB leg had *no* way to verify at all. | **Fixed (DB) / Mitigated (SSH)** | DB proxy: `PAM_DB_UPSTREAM_CA` (pinned bundle) or `PAM_DB_UPSTREAM_TLS_VERIFY` (system roots) now verifies the upstream cert fail-closed, and refuses plaintext when verification is demanded. SSH host-key pinning via `PAM_SSH_KNOWN_HOSTS` already existed (loud warning when unset). |
| 5 | **No brute-force throttling on the proxy auth paths.** SSH (:2222) and DB (:5433) were an unthrottled online oracle against the operator-chosen `PAM_API_KEY`. | **Fixed** | Per-source-IP fixed-window limiter (`PAM_PROXY_AUTH_RATE_LIMIT`, default 10/min) on both proxies, mirroring the API limiter. Tests: `proxy.TestAuthRateLimiter`. |
| 6 | **Rate limiter blind to `X-Forwarded-For`.** Behind the documented TLS-terminating reverse proxy, every client shared one bucket. | **Fixed** | `PAM_TRUSTED_PROXY_HOPS` selects the real client IP from the trusted tail of XFF; 0 (default) keeps the anti-spoofing RemoteAddr behavior. Test: `api.TestClientIPTrustedProxy`. |

## Tier 2 — Consistency & hardening (fixed / mitigated)

| # | Gap | Status | Fix |
|---|-----|--------|-----|
| 7 | Break-glass not audited on `authenticated`-only endpoints (`/me`, `/logout`, `/mfa/*`). | **Fixed** | The `authenticated` middleware now calls `noteBreakGlass`. |
| 8 | Directory (AD/SSO) login sessions never revoked on disable; no admin session-kill. | **Fixed** | New `GET /api/login-sessions` + `POST /api/login-sessions/revoke` (CapManageUsers); identity reconcile now also revokes sessions whose directory subject is disabled/absent. Store gains `ListSessions` + `DeleteSessionsByUsername`. Test: `api.TestRevokeLoginSessions`. |
| 9 | `exportAudit` and `listBrokerAudit` were unbounded (auditor-gated memory exhaustion). | **Fixed** | `exportAudit` defaults to a 90-day window when `since` is unset; `listBrokerAudit` clamps `limit` to 1..500 like `listAudit`. |
| 10 | App-secret fetch bypassed the reveal-disabled kill switch. | **Fixed** | `fetchAppSecret` now honors `revealDisabled`. |
| 11 | SCRAM server-signature not verified on the DB upstream (forfeits SCRAM mutual auth). | **Fixed** | `scramAuth` recomputes and constant-time-compares the ServerSignature. |
| 12 | PostgreSQL fast-path (`FunctionCall`) evaded per-statement audit. | **Fixed** | The relay now audits `FunctionCall` frames. |
| 13 | No strength floor on `PAM_API_KEY` (a 1-char admin key started). | **Mitigated** | Rejected below 16 chars on a real (non-`memory`) database, unless `PAM_ALLOW_WEAK_API_KEY=true`; the in-memory demo is exempt so the quickstart still works. Tests in `config`. |
| 14 | `-rotate-kek` only handled local→local master-key rotation; KMS/HSM KEKs had no re-wrap path, and no audit event. | **Fixed** | `-rotate-kek` now builds both KEKs from `PAM_KEK_*` / `PAM_NEW_KEK_*` (any provider — enables local→KMS migration) and writes a `vault.kek_rotated` audit event. |
| 15 | Plaintext HTTP by default; TLS opt-in. | **Mitigated** | `PAM_REQUIRE_HTTPS` refuses to start without native TLS; a loud warning is logged otherwise. (Default kept permissive for the loopback demo.) |
| 16 | DB proxy operator leg cleartext by default. | **Mitigated** | `PAM_REQUIRE_DB_CLIENT_TLS` refuses to start the DB proxy without operator-leg TLS. |
| 17 | No K8s NetworkPolicy in any deploy flavor. | **Fixed** | `deploy/k8s/networkpolicy.yaml` (default-deny) + a gated Helm template (`networkPolicy.enabled`). |
| 18 | `:latest` image tags in the terraform and conjur manifests. | **Fixed** | Pinned to `0.10.0` (matching the raw k8s deployment) with a comment to pin by digest. |
| 19 | Container healthcheck hard-coded `http://`, breaking under native TLS. | **Fixed** | `runHealthcheck` matches the served scheme (`https` when `PAM_TLS_CERT/KEY` set). |
| 20 | SSH-proxy grant check used a stripped principal (dropped multi-group/custom-profile — fail-closed but denied valid users). | **Fixed** | The handshake now carries the full role set (`ext["roles"]`), reconstructed for `CanConnectTarget`. |
| 21 | Alert webhook accepted `http://` with no warning. | **Mitigated** | A startup warning is logged for a non-HTTPS, non-loopback webhook. |
| 22 | Revoking access left in-flight proxied sessions running (grants/users checked only at connect time). | **Fixed** | Revoking a login, a directory-disable during reconcile, or deleting a *user* grant now kills the matching live sessions (`session.killed`). Role-grant deletions affect only new connections; the registry is per-replica (HA note below). |
| 23 | No cap on concurrent sessions or recording size (resource-exhaustion DoS; a runaway session could fill the recording disk). | **Fixed** | `PAM_MAX_SESSIONS_PER_USER`/`PAM_MAX_SESSIONS_TOTAL` cap concurrent proxied sessions (checked before decrypt); `PAM_MAX_RECORDING_MB` terminates a session that exceeds the recording cap (`session.record_limit`) rather than run it unrecorded. All default off; per-replica in HA. |

## Not changed by design (documented trade-offs)

- **Command control (`cmdguard`) is exec-path only** and best-effort — interactive
  PTY shells stream unparsed, and the exec path is regex over the command string.
  This is inherent (real containment needs a parsing shell/PTY layer) and already
  documented; it must not be read as an enforcement boundary. Use observer sessions
  or restrict shell access for true containment.
- **Session recording is fail-open unless `PAM_REQUIRE_RECORDING`** — the opt-in
  fail-closed control already exists; the default is kept permissive for demos.
- **Decrypted plaintext lives in Go `string`s** (only the data key is zeroed) —
  inherent to idiomatic Go; strings are immutable and can't be wiped.
- **Inventory listing is not scoped by per-target grants** — `CapReadInventory`
  exposes target/credential *metadata* (never secrets); connect/reveal/checkout are
  grant-scoped. This is the documented access model, not a leak.
- **Credential create is two store calls** (insert row → encrypt secret under its
  row id), so a crash between them can orphan an empty-secret row. Inherent to the
  AAD-binds-row-id design; a client cancel already rolls back.

## Tier 3 — Missing capabilities (deferred; new roadmap phases, not fixes)

> These are severity tiers of *found gaps* — not the same as the market-coverage
> "Tier-3/Tier-4" bands in [EXTERNAL-INFRA-GAPS.md](EXTERNAL-INFRA-GAPS.md), which
> is the canonical list of what needs a real account/host to build and verify
> honestly. Where an item below overlaps that list, EXTERNAL-INFRA-GAPS owns the detail.

These are whole subsystems a commercial PAM has and pamv1 does not — building them
is a phase each, out of scope for a security *fix*:

- ~~**Tamper-evident PRIMARY audit trail.**~~ **Fixed (opt-in).** The keyed-HMAC
  chain now covers the main `audit_events` table (reveal, break-glass, db.query,
  sessions), not just broker events. Set `PAM_AUDIT_HMAC_KEY` (base64 32 bytes) to
  activate chaining; verify with `GET /api/audit/verify`. The migration is additive
  and unset leaves the plain table, so it's non-breaking. This was the top deferred
  item; it is now closed. **Tail-truncation detection** is also covered: set
  `PAM_AUDIT_SIGN_SEED` and archive the ed25519-signed checkpoints from
  `GET /api/audit/head` out-of-band.
- **Session-recording playback** (recordings are written to disk; no API/portal
  replays them), **JIT ephemeral account provisioning** on targets, **FIDO2/
  WebAuthn**, **CIEM / cloud-IAM brokering**, **Kubernetes secret/SA delivery**,
  **other DB engines** (MySQL/MSSQL/Oracle), **native audit→SIEM forwarding**
  (syslog/CEF/LEEF), **HSM/KMS-backed SSH-CA signing**, **rotation webhooks**, and
  **HA correctness** (in-memory session registry + scheduler have no leader
  election, so kill-switch/monitoring/rotation are per-replica).
- **Roadmap-deferred**: Kerberos/GSSAPI, serial connectors, SPIRE workload
  attestation, automatic broker-chain checkpoint export. (The in-browser RDP viewer
  has since **shipped** — vendored Guacamole client + bundled guacd.)

## New configuration introduced by these fixes

| Env var | Default | Purpose |
|---|---|---|
| `PAM_TRUSTED_PROXY_HOPS` | `0` | Trusted reverse-proxy hops; picks the client IP from XFF for rate limiting. |
| `PAM_PROXY_AUTH_RATE_LIMIT` | `10` | Failed-auth throttle per IP/min on the SSH & DB proxies (0 disables). |
| `PAM_REQUIRE_HTTPS` | `false` | Refuse to start the API/portal without native TLS. |
| `PAM_REQUIRE_DB_CLIENT_TLS` | `false` | Refuse to start the DB proxy without operator-leg TLS. |
| `PAM_DB_UPSTREAM_CA` | — | PEM CA bundle to VERIFY the upstream PostgreSQL cert (fail-closed). |
| `PAM_DB_UPSTREAM_TLS_VERIFY` | `false` | Verify the upstream PostgreSQL cert against the system roots. |
| `PAM_ALLOW_WEAK_API_KEY` | `false` | Override the 16-char `PAM_API_KEY` floor (demos only). |
| `PAM_NEW_KEK_*` / `PAM_NEW_MASTER_KEY` | — | Target KEK for `-rotate-kek` (any provider; enables migration). |

## New audit actions

`proxy.auth_rate_limited`, `db.session.denied` (enroll-only), `session.revoked`
(admin/reconcile session revocation), `vault.kek_rotated`.
