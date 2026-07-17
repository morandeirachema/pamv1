# pamv1 — Low-Level Architecture (living document)

> **Living document.** Update this whenever code structure, packages, schemas,
> wire formats, env vars or algorithms change. This is the engineer's map of
> the codebase; the conceptual view lives in
> [ARCHITECTURE-HIGH-LEVEL.md](ARCHITECTURE-HIGH-LEVEL.md).
>
> Last updated: 2026-07-18 · Reflects: **Phase 3a** (RBAC + four profiles). Commit the doc update with the code change.

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
  auth/        # roles, capabilities, Principal, Resolver (RBAC)
  store/       # Store interface + domain types + CredentialAAD
    memstore/  # in-memory impl (tests, demo)
    pgstore/   # PostgreSQL impl (embedded schema.sql)
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
  the data key. **Production / vendor-aligned.** AWS KMS / PKCS#11 HSM are the
  next providers (same interface).

`GenerateMasterKey()` → 32 random bytes, urlsafe-base64 (seeds the local KEK).
Selected by `PAM_KEK_PROVIDER` (`local` | `vault-transit`).

### 2.2 `store`

Interface `Store` with `memstore` and `pgstore` implementations. Domain types:
`Target`, `Credential` (field `SecretEnc` is `json:"-"` — **never serialized**),
`AuditEvent`. Sentinel errors `ErrNotFound`, `ErrConflict`.
`CredentialAAD(targetID) = "target:<id>"` — shared by `api` and `proxy` so vault
AAD matches on both encrypt and decrypt paths.

Schema (`pgstore/schema.sql`, applied idempotently on startup): `targets`,
`credentials` (FK `ON DELETE CASCADE`), `audit_events`.

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

**Active Directory login** (`ldap.go`, Phase 3b): the `Authenticator` interface
verifies username+password. `LDAPAuthenticator` binds a service account, searches
the user under `BaseDN`, reads `memberOf`, re-binds as the user to verify the
password, and maps groups → role (`roleForGroups`, highest privilege wins). The
LDAP connection is behind an `ldapConn` interface so tests inject a fake; the
real dial uses LDAPS. `POST /api/login` issues a session token (see `api`).

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
- Login (`authn` optional): `POST /api/login` (public) verifies username+password
  via the configured `Authenticator` and issues a session token (12h TTL, stored
  as SHA-256) with the role from the directory; `POST /api/logout` revokes it.
  Returns 503 when no authenticator is configured.
- Handlers validate input (os_type ∈ {linux,windows}, protocol ∈ {ssh,winrm,rdp}),
  translate store errors to HTTP codes, and append audit events.
- `reveal` (needs `CapRevealSecret`, admin only) decrypts on demand and is audited.

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
- **Resolve** (`resolve`): after handshake, look up target by name (must be
  `protocol=ssh`), pick the credential (matching `creduser` or first), and
  **decrypt the secret** — this is the JIT moment; plaintext lives only here.
- **Upstream** (`dialUpstream`): `ssh.Dial` to `host:port` as the credential
  user, `ssh.Password` or `ssh.PublicKeys` (for `secret_type=ssh_key`).
  `HostKeyCallback` is `InsecureIgnoreHostKey` today → TODO known_hosts (Phase 5).
- **Session** (`handleSession`): for each `session` channel, open an upstream
  session channel and bidirectionally forward: channel requests via
  `pumpRequests` (pty-req, shell, exec, window-change, exit-status), stdin,
  stdout (tee'd into the recording), stderr.
- **Recording** (`record.go`): asciicast v2 (`{header}` line + `[t,"o",data]`
  events) written to `PAM_RECORDING_DIR`, hashed with SHA-256 as it is written;
  on close the audit stores path, byte count and hash (tamper evidence).
- **Host key** (`hostkey.go`): `PAM_SSH_HOST_KEY` PEM path (persisted, generated
  if missing) or ephemeral ed25519.

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
goroutines; the stdout copy runs in the foreground of `handleSession` and we
`Wait` on the upstream→client request pump so `exit-status` is delivered before
the client channel closes.

## 4. Configuration (env `PAM_*`)

| Var | Default | Used by |
|---|---|---|
| `PAM_MASTER_KEY` | — (required) | vault |
| `PAM_API_KEY` | — (required) | api auth, proxy auth |
| `PAM_DATABASE_URL` | — (required); `memory` for demo | store |
| `PAM_BREAK_GLASS_KEY_HASH` | "" (disabled) | api auth |
| `PAM_LISTEN_ADDR` | `:8080` | http server |
| `PAM_SSH_ADDR` | `:2222`; `off` disables | proxy |
| `PAM_SSH_HOST_KEY` | "" (ephemeral) | proxy host key |
| `PAM_RECORDING_DIR` | `recordings` | proxy recordings |
| `PAM_LOG_LEVEL` | `info` | logging (debug/info/warn/error) |
| `PAM_LOG_FORMAT` | `json` | logging (json/text) |
| `PAM_KEK_PROVIDER` | `local` | vault KEK: `local` (dev/test) or `vault-transit` |
| `PAM_MASTER_KEY` | — (local only) | local KEK key (base64, dev/test) |
| `PAM_KEK_TRANSIT_ADDR` / `_TOKEN` / `_KEY` | — | HashiCorp Vault Transit KEK (production) |
| `PAM_LDAP_URL` | — (disabled) | AD/LDAP login; `ldaps://…` enables `/api/login` |
| `PAM_LDAP_BIND_DN` / `_BIND_PASSWORD` | — | service account for user search |
| `PAM_LDAP_BASE_DN` / `_USER_FILTER` | — / `(sAMAccountName=%s)` | search base + filter |
| `PAM_LDAP_GROUP_ADMIN` / `_USER` / `_AUDITOR` / `_APPROVER` | — | group DN → role |
| `PAM_LDAP_INSECURE_SKIP_VERIFY` | `false` | disable TLS verify (dev only) |

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
`credential.delete` · `user.create` · `user.delete` · `login` · `logout` ·
`authz.denied` · `breakglass.access` · `session.start` · `session.record` ·
`session.end` · `session.denied` · `session.error`. The actor is the Principal
name (`bootstrap-admin`, `break-glass`, or a username).

## 6. Security-relevant invariants (do not regress)

1. `Credential.SecretEnc` must never be serialized to any client (`json:"-"`).
2. All key/secret comparisons use `crypto/subtle.ConstantTimeCompare`.
3. Vault AAD on decrypt must equal AAD on encrypt (`store.CredentialAAD`).
3a. Envelope encryption: per-secret data keys are wrapped by the KEK and zeroed
   after use; the base64 `PAM_MASTER_KEY` (local KEK) is dev/test only —
   production uses a KMS-backed KEK.
4. Every code path that reveals or uses a secret appends an audit event.
5. Break-glass config holds only the SHA-256 hash, never the plaintext key.
6. Proxy plaintext secret is confined to `resolve`→`dialUpstream`; never logged.
7. User access tokens are stored only as `TokenHash` (`json:"-"`); the plaintext
   is returned once at creation and never persisted or re-derivable.
8. Every protected route/connection declares a capability; the role→capability
   matrix in `auth` is the single source of truth (don't inline role checks).

## 7. Testing

- `vault`: envelope roundtrip, AAD binding, tamper detection, version rejection, distinct tokens; local KEK wrap/unwrap + tamper; KEK factory; **Transit KMS** wrap/unwrap and full envelope over a mock Vault Transit server.
- `auth`: role→capability matrix, role parsing, resolver (bootstrap/break-glass/token/**session**/unknown); **LDAP** authenticate (success, highest-privilege-wins, wrong password, no mapped group, unknown user) against a fake `ldapConn`.
- `api`: full CRUD flow, auth required, secret-non-leak, cascade delete, break-glass audited, validation/conflict, **RBAC** (user/auditor/approver each allowed only their capabilities), **login session** (issue → use with role enforcement → logout revokes), login-not-configured 503.
- `proxy`: **end-to-end JIT injection** against an in-process upstream sshd that
  accepts only the vaulted password (proves the client never had it), plus wrong-key
  rejection, unknown-target denial, credential selector, recording hash match, and
  **auditor-denied connect** (RBAC gate).
- CI runs `gofmt -l`, `go vet`, `go build`, `go test -race`, and a Docker build.

## 8. Change log

| Date | Change |
|---|---|
| 2026-07-18 | Phase 3b: AD/LDAP login (`ldap.go`, `Authenticator`); login sessions (`store.Session`, `/api/login` + `/api/logout`); resolver session support; portal Sign On with user+password; `PAM_LDAP_*` env |
| 2026-07-18 | Vault envelope encryption + pluggable KEK (`kek.go`, `transit.go`); `v2:` token format; ctx-aware Encrypt/Decrypt; `local` (dev/test) + `vault-transit` (production) providers; `PAM_KEK_*` env |
| 2026-07-18 | Added `logging` package (per-service slog, json/text, `PAM_LOG_LEVEL`/`PAM_LOG_FORMAT`); api access log, proxy session logs, pgstore connect + query tracer; user/admin guides |
| 2026-07-18 | Phase 3a: `auth` package (roles admin/user/auditor/approver, capabilities, Resolver); `store.User` + user CRUD; API `authz` middleware + `/api/users`; proxy `CapConnect` gate; portal tolerates 403 |
| 2026-07-18 | Added `proxy` package (SSH gateway, JIT, recording, host key); `store.CredentialAAD`; proxy env vars |
| 2026-07-17 | Initial packages: config, vault, store(+mem/pg), api, web |
