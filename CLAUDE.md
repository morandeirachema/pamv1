# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

pamv1 is an open-source Privileged Access Management (PAM) system in Go, built **phase by phase with the rule that every phase is fully functional end to end** (it runs, passes tests, and deploys as IaC). `ROADMAP.md` is the source of truth for phase order and status; it is a hard project constraint, not a wishlist. The repo is educational ("for learning purposes" — see `README.md`), not production-hardened.

Stack is fixed by project decision: **Go + PostgreSQL** (no SQLite). The management portal is a deliberately austere **AS/400 / IBM 5250 green-terminal** UI — do not "modernize" it.

## Commands

The `go` toolchain must be on `PATH` (this environment installs it under `~/.local/go/bin`; export it if `go` is not found). There is no Makefile — use raw Go tooling.

```bash
go build ./...                                   # build everything
go test ./...                                    # all tests
go test -race ./...                              # what CI runs
go test ./internal/proxy -run TestJITInjection -v   # a single test
gofmt -l .                                       # must print nothing (CI fails otherwise)
go vet ./...
go mod tidy                                      # after changing imports
```

Run locally with no database (in-memory demo store):

```bash
go build ./cmd/pam-server
export PAM_MASTER_KEY=$(./pam-server -genkey)
export PAM_API_KEY=demo-key
export PAM_DATABASE_URL=memory
./pam-server      # portal+API on :8080, SSH proxy on :2222
```

`pam-server` utility flags: `-genkey` prints a new `PAM_MASTER_KEY`; `-hashkey` reads an emergency key on stdin and prints its SHA-256 for `PAM_BREAK_GLASS_KEY_HASH`.

Full stack (hardened Postgres + server): `cp .env.example .env` (fill the keys), then `docker compose up --build`. Deploy manifests live in `deploy/k8s/` and `deploy/terraform/` (all infra is IaC — do not hand-apply).

CI (`.github/workflows/ci.yml`) gates on: `gofmt -l`, `go vet`, `go build`, `go test -race`, and a Docker image build.

## Architecture

Single binary `cmd/pam-server` wires everything; packages under `internal/`:

- **`vault`** — at-rest secret crypto. `Encrypt(ctx, plaintext, aad)` → `"v2:"+base64(...)` envelope: a per-secret AES-256-GCM data key (random nonce per call) wrapped by a pluggable KEK (`local`/Vault-Transit/AWS-KMS/PKCS#11). The `"v2:"` prefix is a **versioned token format** for key rotation — preserve it.
- **`store`** — `Store` interface + domain types (`Target`, `Credential`, `AuditEvent`, …). Two implementations: `memstore` (tests/demo) and `pgstore` (Postgres via pgx, with embedded versioned migrations in `pgstore/migrations/` applied on startup). Sentinel errors `ErrNotFound`/`ErrConflict` map to HTTP/SSH errors upstream.
- **`api`** — REST (`http.ServeMux` method patterns) + the `auth` middleware, which accepts the `X-API-Key` **or** the break-glass key and sets an actor for audit.
- **`proxy`** — the SSH gateway and the heart of the system (Phase 2). Operator runs `ssh -p 2222 <creduser>@<target>@pam-host` with the PAM API key as the SSH password. The proxy authenticates, resolves the target's credential, **decrypts the secret just-in-time**, dials the real target injecting that secret, records the session (asciicast v2, SHA-256 into audit), and brokers I/O. The operator never sees the credential.
- **`web`** — the 5250-style portal, a single `//go:embed`ed `static/index.html` calling the REST API.
- **`config`** — all runtime config comes from `PAM_*` env vars (table in `docs/ARCHITECTURE-LOW-LEVEL.md`).

The two most load-bearing cross-package couplings:

1. **Vault AAD parity.** `store.CredentialAAD(targetID, credentialID)` produces the AAD used to encrypt a secret in `api` and to decrypt it in `proxy`. Both sides must call it — if they diverge, decryption silently fails. Because it binds the credential's row ID, a new credential is inserted first (to assign the ID) and its secret encrypted + stored in a second step. Never inline the AAD string.
2. **Secrets never leave as data.** `Credential.SecretEnc` is `json:"-"` and must never be serialized to any client. Plaintext exists only transiently inside `proxy.resolve → dialUpstream` and the audited `api` reveal path; never log it.

## Conventions specific to this repo

- **Living architecture docs.** `docs/ARCHITECTURE-HIGH-LEVEL.md` and `docs/ARCHITECTURE-LOW-LEVEL.md` are kept in step with the code; each ends with a change-log table. When you change structure, packages, schema, wire formats, env vars, or the audit vocabulary, update the relevant doc **in the same change**. Read the low-level doc first — it is the fullest map of the codebase.
- **Security invariants (do not regress)** are listed in the low-level doc §6: constant-time comparisons (`crypto/subtle`), every secret use appends an audit event, break-glass config holds only the SHA-256 hash. Treat them as tests-in-prose.
- **Audit everything sensitive.** Adding an action that touches a target, credential, or session means adding an audit event with an actor; keep the action-name vocabulary (low-level doc §5) consistent.
- **Tests exercise real behavior.** The proxy test proves JIT injection end-to-end against an in-process upstream sshd that accepts *only* the vaulted password (so a pass proves the client never had it). Prefer this style over mocking the security-critical path.

## Access model (RBAC — Phase 3a)

`internal/auth` is the single source of truth for authorization. **Four roles** — `admin`, `user`, `auditor`, `approver` — map to a `Capability` set via the `roleCaps` matrix; check with `Role.Can(cap)`, never inline a role name. Identity is resolved by `auth.Resolver` from a presented key (`X-API-Key` header / SSH proxy password): the bootstrap `PAM_API_KEY` (→ admin), the break-glass key (→ admin, loudly audited), or a per-user token (looked up by SHA-256).

- **admin** — full management + reveal + connect + audit + users.
- **user** — connect through the proxy, read inventory.
- **auditor** — read inventory + audit.
- **approver** — read inventory + audit + `CapApprove` (approval endpoints land with the OT/approval phase).

The API `authz(cap, handler)` middleware and the proxy's post-handshake `CapConnect` check both go through `auth`. Admins mint user tokens via `POST /api/users` (token returned once; only its hash is stored). The AD/LDAP login backend (group→role mapping, MFA) is Phase 3b — see `ROADMAP.md`.
