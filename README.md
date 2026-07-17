# pamv1

> ⚠️ **Alpha · for learning purposes.** This is an early-stage (**alpha**) educational
> project built to explore how a Privileged Access Management system works end to end. It has
> **not** been security-audited and is **not** production-ready — do not use it to guard real
> privileged credentials. Use it to learn, experiment and contribute.

[![CI](https://github.com/morandeirachema/pamv1/actions/workflows/ci.yml/badge.svg)](https://github.com/morandeirachema/pamv1/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Open-source **Privileged Access Management** (PAM) in Go: a hardened credential vault, target inventory for Linux/Windows, append-only audit trail, break-glass emergency access, and an unapologetically **AS/400-style admin portal** — because touching a PAM should *feel* serious.

Built step by step, **fully functional at every step**. The **JIT credential-injection SSH session proxy** ([Phase 2](ROADMAP.md#phase-2--session-proxy-with-jit-credential-injection-linuxssh-)), **RBAC** with four profiles ([Phase 3a](ROADMAP.md#3a--rbac-with-four-profiles-)) and **Active Directory login** over LDAPS ([Phase 3b](ROADMAP.md#3b--active-directory-connector-)) now work; see the [ROADMAP](ROADMAP.md) for what's next: Windows targets, OT/industrial adaptation and NIS2 compliance.

🔎 **Live overview:** [interactive project page](https://claude.ai/code/artifact/a1b34e5b-cd84-4fc7-8389-ebb1897495f7) — what works, architecture and roadmap at a glance.

📖 **[Léelo en español →](README.es.md)**

**Documentation** (all living docs, kept in step with the code):

- **[User Guide](docs/USER-GUIDE.md)** — for operators/auditors/approvers: signing in, connecting through the proxy, per-role abilities.
- **[Administrator Guide](docs/ADMIN-GUIDE.md)** — deploy, configure, manage targets/credentials/users/roles, break-glass, logging & audit.
- **[Architecture](docs/ARCHITECTURE-HIGH-LEVEL.md)** ([low-level](docs/ARCHITECTURE-LOW-LEVEL.md)) and the **[ports & network-flow matrix](docs/PORTS-AND-FLOWS.md)** for firewalling and segmentation.

## Architecture

```mermaid
flowchart LR
    subgraph CLIENTS[" Operators / Admins "]
        direction TB
        PORTAL["  Web Portal  <br/>  (5250 style)  "]
        REST["  REST clients  <br/>  (X-API-Key)  "]
    end

    subgraph CORE[" pamv1 core (Go) "]
        direction TB
        API["  REST API  <br/>  auth · audit  "]
        VAULT["  Vault  <br/>  AES-256-GCM  "]
        PROXY["  Session Proxy*  <br/>  JIT injection  "]
        ADC["  AD Connector*  <br/>  LDAP / Kerberos  "]
    end

    DB[("  PostgreSQL  <br/>  hardened  ")]

    subgraph TARGETS[" Targets (IT / OT) "]
        direction TB
        LNX["  Linux  <br/>  SSH  "]
        WIN["  Windows  <br/>  WinRM / RDP  "]
    end

    PORTAL --> API
    REST --> API
    API --> VAULT
    VAULT --> DB
    API -.-> ADC
    PROXY --> VAULT
    PROXY --> LNX
    PROXY -.-> WIN
```

\* dashed components (AD connector, Windows) land in [Phase 3–4](ROADMAP.md); the SSH proxy with JIT injection is live.

## What works today (Phases 1–3a)

- **Role-based access control** — four profiles (`admin`, `user`, `auditor`, `approver`) with a single role→capability matrix enforced by *both* the REST API and the SSH proxy. Admins mint per-user access tokens (stored only as SHA-256); every denial is audited and the audit trail attributes real usernames.
- **Active Directory login** — sign in with an AD username + password over **LDAPS**; AD groups map to the four roles (highest privilege wins) and `POST /api/login` issues a short-lived session token that works in the portal and the proxy. Local tokens and break-glass remain as the AD-down emergency path.
- **Session proxy with JIT injection** — operators connect through an SSH gateway; the proxy authenticates them, pulls the credential from the vault, **decrypts it only at connection time**, injects it into the upstream SSH session and records everything. Proven end-to-end by an integration test where the upstream accepts *only* the vaulted password the client never possessed.
- **Session recording** — each session captured in [asciicast v2](https://docs.asciinema.org/manual/asciicast/v2/) format, hashed with SHA-256, and the hash written to the audit trail for tamper evidence.
- **Hardened vault (envelope encryption)** — each secret is sealed with a per-secret [AES-256-GCM](https://pkg.go.dev/crypto/cipher) data key that is wrapped by a **pluggable Key Encryption Key (KEK)**: a `local` key for dev/test, or **[HashiCorp Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit)** in production so the root key never leaves the KMS. AAD binds each ciphertext to its owning target (a copied token fails to decrypt); versioned `v2:` tokens.
- **Target inventory** — Linux/Windows machines with ssh/winrm/rdp endpoints.
- **Credentials API** — vault, list (never returns secret material), audited on-demand `reveal`, delete. The JSON model *cannot* serialize the ciphertext (`json:"-"`).
- **Audit trail** — append-only record of every sensitive action, with actor attribution.
- **Operational logs** — structured [slog](https://pkg.go.dev/log/slog) to stdout, one line per HTTP request and per proxy session, tagged by service (`server`/`api`/`proxy`/`store`); JSON for a SIEM or text for humans (`PAM_LOG_LEVEL`, `PAM_LOG_FORMAT`). Separate from the audit trail; secrets are never logged.
- **Break-glass** — a sealed emergency key whose SHA-256 hash (never the key) lives in config; using it works instantly but screams: `break-glass` actor on every audit row plus a server warning log.
- **AS/400 portal** — Sign On screen, menu-driven `Work with…` screens, numeric options (`4=Delete`, `5=Display`), F3/F5/F6/F12 keys, green phosphor and scanlines.
- **PostgreSQL storage** via [pgx](https://github.com/jackc/pgx); in-memory store for tests and demos.
- **IaC deployment** — [Docker](https://docs.docker.com/) (distroless, non-root), [docker-compose](https://docs.docker.com/compose/) with hardened Postgres, [Kubernetes](https://kubernetes.io/) manifests under the restricted Pod Security Standard, and a [Terraform](https://developer.hashicorp.com/terraform) module.

## Roles & users

Four profiles, enforced identically by the API and the proxy:

| Role | Can | Cannot |
|---|---|---|
| `admin` | manage targets/credentials/users, reveal secrets, connect, read audit | — |
| `user` | connect to targets through the proxy, read the inventory | manage, reveal, read audit |
| `auditor` | read the inventory and the audit trail | manage, reveal, connect |
| `approver` | read inventory + audit, approve access requests* | manage, reveal, connect |

`*` approval endpoints arrive in a later phase; the role and its capability exist now.

An admin creates a user and receives that user's access token **once**:

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/users \
  -d '{"username":"alice","role":"user"}'
# → {"id":1,"username":"alice","role":"user","token":"pamt_…"}   (store it now)
```

The user then presents that token as `X-API-Key` (portal Sign On) or as the SSH
proxy password. The bootstrap `PAM_API_KEY` is the `admin` identity; the
break-glass key is also `admin` (audited loudly). AD login with group→role
mapping is [Phase 3b](ROADMAP.md#3b--active-directory-connector-).

## Connect through the proxy (JIT injection)

Once a target and its credential are vaulted, operators reach the target **through** pamv1
— the secret is decrypted only for the upstream dial and is never shown:

```bash
# username selects the target; SSH password is your PAM API key (Phase 2 bootstrap auth)
ssh -p 2222 web-01@pam-host                 # first credential of target "web-01"
ssh -p 2222 root@web-01@pam-host            # a specific credential (user "root")
```

The proxy authenticates you, pulls `root`'s password from the vault, injects it into the
upstream SSH connection, records the session (asciicast v2) with a SHA-256 in the audit
trail, and proxies your I/O. You never see the credential. Recordings go to
`PAM_RECORDING_DIR`; disable the proxy with `PAM_SSH_ADDR=off`.

## Quickstart

### Local demo (no database)

```bash
go build ./cmd/pam-server
export PAM_MASTER_KEY=$(./pam-server -genkey)
export PAM_API_KEY=$(openssl rand -hex 24)
export PAM_DATABASE_URL=memory
./pam-server
# → portal at http://localhost:8080 (Sign On with your PAM_API_KEY)
```

### docker-compose (with hardened PostgreSQL)

```bash
cp .env.example .env      # fill PAM_MASTER_KEY, PAM_API_KEY, POSTGRES_PASSWORD
docker compose up --build
# → http://localhost:8080
```

### Kubernetes

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl -n pamv1 create secret generic pam-secrets \
  --from-literal=PAM_MASTER_KEY=... \
  --from-literal=PAM_API_KEY=... \
  --from-literal=PAM_BREAK_GLASS_KEY_HASH=... \
  --from-literal=PAM_DATABASE_URL=postgres://...
kubectl apply -f deploy/k8s/
```

### Terraform (IaC)

```bash
cd deploy/terraform
terraform init
terraform apply \
  -var master_key=... -var api_key=... -var database_url=postgres://...
```

## Configuration

| Variable | Required | Description |
|---|---|---|
| `PAM_MASTER_KEY` | yes | Vault master key (32 bytes urlsafe-base64). Generate: `pam-server -genkey` |
| `PAM_API_KEY` | yes | Admin API key (header `X-API-Key`, portal Sign On) |
| `PAM_DATABASE_URL` | yes | `postgres://…` or `memory` (ephemeral demo) |
| `PAM_BREAK_GLASS_KEY_HASH` | no | Hex SHA-256 of the sealed emergency key; empty disables break-glass |
| `PAM_LISTEN_ADDR` | no | HTTP listen address, default `:8080` |
| `PAM_SSH_ADDR` | no | SSH proxy address, default `:2222`; `off` disables it |
| `PAM_SSH_HOST_KEY` | no | Path to persist the proxy host key (PEM); empty = ephemeral |
| `PAM_RECORDING_DIR` | no | Where session recordings are written, default `recordings` |

## Break-glass procedure

1. Generate a strong emergency key and hash it — the plaintext is **never** configured or stored:
   ```bash
   openssl rand -base64 30                     # the emergency key
   echo -n "<that-key>" | ./pam-server -hashkey  # → PAM_BREAK_GLASS_KEY_HASH
   ```
2. Seal the plaintext key in an envelope / physical safe (dual control recommended). Configure only the hash.
3. **In an emergency** (normal auth path down): use the sealed key as `X-API-Key`. Access works immediately — and every request is audited as actor `break-glass` and logged loudly, blinking red in the portal's audit screen.
4. **After the incident**: rotate the emergency key (new hash), rotate any revealed credentials, review the audit trail.

Quorum unseal, auto-expiry and alerting are planned in [Phase 6](ROADMAP.md#phase-6--break-glass-v2-).

## Security model & hardening

- Secrets are encrypted at the application layer, so a DB dump alone is useless without `PAM_MASTER_KEY` (defense in depth on top of Postgres hardening: `scram-sha-256` auth, TLS and [pgAudit](https://www.pgaudit.org/) in [Phase 5](ROADMAP.md#phase-5--hardening-database-vault-transport-)).
- Constant-time key comparison ([`crypto/subtle`](https://pkg.go.dev/crypto/subtle)), body-size limits, strict CSP on the portal, distroless non-root container, read-only root FS and dropped capabilities in K8s.
- Found a vulnerability? Please open a private security advisory on GitHub rather than a public issue.

## OT / industrial environments

pamv1 is being designed to drop into [IEC 62443](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards)-oriented architectures: the session proxy is intended to live in the industrial DMZ (Purdue level 3.5) as the **only** IT→OT path, with air-gap friendly operation, per-cell protocol allowlists, approval windows and recorded vendor access. Details in [Phase 8](ROADMAP.md#phase-8--ot-adaptation-).

## NIS2

For entities under [Directive (EU) 2022/2555 (NIS2)](https://eur-lex.europa.eu/eli/dir/2022/2555/oj), pamv1 targets the Art. 21 risk-management measures:

| NIS2 Art. 21(2) | pamv1 |
|---|---|
| (i) access control & asset management | Target inventory, RBAC via AD groups (Phase 3) |
| (h) cryptography & encryption policies | AES-256-GCM vault, TLS everywhere (Phase 5) |
| (j) MFA & secured communications | TOTP MFA (Phase 3), proxied recorded sessions (Phase 2) |
| (b)(c) incident handling & business continuity | Audit trail, break-glass procedure, backup runbook (Phase 5) |
| Art. 23 reporting | Audit export hooks for 24h/72h notifications (Phase 9) |

## Development

```bash
go test ./...        # unit + API tests (in-memory store)
go vet ./... && gofmt -l .
```

Contributions are welcome — the [ROADMAP](ROADMAP.md) is the best place to pick something up. Please keep PRs small and covered by tests.

## License

[Apache-2.0](LICENSE)
