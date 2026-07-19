# pamv1

> ⚠️ **Alpha · for learning purposes.** This is an early-stage (**alpha**) educational
> project built to explore how a Privileged Access Management system works end to end. It has
> **not** been security-audited and is **not** production-ready — do not use it to guard real
> privileged credentials. Use it to learn, experiment and contribute.

[![CI](https://github.com/morandeirachema/pamv1/actions/workflows/ci.yml/badge.svg)](https://github.com/morandeirachema/pamv1/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Open-source **Privileged Access Management** (PAM) in Go: a hardened credential vault, target inventory for Linux/Windows, a **just-in-time credential-injection session proxy**, append-only audit trail, break-glass emergency access, and an unapologetically **AS/400-style admin portal** — because touching a PAM should *feel* serious.

Built phase by phase with one rule: **every phase is functional end to end** — it runs, passes tests, and deploys as IaC. All **[ten roadmap phases](ROADMAP.md)** have now shipped, from the JIT SSH proxy and RBAC through AD/OIDC login, Windows targets, break-glass quorum, OT/industrial adaptation and NIS2 tooling. It remains an **alpha, educational** codebase — read it, run it, learn from it, but don't trust it with real secrets.

🔎 **Live overview:** [interactive project page](https://claude.ai/code/artifact/a1b34e5b-cd84-4fc7-8389-ebb1897495f7) — what works, architecture and roadmap at a glance.

📖 **[Léelo en español →](README.es.md)**

**Documentation** (all living docs, kept in step with the code):

- **[User Guide](docs/USER-GUIDE.md)** — for operators/auditors/approvers: signing in, connecting through the proxy, per-role abilities.
- **[Administrator Guide](docs/ADMIN-GUIDE.md)** — deploy, configure, manage targets/credentials/users/roles, break-glass, logging & audit.
- **[Architecture](docs/ARCHITECTURE-HIGH-LEVEL.md)** ([low-level](docs/ARCHITECTURE-LOW-LEVEL.md)), the **[ports & network-flow matrix](docs/PORTS-AND-FLOWS.md)**, and the **[backup & restore runbook](docs/BACKUP-AND-RESTORE.md)**.

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

All components above are implemented. Dashed edges mark optional/back-end paths (the AD/OIDC connector is used only when SSO is configured; Windows targets are brokered over WinRM/RDP).

## What works today

All ten roadmap phases have shipped. Grouped by area:

### Identity & access

- **Role-based access control** — four profiles (`admin`, `user`, `auditor`, `approver`) with a single role→capability matrix enforced by *both* the REST API and the SSH proxy. Admins mint per-user access tokens (stored only as SHA-256); every denial is audited and the audit trail attributes real usernames.
- **AD, Entra ID & OIDC single sign-on** — sign in with an AD username + password over **LDAPS**, with **Microsoft Entra ID**, or via **OIDC Authorization Code + PKCE SSO** (the IdP does the login and its MFA; pamv1 validates the ID token's RS256 signature against the IdP's JWKS). Directory groups / app roles map to the four roles, and login issues a short-lived session token that works in the portal and the proxy. Sources compose; local tokens and break-glass remain as the emergency path.
- **TOTP multi-factor auth** — self-service enrollment ([RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238), works with any authenticator app); the secret is stored vault-encrypted and login requires the 6-digit code once enrolled. Single-use **recovery codes** and an optional **require-MFA-for-all** policy (with enrollment-only first sign-in).

### Sessions & the JIT proxy

- **Session proxy with JIT injection** — operators connect through an SSH gateway; the proxy authenticates them, pulls the credential from the vault, **decrypts it only at connection time** (and only after every authorization gate passes), injects it into the upstream session and records everything. Proven end to end by an integration test where the upstream accepts *only* the vaulted password the client never possessed. Upstream host keys can be pinned (`PAM_SSH_KNOWN_HOSTS`); a jump-host/bastion path and read-only observer sessions are supported.
- **Windows targets (WinRM + RDP)** — run commands on Windows hosts via `POST /api/targets/{id}/winrm` (basic or NTLM auth) or an interactive WinRM loop through the proxy, or broker a full **RDP** desktop through Apache Guacamole (`GET /api/targets/{id}/rdp` WebSocket tunnel, cert-verified by default). Either way the credential is injected just-in-time (AD-joined accounts work), sessions are audited, and the operator never sees the secret.
- **Session recording** — every session (stdout **and** stderr) captured in [asciicast v2](https://docs.asciinema.org/manual/asciicast/v2/) format, hashed with SHA-256 into a tamper-evident chain, and the hash written to the audit trail. Recording failures are audited, and `PAM_REQUIRE_RECORDING` can refuse an unrecordable session outright.

### Vault & credential lifecycle

- **Hardened vault (envelope encryption)** — each secret is sealed with a per-secret [AES-256-GCM](https://pkg.go.dev/crypto/cipher) data key that is wrapped by a **pluggable Key Encryption Key (KEK)**: a `local` key for dev/test, or in production **[HashiCorp Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit)**, **AWS KMS**, or an on-prem **HSM via [PKCS#11](https://en.wikipedia.org/wiki/PKCS_11)** (`pkcs11`-tagged build) — the root key never leaves the KMS/HSM. AAD binds each ciphertext to its owning target (a copied token fails to decrypt); versioned `v2:` tokens; online KEK rotation.
- **Target inventory & credentials API** — Linux/Windows machines with ssh/winrm/rdp endpoints; credentials are vaulted, listed (never returning secret material), revealed on demand (audited), and deleted. The JSON model *cannot* serialize the ciphertext (`json:"-"`).
- **Credential lifecycle (rotation · reconciliation · checkout · discovery)** — `POST /api/credentials/{id}/rotate` generates a strong secret, sets it **on the target** (SSH `chpasswd` / WinRM `net user` / fresh `ssh_key`), and re-vaults it — the new password is never shown. `/reconcile` verifies the vaulted secret still authenticates and flags **out-of-sync drift** (`?remediate=true` heals it). **Checkout/check-in** grants an exclusive time-boxed lease and rotates the secret on return. **Discovery** (`/api/discovery/scan`) probes hosts for SSH/WinRM/RDP ports and can auto-onboard targets. A background worker rotates aged secrets and reconciles on a schedule; secrets are optionally rotated the moment a proxied session ends.

### Audit, break-glass & alerting

- **Audit trail** — append-only record of every sensitive action, with actor attribution, plus a tamper-evident export (`GET /api/audit/export`, JSON/CSV + SHA-256).
- **Operational logs** — structured [slog](https://pkg.go.dev/log/slog) to stdout, one line per HTTP request and per proxy session, tagged by service (`server`/`api`/`proxy`/`store`); JSON for a SIEM or text for humans (`PAM_LOG_LEVEL`, `PAM_LOG_FORMAT`). Separate from the audit trail; secrets are never logged.
- **Break-glass (v2)** — a sealed emergency key, or **M-of-N quorum unseal** ([Shamir shares](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) split with `-split-key`; custodians POST shares to reconstruct it). Either way you get a **short-lived, auto-expiring** admin session, and every break-glass access/unseal is loudly audited and **alerted in real time** (webhook, syslog or email).

### OT / industrial & compliance

- **OT session approval (4-eyes)** — gate a target behind an **approved access request**: a user files a request, a *different* approver approves it (self-approval refused), and only then may the user connect — enforced on the SSH proxy, WinRM **and** RDP, with break-glass as the bypass. Per-target (`require_approval`) or global (`PAM_REQUIRE_APPROVAL`), time-boxed for maintenance windows.
- **OT hardening** — per-zone **protocol allowlists** (`PAM_ALLOWED_PROTOCOLS`), read-only **observer** sessions, and an **air-gap mode** (`PAM_OT_AIRGAP`) that makes zero outbound calls. See the [OT Deployment Guide](docs/OT-DEPLOYMENT.md) and the [NIS2 Compliance Pack](docs/NIS2-COMPLIANCE.md).

### Portal, storage & operations

- **AS/400 portal** — a full role-aware management console in green phosphor: Sign On, a numbered main menu, and menu-driven `Work with…` screens for targets & grants, credentials (reveal/check-out/rotate/reconcile), active sessions (live monitor + kill), 4-eyes access requests, users & roles, MFA, discovery, reconciliation, audit (filter + CSV export) and break-glass — numeric options (`4=Delete`, `5=Display`), F3/F5/F6/F9/F12 keys, scanlines. The menu shows only what your role permits.
- **PostgreSQL storage** via [pgx](https://github.com/jackc/pgx) with embedded migrations; an in-memory store for tests and demos; optional **[CloudNativePG](https://cloudnative-pg.io/) HA**.
- **Observability** — a dependency-free [Prometheus](https://prometheus.io/) `/metrics` endpoint (request counts by status, audit volume, break-glass use, rotations, active-sessions gauge), plus a health/readiness split (`/healthz` liveness, `/readyz` checks the database).
- **IaC deployment** — [Docker](https://docs.docker.com/) (distroless, non-root), [docker-compose](https://docs.docker.com/compose/) with hardened Postgres, [Kubernetes](https://kubernetes.io/) manifests under the restricted Pod Security Standard, a **[Helm chart](deploy/helm/pamv1)**, and a [Terraform](https://developer.hashicorp.com/terraform) module. Releases are built by digest with an **[SBOM](https://www.cisa.gov/sbom), [cosign](https://docs.sigstore.dev/) keyless signature and SLSA provenance**.

## Roles & users

Four profiles, enforced identically by the API and the proxy:

| Role | Can | Cannot |
|---|---|---|
| `admin` | manage targets/credentials/users, reveal secrets, connect, read audit | — |
| `user` | connect to targets through the proxy, read the inventory | manage, reveal, read audit |
| `auditor` | read the inventory and the audit trail | manage, reveal, connect |
| `approver` | read inventory + audit, approve access requests | manage, reveal, connect |

An admin creates a user and receives that user's access token **once**:

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/users \
  -d '{"username":"alice","role":"user"}'
# → {"id":1,"username":"alice","role":"user","token":"pamt_…"}   (store it now)
```

The user then presents that token as `X-API-Key` (portal Sign On) or as the SSH
proxy password. The bootstrap `PAM_API_KEY` is the `admin` identity; the
break-glass key is also `admin` (audited loudly). For directory-backed sign-in,
AD/Entra/OIDC map directory groups to these same four roles.

## Connect through the proxy (JIT injection)

Once a target and its credential are vaulted, operators reach the target **through** pamv1
— the secret is decrypted only for the upstream dial and is never shown:

```bash
# username selects the target; SSH password is your PAM API key (or per-user token)
ssh -p 2222 web-01@pam-host                 # first credential of target "web-01"
ssh -p 2222 root@web-01@pam-host            # a specific credential (user "root")
```

The proxy authenticates you, pulls `root`'s password from the vault, injects it into the
upstream SSH connection, records the session (asciicast v2) with a SHA-256 in the audit
trail, and proxies your I/O. You never see the credential. Recordings go to
`PAM_RECORDING_DIR`; disable the proxy with `PAM_SSH_ADDR=off`.

## Quickstart

> **Run specs** (ports, resource requests/limits, Docker/Kubernetes versions, PostgreSQL, storage, sizing) live in **[docs/REQUIREMENTS.md](docs/REQUIREMENTS.md)**.

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

Or with Helm (readiness/metrics wired, configurable replicas, optional ServiceMonitor):

```bash
helm install pamv1 deploy/helm/pamv1 \
  --set secret.data.PAM_MASTER_KEY=... \
  --set secret.data.PAM_API_KEY=... \
  --set secret.data.PAM_DATABASE_URL=postgres://...
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
| `PAM_SSH_KNOWN_HOSTS` | no | Pin upstream target host keys (known_hosts file); empty = trust-any (logged) |
| `PAM_RECORDING_DIR` | no | Where session recordings are written, default `recordings` |
| `PAM_REQUIRE_RECORDING` | no | Refuse a session if its recording can't be created (fail-closed audit) |

The full set of `PAM_*` variables (KEK providers, AD/OIDC, WinRM/RDP, OT, rotation, alerting) is tabulated in **[docs/ARCHITECTURE-LOW-LEVEL.md](docs/ARCHITECTURE-LOW-LEVEL.md#4-configuration-env-pam_)**.

## Break-glass procedure

1. Generate a strong emergency key and hash it — the plaintext is **never** configured or stored:
   ```bash
   openssl rand -base64 30                     # the emergency key
   echo -n "<that-key>" | ./pam-server -hashkey  # → PAM_BREAK_GLASS_KEY_HASH
   ```
2. Seal the plaintext key in an envelope / physical safe (dual control recommended). Configure only the hash.
3. **In an emergency** (normal auth path down): use the sealed key as `X-API-Key`. Access works immediately — and every request is audited as actor `break-glass` and logged loudly, blinking red in the portal's audit screen.
4. **After the incident**: rotate the emergency key (new hash), rotate any revealed credentials, review the audit trail.

For higher assurance, split the emergency key into **M-of-N [Shamir shares](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing)** (`pam-server -split-key`) held by separate custodians who POST their shares to `/api/breakglass/unseal`; the reconstructed session auto-expires and every unseal is alerted.

## Security model & hardening

- Secrets are encrypted at the application layer, so a DB dump alone is useless without `PAM_MASTER_KEY` — defense in depth on top of Postgres hardening (`scram-sha-256` auth, TLS, [pgAudit](https://www.pgaudit.org/)).
- The vaulted secret is decrypted **only after every authorization gate passes**, held transiently for the upstream dial, and never serialized to a client or written to a log.
- Upstream SSH host keys can be pinned so the proxy won't inject a credential into a spoofed target; the graceful shutdown drains active sessions so their recordings and audit events are flushed.
- Constant-time key comparison ([`crypto/subtle`](https://pkg.go.dev/crypto/subtle)), body-size limits, strict CSP on the portal, distroless non-root container, read-only root FS and dropped capabilities in K8s.
- Found a vulnerability? Please open a private security advisory on GitHub rather than a public issue.

## OT / industrial environments

pamv1 drops into [IEC 62443](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards)-oriented architectures: the session proxy lives in the industrial DMZ (Purdue level 3.5) as the **only** IT→OT path, with air-gap-friendly operation, per-cell protocol allowlists, approval windows and recorded vendor access. Details in the [OT Deployment Guide](docs/OT-DEPLOYMENT.md).

## NIS2

For entities under [Directive (EU) 2022/2555 (NIS2)](https://eur-lex.europa.eu/eli/dir/2022/2555/oj), pamv1 targets the Art. 21 risk-management measures — full mapping in the **[NIS2 Compliance Pack](docs/NIS2-COMPLIANCE.md)**:

| NIS2 Art. 21(2) | pamv1 |
|---|---|
| (i) access control & asset management | Target inventory, RBAC + per-target grants, 4-eyes approval |
| (h) cryptography & encryption policies | Envelope encryption (AES-256-GCM + pluggable KEK), TLS everywhere |
| (j) MFA & secured communications | TOTP MFA + OIDC/Entra SSO, proxied recorded sessions |
| (b)(c) incident handling & business continuity | Audit trail, break-glass quorum, backup runbook |
| Art. 23 reporting | Tamper-evident audit export (`GET /api/audit/export`, JSON/CSV + SHA-256) for 24h/72h notifications |

For **OT/industrial** deployments (IEC 62443 / Purdue), see the **[OT Deployment Guide](docs/OT-DEPLOYMENT.md)**.

## Development

```bash
go build ./...            # build everything
go test -race ./...       # unit + API + proxy tests (in-memory store) — what CI runs
go vet ./... && gofmt -l . # gofmt must print nothing
```

CI additionally runs a live-PostgreSQL store contract, a `pkcs11`-tagged build against SoftHSM2, and a Docker image build. The [architecture low-level doc](docs/ARCHITECTURE-LOW-LEVEL.md) is the fullest map of the codebase — read it first.

Contributions are welcome — the [ROADMAP](ROADMAP.md) is the best place to pick something up. Please keep PRs small and covered by tests.

## License

[Apache-2.0](LICENSE)
