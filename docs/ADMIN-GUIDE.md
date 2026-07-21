# pamv1 — Administrator Guide

A complete, practical guide for **administrators**: deploy pamv1, configure it,
onboard targets and credentials, manage users and roles, run the break-glass
procedure, and read the logs and audit trail.

> **Living document.** Kept in step with the product — update it whenever
> admin-facing behavior changes (config, deployment, management, logging). Add a
> row to the [change log](#12-change-log) with each update.
>
> Last updated: 2026-07-21 · Reflects: **Phases 0–18** — configuration console + custom-profile RBAC + hot-swap (12), the AI-agent access broker (13), SOPS-encrypted secrets (14), the PostgreSQL database session proxy (15), live monitoring + command control (16), safes + dependent-account propagation (17), and optional CyberArk Conjur secret sourcing (18). See the [ROADMAP](../ROADMAP.md).

> ⚠️ **Educational / pre-production.** pamv1 is a learning project and is
> currently intended for **pre-production** use. It has not been security-audited.
> Do not guard real production credentials with it yet.

New here? Read the [concepts](#1-concepts) first, then jump to
[deployment](#3-deployment). Operators/users should read the
[User Guide](USER-GUIDE.md). For the big picture see the
[high-level architecture](ARCHITECTURE-HIGH-LEVEL.md); for firewall rules see the
[ports & flow matrix](PORTS-AND-FLOWS.md).

---

## 1. Concepts

| Term | Meaning |
|---|---|
| **Vault** | Where privileged secrets are stored, always encrypted ([AES-256-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)). The plaintext is never written to the database. |
| **Target** | A machine you grant privileged access to (Linux via SSH today; Windows later). |
| **Credential** | A privileged account (username + secret) on a target, stored in the vault. |
| **Session proxy** | An SSH gateway that operators connect *through*. It injects the credential **just-in-time (JIT)** into the connection to the target — the operator never sees the secret. |
| **Role** | One of `admin`, `user`, `auditor`, `approver` — determines what an identity may do. |
| **Access token** | A per-user secret (shown once) that a user presents as `X-API-Key` or the SSH password. |
| **Break-glass** | An emergency key for admin access when the normal path is unavailable; every use is loudly audited. |
| **Audit trail** | An append-only record (in the database) of every sensitive action. Distinct from operational **logs** (stdout). |

```mermaid
flowchart LR
    OP["Operator"] -->|"HTTPS / SSH"| PAM["pam-server<br/>portal · API · proxy"]
    PAM -->|"encrypt / decrypt"| DB[("PostgreSQL<br/>vault + audit")]
    PAM -->|"JIT credential"| T["Target (SSH)"]
```

---

## 2. Prerequisites

- [Go 1.26+](https://go.dev/dl/) (to build from source), or [Docker](https://docs.docker.com/) / [Kubernetes](https://kubernetes.io/) to run the image.
- A PostgreSQL 14+ database (16/17 recommended; bundled in docker-compose), or `memory` mode for a throwaway demo.
- `openssl` (to generate keys), an SSH client for operators.

Full run specs — ports, resource requests/limits, Docker/Kubernetes versions,
storage and sizing — are in **[REQUIREMENTS.md](REQUIREMENTS.md)**.

---

## 3. Deployment

### 3.1 Generate the secrets first

Every deployment needs a **master key** (encrypts the vault) and an **API key**
(the bootstrap admin identity). Optionally a **break-glass** hash.

```bash
go build ./cmd/pam-server

# Vault master key (32 bytes, url-safe base64) — losing this makes secrets unrecoverable
./pam-server -genkey                       # → PAM_MASTER_KEY

# Bootstrap admin API key (any strong random string)
openssl rand -hex 24                        # → PAM_API_KEY

# (optional) Break-glass: hash the sealed emergency key; store only the hash
echo -n "the-emergency-key" | ./pam-server -hashkey   # → PAM_BREAK_GLASS_KEY_HASH
```

### 3.2 Local demo (no database)

Fastest way to see it work; data is lost on restart.

```bash
export PAM_MASTER_KEY=$(./pam-server -genkey)
export PAM_API_KEY=$(openssl rand -hex 24)
export PAM_DATABASE_URL=memory
./pam-server
# Portal + API → http://localhost:8080   ·   SSH proxy → localhost:2222
```

### 3.3 docker-compose (recommended for pre-production)

Brings up a hardened PostgreSQL ([`scram-sha-256`](https://www.postgresql.org/docs/current/auth-password.html)) plus pam-server.

```bash
cp .env.example .env
# edit .env: set PAM_MASTER_KEY, PAM_API_KEY, POSTGRES_PASSWORD (and optionally the break-glass hash)
docker compose up --build
docker compose logs -f pam        # follow pam-server logs
docker compose logs -f db         # PostgreSQL logs (connections are logged)
```

Host key and session recordings persist in the `pamdata` volume.

### 3.4 Kubernetes

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl -n pamv1 create secret generic pam-secrets \
  --from-literal=PAM_MASTER_KEY=... \
  --from-literal=PAM_API_KEY=... \
  --from-literal=PAM_BREAK_GLASS_KEY_HASH=... \
  --from-literal=PAM_DATABASE_URL='postgres://pam:...@postgres:5432/pam?sslmode=verify-full'
kubectl apply -f deploy/k8s/
kubectl -n pamv1 logs deploy/pam-server -f
```

The `create secret` above keeps the plaintext out of Git but only lives in the
cluster. For **GitOps**, seal the Secret manifest instead: Phase 14 ships a
[SOPS](https://github.com/getsops/sops)+[age](https://age-encryption.org/) flow
under [`deploy/k8s/sops/`](../deploy/k8s/sops/) — `apply.sh` streams
`sops --decrypt | kubectl apply -f -` (plaintext never touches disk) and only the
encrypted manifest is committed. See its [README](../deploy/k8s/sops/README.md)
for Flux/Argo/helm-secrets wiring.

Or, if you run **CyberArk Conjur**, pamv1 can fetch its own bootstrap secrets
from it at startup instead (Phase 18) — set `PAM_CONJUR_URL` and pam-server pulls
`PAM_MASTER_KEY`/`PAM_API_KEY`/`PAM_DATABASE_URL`/… from Conjur, with a
Kubernetes projected-token (`authn-jwt`) so **no secret lives in Git at all**.
SOPS and Conjur both ship; SOPS stays the zero-dependency default. See
[`deploy/k8s/conjur/`](../deploy/k8s/conjur/).

The deployment runs non-root, read-only root filesystem, all capabilities
dropped, under the restricted [Pod Security Standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/). Recordings and the host key live on a writable `/data` volume. Readiness is gated on `/readyz` (DB reachable), liveness on `/healthz`.

Or with **Helm** (`deploy/helm/pamv1`) — configurable replicas, a PVC option, a
Prometheus `ServiceMonitor`, and the same hardened pod security context:

```bash
helm install pamv1 deploy/helm/pamv1 \
  --set secret.data.PAM_MASTER_KEY=... \
  --set secret.data.PAM_API_KEY=... \
  --set secret.data.PAM_DATABASE_URL='postgres://pam:...@postgres:5432/pam?sslmode=verify-full' \
  --set metrics.serviceMonitor.enabled=true
```

For production, set `secret.existingSecret` and manage PAM_* with an external
secret manager (Vault / External Secrets Operator) rather than chart values.

**Highly-available PostgreSQL.** For an in-cluster HA database, install the
[CloudNativePG](https://cloudnative-pg.io/) operator and apply
`deploy/k8s/postgres-cnpg.yaml` (a 3-instance cluster with automatic failover);
point `PAM_DATABASE_URL` at the `pamv1-pg-rw` service. For a cloud-managed
database, `deploy/terraform/cloud-postgres/` is an AWS RDS example (multi-AZ,
encrypted, TLS-forced) to adapt.

### 3.5 Terraform (IaC)

```bash
cd deploy/terraform
terraform init
terraform apply -var master_key=... -var api_key=... -var database_url=postgres://...
```

### 3.6 Put it behind TLS

Operators must reach the portal/API over **HTTPS** and the proxy over SSH only.
Terminate TLS at an ingress/load balancer in front of `:8080`; never expose the
plain-HTTP port off-host. Use `sslmode=verify-full` and, later, LDAPS for AD.

---

## 4. Configuration reference

All configuration is environment variables (12-factor). Full descriptions in
[.env.example](../.env.example) and the [low-level architecture doc](ARCHITECTURE-LOW-LEVEL.md#4-configuration-env-pam_).

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `PAM_KEK_PROVIDER` | | `local` | Vault key backend: `local` (dev/test), `vault-transit`, `aws-kms`, or `pkcs11` (HSM). |
| `PAM_CONJUR_URL` (+ `PAM_CONJUR_*`) | | (off) | Source bootstrap `PAM_*` secrets from CyberArk Conjur at startup (Phase 18); see [deploy/k8s/conjur](../deploy/k8s/conjur/). |
| `PAM_MASTER_KEY` | local only | — | Local KEK key (`-genkey`). **Back it up securely.** Dev/test only. |
| `PAM_KEK_TRANSIT_ADDR` / `_TOKEN` / `_KEY` | transit only | — | HashiCorp Vault Transit KEK (production). |
| `PAM_KEK_AWS_KEY_ID` / `_AWS_REGION` | aws-kms only | — | AWS KMS KEK (production). |
| `PAM_KEK_PKCS11_MODULE` / `_PIN` / `_KEY_LABEL` / `_TOKEN_LABEL` | pkcs11 only | — | On-prem HSM KEK — needs the `pkcs11`-tagged build (`Dockerfile.pkcs11`). |
| `PAM_API_KEY` | ✅ | — | Bootstrap admin key (X-API-Key / SSH password). |
| `PAM_DATABASE_URL` | ✅ | — | `postgres://…` (use `sslmode=verify-full`) or `memory` for demo. |
| `PAM_BREAK_GLASS_KEY_HASH` | | (off) | Hex SHA-256 of the sealed emergency key. |
| `PAM_LISTEN_ADDR` | | `:8080` | HTTP portal/API bind. |
| `PAM_SSH_ADDR` | | `:2222` | SSH proxy bind; `off` disables the proxy. |
| `PAM_DB_ADDR` | | `off` | PostgreSQL session-proxy bind (Phase 15), e.g. `:5433`; `off` disables it. |
| `PAM_COMMAND_DENY_FILE` | | (off) | Regex denylist file for command control (Phase 16); blocks matching commands on exec/WinRM/SQL. |
| `PAM_ANALYTICS_INTERVAL_MIN` | | `0` (off) | Threat-analytics worker interval (Phase 23); `0` leaves the read-only `GET /api/analytics/risk` endpoint on. See §9.7. |
| `PAM_ANALYTICS_WINDOW_MIN` / `_AUTO_KILL` / `_BUSINESS_START` / `_BUSINESS_END` | | `60` / `false` / `7` / `20` | Risk-scoring window (also the re-alert cooldown), auto-kill of critical actors' sessions, and business hours for the off-hours signal. |
| `PAM_ANALYTICS_TIMEZONE` | | (UTC) | IANA timezone the business hours are interpreted in (audit timestamps are UTC). |
| `PAM_APP_SECRETS_ENABLED` | | `false` | Enable the application-secrets API (Phase 24): Conjur-style secret delivery to non-agent apps. Front it with TLS. See §7. |
| `PAM_SSH_HOST_KEY` | | (ephemeral) | Path to persist the proxy SSH host key. |
| `PAM_SSH_CA_KEY` | | (ZSP off) | Path to the Zero Standing Privilege SSH CA key (Phase 22); presence enables `ssh_ca` credentials (mint short-lived certs). See §6. |
| `PAM_SSH_CERT_TTL_MIN` | | `2` | Validity (minutes) of a minted ZSP certificate. |
| `PAM_SSH_KNOWN_HOSTS` | | (trust-any + warn) | OpenSSH known_hosts file pinning **upstream target** host keys. |
| `PAM_RECORDING_DIR` | | `recordings` | Where session recordings are written. |
| `PAM_LOG_LEVEL` | | `info` | `debug` \| `info` \| `warn` \| `error`. |
| `PAM_LOG_FORMAT` | | `json` | `json` (for SIEM) \| `text` (for humans). |
| `PAM_ROTATE_INTERVAL_MIN` | | `0` (off) | Credential-lifecycle worker interval (minutes). |
| `PAM_ROTATE_MAX_AGE_HOURS` | | `0` (report) | Auto-rotate password credentials older than this. |
| `PAM_REQUIRE_APPROVAL` | | `false` | OT: gate every target behind an approved access request (4-eyes). |
| `PAM_APPROVAL_WINDOW_MIN` | | `60` | How long an approved access request stays valid. |
| `PAM_REQUIRE_TICKET` | | `false` | Require an ITSM change/incident ticket on access requests (Phase 20). |
| `PAM_TICKET_PATTERN` / `PAM_TICKET_VALIDATE_URL` | | | Ticket format regex / ITSM validation webhook (`POST {"ticket":…}` → 2xx = valid). |
| `PAM_APPROVALS_REQUIRED` | | `1` | Default distinct approvers per access request — N-of-M chains (Phase 21). |
| `PAM_REQUIRE_REASON` | | `false` | Reject an access request that carries no reason. |
| `PAM_CHECKOUT_TTL_MIN` | | `30` | Credential checkout lease lifetime (minutes). |
| `PAM_OT_AIRGAP` | | `false` | Disable all outbound calls (alert webhooks) for air-gapped sites. |
| `PAM_REVEAL_DISABLED` | | `false` | Make `reveal` break-glass-only (also forces the broker's `reveal_credential` closed). |
| `PAM_BROKER_POLICY_FILE` | | (off) | YAML policy file — **its presence enables the AI-agent access broker** (Phase 13). |
| `PAM_BROKER_AUDIT_KEY` | broker only | — | base64 32-byte HMAC key for the verifiable audit chain (required once the broker is on). |
| `PAM_BROKER_AUDIT_SIGN_SEED` | broker only | — | base64 32-byte ed25519 seed signing the audit-chain head (truncation detection). |
| `PAM_BROKER_TOKEN_TTL_MIN` | | `15` | Lifetime of the single-use approval resume token (minutes). |
| `PAM_BROKER_RATE_PER_MIN` | | `0` (off) | Per-agent tool-call rate limit. |
| `PAM_BROKER_MAX_ARG_BYTES` | | `16384` | Cap on a tool call's serialized arguments (0 = off). |
| `PAM_BROKER_TRUST_DOMAIN` / `_TRUST_DOMAIN_JWKS` / `_AUDIENCE` | SVID only | — | SPIFFE JWT-SVID verification: trust-domain host, file JWKS, and required audience. |
| `PAM_BROKER_MAX_DELEGATION_DEPTH` | | `1` | RFC 8693 `act`-chain delegation depth cap. |

The examples below use `-H "X-API-Key: $PAM_API_KEY"`; in production call the
HTTPS endpoint of your ingress instead of `http://localhost:8080`.

### 4.1 Runtime configuration console (Phase 12)

The **identity, SSO, and operational-policy** settings (the `PAM_LDAP_*`,
`PAM_ENTRA_*`, `PAM_OIDC_*`, `PAM_MFA_REQUIRED`, `PAM_REQUIRE_APPROVAL`,
`PAM_REVEAL_DISABLED`, `PAM_ALLOWED_PROTOCOLS`, … keys) can also be set from the
console at runtime and are persisted in the database, overriding the environment.
Secret values (bind password, client secrets) are **vault-encrypted at rest** and
never returned in plaintext. **Bootstrap and transport settings** — database URL,
master key/KEK, listen addresses, TLS, the SSH proxy — stay environment-only and
require a restart; they are deliberately *not* overridable.

- **Menu 13 — System configuration**: list every overridable key, set an override
  (`PUT /api/config`), or clear one back to the env default (`DELETE /api/config/{key}`).
  Changes **hot-swap without a restart**: the identity backends and policy are
  rebuilt atomically on save. A rejected change (e.g. an unreachable directory) is
  rolled back so it can't also break the next restart.
- **Menu 14 — Effective config & backend health**: a read-only view of which
  backends are wired (`GET /api/config/effective`), plus a one-key **IaC export**
  (`GET /api/config/iac?format=env|helm|terraform`, function keys F6/F7/F8) that
  renders your console-set overrides back into env / Helm values / Terraform locals
  so they can be committed to the IaC that owns the deployment. Secrets export as
  secret-store placeholders, never plaintext.

These endpoints require the `manage_users` capability (admin, or a custom profile
that includes it).

---

## 5. Managing targets

```bash
# Create a target
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/targets \
  -d '{"name":"web-01","host":"10.0.0.5","port":22,"os_type":"linux","protocol":"ssh"}'

# List / inspect / delete
curl -H "X-API-Key: $PAM_API_KEY" http://localhost:8080/api/targets
curl -H "X-API-Key: $PAM_API_KEY" http://localhost:8080/api/targets/1
curl -H "X-API-Key: $PAM_API_KEY" -X DELETE http://localhost:8080/api/targets/1   # cascades to its credentials
```

`os_type` ∈ `linux|windows`; `protocol` ∈ `ssh|winrm|rdp`.

**Per-target access grants** restrict who may connect. A target with no grants is
open to any connect-capable user; add grants to lock it down (admins always have
access):

```bash
# Only members of the "user" role, plus alice specifically, may connect to target 1
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/targets/1/grants -d '{"subject_type":"role","subject":"user"}'
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/targets/1/grants -d '{"subject_type":"user","subject":"alice"}'
curl -H "X-API-Key: $PAM_API_KEY" http://localhost:8080/api/targets/1/grants          # list
curl -H "X-API-Key: $PAM_API_KEY" -X DELETE http://localhost:8080/api/targets/1/grants/2
```

Grants are enforced by the SSH proxy, WinRM and RDP alike. To force every access
through the recorded proxy, set `PAM_REVEAL_DISABLED=true` so credential reveal
becomes break-glass-only.

## 6. Managing credentials

```bash
# Vault a credential for a target (secret is encrypted before storage)
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/credentials \
  -d '{"target_id":1,"username":"root","secret":"S3cret-P@ss","secret_type":"password"}'

# List (never returns the secret) · reveal (admin only, audited) · delete
curl -H "X-API-Key: $PAM_API_KEY" "http://localhost:8080/api/credentials?target_id=1"
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/credentials/1/reveal
curl -H "X-API-Key: $PAM_API_KEY" -X DELETE http://localhost:8080/api/credentials/1
```

`secret_type` is `password` or `ssh_key` (paste the PEM private key as `secret`).
Once the proxy is your normal path, **`reveal` should be the exception** — prefer
brokered sessions so the secret is never shown.

### Rotation & reconciliation (credential lifecycle)

pamv1 can change the password **on the target** and re-vault it, so the account's
secret is one only pamv1 knows — and can prove is current. Rotation and
reconciliation run over the same secure protocols as the proxy: SSH (`chpasswd`,
fed on stdin so the new password never hits a shell command line) and WinRM
(`net user`). The rotating account must be able to set its own password (root /
a sudoer on Linux; a suitably privileged account on Windows).

```bash
# Rotate now: generate a strong secret, set it on the target, re-vault it.
# The new secret is NEVER returned — the proxy injects it just-in-time.
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/credentials/1/rotate
# → {"id":1,"target":"web-01","username":"root","rotated":true,"rotated_at":"..."}

# Reconcile one credential: does the vaulted secret still authenticate?
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/credentials/1/reconcile
# → {"credential_id":1,...,"status":"in_sync"}   (or "out_of_sync" on drift)

# Reconcile + heal drift by rotating to a fresh PAM-managed secret
curl -H "X-API-Key: $PAM_API_KEY" -X POST "http://localhost:8080/api/credentials/1/reconcile?remediate=true"

# Read-only drift scan across every credential (safe to run on a schedule)
curl -H "X-API-Key: $PAM_API_KEY" http://localhost:8080/api/reconcile
# → {"checked":12,"out_of_sync":1,"results":[...]}
```

To automate it, enable the background lifecycle worker: it reconciles every
credential on each pass and rotates password credentials older than a max age.

```bash
PAM_ROTATE_INTERVAL_MIN=60       # run hourly
PAM_ROTATE_MAX_AGE_HOURS=168     # rotate secrets older than 7 days (0 = report only)
```

Every action is audited (`credential.rotate`, `credential.reconcile`,
`credential.remediate`; the worker acts as `system-scheduler`). **Password**
credentials rotate over SSH (`chpasswd`) / WinRM (`net user`); **`ssh_key`**
credentials rotate over SSH by generating a fresh keypair and replacing the
account's `authorized_keys` (the old key stops working). AD/LDAPS account
password-change (`unicodePwd`) and identity reconciliation (revoking users the
directory reports as disabled) shipped in Phase 7.

**Checkout / check-in (exclusive lease).** For accounts a person or app must use
the password directly, check it out: you get the secret exclusively for a lease
(`PAM_CHECKOUT_TTL_MIN`, default 30 min), and on check-in the credential is
**rotated** so the password you saw is dead. Only one holder at a time.

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/credentials/1/checkout \
  -d '{"reason":"deploy hotfix"}'
# → {"checkout_id":7,"username":"root","secret":"...","expires_at":"..."}
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/credentials/1/checkin
# → {"returned":true,"rotated":true}          # the seen secret is now invalid
curl -H "X-API-Key: $PAM_API_KEY" "http://localhost:8080/api/checkouts?active=true"
```

**Discovery.** Probe hosts for reachable management ports and optionally onboard
them (reachability only — no credentials are tried):

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/discovery/scan \
  -d '{"hosts":["10.0.0.5","10.0.0.6"],"ports":[22,3389,5986],"create":true}'
# → {"candidates":[{"host":"10.0.0.5","port":22,"protocol":"ssh",...}],"created":[...]}
```

### Zero Standing Privilege: ephemeral SSH certificates (Phase 22)

Instead of storing a password or key for an account, pamv1 can sign a
**short-lived SSH certificate just-in-time** for each session. The account then
has **no standing secret at all** — the target trusts only the pamv1 CA, and each
certificate is minted fresh and expires in minutes (the Teleport / CyberArk ZSP
model). Enable it by giving pamv1 a persistent CA key path:

```bash
PAM_SSH_CA_KEY=/data/pamv1_ssh_ca      # created on first use (0600); keep it persistent
PAM_SSH_CERT_TTL_MIN=2                 # minted certificate validity (default 2 minutes)
```

**1. Install the CA on each target.** Fetch the CA public key and trust it:

```bash
curl -H "X-API-Key: $PAM_API_KEY" http://localhost:8080/api/ca/ssh
# → {"type":"ssh_ca","public_key":"ssh-ed25519 AAAA... pamv1-ca","fingerprint":"SHA256:...","install_hint":"..."}
```

On the target: write `public_key` to `/etc/ssh/pamv1_ca.pub`, add
`TrustedUserCAKeys /etc/ssh/pamv1_ca.pub` to `sshd_config`, and reload sshd.

**2. Create a Zero Standing Privilege credential** — no secret is stored:

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/credentials \
  -d '{"target_id":1,"username":"root","secret_type":"ssh_ca"}'
# note: an ssh_ca credential must NOT carry a secret, and is only valid on ssh targets
```

**3. Connect as usual** — `ssh root@web-01@pam-host`. The proxy mints a
certificate for `root`, valid for a couple of minutes, and authenticates with it;
nothing is ever stored for the account. Each issuance is audited
`session.cert_issued` (serial, principal, validity, key-id — never the key).
Because there is no stored secret, an `ssh_ca` credential is never rotated or
reconciled (reconcile reports it as `unsupported`).

### Windows targets (WinRM)

Create a Windows target (`os_type=windows`, `protocol=winrm`, port `5986` for
HTTPS) with a credential (an AD-joined domain account like `CONTOSO\\svc-admin`
works). Users with the connect capability run commands through pamv1 — the
credential is injected just-in-time and never shown:

```bash
curl -H "X-API-Key: $TOKEN" -X POST http://localhost:8080/api/targets/1/winrm \
  -d '{"command":"whoami; hostname"}'
# → {"target":"win-01","exit_code":0,"stdout":"contoso\\svc-admin\r\n...","stderr":""}
```

Every run is recorded (a `.winrm.log` transcript with its SHA-256 in the audit as
`winrm.run`). WinRM uses HTTPS by default (`PAM_WINRM_HTTPS`); only set
`PAM_WINRM_INSECURE_SKIP_VERIFY=true` in isolated dev. Most AD-joined hosts
disable basic auth — set `PAM_WINRM_AUTH=ntlm` for NTLMv2.

### RDP (via Apache Guacamole)

pamv1 brokers RDP through [Apache Guacamole](https://guacamole.apache.org/)'s
`guacd` daemon so the operator sees the desktop but never the password. Run guacd
(e.g. the `guacamole/guacd` container) reachable from pam-server and set:

```bash
PAM_GUACD_ADDR=127.0.0.1:4822
```

By default guacd **verifies the RDP server certificate** and negotiates the
security mode. For self-signed or legacy hosts, opt out or pin the mode:

```bash
PAM_GUACD_RDP_SECURITY=nla     # force a mode (nla|tls|rdp); empty = negotiate
PAM_GUACD_IGNORE_CERT=true     # dev only — skip RDP server-cert verification
```

Create the target with `protocol=rdp`, port `3389`, and a credential. The
WebSocket endpoint `GET /api/targets/{id}/rdp?token=<session-token>` decrypts the
credential just-in-time, injects it into the guacd handshake, and tunnels the
Guacamole protocol to the browser (`rdp.connect` / `rdp.end` in the audit). The
in-browser display uses the [guacamole-common-js](https://guacamole.apache.org/doc/gug/writing-you-own-guacamole-app.html)
client — bundling that viewer into the portal is the remaining step; the tunnel
itself is usable by any Guacamole-compatible client today.

### Database targets (PostgreSQL)

The database session proxy (Phase 15) extends the same JIT chokepoint to
**PostgreSQL**: an operator connects with `psql` and their PAM key, the proxy
injects the vaulted database credential, and **every SQL statement is audited**
(`db.query`) and recorded. The operator never sees the database password. Enable
the listener:

```bash
PAM_DB_ADDR=:5433     # off by default
```

Create a `postgres` target and a credential for the database login:

```bash
curl -sX POST https://pam.example/api/targets -H "X-API-Key: $PAM_API_KEY" \
  -d '{"name":"appdb","host":"10.0.0.20","port":5432,"os_type":"linux","protocol":"postgres"}'
# then POST /api/targets/{id}/credentials with the DB username + password
```

Operators then connect through the proxy — the username selects the credential
and target, the password is their PAM key (or per-user token):

```bash
psql "host=pam.example port=5433 user=dbuser@appdb dbname=orders"
# Password: <your PAM key>
```

The proxy runs the same authorization gates as the SSH proxy (role capability,
per-target grants, protocol allowlist, and the 4-eyes/approval gate), then
authenticates upstream with the vaulted secret — supporting **SCRAM-SHA-256**
(PostgreSQL 14+ default), MD5, and cleartext, and best-effort upstream TLS. Set
`PAM_TLS_CERT`/`PAM_TLS_KEY` to also encrypt the operator-facing leg; otherwise
terminate TLS at the ingress (the PAM key would otherwise travel in cleartext).
Sessions appear in *Work with active sessions* (protocol `postgres`) and can be
killed like any other. MySQL/MSSQL/Oracle are follow-on connectors on the same
pattern.

## 7. Managing users & roles

Only `admin` may manage users. Creating a user returns the access token **once** —
store it immediately; it cannot be retrieved again (only its hash is kept).

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/users \
  -d '{"username":"alice","role":"user"}'
# → {"id":1,"username":"alice","role":"user","token":"pamt_…"}

curl -H "X-API-Key: $PAM_API_KEY" http://localhost:8080/api/users          # list (no tokens)
curl -H "X-API-Key: $PAM_API_KEY" -X DELETE http://localhost:8080/api/users/1
```

### Roles at a glance

| Role | Manage targets/creds/users | Reveal secret | Connect via proxy | Read audit | Approve requests* |
|---|:--:|:--:|:--:|:--:|:--:|
| `admin` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `user` | — | — | ✅ | — | — |
| `auditor` | — | — | — | ✅ | — |
| `approver` | — | — | — | ✅ | ✅ |

`*` the `approver` role wields the 4-eyes access-request approval workflow (shipped in Phase 8).

Give the user their token; they use it in the portal Sign On or as the SSH proxy
password (see the [User Guide](USER-GUIDE.md)).

### Custom permission profiles (Phase 12)

Beyond the four built-in roles you can define **named capability sets** and assign
them to users exactly like a role. Manage them under **menu 12 — Work with
permission profiles** (or `POST/GET /api/profiles`, `DELETE /api/profiles/{id}`;
`manage_users`). A profile is a name plus any subset of the capability vocabulary
— `read_inventory`, `manage_targets`, `manage_credentials`, `reveal_secret`,
`connect`, `read_audit`, `manage_users`, `approve`, `call_tool`. A profile name may
not collide with a built-in role. When adding a user, the role/profile picker lists
the built-in roles followed by your custom profiles; the built-in roles are
unchanged, so existing users are unaffected.

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/profiles \
  -d '{"name":"ops-readonly","capabilities":["read_inventory","read_audit"]}'
# then assign it:
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/users \
  -d '{"username":"dana","role":"ops-readonly"}'
```

### Safes: delegated-access containers (Phase 17)

A **safe** groups targets and delegates who may reach them — the container model
CyberArk builds its authorization around. A member of a safe may connect to
**every target in the safe**, an authorization path alongside per-target grants;
a `can_manage` member is a **delegated safe administrator** who can add/remove
members of that safe without being a global target manager.

```bash
# create a safe, add a role member, and place a target in it
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/safes \
  -d '{"name":"prod-linux","description":"production Linux estate"}'      # → {"id":1,...}
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/safes/1/members \
  -d '{"subject_type":"role","subject":"user","can_manage":false}'
curl -H "X-API-Key: $PAM_API_KEY" -X PUT http://localhost:8080/api/targets/7/safe \
  -d '{"safe_id":1}'      # target 7 is now reachable only by safe members
```

Placing a target in a safe **restricts** it to the safe's members (plus any
direct grants) — an empty safe leaves its targets open. Clear a target's safe
with `{"safe_id":null}`. Delegate ownership by adding a `can_manage` member; they
can then manage that safe's membership (`POST`/`DELETE /api/safes/{id}/members`)
even as a non-admin.

### Dependent accounts: safe service-account rotation (Phase 17)

When a service account's password rotates, the **Windows Services, Scheduled
Tasks and IIS App Pools** that log on with it must be updated too — otherwise
rotation breaks production. Declare those consumers and pamv1 updates each over
WinRM after the rotation:

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/credentials/3/dependencies \
  -d '{"kind":"windows_service","host":"app-01","name":"MyAppSvc"}'
# kinds: windows_service | scheduled_task | iis_apppool ; port defaults to 5985 (WinRM)
```

On the next rotation of credential 3, pamv1 sets the new password on the target,
re-vaults it, then runs the appropriate WinRM command on each consumer's host
(`sc.exe config` / `schtasks /Change /RP` / `appcmd …processModel.password`) with
the new secret. A propagation failure is audited (`credential.dependency_failed`)
but does **not** fail the rotation — the new secret is already vaulted, so the
fix is to update the stale consumer, not to roll back. *(The propagation
currently connects as the rotated account; a per-consumer management credential
is a documented follow-on.)*

### Active Directory login (optional)

Instead of (or alongside) local tokens, users can sign in with their **AD
username + password**. Set `PAM_LDAP_URL` (use **LDAPS**) and map AD groups to
the four roles:

```bash
PAM_LDAP_URL=ldaps://dc.example.com:636
PAM_LDAP_BIND_DN=CN=svc-pam,OU=Service,DC=example,DC=com
PAM_LDAP_BIND_PASSWORD=…            # service account for user search
PAM_LDAP_BASE_DN=DC=example,DC=com
PAM_LDAP_USER_FILTER=(sAMAccountName=%s)
PAM_LDAP_GROUP_ADMIN=CN=PAM-Admins,OU=Groups,DC=example,DC=com
PAM_LDAP_GROUP_USER=CN=PAM-Users,OU=Groups,DC=example,DC=com
PAM_LDAP_GROUP_AUDITOR=CN=PAM-Auditors,OU=Groups,DC=example,DC=com
PAM_LDAP_GROUP_APPROVER=CN=PAM-Approvers,OU=Groups,DC=example,DC=com
```

How it works: pam-server binds the service account, finds the user, verifies the
password by binding as them, and derives roles from group membership. A user in
several mapped groups keeps **all** of them and is granted the **union** of their
capabilities (not just the single highest role) — e.g. someone in both PAM-Users
and PAM-Auditors can connect *and* read the audit trail. `POST /api/login` then
returns a **session token** (12h) that works in the portal and the SSH proxy
exactly like a per-user token. A user in no mapped group is rejected. Keep the bootstrap `PAM_API_KEY` and break-glass key as
the local emergency path if AD is unreachable.

**Identity reconciliation.** With LDAP configured, revoke pamv1 access for users
the directory has **disabled** (AD `userAccountControl`), and surface local-only
accounts:

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST "http://localhost:8080/api/identity/reconcile?dry_run=true"
# → {"checked":12,"disabled":1,"dry_run":true,"results":[{"username":"bob","status":"disabled"},…]}
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/identity/reconcile   # actually revoke
```

Disabled directory users are deleted (`user.revoked`); users absent from the
directory are reported `not_in_directory` but **never auto-revoked** (they may be
local service accounts). A directory error never revokes.

### Microsoft Entra ID (Azure AD) login (optional)

For cloud identities, enable Entra ID login alongside or instead of on-prem AD.
pamv1 uses the OAuth2 **resource-owner-password** grant against your tenant and
reads the user's **app roles** (or group ids) from the token to derive roles —
several matched app-roles/groups grant the **union** of their capabilities, the
same as on-prem AD.

```bash
PAM_ENTRA_TENANT_ID=<tenant-guid>
PAM_ENTRA_CLIENT_ID=<app-registration-client-id>
PAM_ENTRA_CLIENT_SECRET=<client-secret>
# PAM_ENTRA_SCOPE defaults to "<client-id>/.default"
# PAM_ENTRA_AUTHORITY_HOST=login.microsoftonline.com   # sovereign clouds differ
PAM_ENTRA_ROLE_ADMIN=pam.admin      # app role value (or a group object id)
PAM_ENTRA_ROLE_USER=pam.user
PAM_ENTRA_ROLE_AUDITOR=pam.auditor
PAM_ENTRA_ROLE_APPROVER=pam.approver
```

Setup in Azure: create an **app registration**, define **app roles** (e.g.
`pam.admin`) and assign users/groups to them, add a **client secret**, and enable
the ROPC (password) grant for the app. If both LDAP and Entra are configured,
pamv1 tries each (chain). **Caveats:** ROPC does not trigger Entra Conditional
Access or IdP-side MFA — layer pamv1's own TOTP MFA on top; the OIDC auth-code
flow is the production-recommended upgrade (roadmap). Always use HTTPS.

### OIDC single sign-on (recommended for Entra)

The **Authorization Code + PKCE** flow is the production-grade alternative to
ROPC: the user authenticates *at the IdP* (so its MFA and Conditional Access
apply) and pamv1 validates the returned ID token's **RS256 signature** against
the IdP's JWKS. Enable it:

```bash
PAM_OIDC_ISSUER=https://login.microsoftonline.com/<tenant>/v2.0
PAM_OIDC_CLIENT_ID=<app-client-id>
PAM_OIDC_CLIENT_SECRET=<client-secret>
PAM_OIDC_REDIRECT_URL=https://pam.example.com/api/auth/oidc/callback
PAM_OIDC_ROLE_ADMIN=pam.admin   # app role value / group id -> role
PAM_OIDC_ROLE_USER=pam.user
```

Register `PAM_OIDC_REDIRECT_URL` as a redirect URI in the app registration. The
authorize/token/JWKS endpoints are auto-discovered from the issuer. Users click
**Single sign-on** on the portal (or hit `/api/auth/oidc/start`); after the IdP,
the callback issues a pamv1 session and returns to the portal. Note: pamv1's own
TOTP is not layered on OIDC (the IdP owns MFA there). The OIDC login state is
held in a shared store (Phase 10), so the callback can land on any replica in HA.

### Multi-factor authentication (TOTP)

Users can add a second factor ([TOTP](https://en.wikipedia.org/wiki/Time-based_one-time_password),
RFC 6238) that works with Google Authenticator, Microsoft Authenticator, 1Password,
etc. It is **self-service and per-user opt-in**, and applies to the password-login
path. Once enrolled, `POST /api/login` requires the 6-digit code.

```bash
# 1. Enroll (as the signed-in user): returns the secret + otpauth URI, once
curl -H "X-API-Key: $TOKEN" -X POST http://localhost:8080/api/mfa/enroll
# → {"secret":"…","otpauth_uri":"otpauth://totp/pamv1:alice?…"}
#    add the otpauth URI / secret to your authenticator app

# 2. Confirm with a code from the app
curl -H "X-API-Key: $TOKEN" -X POST http://localhost:8080/api/mfa/verify -d '{"otp":"123456"}'

# status / disable
curl -H "X-API-Key: $TOKEN" http://localhost:8080/api/mfa
curl -H "X-API-Key: $TOKEN" -X DELETE http://localhost:8080/api/mfa
```

The TOTP secret is stored **vault-encrypted** and returned only once at enrollment.
The portal Sign On has an *MFA code* field for enrolled users. MFA covers NIS2
Art. 21(2)(j).

**Recovery codes:** `POST /api/mfa/recovery-codes` (as an MFA-enrolled user) issues
10 single-use backup codes, shown once. Enter one in place of your MFA code at
login if you lose your authenticator; each works exactly once.

**Require MFA for everyone:** set `PAM_MFA_REQUIRED=true`. Then a password login by
a user without confirmed MFA returns an **enrollment-only** session — it can *only*
call the `/api/mfa/*` endpoints (everything else, including the SSH proxy, is
refused) until the user enrolls and confirms, then logs in again with a code.

### AI-agent access broker (Phase 13)

The broker extends the "trust the chokepoint, not the agent" model to AI agents:
an agent holds only an identity key, a **policy** decides `allow` / `require_approval`
/ `deny` on each tool call **and its arguments**, approved actions run **server-side
with a just-in-time credential**, and the agent gets back only the result — never
a secret. It is **off** until you point `PAM_BROKER_POLICY_FILE` at a policy file;
the audit key + sign seed are then required (fail-loud). See the [config
reference](#4-configuration-reference) for the full `PAM_BROKER_*` set.

**Enable it:**

```bash
export PAM_BROKER_POLICY_FILE=/etc/pam/broker-policy.yaml
export PAM_BROKER_AUDIT_KEY=$(openssl rand -base64 32)        # HMAC chain key
export PAM_BROKER_AUDIT_SIGN_SEED=$(openssl rand -base64 32)  # ed25519 head signer
# optional: PAM_BROKER_RATE_PER_MIN=60  PAM_BROKER_TOKEN_TTL_MIN=15
```

**Policy** is ordered, **first-match-wins**, and **implicit-deny** (no match =
denied). Conditions match an argument's value exactly (no regex/numeric/OR):

```yaml
rules:
  - id: allow-read-inventory
    tool: list_targets
    effect: allow
  - id: prod-needs-human
    tool: winrm_exec
    when: { args.target: prod-dc-01 }
    effect: require_approval
    approvers: [platform-team]
  - id: never-reveal
    tool: reveal_credential
    effect: deny            # reveal_credential ships default-deny anyway
```

**Mint an agent identity** (admin, `CapManageUsers`); the token is shown once:

```bash
curl -sX POST https://pam.example/v1/agents -H "X-API-Key: $PAM_API_KEY" \
  -d '{"name":"ci-bot","owner":"alice"}'      # → {"id":1,"token":"agt_…"}
```

The agent then calls tools with `Authorization: Bearer agt_…` at `POST /v1/tool-calls`
(or over MCP JSON-RPC at `POST /mcp`). An `allow` executes and returns the result;
a `require_approval` **parks** the call and returns a `call_id` + single-use resume
token. Revoke/list agents with `DELETE /v1/agents/{id}` / `GET /v1/agents`.

**Approve parked calls** (an `approver`, four-eyes — you can't approve your own
agent's call): `GET /v1/approvals`, then `POST /v1/approvals/{call_id}/decision`
with `{"approve":true}`. On approve the broker executes server-side and the agent
collects the result once via its resume token. A call whose agent key was revoked —
or whose SVID expired — since parking is **refused at approval time**, not run.

**Verify the tamper-evident trail:** every tool call is written to a keyed-HMAC
hash chain. `GET /v1/audit/verify` walks it and reports the first broken id (an
edit or mid-history deletion); `GET /v1/audit/head` returns an ed25519-signed
anchor so an auditor can later detect tail truncation. Appends are serialized
across processes by a Postgres advisory lock, so a rolling deploy or HA replica
can't fork the chain.

For SPIFFE JWT-SVID agents and RFC 8693 delegation, set `PAM_BROKER_TRUST_DOMAIN`,
`PAM_BROKER_TRUST_DOMAIN_JWKS`, and `PAM_BROKER_AUDIENCE`; delegation depth is
capped by `PAM_BROKER_MAX_DELEGATION_DEPTH`.

### Application-secrets API (Phase 24, Tier-4)

For a **non-agent application** (a CI job, a legacy service) that just needs to
fetch a secret at startup — not an operator through the proxy, not the AI-agent
tool broker — pamv1 offers a **Conjur-style** delivery path. It is **opt-in** and
**default-deny**: an app retrieves only the specific credentials it has been
explicitly granted.

```bash
PAM_APP_SECRETS_ENABLED=true          # off by default; front it with TLS
```

```bash
# 1. Mint an application identity (CapManageUsers); the token is shown once.
curl -sX POST https://pam.example/v1/apps -H "X-API-Key: $PAM_API_KEY" \
  -d '{"name":"orders-svc","owner":"payments-team"}'   # → {"id":3,"token":"pamt_…"}

# 2. Grant it one credential (needs CapRevealSecret — you can only hand out a
#    secret you could reveal yourself).
curl -sX POST https://pam.example/v1/apps/3/grants -H "X-API-Key: $PAM_API_KEY" \
  -d '{"credential_id":42}'

# 3. The application fetches exactly that secret with its bearer key.
curl -s https://pam.example/v1/app-secrets/42 -H "Authorization: Bearer pamt_…"
# → {"credential_id":42,"target":"appdb","username":"svc","secret_type":"password","secret":"…"}
```

A credential the app was **not** granted returns 403 (`app.secret_denied`); a
disabled/unknown app returns 401; every successful retrieval is audited
`app.secret_retrieved` (never the secret). Revoke an app (`DELETE /v1/apps/{id}`)
or a single grant (`DELETE /v1/apps/{id}/grants/{gid}`); both cascade. This path
delivers **plaintext** to machines, so run it only over HTTPS and grant narrowly.

In the **portal**, this is menu **15** (*Work with application secrets*): mint or
revoke applications (the bearer token is shown once), and option **5** on an app
opens *Work with secret grants* to grant or revoke individual credentials.

---

## 8. Break-glass procedure

For emergencies when the normal admin path is unavailable.

1. **Prepare** (before you need it):
   ```bash
   openssl rand -base64 30                      # the emergency key
   echo -n "<that-key>" | ./pam-server -hashkey  # → PAM_BREAK_GLASS_KEY_HASH
   ```
   Configure only the hash. Seal the plaintext key in an envelope / physical safe
   (dual control recommended).
2. **Use** in an emergency: present the sealed key as `X-API-Key` (or SSH proxy
   password). It grants `admin` immediately.
3. **It is loud:** every break-glass request is logged (`WARN BREAK-GLASS access`)
   and written to the audit trail as actor `break-glass` (blinking red in the
   portal's audit screen).
4. **After the incident:** rotate the emergency key (new hash), rotate any
   revealed credentials, and review the audit trail.

### Break-glass v2: M-of-N quorum unseal

Instead of a single sealed key, split it among **custodians** so no one person
can invoke break-glass alone. Split the key offline (the server never sees the
shares):

```bash
echo -n "<emergency-key>" | PAM_BREAK_GLASS_SHARES=5 PAM_BREAK_GLASS_THRESHOLD=3 ./pam-server -split-key
# → 5 hex shares; any 3 reconstruct the key. Give one to each custodian.
```

Configure the server with the key's hash and the threshold:
`PAM_BREAK_GLASS_KEY_HASH=<hash>`, `PAM_BREAK_GLASS_THRESHOLD=3`. In an emergency,
custodians each POST their share:

```bash
curl -X POST https://PAM_HOST/api/breakglass/unseal -d '{"share":"<hex-share>"}'
# → {"collected":1,"needed":3} … until the 3rd:
# → {"token":"pamt_…","role":"admin","expires_at":"…"}
```

The reconstructed key is verified against the configured hash; a valid quorum
yields a **short-lived admin session** (`PAM_BREAK_GLASS_TTL_MIN`, default 15 min)
that auto-expires. Every unseal and every subsequent break-glass request is
audited (`breakglass.unseal` / `breakglass.access`) and, if `PAM_ALERT_WEBHOOK`
is set, **alerted in real time**. Keep custodians and their shares under dual
control, and run periodic drills.

### Rotating the vault key

To rotate the local master key (re-encrypt every secret under a new key), run the
maintenance command **offline** (nothing else writing secrets):

```bash
export PAM_MASTER_KEY=<current-key>
export PAM_NEW_MASTER_KEY=$(./pam-server -genkey)
export PAM_DATABASE_URL=postgres://…
./pam-server -rotate-kek   # → "rotated N secrets; set PAM_MASTER_KEY to the new key and restart"
```

Then set `PAM_MASTER_KEY` to the new key and restart. With a KMS-backed KEK
(`vault-transit`), rotate the key inside the KMS instead.

### On-prem HSM (PKCS#11 KEK)

For a hardware security module, the AES wrapping key lives *inside* the HSM and
data keys are wrapped/unwrapped there — the KEK never leaves the token. This
provider needs cgo and the vendor PKCS#11 module, so it is **not** in the default
static image; build with the tag (`go build -tags pkcs11`) or use
`Dockerfile.pkcs11`. Example with [SoftHSM2](https://www.opendnssec.org/softhsm/)
(swap in your vendor module for a real HSM):

```bash
softhsm2-util --init-token --free --label pamv1 --pin 1234 --so-pin 5678
# create an AES-256 wrapping key labelled pamv1-kek (pkcs11-tool, or your HSM's tooling)

export PAM_KEK_PROVIDER=pkcs11
export PAM_KEK_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export PAM_KEK_PKCS11_PIN=1234
export PAM_KEK_PKCS11_KEY_LABEL=pamv1-kek
export PAM_KEK_PKCS11_TOKEN_LABEL=pamv1
```

Mount the vendor module read-only into the container. Integrity of the vault token
is still provided by the inner AES-256-GCM layer, so the HSM only handles the
confidentiality of the data keys.

---

## 9. Logs & audit

pamv1 produces **two** independent streams — keep them both:

### 9.1 Operational logs (stdout)

Structured [slog](https://pkg.go.dev/log/slog) lines, one per event, tagged with
`service=` so you can filter per component. Set `PAM_LOG_FORMAT=json` (default)
for a SIEM, or `text` for humans; set verbosity with `PAM_LOG_LEVEL`.

| `service` | Emits |
|---|---|
| `server` | Startup, listening addresses, shutdown |
| `api` | One line per HTTP request (method, path, status, actor, duration), auth failures, `authz` denials, audit mirror |
| `proxy` | Connection authenticated, session started/ended, denials, upstream errors |
| `store` | Postgres connect; per-query trace at `debug` (SQL + duration + rows, **never** arguments) |

Example (JSON):

```json
{"time":"…","level":"WARN","service":"api","msg":"authorization denied","actor":"bob","role":"auditor","method":"POST","path":"/api/targets"}
{"time":"…","level":"INFO","service":"proxy","msg":"session started","actor":"alice","target":"web-01","cred_user":"root"}
```

Collect them where the platform puts stdout: `docker compose logs pam`,
`kubectl -n pamv1 logs deploy/pam-server`, or your log shipper. **PostgreSQL** logs
connections/disconnections in its own container (`docker compose logs db`).

Secrets are never logged: the vault does not log secret operations, and the store
query tracer logs SQL text only, never argument values.

### 9.2 Audit trail (database)

The security record of *who did what*. Read it via the API or the portal's
**Display Audit Trail** screen:

```bash
curl -H "X-API-Key: $PAM_API_KEY" "http://localhost:8080/api/audit?limit=100"
```

Actions include: `target.create/delete`, `credential.create/reveal/delete/rotate/reconcile`,
`user.create/delete`, `access.request/approve/deny/denied`, `authz.denied`,
`breakglass.access/unseal`, `session.start/record/end/denied/error`. The actor is
the real username (or `bootstrap-admin` / `break-glass` / `system-scheduler`).

**Incident-report export (NIS2 Art. 23).** Produce a scoped, tamper-evident slice
of the audit trail for a regulator. The response carries a SHA-256 over the exact
event list (JSON `sha256` field + `X-PAM-Export-SHA256` header) so the file's
integrity can be re-verified later.

```bash
# JSON, a time window, with the integrity digest
curl -H "X-API-Key: $PAM_API_KEY" \
  "http://localhost:8080/api/audit/export?since=2026-07-19T00:00:00Z&until=2026-07-19T06:00:00Z"
# Scope to an actor/action; CSV for a spreadsheet
curl -H "X-API-Key: $PAM_API_KEY" \
  "http://localhost:8080/api/audit/export?actor=break-glass&format=csv" -o breakglass.csv
```

See the [NIS2 Compliance Pack](NIS2-COMPLIANCE.md) for the full Art. 21 control
matrix and the Art. 23 reporting workflow.

### 9.3 Session recordings

Each proxied session is recorded in [asciicast v2](https://docs.asciinema.org/manual/asciicast/v2/)
under `PAM_RECORDING_DIR`, and its SHA-256 is written to the audit trail (tamper
evidence). Replay with [asciinema](https://asciinema.org/): `asciinema play <file>.cast`.

### 9.4 Supervising live sessions & command control (Phase 16)

Beyond after-the-fact recordings, a supervisor can **watch a session as it
happens** and policy can **block a dangerous command mid-stream**.

**Live monitoring.** `GET /api/sessions/{id}/stream` streams a live session's
output as [Server-Sent Events](https://developer.mozilla.org/docs/Web/API/Server-sent_events)
(requires `CapReadAudit`; the watch is audited `session.monitor`). List the live
sessions first to get an id, then follow one:

```bash
curl -s https://pam.example/api/sessions -H "X-API-Key: $PAM_API_KEY"
curl -N https://pam.example/api/sessions/<id>/stream -H "X-API-Key: $PAM_API_KEY"
```

It works for SSH and PostgreSQL sessions; delivery is non-blocking (a slow
watcher drops frames and never stalls the session being observed).

**Command control.** Point `PAM_COMMAND_DENY_FILE` at a file of regular
expressions (one per line, `#` comments). A command matching any pattern is
**refused before it reaches the target** and audited `command.blocked`:

```
# /data/command-deny.txt — deny destructive commands
rm\s+-rf\s+/
(?i)drop\s+(table|database)
(?i)truncate\s+table
:\s*\(\s*\)\s*\{         # shell fork bomb
```

Enforcement covers the paths where a discrete command is visible: SSH `exec`
(`ssh target "cmd"` — the request is refused, never forwarded), each interactive
**WinRM** command-loop line, and each **PostgreSQL** statement (a simple query is
refused but the session stays usable; an extended/prepared statement fails
closed). Interactive SSH **shells** stream a raw terminal and are *not* parsed —
use read-only observer sessions (`ssh <cred>@<target>+observe@pam`) or restrict
shell access where you need that guarantee.

### 9.5 Metrics & probes

- `GET /metrics` — a Prometheus exposition: `pam_http_requests_total{status}`,
  `pam_audit_events_total`, `pam_breakglass_access_total`,
  `pam_auth_failures_total`, `pam_credential_rotations_total`, and the
  `pam_active_sessions` gauge. It is **unauthenticated** (like `/healthz`) and
  exposes only low-sensitivity counts — restrict it at the ingress/network. The
  Helm chart can render a `ServiceMonitor` (`metrics.serviceMonitor.enabled`).
- `GET /healthz` — liveness (process up). `GET /readyz` — readiness (returns 503
  until the database is reachable); point your load balancer at `/readyz`.
- `pam-server -healthcheck` probes `/healthz` on `PAM_LISTEN_ADDR` and exits
  non-zero when unhealthy. The container images use it as their `HEALTHCHECK`
  because the distroless base has no shell or curl.

### 9.6 Access certification campaigns (Phase 19)

A **certification campaign** is the periodic "recertify or revoke who has access
to what" review that SOX / ISO 27001 / NIS2 Art. 21(2) expect. Creating a
campaign **snapshots the current access grants** — every target grant and every
safe member — into reviewable items; you then certify (keep) or revoke each, and
a **revoke actually removes the underlying grant**.

```bash
# create a campaign (CapManageUsers) — snapshots current access
curl -sX POST https://pam.example/api/campaigns -H "X-API-Key: $PAM_API_KEY" \
  -d '{"name":"Q3 access review"}'      # → {"campaign":{"id":1,...},"items":N}

# review the items, then decide each one
curl -s https://pam.example/api/campaigns/1 -H "X-API-Key: $PAM_API_KEY"
curl -sX POST https://pam.example/api/campaigns/1/items/7/decision \
  -H "X-API-Key: $PAM_API_KEY" -d '{"decision":"revoke"}'   # deletes that grant
curl -sX POST https://pam.example/api/campaigns/1/items/8/decision \
  -H "X-API-Key: $PAM_API_KEY" -d '{"decision":"certify"}'  # attests, keeps it

# close the campaign — the attestation record; further decisions are refused
curl -sX POST https://pam.example/api/campaigns/1/close -H "X-API-Key: $PAM_API_KEY"
```

Management (create / decide / close) requires `CapManageUsers`; **reading** a
campaign and its items requires `CapReadAudit`, so an **auditor** can review the
attestation evidence without being able to change access. Every decision is
audited (`certification.item_certified` / `certification.item_revoked`), and the
campaign itself is the point-in-time record for your evidence file.

### 9.7 Privileged threat analytics (Phase 23)

pamv1 scores the audit trail into **behavioral risk** per actor, so a supervisor
can see who is behaving abnormally — and optionally respond automatically. The
scoring is deliberately **explainable**: every point traces to a named signal
(break-glass use, blocked commands, authentication-failure bursts, off-hours
activity, credential-decryption failures, session velocity), not an opaque model.

```bash
# Highest-risk actors over the last hour (CapReadAudit — an auditor may read it)
curl -s https://pam.example/api/analytics/risk -H "X-API-Key: $PAM_API_KEY"
# → {"window_minutes":60,"scored_events":420,"findings":[
#      {"actor":"mallory","score":100,"level":"critical",
#       "signals":[{"name":"break_glass","count":2,"points":100}],"events":5,...}]}

# Only high-and-above, over a 24h window
curl -s "https://pam.example/api/analytics/risk?min_level=high&window_min=1440" \
  -H "X-API-Key: $PAM_API_KEY"
```

To run it continuously, enable the background worker. Each pass scores the window
and, for a **newly elevated** high/critical actor, appends an
`analytics.risk_flagged` audit event and fires your alert channel
(`PAM_ALERT_WEBHOOK` / syslog / email). With auto-kill on, a **critical** actor's
live sessions are terminated (`analytics.auto_response`):

```bash
PAM_ANALYTICS_INTERVAL_MIN=5      # score every 5 minutes (0 = worker off, endpoint stays on)
PAM_ANALYTICS_WINDOW_MIN=60       # how far back each pass looks
PAM_ANALYTICS_AUTO_KILL=true      # cut off a critical-risk actor's live sessions
PAM_ANALYTICS_BUSINESS_START=7    # business hours for the off-hours signal…
PAM_ANALYTICS_BUSINESS_END=20     # …outside 07:00–20:00 or on a weekend counts as off-hours
PAM_ANALYTICS_TIMEZONE=America/New_York   # interpret business hours in this zone (empty = UTC)
```

Audit timestamps are stored in **UTC**, so set `PAM_ANALYTICS_TIMEZONE` (an IANA
name) if your business hours are local — otherwise the off-hours window is
evaluated in UTC. A high-risk actor is not re-alerted every pass, but a sustained
or recurring incident **is** re-alerted (and, if critical, re-killed) once per
`PAM_ANALYTICS_WINDOW_MIN`, so a repeat incident is never silently suppressed. The
read endpoint's `?window_min=` is capped (at 7 days) so a single request can't be
made to score the entire audit history. Leave auto-kill off until you trust the
scores in your environment.

---

## 10. Security & hardening notes

- **Secure protocols only.** Front the portal/API with **HTTPS**; use `sslmode=verify-full`
  to Postgres; prefer **LDAPS** for AD. Plain HTTP/LDAP only in isolated dev.
- **Vault key management (envelope encryption).** Secrets are sealed with per-secret
  data keys that are wrapped by a Key Encryption Key (KEK). In **production use a
  KMS-backed KEK** (`PAM_KEK_PROVIDER=vault-transit`, [HashiCorp Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit))
  so the root key never leaves the KMS. The `local` KEK (`PAM_MASTER_KEY`, base64
  in an env var) is **for development and tests only**.
- **Protect `PAM_MASTER_KEY`** (local KEK). It wraps the entire vault. Back it up out-of-band; a DB dump without it is useless (that's the point). With a KMS KEK there is no local key to protect.
- **Rotate** the bootstrap `PAM_API_KEY` and any per-user tokens periodically; delete users who no longer need access.
- **Least privilege on the network:** see the [ports & flow matrix](PORTS-AND-FLOWS.md) for the firewall/NetworkPolicy baseline. The database must be unreachable from operator and target zones.
- **Upgrades that cross the vault format are breaking (pre-1.0).** The current token format is `v2:` with a per-credential AAD; there is no in-place migration from earlier ciphertext (older AAD, or the pre-GCM PKCS#11 wrap). A deployment that carries vaulted secrets across such a change must re-enter its credentials. Fresh installs are unaffected.
- Transport/data hardening — native HTTPS, security headers, per-IP rate limiting, versioned migrations, and vault key rotation — shipped in [Phase 5](../ROADMAP.md#phase-5--hardening-database-vault-transport-); enforce `sslmode=verify-full` to Postgres at deploy time.

## 11. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `401 invalid or missing API key` | Wrong/expired key or token; check `X-API-Key`. |
| `403 your role does not permit this action` | The identity's role lacks the capability — expected for non-admins. |
| Proxy: `your role may not open sessions` | The token belongs to an `auditor`/`approver`; only `admin`/`user` can connect. |
| Proxy: `upstream connection failed` | Target host/port wrong or unreachable, or the vaulted credential is invalid. |
| `PAM_MASTER_KEY is required` at startup | Env var unset — generate with `-genkey`. |
| Portal shows empty panels for a non-admin | Expected: panels the role can't read stay empty (403s are tolerated). |

---

## 12. Change log

| Date | Change |
|---|---|
| 2026-07-21 | Phase 24: **application-secrets API** (Tier-4) — a Conjur-style path (`PAM_APP_SECRETS_ENABLED`) where a non-agent app retrieves the secrets it was explicitly granted with a bearer key (`GET /v1/app-secrets/{credential_id}`); default-deny, granting needs `reveal_secret`, every retrieval audited. See §7. The portal is now **keyboard-first** (mouse optional): focus lands on each screen's field, Esc goes back, ↑/↓ move subfile rows. |
| 2026-07-21 | Phase 23: **privileged threat analytics** — explainable behavioral risk scoring over the audit trail (`GET /api/analytics/risk`, `CapReadAudit`); a background worker (`PAM_ANALYTICS_INTERVAL_MIN`) alerts on newly elevated high/critical actors and, with `PAM_ANALYTICS_AUTO_KILL`, terminates a critical actor's live sessions. See §9.7 |
| 2026-07-21 | Phase 22: **Zero Standing Privilege** — an `ssh_ca` credential stores no secret; the proxy mints a short-lived SSH certificate just-in-time per session (`PAM_SSH_CA_KEY`, `PAM_SSH_CERT_TTL_MIN`). Install the CA on targets from `GET /api/ca/ssh`. See §6 → *Zero Standing Privilege* |
| 2026-07-21 | Phase 21: **richer approval workflows** — multi-tier N-of-M approval chains (`PAM_APPROVALS_REQUIRED`, or per-request `approvals`), scheduled maintenance windows (`not_before`/`not_after` on a request), and mandatory reason codes (`PAM_REQUIRE_REASON`) |
| 2026-07-21 | Phase 20: **ITSM / ticketing gate** — an access request can require a change/incident ticket (`PAM_REQUIRE_TICKET`), validated by a format regex (`PAM_TICKET_PATTERN`) and/or an ITSM webhook (`PAM_TICKET_VALIDATE_URL`); the ticket is recorded in the audit trail |
| 2026-07-21 | Phase 19: **access certification campaigns** — `POST /api/campaigns` snapshots current access (target grants + safe members); certify/revoke each item (`revoke` deletes the grant); close to record the attestation. Management `CapManageUsers`, reading `CapReadAudit`. See §9.6 |
| 2026-07-21 | Phase 18: **Conjur secret sourcing** — an alternative to SOPS: set `PAM_CONJUR_URL` and pam-server fetches its own bootstrap secrets from CyberArk Conjur at startup (authn-api-key or Kubernetes authn-jwt). Both ship; SOPS stays the default. See [deploy/k8s/conjur/README.md](../deploy/k8s/conjur/README.md) |
| 2026-07-21 | Phase 17: **safes + dependent-account propagation** — group targets into delegated-access safes (`/api/safes`, a member reaches every target in the safe; `can_manage` delegated administration) and declare a credential's consumers (`/api/credentials/{id}/dependencies`) so rotation updates the Windows Services / Scheduled Tasks / IIS App Pools that use it. See §7 → *Safes* and *Dependent accounts* |
| 2026-07-21 | Phase 16: **live session monitoring + command control** — watch an SSH/PostgreSQL session live over `GET /api/sessions/{id}/stream` (SSE, `CapReadAudit`); block dangerous commands on exec/WinRM/SQL via a regex denylist (`PAM_COMMAND_DENY_FILE`, audited `command.blocked`). See §9.4 |
| 2026-07-20 | Phase 15: **PostgreSQL database session proxy** (`PAM_DB_ADDR`) — brokers `postgres` targets with JIT credential injection and **per-statement query audit** (`db.query`); operators use `psql user=<dbcred>@<target>` with their PAM key. Same authorization gates as the SSH proxy; upstream auth via SCRAM-SHA-256/MD5/cleartext. See §5 → *Database targets (PostgreSQL)* |
| 2026-07-20 | Post-review hardening: directory logins grant the **union** of every mapped group's role (not the single highest); a parked agent approval is **re-validated at decision time** (revoked key / expired SVID refused); broker-audit append serializes under a Postgres advisory lock so a rolling-deploy/HA overlap can't fork the hash chain; numeric policy arguments match in plain decimal |
| 2026-07-20 | Phase 14: **SOPS-encrypted Kubernetes secrets** — seal the Secret manifest with [SOPS](https://github.com/getsops/sops)+[age](https://age-encryption.org/) and keep it in Git; `deploy/k8s/sops/apply.sh` streams decrypt→`kubectl apply` (plaintext never on disk). See [deploy/k8s/sops/README.md](../deploy/k8s/sops/README.md) |
| 2026-07-20 | Phase 13: **AI-agent access broker** — opt-in via `PAM_BROKER_POLICY_FILE`; policy-gated tool calls with JIT server-side execution, approval/resume + single-use tokens, an MCP transport (`POST /mcp`), SPIFFE JWT-SVID identity, and a keyed-HMAC verifiable audit chain (`GET /v1/audit/verify`/`/head`). See §7 → *AI-agent access broker* |
| 2026-07-20 | Phase 12: **configuration subsystem + custom-profile RBAC** — DB-persisted `PAM_*` overrides editable from the 5250 console and **hot-swapped without a restart** (`GET/PUT /api/config`, §4.1), named permission profiles (`/api/profiles`, §7), and effective-config/IaC export (`GET /api/config/iac`) |
| 2026-07-20 | Phase 11: **management console** — the 5250 portal becomes a role-aware console over every API (`GET /api/me`-driven menu) |
| 2026-07-19 | PKCS#11 HSM KEK provider (`pkcs11` build tag, `Dockerfile.pkcs11`, `PAM_KEK_PKCS11_*`); verified against SoftHSM2 |
| 2026-07-19 | Phase 7 follow-ons: credential checkout/check-in leases (auto-rotate on return), discovery scan; system requirements ([REQUIREMENTS.md](REQUIREMENTS.md)) |
| 2026-07-19 | Phase 10: scale & ops — Prometheus `/metrics`, `/readyz` readiness, Helm chart (`deploy/helm/pamv1`), SBOM + cosign-signed release workflow |
| 2026-07-19 | Phase 9: NIS2 pack — tamper-evident audit export (`GET /api/audit/export`, JSON/CSV + SHA-256) for Art. 23; see [NIS2-COMPLIANCE.md](NIS2-COMPLIANCE.md) |
| 2026-07-19 | Phase 8: OT adaptation — 4-eyes access-request approval (`/api/access-requests`), per-target/global gate (`PAM_REQUIRE_APPROVAL`), air-gap mode (`PAM_OT_AIRGAP`); see [OT-DEPLOYMENT.md](OT-DEPLOYMENT.md) |
| 2026-07-19 | Phase 7: credential lifecycle — rotation (`/api/credentials/{id}/rotate`), reconciliation (`/reconcile`, `?remediate`, `GET /api/reconcile`), scheduled worker (`PAM_ROTATE_*`) |
| 2026-07-19 | Phase 6: break-glass v2 (M-of-N quorum unseal, auto-expiring sessions, alerting); AWS KMS KEK |
| 2026-07-18 | Phase 4: NTLM WinRM auth; RDP brokering via Guacamole guacd |
| 2026-07-18 | Phase 3b: OIDC single sign-on (Authorization Code + PKCE, JWKS validation) |
| 2026-07-18 | Phase 4: Windows targets — WinRM command execution with JIT credentials |
| 2026-07-18 | Phase 3b: enforce-MFA policy (`PAM_MFA_REQUIRED`) + single-use recovery codes |
| 2026-07-18 | Phase 3b: Microsoft Entra ID (Azure AD) login setup (app roles → roles, sovereign host) |
| 2026-07-18 | Phase 3b: TOTP MFA (self-service enroll/verify, enforced on login) |
| 2026-07-18 | Phase 3b: Active Directory login setup (LDAPS, group→role, session tokens); envelope-encryption KEK config |
| 2026-07-18 | Initial admin guide (Phase 3a): deployment, config, target/credential/user management, break-glass, logging & audit, hardening, troubleshooting |

*See also the [User Guide](USER-GUIDE.md) and the [ROADMAP](../ROADMAP.md).*
