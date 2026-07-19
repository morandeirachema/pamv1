# pamv1 — Administrator Guide

A complete, practical guide for **administrators**: deploy pamv1, configure it,
onboard targets and credentials, manage users and roles, run the break-glass
procedure, and read the logs and audit trail.

> **Living document.** Kept in step with the product — update it whenever
> admin-facing behavior changes (config, deployment, management, logging). Add a
> row to the [change log](#12-change-log) with each update.
>
> Last updated: 2026-07-18 · Reflects: **Phase 3a** (RBAC + four roles) + operational logging.

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
- A PostgreSQL 16/17 database (bundled in docker-compose), or `memory` mode for a throwaway demo.
- `openssl` (to generate keys), an SSH client for operators.

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
| `PAM_KEK_PROVIDER` | | `local` | Vault key backend: `local` (dev/test) or `vault-transit` (production). |
| `PAM_MASTER_KEY` | local only | — | Local KEK key (`-genkey`). **Back it up securely.** Dev/test only. |
| `PAM_KEK_TRANSIT_ADDR` / `_TOKEN` / `_KEY` | transit only | — | HashiCorp Vault Transit KEK (production). |
| `PAM_API_KEY` | ✅ | — | Bootstrap admin key (X-API-Key / SSH password). |
| `PAM_DATABASE_URL` | ✅ | — | `postgres://…` (use `sslmode=verify-full`) or `memory` for demo. |
| `PAM_BREAK_GLASS_KEY_HASH` | | (off) | Hex SHA-256 of the sealed emergency key. |
| `PAM_LISTEN_ADDR` | | `:8080` | HTTP portal/API bind. |
| `PAM_SSH_ADDR` | | `:2222` | SSH proxy bind; `off` disables the proxy. |
| `PAM_SSH_HOST_KEY` | | (ephemeral) | Path to persist the proxy SSH host key. |
| `PAM_RECORDING_DIR` | | `recordings` | Where session recordings are written. |
| `PAM_LOG_LEVEL` | | `info` | `debug` \| `info` \| `warn` \| `error`. |
| `PAM_LOG_FORMAT` | | `json` | `json` (for SIEM) \| `text` (for humans). |
| `PAM_ROTATE_INTERVAL_MIN` | | `0` (off) | Credential-lifecycle worker interval (minutes). |
| `PAM_ROTATE_MAX_AGE_HOURS` | | `0` (report) | Auto-rotate password credentials older than this. |
| `PAM_REQUIRE_APPROVAL` | | `false` | OT: gate every target behind an approved access request (4-eyes). |
| `PAM_APPROVAL_WINDOW_MIN` | | `60` | How long an approved access request stays valid. |
| `PAM_OT_AIRGAP` | | `false` | Disable all outbound calls (alert webhooks) for air-gapped sites. |

The examples below use `-H "X-API-Key: $PAM_API_KEY"`; in production call the
HTTPS endpoint of your ingress instead of `http://localhost:8080`.

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
`credential.remediate`; the worker acts as `system-scheduler`). Only `password`
credentials are rotated; `ssh_key` rotation and the AD/LDAPS password-change and
identity-reconciliation connectors are on the roadmap.

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

Create the target with `protocol=rdp`, port `3389`, and a credential. The
WebSocket endpoint `GET /api/targets/{id}/rdp?token=<session-token>` decrypts the
credential just-in-time, injects it into the guacd handshake, and tunnels the
Guacamole protocol to the browser (`rdp.connect` / `rdp.end` in the audit). The
in-browser display uses the [guacamole-common-js](https://guacamole.apache.org/doc/gug/writing-you-own-guacamole-app.html)
client — bundling that viewer into the portal is the remaining step; the tunnel
itself is usable by any Guacamole-compatible client today.

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

`*` approval endpoints arrive in a later phase; the capability exists now.

Give the user their token; they use it in the portal Sign On or as the SSH proxy
password (see the [User Guide](USER-GUIDE.md)).

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
password by binding as them, and derives the role from group membership (highest
privilege wins). `POST /api/login` then returns a **session token** (12h) that
works in the portal and the SSH proxy exactly like a per-user token. A user in no
mapped group is rejected. Keep the bootstrap `PAM_API_KEY` and break-glass key as
the local emergency path if AD is unreachable.

### Microsoft Entra ID (Azure AD) login (optional)

For cloud identities, enable Entra ID login alongside or instead of on-prem AD.
pamv1 uses the OAuth2 **resource-owner-password** grant against your tenant and
reads the user's **app roles** (or group ids) from the token to derive the role.

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
TOTP is not layered on OIDC (the IdP owns MFA there). A shared state store for
multi-replica HA is on the roadmap.

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

### 9.4 Metrics & probes

- `GET /metrics` — a Prometheus exposition: `pam_http_requests_total{status}`,
  `pam_audit_events_total`, `pam_breakglass_access_total`,
  `pam_auth_failures_total`, `pam_credential_rotations_total`, and the
  `pam_active_sessions` gauge. It is **unauthenticated** (like `/healthz`) and
  exposes only low-sensitivity counts — restrict it at the ingress/network. The
  Helm chart can render a `ServiceMonitor` (`metrics.serviceMonitor.enabled`).
- `GET /healthz` — liveness (process up). `GET /readyz` — readiness (returns 503
  until the database is reachable); point your load balancer at `/readyz`.

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
- Planned hardening (Postgres TLS enforcement, migrations, vault key rotation, native HTTPS, rate limiting) is [Phase 5](../ROADMAP.md#phase-5--hardening-database-vault-transport-).

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
