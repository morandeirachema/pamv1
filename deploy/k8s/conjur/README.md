# Sourcing pamv1's bootstrap secrets from CyberArk Conjur (Phase 18)

pamv1 can fetch its **own** bootstrap secrets — `PAM_MASTER_KEY`, `PAM_API_KEY`,
`PAM_DATABASE_URL`, the break-glass hash, and the broker audit keys — from a
[CyberArk Conjur](https://www.conjur.org/) instance at startup, instead of from a
Kubernetes Secret. This is the **runtime-broker** alternative to the
[SOPS GitOps sealing](../sops/) (Phase 14).

**Both mechanisms ship; neither is mandatory.** SOPS stays the zero-dependency
default (great for the demo, air-gapped/OT sites, and simple GitOps). Conjur is
opt-in for shops that already run it and want machine-identity auth, central
rotation, and per-access audit of pamv1's own secrets.

## How pamv1 uses Conjur

At boot, when `PAM_CONJUR_URL` is set, pamv1 authenticates to Conjur and fills
**any empty** bootstrap `PAM_*` secret from the variables under
`PAM_CONJUR_POLICY_PREFIX` (default `pamv1`):

| Bootstrap secret | Conjur variable |
|---|---|
| `PAM_MASTER_KEY` | `pamv1/master-key` |
| `PAM_API_KEY` | `pamv1/api-key` |
| `PAM_DATABASE_URL` | `pamv1/database-url` |
| `PAM_BREAK_GLASS_KEY_HASH` | `pamv1/break-glass-key-hash` |
| `PAM_BROKER_AUDIT_KEY` | `pamv1/broker-audit-key` |
| `PAM_BROKER_AUDIT_SIGN_SEED` | `pamv1/broker-audit-sign-seed` |

An **explicit environment value always wins** (Conjur only fills gaps), and a
variable that isn't defined in Conjur (HTTP 404) is simply skipped — provide it
via env/SOPS instead. A configured-but-unreachable Conjur is **fail-loud**: the
server refuses to start rather than come up with empty secrets.

The retrieval is one-shot at startup (like SOPS is one-shot at apply); rotating a
value in Conjur takes effect on the next restart.

## Setup

1. Load the policy and set the values (they live only in Conjur):

   ```bash
   conjur policy load -b root -f policy.yaml
   conjur variable set -i pamv1/master-key           -v "$(./pam-server -genkey)"
   conjur variable set -i pamv1/api-key              -v "$(openssl rand -hex 24)"
   conjur variable set -i pamv1/database-url         -v 'postgres://pam:...@postgres:5432/pam?sslmode=verify-full'
   conjur variable set -i pamv1/break-glass-key-hash -v '<sha256-hex>'
   ```

2. Point pam-server at Conjur and pick an authenticator:

   **authn-jwt (recommended, Kubernetes-native — no bootstrap secret in Git).**
   The pod presents a projected service-account token; Conjur's
   [`authn-jwt`](https://docs.conjur.org/) verifies it against the cluster's JWKS.
   `deployment.yaml` shows the projected-token volume and the env:

   ```
   PAM_CONJUR_URL=https://conjur.pamv1.svc.cluster.local
   PAM_CONJUR_AUTHN_JWT_SERVICE_ID=kubernetes
   PAM_CONJUR_JWT_FILE=/var/run/secrets/conjur/token
   PAM_CONJUR_CACERT=/etc/conjur/ca.pem
   ```

   **authn-api-key (portable).** A host API key (`conjur host rotate-api-key -i
   host/pamv1/pam-server`) in a small Secret:

   ```
   PAM_CONJUR_URL=https://conjur.example
   PAM_CONJUR_AUTHN_LOGIN=host/pamv1/pam-server
   PAM_CONJUR_API_KEY=<host api key>
   ```

3. Deploy: `kubectl apply -f deployment.yaml` (adjust the Conjur URL, CA, and the
   authn-jwt policy on the Conjur side).

## SOPS vs Conjur — when to use which

| | [SOPS](../sops/) (Phase 14) | Conjur (Phase 18) |
|---|---|---|
| Model | secret **at rest** in Git (GitOps) | secret **broker** fetched at runtime |
| Runtime dependency | none | a running Conjur |
| Secret in Git | encrypted | **none** (with authn-jwt) |
| Rotation / access audit | in Git history | **central, in Conjur** |
| Works air-gapped / `docker compose up` demo | yes | needs Conjur reachable |

pamv1 already externalizes its **KEK** (Vault-Transit / AWS-KMS / PKCS#11);
sourcing the bootstrap secrets from Conjur is the same philosophy applied to the
values themselves.

## Env vars

| Variable | Purpose |
|---|---|
| `PAM_CONJUR_URL` | Conjur appliance URL — **presence enables the provider** |
| `PAM_CONJUR_ACCOUNT` | Conjur account (default `default`) |
| `PAM_CONJUR_POLICY_PREFIX` | variable-name prefix (default `pamv1`) |
| `PAM_CONJUR_AUTHN_LOGIN` / `PAM_CONJUR_API_KEY` | authn-api-key credentials |
| `PAM_CONJUR_AUTHN_JWT_SERVICE_ID` / `PAM_CONJUR_JWT_FILE` | authn-jwt service id + JWT file |
| `PAM_CONJUR_CACERT` | PEM CA bundle path for TLS to Conjur (optional) |
| `PAM_SECRETS_PROVIDER=conjur` | optional explicit enable (requires `PAM_CONJUR_URL`) |

## Deferred

Runtime secret refresh (re-fetch without a restart), a per-variable override map,
and pushing pamv1's *managed* secrets out to Conjur (Secrets-Hub-style sync) are
documented follow-ons — this phase covers sourcing pamv1's own bootstrap secrets.
