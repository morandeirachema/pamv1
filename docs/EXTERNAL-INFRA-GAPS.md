# pamv1 — External Infrastructure & Accounts Checklist

> 🟢 **Living document** — updated in the same change as the code, without a separate ask (see the [docs hub](README.md)).

> **Purpose.** pamv1 follows a hard rule: *every phase is fully functional and
> tested end-to-end without faking the security-critical path.* Where a feature
> can only be **verified honestly against a real external system or a paid
> account**, we build the code, test it against an in-process fake or mock, and
> record the real-world dependency here rather than pretend it was validated
> live. This is the operator's checklist of what you must stand up (and what to
> re-verify) before relying on each capability in production.
>
> Last updated: 2026-07-23 · Reflects: Phases 0–24 + the 2026-07 hardening pass.

## Legend

- **CI proof** — how the code is exercised in the automated test suite today.
  - `fake/mock` — an in-process fake or mock stands in for the external system
    (the protocol/logic is tested; the third party is not contacted).
  - `SoftHSM2` / `mock server` — a real software implementation is run in CI.
  - `— none` — no automated test; the code path needs live infra even to smoke-test.
- **You must provide** — the external infrastructure or account to run it for real.
- **Verify** — what to check once the real system is wired up.

---

## 1. Identity providers & directories (accounts)

| Capability | Env / code | CI proof | You must provide | Verify |
|---|---|---|---|---|
| **Active Directory / LDAP login** | `PAM_LDAP_*`, `internal/auth/ldap.go` | fake `ldapConn` | An AD/LDAPS directory + a service (bind) account | User bind verifies the password; `memberOf` groups map to roles; LDAPS cert validates |
| **Microsoft Entra ID (Azure AD)** | `PAM_ENTRA_*`, `internal/auth/entra.go` | mock token endpoint + RS256 JWKS | An Entra tenant + app registration (client id/secret) | ROPC returns an id_token; its signature validates against the tenant JWKS; app roles/groups map |
| **OIDC Authorization Code + PKCE** | `PAM_OIDC_*`, `internal/oidc` | RSA-signed token, mock IdP | An OIDC IdP (Okta/Keycloak/Entra/Google) | Auth-code round-trip; ID-token signature/iss/aud/nonce/exp verified; IdP-side MFA/Conditional Access applies |
| **Kerberos bind (LDAP)** — *deferred* | Phase 3b | — none | A **KDC** (AD domain) | GSSAPI bind against the KDC. Not implemented — needs a KDC to build and test honestly |
| **Directory-driven identity reconciliation** | `POST /api/identity/reconcile` | fake directory | A live directory (LDAP) reporting disabled users | Disabled directory users are revoked; local-only accounts are surfaced, not revoked |

MFA (TOTP, RFC 6238) and recovery codes are **self-contained** — no external
dependency — and fully unit-tested.

---

## 2. Secret & key management backends (accounts / appliances)

The vault KEK is pluggable; the **local** KEK (dev/test) needs nothing. The
production backends externalize the root of trust and need the real service to
verify end-to-end:

| Capability | Env / code | CI proof | You must provide | Verify |
|---|---|---|---|---|
| **HashiCorp Vault Transit KEK** | `PAM_KEK_TRANSIT_*`, `vault/transit.go` | mock Transit server | A Vault server with a Transit key | Wrap/unwrap round-trips; the KEK never leaves Vault |
| **AWS KMS KEK** | `PAM_KEK_AWS_*`, `vault/awskms.go` | mock `kmsAPI` | An AWS account + a KMS CMK + IAM | Data key wrap/unwrap via KMS with the `app=pamv1` encryption context |
| **PKCS#11 HSM KEK** | `PAM_KEK_PKCS11_*`, `vault/pkcs11.go` (`pkcs11` build tag) | **SoftHSM2 in CI** | A real HSM/token (or SoftHSM2) | AES wrap/unwrap inside the token; the key never leaves the HSM |
| **CyberArk Conjur secret sourcing** | `PAM_CONJUR_*`, `internal/conjur` | in-process fake Conjur | A Conjur appliance (+ authn-api-key host or Kubernetes authn-jwt) | Bootstrap `PAM_*` secrets are sourced at startup; fail-loud if unreachable |
| **SOPS + age sealed secrets** | `deploy/k8s/sops/`, `deploy/.sops.yaml` | round-trip with a committed demo key | Real age/PGP/cloud-KMS recipients for operators | `sops -d \| kubectl apply` decrypts only for held keys; cloud-KMS recipients wired into the chart is a follow-on |

---

## 3. Target connectors (real machines / services)

The SSH proxy's JIT path is proven against an in-process sshd. Everything that
touches a **real Windows host, database, bastion, or device** needs that system
to exercise fully:

| Capability | Env / code | CI proof | You must provide | Verify |
|---|---|---|---|---|
| **WinRM command execution (JIT)** | `POST /api/targets/{id}/winrm`, `internal/winrm` | fake `Runner` | A Windows host with WinRM (basic or NTLM) | Command runs with the vaulted credential; caller never sees the secret |
| **NTLM / Kerberos WinRM auth** | `PAM_WINRM_AUTH` | client-construction test | An AD-joined Windows host (+ a KDC for Kerberos) | NTLMv2 auth to a domain host. **Kerberos WinRM is deferred** — needs a KDC + AD-joined host |
| **RDP via Apache Guacamole** | `PAM_GUACD_ADDR`, `internal/guacd` | mock guacd handshake | An RDP host (a `guacd` daemon now **ships** with the Docker/K8s/Helm deploys; bring your own or use the bundled one) | JIT credential reaches guacd, never the browser; server-side recording |
| **Browser RDP viewer** — *shipped* | portal option 7, `web` (vendored guacamole-common-js), `POST /api/rdp-token` | full WebSocket round-trip vs a fake guacd (`TestRDPTunnelEndToEnd`) | An RDP host — to see the **rendered desktop** (only the pixels are unverifiable without one) | In-portal canvas display. The renderer is vendored and the whole path is tested; only the actual on-screen image needs a live host. See [RDP-TESTING.md](RDP-TESTING.md) |
| **SSH jump host / bastion** | `PAM_SSH_JUMP_*` | in-process (via proxy tests) | A real bastion for production topology | `direct-tcpip` tunnel to targets only reachable via the bastion |
| **Credential rotation (SSH/WinRM)** | `internal/rotate` | in-process sshd; fake WinRM | Real Linux/Windows hosts | Password/`ssh_key` actually changes on the target; the old secret stops working |
| **Account & identity reconciliation** | `/api/reconcile`, `/reconcile` | in-process | Real hosts to detect out-of-band drift | Drift is detected and (opt-in) remediated |
| **Discovery scan** | `POST /api/discovery/scan` | injected dialer | A network with reachable SSH/WinRM/RDP hosts | Reachable management ports are found and (opt-in) onboarded |
| **Dependent-account propagation** | `/api/credentials/{id}/dependencies` | fake WinRM | A Windows host running Services / Scheduled Tasks / IIS App Pools | The consumer's stored password is updated on rotation so the service keeps running |
| **PostgreSQL session proxy** | `PAM_DB_ADDR`, `dbproxy.go` | in-process fake upstream | (optional) a real Postgres for interop breadth | JIT injection + per-statement `db.query` audit against a managed/SCRAM Postgres; the SCRAM server signature is verified |
| **Upstream DB TLS verification** | `PAM_DB_UPSTREAM_CA` / `_TLS_VERIFY` | in-process fake upstream | A Postgres with a CA-issued (or pinned) server cert | With a CA set, the proxy verifies the target's certificate fail-closed (no MITM of the injected credential); unset = trust-any + startup warning |
| **Zero Standing Privilege (SSH certs)** | `PAM_SSH_CA_KEY`, `internal/sshca` (Phase 22) | in-process cert-only sshd | A target sshd trusting the pamv1 CA (`TrustedUserCAKeys`) | A minted short-lived cert authenticates; no standing secret exists for the account |
| **Serial (RS-232) connectors** — *deferred* | Phase 8 | — none | Serial hardware / a terminal server | Legacy OT equipment reached over serial. Not implemented — needs the hardware |

---

## 4. Cloud & Kubernetes deployment (accounts / clusters)

| Capability | Code | You must provide | Verify |
|---|---|---|---|
| **Helm deploy** | `deploy/helm/pamv1` | A Kubernetes cluster | Pod runs with the hardened security context; ServiceMonitor scrapes `/metrics` |
| **Postgres HA (CloudNativePG)** | `deploy/k8s/postgres-cnpg.yaml` | K8s + the CNPG operator | 3-instance cluster, automatic failover, scram-sha-256, optional PITR |
| **Cloud-managed Postgres (Terraform)** | `deploy/terraform/cloud-postgres` | An AWS account (RDS) | Multi-AZ, encrypted, `force_ssl` instance provisioned |
| **Signed releases (cosign + SLSA)** | `.github/workflows/release.yml` | GitHub Actions OIDC + registry | Keyless image signature, SBOM attestation, build provenance on a version tag |
| **Conjur authn-jwt (K8s-native)** | `deploy/k8s/conjur/` | A Conjur appliance reachable from the cluster | Pod presents its projected SA token; no bootstrap secret in Git |

---

## 5. Alerting & SIEM (endpoints)

| Channel | Env | You must provide | Verify |
|---|---|---|---|
| **Webhook alerts** | `PAM_ALERT_WEBHOOK` | An HTTP endpoint (Slack/PagerDuty/etc.) | Break-glass and analytics events POST as JSON |
| **Syslog alerts** | `PAM_ALERT_SYSLOG` | A syslog collector (udp/tcp) | Events arrive at the collector |
| **Email alerts** | `PAM_ALERT_EMAIL_*` | An SMTP server + credentials | Alert email is delivered to the recipient list |
| **Audit / SIEM forwarding** | JSON logs on stdout (Phase 9) | A log collector / SIEM | The append-only audit trail and JSON logs are ingested for detection |

Air-gapped deployments (`PAM_OT_AIRGAP`) disable all outbound alerting by design.

---

## 6. Zero-trust agent identity (SPIFFE / SPIRE)

| Capability | Env / code | CI proof | You must provide | Verify |
|---|---|---|---|---|
| **SPIFFE JWT-SVID verification** | `PAM_BROKER_TRUST_DOMAIN_JWKS`, `internal/agentid/svid.go` | file JWKS + signed SVIDs | A trust-domain JWKS (from SPIRE or another issuer) | SVIDs validate (subject/audience/exp); RFC 8693 `act` delegation depth is capped |
| **Live SPIRE workload attestation** — *deferred* | Phase 13 | — none | A SPIRE deployment | Workloads receive SVIDs via the SPIRE agent, attested by the node/workload |
| **RFC 8693 token-exchange minting** — *deferred* | Phase 13 | — none | An STS / token-exchange endpoint | pamv1 mints delegated tokens rather than only verifying them |

---

## 7. Tier-3 market-frontier gaps not yet built (need infra to build honestly)

Two Tier-3 gaps **shipped** and are tested in-process — **Zero Standing
Privilege** (Phase 22, §3) and **privileged threat analytics** (Phase 23). The
remaining three cannot be *built and verified honestly* without external systems,
so they are scoped here rather than stubbed:

| Gap | What it needs to build honestly | Fit in pamv1 |
|---|---|---|
| **Connector / plugin breadth** — network devices (Cisco/Juniper/F5/Palo Alto), MySQL/MSSQL/Oracle, VMware/SAP/mainframe | The real devices/databases (network gear speaks SSH and already rides the existing proxy; new DB wire protocols each need a real server to prove interop) | New `Rotator`/`Verifier` connectors and new DB wire-protocol proxies on the Phase 15 pattern |
| **Cloud privileged access (CIEM-lite)** — federated console + short-lived cloud credentials, entitlement right-sizing | A cloud account (AWS STS `AssumeRole` / Azure / GCP) to mint and verify short-lived credentials | A broker tool that mints short-lived cloud creds JIT (mirrors the ZSP philosophy for cloud IAM) |
| **Web / SaaS session proxying** — record + inject into web admin consoles | A headless browser + a real SaaS console to drive and record | The heaviest lift; a reverse-proxy/browser-isolation layer alongside SSH/RDP |

---

## 8. Tier-4 ecosystem (external systems / registries)

The **application-secrets API** (Conjur-style secret delivery for non-agent apps)
**shipped in Phase 24** — it is fully in-process and tested (`PAM_APP_SECRETS_ENABLED`,
`GET /v1/app-secrets/{credential_id}`). The rest of Tier 4 needs an external system,
account, or a separate module/registry:

| Item | Needs |
|---|---|
| **Terraform provider** for pamv1 objects | A separate Go module (terraform-plugin-framework) + the Terraform Registry; acceptance tests need a running pamv1 to target |
| **Secrets-Hub-style sync-out** | AWS Secrets Manager / Azure Key Vault accounts to push managed secrets to (and a deliberate decision to export secrets outward) |
| **SSH-key fleet discovery** at scale | A fleet of hosts with existing authorized_keys to inventory (the read mechanism is unit-testable in-process, like the rotation connectors) |
| **Thick-app connection components** (SSMS / Toad / vSphere via RDP RemoteApp) | Windows RemoteApp hosts + the thick clients |

---

## Deliberate non-goal

**Endpoint Privilege Management** (removing local admin / elevating sudo via an
endpoint agent) is a different product category that does not fit a vault + proxy
chokepoint, and is **out of scope** by design — it is not an infra gap, it is not
planned.
