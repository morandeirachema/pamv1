# System Requirements & Run Specs

> **Alpha, for learning purposes. Not production, not audited.** These are the
> specs to *run* pamv1 in Docker and Kubernetes, plus rough sizing. Validate
> against your own load.

## At a glance

| Component | Requirement |
|---|---|
| Build toolchain | Go **1.26+** (only to build from source) |
| Container image | `gcr.io/distroless/static-debian12:nonroot` — runs as non-root UID **65532**, read-only root FS, no shell. (HSM/PKCS#11 KEK uses `Dockerfile.pkcs11`: cgo + glibc `distroless/base`, still non-root.) |
| Database | **PostgreSQL 14+** (compose ships **17**); TLS strongly recommended (`sslmode=verify-full`) |
| Ports | **8080** portal + REST API (HTTP or native HTTPS) · **2222** SSH session proxy · **5433** PostgreSQL session proxy (off by default) |
| Docker | Engine **24+**, Compose **v2** |
| Kubernetes | **1.25+** (restricted Pod Security Standard); optional Prometheus Operator for the ServiceMonitor |
| Architectures | linux/amd64, linux/arm64 |

## Ports & protocols

| Port | Purpose | Notes |
|---|---|---|
| 8080/tcp | Portal + REST API | HTTP, or TLS 1.2+ when `PAM_TLS_CERT`/`PAM_TLS_KEY` are set. Front with an HTTPS ingress otherwise. `/metrics`, `/healthz`, `/readyz` live here. |
| 2222/tcp | SSH session proxy | Operators `ssh -p 2222 <cred>@<target>@host`. Set `PAM_SSH_ADDR=off` to disable. |
| 5433/tcp | PostgreSQL session proxy | Operators `psql "host=... port=5433 user=<cred>@<target> dbname=..."`. Enable with `PAM_DB_ADDR` (off by default). |
| 636/5986/3389/5432 | Outbound to targets/IdP | LDAPS to AD, WinRM-HTTPS, RDP-via-guacd, PostgreSQL to `postgres` targets — **egress** from pamv1, not listeners. See [PORTS-AND-FLOWS.md](PORTS-AND-FLOWS.md). |

## Prerequisites (secrets)

Generate before first run (see the [Admin Guide](ADMIN-GUIDE.md#31-generate-the-secrets-first)):

- `PAM_MASTER_KEY` — `./pam-server -genkey` (or use a KMS-backed KEK).
- `PAM_API_KEY` — the bootstrap admin key.
- `PAM_DATABASE_URL` — `postgres://…?sslmode=verify-full` (or `memory` for the demo).
- Optional: `PAM_BREAK_GLASS_KEY_HASH` (`-hashkey`), TLS cert/key, OIDC/LDAP/Entra config.

## Docker / docker-compose

Minimums: Docker Engine 24+, Compose v2. The bundled `docker-compose.yml` runs a
hardened PostgreSQL 17 (scram-sha-256) plus pam-server.

```bash
cp .env.example .env      # fill PAM_MASTER_KEY, PAM_API_KEY, POSTGRES_PASSWORD
docker compose up --build
```

Container resource guidance (per pam-server instance):

| | CPU | Memory |
|---|---|---|
| Request / idle | 50m | 64 MiB |
| Limit / small prod | 500m | 256 MiB |

Volumes:

- pam-server `/data` — SSH host key + session recordings (persist it to keep
  recordings and a stable host key across restarts).
- PostgreSQL `/var/lib/postgresql/data` — the database (a named volume/PVC).

The image has **no shell** and runs read-only as non-root; write paths are limited
to the mounted `/data` volume.

## Kubernetes

Requires **1.25+** for the restricted [Pod Security Standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
the manifests/chart assume. Two paths:

```bash
# Raw manifests
kubectl apply -f deploy/k8s/

# Or Helm (deploy/helm/pamv1)
helm install pamv1 deploy/helm/pamv1 \
  --set secret.data.PAM_MASTER_KEY=... \
  --set secret.data.PAM_API_KEY=... \
  --set secret.data.PAM_DATABASE_URL='postgres://...?sslmode=verify-full'
```

Pod spec (defaults in `deploy/k8s/deployment.yaml` and the chart):

- **Security context:** `runAsNonRoot`, `readOnlyRootFilesystem`, all capabilities
  dropped, `seccompProfile: RuntimeDefault`, `automountServiceAccountToken: false`.
- **Resources:** requests `cpu: 50m`, `memory: 64Mi`; limit `memory: 256Mi`.
- **Probes:** liveness `GET /healthz`, readiness `GET /readyz` (returns 503 until
  the database is reachable — gate Service traffic on it).
- **Storage:** `/data` is `emptyDir` by default; set `persistence.enabled=true`
  (chart) or swap in a PVC to retain recordings + host key. **RWO** is sufficient
  for a single writer.
- **Metrics:** scrape `GET /metrics` (pod annotations are set; enable
  `metrics.serviceMonitor.enabled=true` with the Prometheus Operator).
- **TLS:** terminate at the Ingress, or set `PAM_TLS_CERT`/`PAM_TLS_KEY` for native
  HTTPS. Expose 2222 via a `LoadBalancer`/`NodePort` Service if operators need the
  SSH proxy from outside the cluster.

**PostgreSQL:** run 14+ with TLS. For HA use an operator such as
[CloudNativePG](https://cloudnative-pg.io/). Migrations apply automatically on
pam-server startup.

**Scaling / HA:** the server is stateless enough to run multiple replicas —
**OIDC login state is shared via the database**, so the auth-code callback can
land on any replica. Two things remain per-replica: the auth **rate-limiter**
(best-effort; slightly looser limits across N replicas, acceptable) and the
**break-glass quorum-unseal shares** (kept in memory *by design* — persisting key
shares to the DB would weaken the offline-shares guarantee). For the unseal flow,
submit all shares to one replica (a sticky session, or scale to 1 during an
emergency). All other operations (proxy, WinRM, RDP, rotation, reveal, approval,
checkout) are safe across replicas.

## Sizing (rough)

| Scale | pam-server | PostgreSQL |
|---|---|---|
| Demo / lab | 1 replica, 64–128 MiB | `memory` store or 1 small instance |
| Small team | 1–2 replicas, 256 MiB, 250m | 1 vCPU / 1–2 GiB, 10–20 GiB disk |
| Recording-heavy | add disk for `/data` (asciicast files grow with session volume) | — |

Session recordings dominate disk growth; budget storage for `PAM_RECORDING_DIR`
and rotate/archive it per your retention policy (see [NIS2-COMPLIANCE.md](NIS2-COMPLIANCE.md#3-audit-retention--siem-forwarding)).

---

*See also: [ADMIN-GUIDE.md](ADMIN-GUIDE.md), [PORTS-AND-FLOWS.md](PORTS-AND-FLOWS.md), [ARCHITECTURE-HIGH-LEVEL.md](ARCHITECTURE-HIGH-LEVEL.md).*
