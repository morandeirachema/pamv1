# Docker / docker-compose

The container build and the local full-stack demo. Kept here (not at the repo
root) to keep the root uncluttered; the build context is still the **repo root**.

| File | What it is |
|---|---|
| `Dockerfile` | The default image — `CGO_ENABLED=0`, static, `distroless/static`, non-root, read-only root FS |
| `Dockerfile.pkcs11` | Optional image with the PKCS#11 **HSM KEK** provider (needs cgo + a glibc base) |
| `docker-compose.yml` | Local full stack: hardened PostgreSQL 17 (scram-sha-256) + pam-server |
| `.env.example` | Copy to `.env` and fill the keys before `docker compose up` |
| `docker-compose.rdp-demo.yml` | End-to-end **RDP viewer demo** — a real xrdp desktop + guacd + pam-server, target auto-seeded (see below) |
| `rdp-target/` | The demo's throwaway RDP target image (XFCE over xrdp). Demo only — never deploy |

## Run the full stack

```bash
cd deploy/docker
cp .env.example .env      # fill PAM_MASTER_KEY, PAM_API_KEY, POSTGRES_PASSWORD
docker compose up --build
# → portal + REST API on http://localhost:8080, SSH proxy on :2222
```

## Run the RDP viewer demo (see the pixels, no Windows host)

Brings up a real **xrdp Linux desktop** as an RDP target, guacd, and pam-server,
and auto-seeds the pamv1 target + credential — so you can watch a desktop render
through the in-portal viewer end to end.

```bash
cd deploy/docker
docker compose -f docker-compose.rdp-demo.yml up --build
# open http://localhost:8080
#   sign on: leave Password blank, enter the access token  demo-api-key-pamv1
#   Work with Targets → type 7 next to "demo-rdp" → Enter → an XFCE desktop renders
#   Ctrl+Alt+Q disconnects
```

**Demo only** — a throwaway master key, a weak API key, an in-memory store, and an
unhardened **root** xrdp target with a well-known password. Never deploy it. If the
desktop never paints, set `PAM_GUACD_RDP_SECURITY=rdp` on the `pam` service and
re-up. Full verification checklist: [docs/RDP-TESTING.md §4](../../docs/RDP-TESTING.md).

## Build the image directly (context = repo root)

```bash
# from the repo root:
docker build -f deploy/docker/Dockerfile -t pamv1 .
docker build -f deploy/docker/Dockerfile.pkcs11 -t pamv1:pkcs11 .   # HSM variant
```

The compose file sets `build.context: ../..` (the repo root) and
`build.dockerfile: deploy/docker/Dockerfile`, so `COPY . .` still copies the source
and honors the root `.dockerignore`. CI builds with
`docker build -f deploy/docker/Dockerfile .` and the release workflow passes
`file: ./deploy/docker/Dockerfile`.
