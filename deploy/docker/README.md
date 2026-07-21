# Docker / docker-compose

The container build and the local full-stack demo. Kept here (not at the repo
root) to keep the root uncluttered; the build context is still the **repo root**.

| File | What it is |
|---|---|
| `Dockerfile` | The default image — `CGO_ENABLED=0`, static, `distroless/static`, non-root, read-only root FS |
| `Dockerfile.pkcs11` | Optional image with the PKCS#11 **HSM KEK** provider (needs cgo + a glibc base) |
| `docker-compose.yml` | Local full stack: hardened PostgreSQL 17 (scram-sha-256) + pam-server |
| `.env.example` | Copy to `.env` and fill the keys before `docker compose up` |

## Run the full stack

```bash
cd deploy/docker
cp .env.example .env      # fill PAM_MASTER_KEY, PAM_API_KEY, POSTGRES_PASSWORD
docker compose up --build
# → portal + REST API on http://localhost:8080, SSH proxy on :2222
```

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
