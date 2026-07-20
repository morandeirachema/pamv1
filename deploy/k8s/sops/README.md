# SOPS-encrypted Kubernetes secrets (Phase 14)

pamv1's secrets (`PAM_MASTER_KEY`, `PAM_API_KEY`, the database URL, …) must reach the
cluster without ever sitting in plaintext in git. This directory uses
**[SOPS](https://github.com/getsops/sops)** with **[age](https://age-encryption.org/)** to
encrypt *only the values* of a Kubernetes `Secret` — `kind`, `metadata` and the keys stay
readable, so the manifest is still reviewable and diffable, but the secret material is
sealed to a key only your operators (or a KMS/HSM) hold.

```
deploy/k8s/sops/
├── secrets.sops.example.yaml   # a real SOPS-encrypted Secret you can decrypt & study
├── age-example.key             # THROWAWAY demo key (public in this repo — DO NOT reuse)
├── apply.sh                    # decrypt → kubectl apply, plaintext never touches disk
└── README.md                   # this file
```

The encryption rules live in the repo-root [`.sops.yaml`](../../../.sops.yaml): any file
matching `deploy/k8s/sops/secrets*.yaml` gets its `data`/`stringData` values encrypted to the
configured age recipient. SOPS also works with **AWS/GCP/Azure KMS, HashiCorp Vault and PGP**
recipients — mix them in `.sops.yaml` for cloud KMS or multi-custodian setups.

## Try the example (learning)

The committed example is encrypted to a **throwaway key that is public in this repo**, so
you can decrypt it and see the whole flow. Never seal real secrets to it.

```bash
# install the tools (Go module installs work anywhere Go is available)
go install github.com/getsops/sops/v3/cmd/sops@latest
go install filippo.io/age/cmd/age-keygen@latest

# decrypt the example to inspect it (values come back in cleartext)
SOPS_AGE_KEY_FILE=deploy/k8s/sops/age-example.key \
  sops --decrypt deploy/k8s/sops/secrets.sops.example.yaml
```

## Real usage

```bash
# 1. Generate YOUR key and keep the private half out of git (.gitignore covers *.key)
age-keygen -o age.key
grep 'public key' age.key            # copy the age1... recipient

# 2. Put that recipient in .sops.yaml (replace the example one)

# 3. Author your secret from the plaintext template, then seal it in place
cp deploy/k8s/secret.example.yaml deploy/k8s/sops/secrets.sops.yaml
$EDITOR deploy/k8s/sops/secrets.sops.yaml     # fill real values
sops --encrypt --in-place deploy/k8s/sops/secrets.sops.yaml   # now safe to commit

# 4. Deploy — decrypt streams straight into kubectl, plaintext never hits disk
SOPS_AGE_KEY_FILE=age.key ./deploy/k8s/sops/apply.sh deploy/k8s/sops/secrets.sops.yaml
```

Edit a sealed file later with `sops deploy/k8s/sops/secrets.sops.yaml` (it decrypts into your
editor and re-encrypts on save), and rotate recipients with
`sops updatekeys deploy/k8s/sops/secrets.sops.yaml`.

## GitOps

- **Flux** decrypts SOPS natively — point a `Kustomization` at `.spec.decryption.provider: sops`
  with the age key in a cluster Secret. See the [Flux SOPS guide](https://fluxcd.io/flux/guides/mozilla-sops/).
- **Argo CD** works via the [helm-secrets](https://github.com/jkroepke/helm-secrets) or
  [ksops](https://github.com/viaduct-ai/kustomize-sops) plugins.
- **Helm**: [`helm secrets`](https://github.com/jkroepke/helm-secrets) wraps `helm` so a
  `deploy/helm/**/secrets*.sops.yaml` values file is decrypted at install/upgrade time.

Nothing in pamv1 *requires* SOPS — a plain `kubectl create secret` (or the Helm
`secret.data` values) still works. SOPS is the recommended way to keep the secret manifest
**in the same IaC repo** as the rest of the deployment without leaking it.
