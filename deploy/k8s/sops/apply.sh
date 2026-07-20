#!/usr/bin/env bash
# Decrypt a SOPS-sealed Secret and apply it to the cluster, without ever writing
# the plaintext to disk (it streams straight into kubectl). Phase 14.
#
# Usage:
#   SOPS_AGE_KEY_FILE=~/.config/sops/age/keys.txt \
#     ./deploy/k8s/sops/apply.sh [deploy/k8s/sops/secrets.sops.yaml]
#
# Requirements: sops + age on PATH, and your age private key reachable via
# SOPS_AGE_KEY_FILE (or SOPS_AGE_KEY). For the committed example you can point at
# the throwaway key — DEMO ONLY:
#   SOPS_AGE_KEY_FILE=deploy/k8s/sops/age-example.key ./deploy/k8s/sops/apply.sh \
#     deploy/k8s/sops/secrets.sops.example.yaml
set -euo pipefail

FILE="${1:-deploy/k8s/sops/secrets.sops.yaml}"

command -v sops >/dev/null || { echo "sops not found on PATH (see deploy/k8s/sops/README.md)"; exit 1; }
[ -f "$FILE" ] || { echo "no such SOPS file: $FILE"; exit 1; }
if [ -z "${SOPS_AGE_KEY_FILE:-}" ] && [ -z "${SOPS_AGE_KEY:-}" ]; then
  echo "set SOPS_AGE_KEY_FILE (or SOPS_AGE_KEY) to your age private key"; exit 1
fi

echo "decrypting $FILE and applying to the cluster…"
sops --decrypt "$FILE" | kubectl apply -f -
echo "done. (the plaintext was never written to disk)"
