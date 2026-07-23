# pamv1 — documentation

> **Living docs, kept in step with the code.** Every doc here carries a
> `Last updated · Reflects Phases 0–N` line and, where it tracks change, a
> change-log table at the foot. New to the project? Read the
> [main README](../README.md) first, then follow your audience path below.
>
> 🟢 **These are living documents — updated in the same change as the code, automatically.**
> Whenever a change touches structure, packages, schema, wire formats, env vars, the
> audit vocabulary, deploy manifests, ports/flows, or user-visible behavior, the affected
> living documents (and the two shareable overview artifacts, below) are updated in the
> **same** change — no separate approval step, no waiting to be asked. The full set is
> **every file listed under [Every document](#every-document)** plus `ROADMAP.md`, the root
> `README.md` / `README.es.md`, and the living overview artifacts
> ([English](https://claude.ai/code/artifact/a1b34e5b-cd84-4fc7-8389-ebb1897495f7) ·
> [Español](https://claude.ai/code/artifact/b9f19443-5ad1-42d2-955f-e43ca17ac542)).
> `ARCHITECTURE-DIAGRAMS.md` is **code-generated** (`go run ./cmd/archgen`, CI-enforced) — never hand-edited.

> ⚠️ **Alpha · for learning purposes.** pamv1 has not been security-audited and is
> not production-ready.

## Pick your path

| You are… | Read, in order |
|---|---|
| **New / evaluating** | [Sysadmin Guide](SYSADMIN-GUIDE.md) → [High-Level Architecture](ARCHITECTURE-HIGH-LEVEL.md) → [Requirements](REQUIREMENTS.md) |
| **Day-to-day operator** (connect, approve, audit) | [User Guide](USER-GUIDE.md) → [Sysadmin Guide (runbook)](SYSADMIN-GUIDE.md#6-day-to-day-operations-the-runbook) |
| **Administrator / deployer** | [Admin Guide](ADMIN-GUIDE.md) → [Requirements](REQUIREMENTS.md) → [Ports & Flows](PORTS-AND-FLOWS.md) → [Backup & Restore](BACKUP-AND-RESTORE.md) → [External-Infra Gaps](EXTERNAL-INFRA-GAPS.md) |
| **Developer / contributor** | [Low-Level Architecture](ARCHITECTURE-LOW-LEVEL.md) → [Code Guide](CODE-GUIDE.md) → [Architecture Diagrams](ARCHITECTURE-DIAGRAMS.md) → [ROADMAP](../ROADMAP.md) → [Security Gaps](SECURITY-GAPS.md) |
| **Auditor / compliance** | [NIS2 Compliance](NIS2-COMPLIANCE.md) → [Security Gaps](SECURITY-GAPS.md) → [User Guide (auditor)](USER-GUIDE.md) → [Admin Guide (audit)](ADMIN-GUIDE.md#92-audit-trail-database) |
| **OT / industrial operator** | [OT Deployment](OT-DEPLOYMENT.md) → [NIS2 Compliance](NIS2-COMPLIANCE.md) → [Ports & Flows](PORTS-AND-FLOWS.md) → [Admin Guide](ADMIN-GUIDE.md) |

## Every document

### Guides (task-oriented)
- **[SYSADMIN-GUIDE.md](SYSADMIN-GUIDE.md)** — the mental model + a `curl`/`ssh` runbook; the best first read for a shell-native admin.
- **[USER-GUIDE.md](USER-GUIDE.md)** — for operators, auditors and approvers: sign in, connect through the proxy, per-role abilities.
- **[ADMIN-GUIDE.md](ADMIN-GUIDE.md)** — the full reference: deploy, every `PAM_*` flag, manage targets/credentials/users/roles, break-glass, logging & audit.

### Architecture & code
- **[ARCHITECTURE-HIGH-LEVEL.md](ARCHITECTURE-HIGH-LEVEL.md)** — conceptual view: components, trust zones, data flows.
- **[ARCHITECTURE-LOW-LEVEL.md](ARCHITECTURE-LOW-LEVEL.md)** — the engineer's map: packages, schema, wire formats, the full `PAM_*` table, audit vocabulary, invariants. Read it first as a contributor.
- **[ARCHITECTURE-DIAGRAMS.md](ARCHITECTURE-DIAGRAMS.md)** — code-generated package graph, data model and REST-surface map (CI-enforced current; do not hand-edit).
- **[CODE-GUIDE.md](CODE-GUIDE.md)** — a narrative walkthrough of how the code actually runs, package by package and flow by flow.

### Deploy & operate
- **[REQUIREMENTS.md](REQUIREMENTS.md)** — run specs: ports, resource requests/limits, versions, rough sizing.
- **[PORTS-AND-FLOWS.md](PORTS-AND-FLOWS.md)** — the listener/egress matrix for firewalls, security groups, NetworkPolicies and OT segmentation.
- **[BACKUP-AND-RESTORE.md](BACKUP-AND-RESTORE.md)** — runbook for backing up the database and the vault KEK *separately*.
- **[EXTERNAL-INFRA-GAPS.md](EXTERNAL-INFRA-GAPS.md)** — what needs a real host/account to verify honestly before you rely on it.
- **[RDP-TESTING.md](RDP-TESTING.md)** — the procedure to verify the RDP path end to end: automated tests, a local runbook, and troubleshooting.

### Security, compliance & OT
- **[SECURITY-GAPS.md](SECURITY-GAPS.md)** — a security self-audit: every gap found, and whether it was fixed, mitigated or deferred.
- **[NIS2-COMPLIANCE.md](NIS2-COMPLIANCE.md)** — maps pamv1 features to Directive (EU) 2022/2555 (NIS2) Art. 21/23.
- **[OT-DEPLOYMENT.md](OT-DEPLOYMENT.md)** — the IEC 62443 / Purdue-model deployment pattern and OT-specific controls.

### Landscape
- **[RELATED-PROJECTS.md](RELATED-PROJECTS.md)** — where pamv1 sits among open-source projects and commercial PAM vendors.

## House style (for doc authors)

Keep the set reading as one product:

1. **H1** is `# pamv1 — <Title>` (project name first, em-dash separator, one per file).
2. **Status header**, a blockquote right under the H1: `> Last updated: YYYY-MM-DD · Reflects: Phases 0–N …` (use `Last updated`, ISO dates).
3. **Living-document note** (a blockquote) for any doc that tracks code: `> **Living document.** Update when <trigger> changes.` Generated docs say `> **Do not edit by hand.**` instead.
4. **Alpha banner** on every reader-facing doc: one blockquote, wording as above.
5. **Change-log table** at the foot of any doc that evolves — `| Date | Change |`, newest first, ISO dates. Bump the `Last updated` line to the newest change-log date.
6. **Diagrams are [Mermaid](https://mermaid.js.org/), never ASCII** (repo hard rule); wrap wide diagrams so they scroll, not the page.
7. **Cross-links are relative paths**: bare `FILE.md` for siblings here, `../ROADMAP.md` / `../README.md` / `../deploy/…` for repo-root and code; deep-link a section with `#anchor`. No absolute GitHub URLs for in-repo files.
8. **Fixed vocabulary**: *target* (an onboarded machine/database), *credential* (the vaulted object) vs *secret* (its plaintext), *operator* (a human using the proxy) vs *user* (the RBAC role), *portal* (the web app) vs *console* (its 5250 UI), **PAM token** (a per-user/session token) vs **bootstrap API key** (`PAM_API_KEY`).
9. **Every reader-facing doc links back** here or to the [README](../README.md), so no doc is a dead end.
10. **Update the doc in the same commit as the code it describes** — that is what keeps this set trustworthy.
