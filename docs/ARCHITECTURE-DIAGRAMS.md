# pamv1 — Architecture Diagrams (generated)

> **Do not edit by hand.** This file is regenerated from the source by
> `go run ./cmd/archgen` (or `go generate ./...`). CI runs the
> generator and fails if the committed copy is stale, so these diagrams stay in
> step with the code on every change. Conceptual flows (trust zones, the JIT
> proxy sequence, deployment) live in the hand-authored
> [High-Level Architecture](ARCHITECTURE-HIGH-LEVEL.md) and
> [Low-Level Architecture](ARCHITECTURE-LOW-LEVEL.md).

Rendering: these are [Mermaid](https://mermaid.js.org/) diagrams; GitHub renders
them inline.

## 1. Package dependency graph

Every Go package in the module and the imports between them. Arrows point from a package to the packages it imports.

```mermaid
flowchart LR
  subgraph n_Entry_point["Entry point"]
    n_archgen[archgen]
    n_pam_server[pam-server]
  end
  subgraph n_Interface["Interface"]
    n_api[api]
    n_proxy[proxy]
    n_web[web]
  end
  subgraph n_Identity___authz["Identity & authz"]
    n_auth[auth]
    n_mfa[mfa]
    n_oidc[oidc]
  end
  subgraph n_Secrets["Secrets"]
    n_shamir[shamir]
    n_vault[vault]
  end
  subgraph n_Persistence["Persistence"]
    n_memstore[memstore]
    n_pgstore[pgstore]
    n_store[store]
    n_storetest[storetest]
  end
  subgraph n_Connectors["Connectors"]
    n_discovery[discovery]
    n_guacd[guacd]
    n_rotate[rotate]
    n_winrm[winrm]
  end
  subgraph n_Agent_broker["Agent broker"]
    n_agentid[agentid]
    n_auditchain[auditchain]
    n_broker[broker]
    n_mcp[mcp]
    n_policy[policy]
  end
  subgraph n_Platform["Platform"]
    n_alert[alert]
    n_config[config]
    n_logging[logging]
    n_maint[maint]
    n_metrics[metrics]
    n_session[session]
  end
  subgraph n_Other["Other"]
    n_conjur[conjur]
  end
  n_agentid --> n_auth
  n_agentid --> n_store
  n_alert --> n_logging
  n_api --> n_agentid
  n_api --> n_alert
  n_api --> n_auditchain
  n_api --> n_auth
  n_api --> n_broker
  n_api --> n_config
  n_api --> n_discovery
  n_api --> n_guacd
  n_api --> n_logging
  n_api --> n_mcp
  n_api --> n_metrics
  n_api --> n_mfa
  n_api --> n_oidc
  n_api --> n_policy
  n_api --> n_rotate
  n_api --> n_session
  n_api --> n_shamir
  n_api --> n_store
  n_api --> n_vault
  n_api --> n_web
  n_api --> n_winrm
  n_auditchain --> n_store
  n_auth --> n_oidc
  n_auth --> n_store
  n_broker --> n_agentid
  n_broker --> n_alert
  n_broker --> n_auditchain
  n_broker --> n_auth
  n_broker --> n_logging
  n_broker --> n_policy
  n_broker --> n_store
  n_conjur --> n_logging
  n_maint --> n_store
  n_maint --> n_vault
  n_memstore --> n_store
  n_pam_server --> n_agentid
  n_pam_server --> n_alert
  n_pam_server --> n_api
  n_pam_server --> n_auditchain
  n_pam_server --> n_auth
  n_pam_server --> n_config
  n_pam_server --> n_conjur
  n_pam_server --> n_logging
  n_pam_server --> n_maint
  n_pam_server --> n_memstore
  n_pam_server --> n_oidc
  n_pam_server --> n_pgstore
  n_pam_server --> n_policy
  n_pam_server --> n_proxy
  n_pam_server --> n_session
  n_pam_server --> n_shamir
  n_pam_server --> n_store
  n_pam_server --> n_vault
  n_pam_server --> n_winrm
  n_pgstore --> n_logging
  n_pgstore --> n_store
  n_proxy --> n_auth
  n_proxy --> n_logging
  n_proxy --> n_session
  n_proxy --> n_store
  n_proxy --> n_vault
  n_proxy --> n_winrm
  n_rotate --> n_store
  n_rotate --> n_winrm
  n_storetest --> n_store
```

## 2. Domain data model

Entities are the exported structs in `internal/store/store.go` (never-serialized fields such as `SecretEnc`/`TokenHash` are omitted). Relationships are inferred from `<Entity>ID` foreign keys.

```mermaid
erDiagram
  AccessRequest {
    int64 ID
    string Requester
    int64 TargetID
    string Reason
    string Status
    string Approver
    time_Time CreatedAt
    ptr_time_Time DecidedAt
    time_Time ExpiresAt
  }
  AgentKey {
    int64 ID
    string Name
    string Owner
    bool Disabled
    time_Time CreatedAt
  }
  AuditEvent {
    int64 ID
    time_Time TS
    string Actor
    string Action
    string Detail
  }
  BrokerAuditEvent {
    int64 ID
    time_Time TS
    string Actor
    string OnBehalfOf
    string ActorChain
    string Action
    string Detail
    string Scope
    arr_byte HMAC
  }
  BrokerToken {
    string CallID
    time_Time ExpiresAt
    ptr_time_Time UsedAt
  }
  Checkout {
    int64 ID
    int64 CredentialID
    int64 TargetID
    string Holder
    string Reason
    time_Time CheckedOutAt
    time_Time ExpiresAt
    ptr_time_Time ReturnedAt
  }
  Credential {
    int64 ID
    int64 TargetID
    string Username
    string SecretType
    time_Time CreatedAt
    ptr_time_Time RotatedAt
  }
  CredentialDependency {
    int64 ID
    int64 CredentialID
    string Kind
    string Host
    int Port
    string Name
  }
  MFAEnrollment {
    string Username
    bool Confirmed
    time_Time CreatedAt
  }
  Profile {
    int64 ID
    string Name
    arr_string Capabilities
    time_Time CreatedAt
  }
  Safe {
    int64 ID
    string Name
    string Description
    time_Time CreatedAt
  }
  SafeMember {
    int64 ID
    int64 SafeID
    string SubjectType
    string Subject
    bool CanManage
  }
  Session {
    int64 ID
    string Username
    string Role
    string Roles
    string Scope
    time_Time CreatedAt
    time_Time ExpiresAt
  }
  Setting {
    string Key
    string Value
    bool Secret
    time_Time UpdatedAt
  }
  Target {
    int64 ID
    string Name
    string Host
    int Port
    string OSType
    string Protocol
    bool RequireApproval
    ptr_int64 SafeID
    time_Time CreatedAt
  }
  TargetGrant {
    int64 ID
    int64 TargetID
    string SubjectType
    string Subject
  }
  User {
    int64 ID
    string Username
    string Role
    time_Time CreatedAt
  }
  Credential ||--o{ Checkout : "has"
  Credential ||--o{ CredentialDependency : "has"
  Safe ||--o{ SafeMember : "has"
  Safe ||--o{ Target : "has"
  Target ||--o{ AccessRequest : "has"
  Target ||--o{ Checkout : "has"
  Target ||--o{ Credential : "has"
  Target ||--o{ TargetGrant : "has"
```

## 3. REST API surface

The 78 routes registered on the API mux, with the capability or guard each enforces (see `internal/auth` for the role → capability matrix).

| Method | Path | Guard |
|---|---|---|
| GET | `/api/access-requests` | CapApprove |
| POST | `/api/access-requests` | CapConnect |
| POST | `/api/access-requests/{id}/approve` | CapApprove |
| POST | `/api/access-requests/{id}/deny` | CapApprove |
| GET | `/api/audit` | CapReadAudit |
| GET | `/api/audit/export` | CapReadAudit |
| GET | `/api/auth/oidc/callback` | public (rate-limited) |
| GET | `/api/auth/oidc/start` | public (rate-limited) |
| POST | `/api/breakglass/unseal` | public (rate-limited) |
| GET | `/api/checkouts` | CapReadAudit |
| GET | `/api/config` | CapManageUsers |
| PUT | `/api/config` | CapManageUsers |
| GET | `/api/config/effective` | CapManageUsers |
| GET | `/api/config/iac` | CapManageUsers |
| DELETE | `/api/config/{key}` | CapManageUsers |
| GET | `/api/credentials` | CapReadInventory |
| POST | `/api/credentials` | CapManageCredentials |
| DELETE | `/api/credentials/{id}` | CapManageCredentials |
| POST | `/api/credentials/{id}/checkin` | CapRevealSecret |
| POST | `/api/credentials/{id}/checkout` | CapRevealSecret |
| GET | `/api/credentials/{id}/dependencies` | CapReadInventory |
| POST | `/api/credentials/{id}/dependencies` | CapManageCredentials |
| DELETE | `/api/credentials/{id}/dependencies/{did}` | CapManageCredentials |
| POST | `/api/credentials/{id}/reconcile` | CapManageCredentials |
| POST | `/api/credentials/{id}/reveal` | CapRevealSecret |
| POST | `/api/credentials/{id}/rotate` | CapManageCredentials |
| POST | `/api/discovery/scan` | CapManageTargets |
| POST | `/api/identity/reconcile` | CapManageUsers |
| POST | `/api/login` | public (rate-limited) |
| POST | `/api/logout` | authenticated |
| GET | `/api/me` | authenticated |
| DELETE | `/api/mfa` | authenticated |
| GET | `/api/mfa` | authenticated |
| POST | `/api/mfa/enroll` | authenticated |
| POST | `/api/mfa/recovery-codes` | authenticated |
| POST | `/api/mfa/verify` | authenticated |
| GET | `/api/profiles` | CapManageUsers |
| POST | `/api/profiles` | CapManageUsers |
| DELETE | `/api/profiles/{id}` | CapManageUsers |
| GET | `/api/reconcile` | CapManageCredentials |
| GET | `/api/safes` | CapReadInventory |
| POST | `/api/safes` | CapManageTargets |
| DELETE | `/api/safes/{id}` | CapManageTargets |
| GET | `/api/safes/{id}/members` | CapReadInventory |
| POST | `/api/safes/{id}/members` | CapReadInventory |
| DELETE | `/api/safes/{id}/members/{mid}` | CapReadInventory |
| GET | `/api/sessions` | CapReadAudit |
| DELETE | `/api/sessions/{id}` | CapManageTargets |
| GET | `/api/sessions/{id}/stream` | CapReadAudit |
| GET | `/api/targets` | CapReadInventory |
| POST | `/api/targets` | CapManageTargets |
| DELETE | `/api/targets/{id}` | CapManageTargets |
| GET | `/api/targets/{id}` | CapReadInventory |
| GET | `/api/targets/{id}/grants` | CapManageTargets |
| POST | `/api/targets/{id}/grants` | CapManageTargets |
| DELETE | `/api/targets/{id}/grants/{gid}` | CapManageTargets |
| GET | `/api/targets/{id}/rdp` | token (query) |
| PUT | `/api/targets/{id}/safe` | CapManageTargets |
| POST | `/api/targets/{id}/winrm` | CapConnect |
| GET | `/api/users` | CapManageUsers |
| POST | `/api/users` | CapManageUsers |
| DELETE | `/api/users/{id}` | CapManageUsers |
| GET | `/healthz` | public |
| POST | `/mcp` | public |
| GET | `/metrics` | public |
| GET | `/readyz` | public |
| GET | `/v1/agents` | CapManageUsers |
| POST | `/v1/agents` | CapManageUsers |
| DELETE | `/v1/agents/{id}` | CapManageUsers |
| GET | `/v1/approvals` | CapApprove |
| POST | `/v1/approvals/{id}/decision` | CapApprove |
| GET | `/v1/audit` | CapReadAudit |
| GET | `/v1/audit/head` | CapReadAudit |
| GET | `/v1/audit/verify` | CapReadAudit |
| POST | `/v1/tool-calls` | public |
| GET | `/v1/tool-calls/{id}` | public |
| POST | `/v1/tool-calls/{id}/resume` | public |
| GET | `/{$}` | public |

