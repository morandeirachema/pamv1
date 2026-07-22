// Package store defines the persistence contract for the PAM inventory,
// vaulted credentials and the audit trail. The production implementation
// is PostgreSQL (pgstore); memstore backs tests and ephemeral demos.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: already exists")
)

// CredentialAAD is the additional-authenticated-data string that binds a
// vaulted secret to its owning target AND its specific credential row, so a
// ciphertext copied onto another credential (even on the same target) fails to
// decrypt. The API, the session proxy and the rotation/maintenance paths must
// all use the same value or decryption fails. Because it needs the credential's
// ID, a newly created credential is inserted first (to assign the ID) and its
// secret encrypted and stored in a second step.
func CredentialAAD(targetID, credentialID int64) string {
	return fmt.Sprintf("target:%d/cred:%d", targetID, credentialID)
}

// MFAAAD binds a vaulted TOTP secret to its owning user.
func MFAAAD(username string) string {
	return "mfa:" + username
}

// ConfigAAD binds a vault-encrypted configuration setting (e.g. an LDAP bind
// password or an OIDC client secret) to its key.
func ConfigAAD(key string) string {
	return "config:" + key
}

// Target is a machine reachable through the PAM (a future proxy session
// connects to it injecting a vaulted credential just-in-time).
type Target struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	OSType   string `json:"os_type"`  // linux | windows
	Protocol string `json:"protocol"` // ssh | winrm | rdp
	// RequireApproval gates connections behind an approved access request
	// (4-eyes / maintenance-window control, used in OT deployments).
	RequireApproval bool `json:"require_approval"`
	// SafeID, when set, places the target in a safe (Phase 17): safe members may
	// connect to every target in the safe. nil means the target is not in a safe.
	SafeID    *int64    `json:"safe_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Campaign is an access-certification (attestation) campaign: a point-in-time
// review of who has access to what, so a reviewer certifies or revokes each
// grant (Phase 19 — a SOX / ISO 27001 / NIS2 access-review control).
type Campaign struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	DueAt     *time.Time `json:"due_at,omitempty"`
	Status    string     `json:"status"` // open | closed
	ClosedAt  *time.Time `json:"closed_at,omitempty"`
}

// CampaignItem is one access grant under review in a campaign. RefID points at
// the underlying grant so a "revoke" decision can delete it.
type CampaignItem struct {
	ID          int64      `json:"id"`
	CampaignID  int64      `json:"campaign_id"`
	Kind        string     `json:"kind"`   // target_grant | safe_member
	RefID       int64      `json:"ref_id"` // id of the underlying grant/member
	SubjectType string     `json:"subject_type"`
	Subject     string     `json:"subject"`
	Detail      string     `json:"detail"`   // human-readable ("grant on target web-01")
	Decision    string     `json:"decision"` // pending | certified | revoked
	DecidedBy   string     `json:"decided_by,omitempty"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
}

// CredentialDependency declares a consumer of a credential — a Windows Service,
// Scheduled Task or IIS App Pool that logs on with the account — so that when
// the credential is rotated, pamv1 also updates the consumer over WinRM and the
// rotation does not break production (Phase 17).
type CredentialDependency struct {
	ID           int64  `json:"id"`
	CredentialID int64  `json:"credential_id"`
	Kind         string `json:"kind"` // windows_service | scheduled_task | iis_apppool
	Host         string `json:"host"` // WinRM-reachable host running the consumer
	Port         int    `json:"port"` // WinRM port (0 → 5985)
	Name         string `json:"name"` // service / task / app-pool name
}

// Safe is a named container that groups targets and delegates who may access
// them (Phase 17). Membership is an additional grant path alongside per-target
// grants: a member of a target's safe may connect to it.
type Safe struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// SafeMember authorizes a subject (a user or a role) on a safe. CanManage marks
// a delegated safe administrator (may add/remove members of that safe).
type SafeMember struct {
	ID          int64  `json:"id"`
	SafeID      int64  `json:"safe_id"`
	SubjectType string `json:"subject_type"` // user | role
	Subject     string `json:"subject"`
	CanManage   bool   `json:"can_manage"`
}

// AccessRequest is a user's request to connect to a target, subject to approval
// by a different principal (4-eyes). When a target (or global OT policy) requires
// approval, connect paths admit only a requester with an approved, unexpired
// request. Statuses: pending | approved | denied.
type AccessRequest struct {
	ID        int64      `json:"id"`
	Requester string     `json:"requester"`
	TargetID  int64      `json:"target_id"`
	Reason    string     `json:"reason"`
	Status    string     `json:"status"`
	Approver  string     `json:"approver,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	DecidedAt *time.Time `json:"decided_at,omitempty"`
	ExpiresAt time.Time  `json:"expires_at"`
	// Ticket is an optional ITSM change/incident reference (Phase 20). When
	// ticket validation is configured it is validated before the request is
	// created, and it is recorded in the audit trail.
	Ticket string `json:"ticket,omitempty"`
	// RequiredApprovals is how many DISTINCT approvers must approve before the
	// request is granted (Phase 21 multi-tier chains; default 1). ApprovedBy is
	// the comma-joined set of approvers so far. NotBefore, when set, delays when
	// an approved request becomes active (a scheduled maintenance window).
	RequiredApprovals int        `json:"required_approvals,omitempty"`
	ApprovedBy        string     `json:"approved_by,omitempty"`
	NotBefore         *time.Time `json:"not_before,omitempty"`
}

// Credential is a privileged account on a Target. SecretEnc is always an
// encrypted vault token — plaintext never touches the store or the JSON
// encoder (note the "-" tag).
type Credential struct {
	ID         int64      `json:"id"`
	TargetID   int64      `json:"target_id"`
	Username   string     `json:"username"`
	SecretType string     `json:"secret_type"` // password | ssh_key
	SecretEnc  string     `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	RotatedAt  *time.Time `json:"rotated_at,omitempty"`
}

// TargetGrant authorizes a subject (a specific user, or a whole role) to connect
// to a target. A target with no grants is open to any connect-capable principal;
// once it has grants, only matching subjects (plus admins) may connect.
type TargetGrant struct {
	ID          int64  `json:"id"`
	TargetID    int64  `json:"target_id"`
	SubjectType string `json:"subject_type"` // user | role
	Subject     string `json:"subject"`
}

// Checkout is an exclusive, time-boxed lease on a credential. While a checkout
// is active no other holder may check the same credential out; on check-in the
// credential is rotated so the password the holder saw can no longer be used.
type Checkout struct {
	ID           int64      `json:"id"`
	CredentialID int64      `json:"credential_id"`
	TargetID     int64      `json:"target_id"`
	Holder       string     `json:"holder"`
	Reason       string     `json:"reason"`
	CheckedOutAt time.Time  `json:"checked_out_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	ReturnedAt   *time.Time `json:"returned_at,omitempty"`
}

type AuditEvent struct {
	ID     int64     `json:"id"`
	TS     time.Time `json:"ts"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Detail string    `json:"detail"`
}

// User is a local identity with a role. The access token is stored only as a
// hex SHA-256 (TokenHash, never serialized); the plaintext token is shown to
// the admin exactly once, at creation.
type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"` // admin | user | auditor | approver
	TokenHash string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

// AgentKey is an AI-agent identity for the access broker: a bearer key whose
// SHA-256 hash is stored, granting only the ability to request brokered tool
// calls (never a credential). Owner is the accountable human/service recorded in
// every audit entry the agent produces.
type AgentKey struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Owner     string    `json:"owner"`
	TokenHash string    `json:"-"`
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"created_at"`
}

// AppKey is a non-human application identity for the application-secrets API
// (Phase 24, Tier-4 Conjur-style secret delivery): a bearer key whose SHA-256
// hash is stored, letting an application retrieve only the specific secrets it
// has been explicitly granted — nothing else. Owner is the accountable
// human/team recorded in the audit trail.
type AppKey struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Owner     string    `json:"owner"`
	TokenHash string    `json:"-"`
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"created_at"`
}

// AppSecretGrant authorizes an application (AppKey) to retrieve one specific
// credential's secret through the application-secrets API. Access is
// default-deny: an app may fetch only the credentials it has an explicit grant
// for.
type AppSecretGrant struct {
	ID           int64     `json:"id"`
	AppID        int64     `json:"app_id"`
	CredentialID int64     `json:"credential_id"`
	CreatedAt    time.Time `json:"created_at"`
}

// BrokerToken is a short-lived, single-use ticket the broker mints when a tool
// call is parked for approval (Phase 13). The agent presents its opaque token to
// resume and collect the post-approval result exactly once; the stored JTI is the
// token's SHA-256 hash, bound to the parked call and an expiry.
type BrokerToken struct {
	JTI       string     `json:"-"` // SHA-256 hex of the opaque token
	CallID    string     `json:"call_id"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
}

// Profile is a named, custom capability set (Phase 12) assignable to users as an
// alternative to the four built-in roles. Capabilities holds the stable
// capability names defined in internal/auth.
type Profile struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	Capabilities []string  `json:"capabilities"`
	CreatedAt    time.Time `json:"created_at"`
}

// Setting is a persisted configuration override (Phase 12): a PAM_* key whose
// value takes precedence over the environment for the identity backends, SSO,
// and operational policy. Secret values (bind passwords, client secrets) are
// stored vault-encrypted (Value is a "v2:" token, Secret is true).
type Setting struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	Secret    bool      `json:"secret"`
	UpdatedAt time.Time `json:"updated_at"`
}

// BrokerAuditEvent is one entry in the broker's tamper-evident, keyed-HMAC
// hash-chained audit log (separate from the general audit_events trail). Each
// row's HMAC covers the previous row's HMAC, so any edit or truncation breaks
// the chain. The broker is the sole writer, so rows chain in id order.
type BrokerAuditEvent struct {
	ID         int64     `json:"id"`
	TS         time.Time `json:"ts"`
	Actor      string    `json:"actor"`        // agent name
	OnBehalfOf string    `json:"on_behalf_of"` // accountable owner / SVID on_behalf_of
	ActorChain string    `json:"actor_chain"`  // JSON array of the delegation actor chain
	Action     string    `json:"action"`
	Detail     string    `json:"detail"`
	Scope      string    `json:"scope"`
	PrevHash   []byte    `json:"-"`    // previous row's HMAC (chain link); derivable, not exposed
	HMAC       []byte    `json:"hmac"` // HMAC-SHA256(key, prev_hash || canonical(event))
}

// Session is a short-lived bearer token issued after a password login (e.g.
// Active Directory). Only the token's hex SHA-256 is stored (never serialized).
type Session struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	// Roles is the comma-separated set of directory-matched roles for a multi-group
	// login (empty for a single role), so the resolved principal gets their union.
	Roles     string    `json:"roles,omitempty"`
	Scope     string    `json:"scope"` // "" (full) | "enroll" (MFA enrollment only)
	TokenHash string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// MFAEnrollment is a user's TOTP second factor. SecretEnc is the vault-encrypted
// TOTP secret (never serialized); Confirmed is set once the user proves they can
// generate a valid code.
type MFAEnrollment struct {
	Username  string    `json:"username"`
	SecretEnc string    `json:"-"`
	Confirmed bool      `json:"confirmed"`
	CreatedAt time.Time `json:"created_at"`
	// LastTOTPStep is the highest TOTP time-step counter accepted for this user,
	// used to reject a code replayed within the skew window.
	LastTOTPStep int64 `json:"-"`
}

type Store interface {
	// CreateTarget inserts a target, populating its ID and CreatedAt.
	CreateTarget(ctx context.Context, t *Target) error
	// ListTargets returns all targets.
	ListTargets(ctx context.Context) ([]Target, error)
	// GetTarget returns one target by ID, or ErrNotFound.
	GetTarget(ctx context.Context, id int64) (*Target, error)
	// DeleteTarget removes a target (cascading to its dependents), or ErrNotFound.
	DeleteTarget(ctx context.Context, id int64) error

	// CreateCredential inserts a credential for a target, or ErrNotFound if the target is missing.
	CreateCredential(ctx context.Context, c *Credential) error
	// ListCredentials returns credentials for one target, or all when targetID is 0.
	ListCredentials(ctx context.Context, targetID int64) ([]Credential, error)
	// GetCredential returns one credential by ID, or ErrNotFound.
	GetCredential(ctx context.Context, id int64) (*Credential, error)
	// UpdateCredentialSecretEnc replaces a credential's encrypted secret (used
	// by vault key rotation). It deliberately does NOT touch rotated_at — a KEK
	// re-wrap is not a credential rotation.
	UpdateCredentialSecretEnc(ctx context.Context, id int64, secretEnc string) error
	// RotateCredentialSecret replaces the encrypted secret AND stamps rotated_at
	// (used by the credential-lifecycle rotation, where the secret on the target
	// actually changed).
	RotateCredentialSecret(ctx context.Context, id int64, secretEnc string, rotatedAt time.Time) error
	// DeleteCredential removes a credential by ID, or ErrNotFound.
	DeleteCredential(ctx context.Context, id int64) error

	// CreateTargetGrant adds an authorization grant to a target.
	CreateTargetGrant(ctx context.Context, g *TargetGrant) error
	// ListTargetGrants returns the grants for a target.
	ListTargetGrants(ctx context.Context, targetID int64) ([]TargetGrant, error)
	// DeleteTargetGrant removes a grant by ID, or ErrNotFound.
	DeleteTargetGrant(ctx context.Context, id int64) error
	// EffectiveTargetGrants returns a target's direct grants unioned with the
	// grants derived from its safe's membership (Phase 17). The connect-time
	// authorization decision uses this, so a target in a safe is reachable by the
	// safe's members. An empty result means the target is unrestricted (open).
	EffectiveTargetGrants(ctx context.Context, targetID int64) ([]TargetGrant, error)

	// CreateSafe inserts a safe, populating its ID and CreatedAt.
	CreateSafe(ctx context.Context, s *Safe) error
	// ListSafes returns all safes ordered by name.
	ListSafes(ctx context.Context) ([]Safe, error)
	// GetSafe returns a safe by ID, or ErrNotFound.
	GetSafe(ctx context.Context, id int64) (*Safe, error)
	// DeleteSafe removes a safe by ID (its members cascade; member targets are
	// unassigned), or ErrNotFound.
	DeleteSafe(ctx context.Context, id int64) error
	// AddSafeMember adds a member to a safe (ErrConflict on a duplicate subject,
	// ErrNotFound if the safe does not exist).
	AddSafeMember(ctx context.Context, m *SafeMember) error
	// ListSafeMembers returns a safe's members ordered by id.
	ListSafeMembers(ctx context.Context, safeID int64) ([]SafeMember, error)
	// DeleteSafeMember removes a safe member by ID, or ErrNotFound.
	DeleteSafeMember(ctx context.Context, id int64) error
	// AssignTargetSafe sets (or clears, when safeID is nil) a target's safe.
	AssignTargetSafe(ctx context.Context, targetID int64, safeID *int64) error

	// CreateCredentialDependency declares a consumer of a credential (ErrNotFound
	// if the credential does not exist).
	CreateCredentialDependency(ctx context.Context, d *CredentialDependency) error
	// ListCredentialDependencies returns a credential's declared consumers.
	ListCredentialDependencies(ctx context.Context, credentialID int64) ([]CredentialDependency, error)
	// DeleteCredentialDependency removes a dependency by ID, or ErrNotFound.
	DeleteCredentialDependency(ctx context.Context, id int64) error

	// CreateCampaign inserts a certification campaign, populating ID/CreatedAt.
	CreateCampaign(ctx context.Context, c *Campaign) error
	// ListCampaigns returns all campaigns, newest first.
	ListCampaigns(ctx context.Context) ([]Campaign, error)
	// GetCampaign returns a campaign by ID, or ErrNotFound.
	GetCampaign(ctx context.Context, id int64) (*Campaign, error)
	// CloseCampaign marks a campaign closed at the given time, or ErrNotFound.
	CloseCampaign(ctx context.Context, id int64, at time.Time) error
	// AddCampaignItem adds one access item to a campaign (ErrNotFound if absent).
	AddCampaignItem(ctx context.Context, item *CampaignItem) error
	// ListCampaignItems returns a campaign's items ordered by id.
	ListCampaignItems(ctx context.Context, campaignID int64) ([]CampaignItem, error)
	// GetCampaignItem returns one item by ID, or ErrNotFound.
	GetCampaignItem(ctx context.Context, id int64) (*CampaignItem, error)
	// DecideCampaignItem records a certify/revoke decision on an item.
	DecideCampaignItem(ctx context.Context, id int64, decision, decidedBy string, at time.Time) error

	// Access requests (4-eyes approval workflow).
	CreateAccessRequest(ctx context.Context, ar *AccessRequest) error
	// GetAccessRequest returns one access request by ID, or ErrNotFound.
	GetAccessRequest(ctx context.Context, id int64) (*AccessRequest, error)
	// ListAccessRequests returns requests with the given status, or all when
	// status is "".
	ListAccessRequests(ctx context.Context, status string) ([]AccessRequest, error)
	// DecideAccessRequest records an approve/deny decision by approver.
	DecideAccessRequest(ctx context.Context, id int64, status, approver string, decidedAt time.Time) error
	// SetApprovalState records a multi-approver decision (Phase 21): the updated
	// distinct-approver set, the resulting status ("pending" while partial,
	// "approved" once the required count is met), the final approver, and the
	// decided-at time (nil while still partial).
	SetApprovalState(ctx context.Context, id int64, approvedBy, status, approver string, decidedAt *time.Time) error
	// HasActiveApproval reports whether requester has an approved, unexpired
	// request for targetID as of now.
	HasActiveApproval(ctx context.Context, requester string, targetID int64, now time.Time) (bool, error)

	// Credential checkout/check-in (exclusive time-boxed leases).
	// CreateCheckout fails with ErrConflict if the credential already has an
	// active (unreturned, unexpired) checkout as of now.
	CreateCheckout(ctx context.Context, co *Checkout, now time.Time) error
	// GetActiveCheckout returns the active checkout for a credential, or ErrNotFound.
	GetActiveCheckout(ctx context.Context, credentialID int64, now time.Time) (*Checkout, error)
	// CheckinCheckout marks a checkout returned; ErrNotFound if missing or already returned.
	CheckinCheckout(ctx context.Context, id int64, at time.Time) error
	// ListCheckouts lists checkouts; activeOnly limits to unreturned, unexpired ones.
	ListCheckouts(ctx context.Context, activeOnly bool, now time.Time) ([]Checkout, error)

	// AppendAudit appends an audit event, populating its ID and TS.
	AppendAudit(ctx context.Context, e *AuditEvent) error
	// ListAudit returns the most recent audit events, newest first.
	ListAudit(ctx context.Context, limit int) ([]AuditEvent, error)
	// ExportAudit returns every audit event with since <= ts < until, ordered
	// oldest-first (for NIS2 incident-report exports). A zero since means "from
	// the beginning"; a zero until means "up to now".
	ExportAudit(ctx context.Context, since, until time.Time) ([]AuditEvent, error)

	// CreateUser inserts a user, populating its ID and CreatedAt.
	CreateUser(ctx context.Context, u *User) error
	// ListUsers returns all users.
	ListUsers(ctx context.Context) ([]User, error)
	// GetUserByTokenHash returns the user whose token hash matches, or ErrNotFound.
	GetUserByTokenHash(ctx context.Context, tokenHashHex string) (*User, error)
	// DeleteUser removes a user by ID, or ErrNotFound.
	DeleteUser(ctx context.Context, id int64) error

	// CreateAgentKey inserts an AI-agent identity key, populating ID and CreatedAt.
	CreateAgentKey(ctx context.Context, k *AgentKey) error
	// GetAgentKey returns an agent key by ID, or ErrNotFound — used to re-check an
	// agent is still enabled at approval time (post-park revocation).
	GetAgentKey(ctx context.Context, id int64) (*AgentKey, error)
	// GetAgentKeyByTokenHash returns the enabled agent key whose token hash
	// matches, or ErrNotFound (a disabled key is treated as not found).
	GetAgentKeyByTokenHash(ctx context.Context, tokenHashHex string) (*AgentKey, error)
	// ListAgentKeys returns all agent keys.
	ListAgentKeys(ctx context.Context) ([]AgentKey, error)
	// DeleteAgentKey removes an agent key by ID, or ErrNotFound.
	DeleteAgentKey(ctx context.Context, id int64) error

	// CreateAppKey inserts an application identity key, populating ID and CreatedAt
	// (ErrConflict on a duplicate token hash).
	CreateAppKey(ctx context.Context, k *AppKey) error
	// GetAppKeyByTokenHash returns the enabled app key whose token hash matches, or
	// ErrNotFound (a disabled key is treated as not found).
	GetAppKeyByTokenHash(ctx context.Context, tokenHashHex string) (*AppKey, error)
	// ListAppKeys returns all application keys.
	ListAppKeys(ctx context.Context) ([]AppKey, error)
	// DeleteAppKey removes an app key by ID (cascading its secret grants), or ErrNotFound.
	DeleteAppKey(ctx context.Context, id int64) error
	// GrantAppSecret authorizes an app to retrieve a credential's secret
	// (ErrConflict on a duplicate grant, ErrNotFound if the app or credential is missing).
	GrantAppSecret(ctx context.Context, g *AppSecretGrant) error
	// ListAppSecretGrants returns an app's secret grants ordered by id.
	ListAppSecretGrants(ctx context.Context, appID int64) ([]AppSecretGrant, error)
	// DeleteAppSecretGrant removes a grant by ID, or ErrNotFound.
	DeleteAppSecretGrant(ctx context.Context, id int64) error
	// AppMayAccessCredential reports whether app appID has a grant for credentialID.
	AppMayAccessCredential(ctx context.Context, appID, credentialID int64) (bool, error)

	// CreateBrokerToken stores a single-use resume token (its JTI is the token's
	// SHA-256 hash) for a parked, approval-pending tool call.
	CreateBrokerToken(ctx context.Context, t *BrokerToken) error
	// ConsumeBrokerToken atomically spends the token identified by jti, returning
	// the bound call id. It succeeds at most once: a used, expired, or unknown jti
	// yields ErrNotFound, so a replayed token can never collect a result twice.
	ConsumeBrokerToken(ctx context.Context, jti string) (callID string, err error)
	// PeekBrokerToken returns the call id a token is bound to WITHOUT spending it
	// (ErrNotFound if used/expired/unknown), so a resume can avoid burning the
	// token before the parked call is ready to collect.
	PeekBrokerToken(ctx context.Context, jti string) (callID string, err error)
	// DeleteExpiredBrokerTokens removes spent or expired tokens, returning the
	// count deleted; a periodic sweep keeps the table bounded.
	DeleteExpiredBrokerTokens(ctx context.Context) (int64, error)

	// PutSetting upserts a configuration override, stamping UpdatedAt.
	PutSetting(ctx context.Context, s *Setting) error
	// GetSetting returns the override for key, or ErrNotFound.
	GetSetting(ctx context.Context, key string) (*Setting, error)
	// ListSettings returns all configuration overrides.
	ListSettings(ctx context.Context) ([]Setting, error)
	// DeleteSetting removes the override for key, or ErrNotFound.
	DeleteSetting(ctx context.Context, key string) error

	// CreateProfile inserts a custom permission profile; ErrConflict on a
	// duplicate name.
	CreateProfile(ctx context.Context, p *Profile) error
	// GetProfile returns the profile with the given name, or ErrNotFound.
	GetProfile(ctx context.Context, name string) (*Profile, error)
	// ListProfiles returns all custom profiles.
	ListProfiles(ctx context.Context) ([]Profile, error)
	// DeleteProfile removes a profile by ID, or ErrNotFound.
	DeleteProfile(ctx context.Context, id int64) error

	// AppendBrokerAuditLinked appends one broker audit event whose hash-chain
	// link is computed from the CURRENT persisted head under a serialization
	// that also holds across processes (a Postgres advisory lock in pgstore),
	// so two writers — e.g. an old and a new pod overlapping during a rolling
	// deploy, or HA replicas — cannot fork the chain. link receives the current
	// head (nil at genesis) and returns the fully-linked event (its PrevHash and
	// HMAC set from that head); the store assigns ID and TS, inserts it, and
	// returns the stored event. Reading the head and inserting are one atomic
	// step, so the in-memory head an appender may cache is only advisory.
	AppendBrokerAuditLinked(ctx context.Context, link func(head *BrokerAuditEvent) BrokerAuditEvent) (BrokerAuditEvent, error)
	// ListBrokerAudit returns broker audit events ordered oldest-first (id ASC);
	// limit <= 0 returns all (used by the chain verifier).
	ListBrokerAudit(ctx context.Context, limit int) ([]BrokerAuditEvent, error)
	// GetBrokerAuditHead returns the most recent broker audit event, or (nil, nil)
	// when the log is empty (genesis).
	GetBrokerAuditHead(ctx context.Context) (*BrokerAuditEvent, error)

	// CreateSession inserts a login session, populating its ID and CreatedAt.
	CreateSession(ctx context.Context, s *Session) error
	// GetSessionByTokenHash returns a non-expired session, or ErrNotFound.
	GetSessionByTokenHash(ctx context.Context, tokenHashHex string) (*Session, error)
	// DeleteSession removes the session with the given token hash, or ErrNotFound.
	DeleteSession(ctx context.Context, tokenHashHex string) error
	// ListSessions returns all non-expired login sessions (newest first), so an
	// admin can see and revoke active logins.
	ListSessions(ctx context.Context) ([]Session, error)
	// DeleteSessionsByUsername revokes every login session for a username (e.g. a
	// directory user disabled upstream, or a compromised account), returning how
	// many were removed. It is idempotent — zero is not an error.
	DeleteSessionsByUsername(ctx context.Context, username string) (int, error)

	// UpsertMFAEnrollment creates or replaces a user's TOTP enrollment.
	UpsertMFAEnrollment(ctx context.Context, e *MFAEnrollment) error
	// GetMFAEnrollment returns a user's TOTP enrollment, or ErrNotFound.
	GetMFAEnrollment(ctx context.Context, username string) (*MFAEnrollment, error)
	// ListMFAEnrollments returns all TOTP enrollments.
	ListMFAEnrollments(ctx context.Context) ([]MFAEnrollment, error)
	// DeleteMFAEnrollment removes a user's enrollment (and recovery codes), or ErrNotFound.
	DeleteMFAEnrollment(ctx context.Context, username string) error
	// ConsumeTOTPStep atomically records step as the user's last-used TOTP
	// time-step, returning true if step is newer than the last recorded one
	// (accept) and false if it was already used (a replay to reject).
	ConsumeTOTPStep(ctx context.Context, username string, step int64) (bool, error)

	// ReplaceMFARecoveryCodes stores a fresh set of recovery-code hashes for a
	// user, discarding any previous set.
	ReplaceMFARecoveryCodes(ctx context.Context, username string, codeHashes []string) error
	// ConsumeMFARecoveryCode removes a matching unused recovery code and reports
	// whether one was consumed.
	ConsumeMFARecoveryCode(ctx context.Context, username, codeHash string) (bool, error)
	// CountMFARecoveryCodes returns how many recovery codes remain.
	CountMFARecoveryCodes(ctx context.Context, username string) (int, error)

	// OIDC login PKCE/nonce state, shared across replicas so the auth-code
	// callback can land on any instance (HA).
	PutOIDCState(ctx context.Context, state, verifier, nonce string, expiresAt time.Time) error
	// TakeOIDCState atomically fetches and deletes an unexpired state; ok is false
	// if it is missing or expired.
	TakeOIDCState(ctx context.Context, state string, now time.Time) (verifier, nonce string, ok bool, err error)

	// Ping reports whether the backend is reachable (readiness probe).
	Ping(ctx context.Context) error

	// Close releases the backend's resources.
	Close()
}
