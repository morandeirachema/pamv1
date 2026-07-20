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
	RequireApproval bool      `json:"require_approval"`
	CreatedAt       time.Time `json:"created_at"`
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
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
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

	// Access requests (4-eyes approval workflow).
	CreateAccessRequest(ctx context.Context, ar *AccessRequest) error
	// GetAccessRequest returns one access request by ID, or ErrNotFound.
	GetAccessRequest(ctx context.Context, id int64) (*AccessRequest, error)
	// ListAccessRequests returns requests with the given status, or all when
	// status is "".
	ListAccessRequests(ctx context.Context, status string) ([]AccessRequest, error)
	// DecideAccessRequest records an approve/deny decision by approver.
	DecideAccessRequest(ctx context.Context, id int64, status, approver string, decidedAt time.Time) error
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
	// GetAgentKeyByTokenHash returns the enabled agent key whose token hash
	// matches, or ErrNotFound (a disabled key is treated as not found).
	GetAgentKeyByTokenHash(ctx context.Context, tokenHashHex string) (*AgentKey, error)
	// ListAgentKeys returns all agent keys.
	ListAgentKeys(ctx context.Context) ([]AgentKey, error)
	// DeleteAgentKey removes an agent key by ID, or ErrNotFound.
	DeleteAgentKey(ctx context.Context, id int64) error

	// PutSetting upserts a configuration override, stamping UpdatedAt.
	PutSetting(ctx context.Context, s *Setting) error
	// GetSetting returns the override for key, or ErrNotFound.
	GetSetting(ctx context.Context, key string) (*Setting, error)
	// ListSettings returns all configuration overrides.
	ListSettings(ctx context.Context) ([]Setting, error)
	// DeleteSetting removes the override for key, or ErrNotFound.
	DeleteSetting(ctx context.Context, key string) error

	// AppendBrokerAudit appends a pre-chained broker audit event (HMAC and
	// PrevHash already computed by the caller), populating its ID and TS. The
	// broker is the sole writer so rows chain in insertion order.
	AppendBrokerAudit(ctx context.Context, e *BrokerAuditEvent) error
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
