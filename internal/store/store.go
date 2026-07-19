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
// vaulted secret to its owning target. The API and the session proxy must
// use the same value or decryption fails.
func CredentialAAD(targetID int64) string {
	return fmt.Sprintf("target:%d", targetID)
}

// MFAAAD binds a vaulted TOTP secret to its owning user.
func MFAAAD(username string) string {
	return "mfa:" + username
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
}

type Store interface {
	CreateTarget(ctx context.Context, t *Target) error
	ListTargets(ctx context.Context) ([]Target, error)
	GetTarget(ctx context.Context, id int64) (*Target, error)
	DeleteTarget(ctx context.Context, id int64) error

	CreateCredential(ctx context.Context, c *Credential) error
	// ListCredentials returns credentials for one target, or all when targetID is 0.
	ListCredentials(ctx context.Context, targetID int64) ([]Credential, error)
	GetCredential(ctx context.Context, id int64) (*Credential, error)
	// UpdateCredentialSecretEnc replaces a credential's encrypted secret (used
	// by vault key rotation). It deliberately does NOT touch rotated_at — a KEK
	// re-wrap is not a credential rotation.
	UpdateCredentialSecretEnc(ctx context.Context, id int64, secretEnc string) error
	// RotateCredentialSecret replaces the encrypted secret AND stamps rotated_at
	// (used by the credential-lifecycle rotation, where the secret on the target
	// actually changed).
	RotateCredentialSecret(ctx context.Context, id int64, secretEnc string, rotatedAt time.Time) error
	DeleteCredential(ctx context.Context, id int64) error

	CreateTargetGrant(ctx context.Context, g *TargetGrant) error
	ListTargetGrants(ctx context.Context, targetID int64) ([]TargetGrant, error)
	DeleteTargetGrant(ctx context.Context, id int64) error

	// Access requests (4-eyes approval workflow).
	CreateAccessRequest(ctx context.Context, ar *AccessRequest) error
	GetAccessRequest(ctx context.Context, id int64) (*AccessRequest, error)
	// ListAccessRequests returns requests with the given status, or all when
	// status is "".
	ListAccessRequests(ctx context.Context, status string) ([]AccessRequest, error)
	// DecideAccessRequest records an approve/deny decision by approver.
	DecideAccessRequest(ctx context.Context, id int64, status, approver string, decidedAt time.Time) error
	// HasActiveApproval reports whether requester has an approved, unexpired
	// request for targetID as of now.
	HasActiveApproval(ctx context.Context, requester string, targetID int64, now time.Time) (bool, error)

	AppendAudit(ctx context.Context, e *AuditEvent) error
	ListAudit(ctx context.Context, limit int) ([]AuditEvent, error)

	CreateUser(ctx context.Context, u *User) error
	ListUsers(ctx context.Context) ([]User, error)
	GetUserByTokenHash(ctx context.Context, tokenHashHex string) (*User, error)
	DeleteUser(ctx context.Context, id int64) error

	CreateSession(ctx context.Context, s *Session) error
	// GetSessionByTokenHash returns a non-expired session, or ErrNotFound.
	GetSessionByTokenHash(ctx context.Context, tokenHashHex string) (*Session, error)
	DeleteSession(ctx context.Context, tokenHashHex string) error

	// UpsertMFAEnrollment creates or replaces a user's TOTP enrollment.
	UpsertMFAEnrollment(ctx context.Context, e *MFAEnrollment) error
	GetMFAEnrollment(ctx context.Context, username string) (*MFAEnrollment, error)
	ListMFAEnrollments(ctx context.Context) ([]MFAEnrollment, error)
	DeleteMFAEnrollment(ctx context.Context, username string) error

	// ReplaceMFARecoveryCodes stores a fresh set of recovery-code hashes for a
	// user, discarding any previous set.
	ReplaceMFARecoveryCodes(ctx context.Context, username string, codeHashes []string) error
	// ConsumeMFARecoveryCode removes a matching unused recovery code and reports
	// whether one was consumed.
	ConsumeMFARecoveryCode(ctx context.Context, username, codeHash string) (bool, error)
	// CountMFARecoveryCodes returns how many recovery codes remain.
	CountMFARecoveryCodes(ctx context.Context, username string) (int, error)

	Close()
}
