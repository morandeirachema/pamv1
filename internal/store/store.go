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
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	OSType    string    `json:"os_type"`  // linux | windows
	Protocol  string    `json:"protocol"` // ssh | winrm | rdp
	CreatedAt time.Time `json:"created_at"`
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
	DeleteCredential(ctx context.Context, id int64) error

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
	DeleteMFAEnrollment(ctx context.Context, username string) error

	Close()
}
