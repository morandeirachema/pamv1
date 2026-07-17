// Package auth defines pamv1's identity and role-based access control.
//
// There are four profiles (roles):
//
//	admin    — manage targets, credentials, users and configuration; reveal secrets
//	user     — connect to targets through the session proxy; read the inventory
//	auditor  — read-only access to the inventory and the audit trail
//	approver — review and approve/deny access requests; read inventory and audit
//
// A Resolver turns a presented key (the X-API-Key header or the SSH proxy
// password) into a Principal. Three key kinds are accepted, in order: the
// bootstrap admin key (PAM_API_KEY), the sealed break-glass key, and per-user
// tokens minted by an admin (stored only as a SHA-256 hash).
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/morandeirachema/pamv1/internal/store"
)

var ErrUnauthorized = errors.New("auth: unauthorized")

// Role is one of the four profiles.
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleUser     Role = "user"
	RoleAuditor  Role = "auditor"
	RoleApprover Role = "approver"
)

func ParseRole(s string) (Role, error) {
	switch Role(s) {
	case RoleAdmin, RoleUser, RoleAuditor, RoleApprover:
		return Role(s), nil
	default:
		return "", fmt.Errorf("auth: invalid role %q (want admin|user|auditor|approver)", s)
	}
}

// Capability is a single permission checked at each protected operation.
type Capability int

const (
	CapReadInventory     Capability = iota // list targets/credentials (no secrets)
	CapManageTargets                       // create/delete targets
	CapManageCredentials                   // create/delete credentials
	CapRevealSecret                        // decrypt a secret via the API
	CapConnect                             // open a proxied session to a target
	CapReadAudit                           // read the audit trail
	CapManageUsers                         // create/delete users
	CapApprove                             // review and approve/deny access requests
)

// roleCaps is the authoritative role → capability matrix.
var roleCaps = map[Role]map[Capability]bool{
	RoleAdmin: {
		CapReadInventory: true, CapManageTargets: true, CapManageCredentials: true,
		CapRevealSecret: true, CapConnect: true, CapReadAudit: true, CapManageUsers: true,
		CapApprove: true,
	},
	RoleUser: {
		CapReadInventory: true, CapConnect: true,
	},
	RoleAuditor: {
		CapReadInventory: true, CapReadAudit: true,
	},
	RoleApprover: {
		CapReadInventory: true, CapReadAudit: true, CapApprove: true,
	},
}

// Can reports whether the role is granted the capability.
func (r Role) Can(c Capability) bool {
	return roleCaps[r][c]
}

// Principal is an authenticated identity for the duration of a request or
// session.
type Principal struct {
	Name       string
	Role       Role
	BreakGlass bool // authenticated via the emergency key; use is audited loudly
}

// Directory is the slice of the store the resolver needs: per-user tokens and
// login sessions, both looked up by token hash.
type Directory interface {
	GetUserByTokenHash(ctx context.Context, tokenHashHex string) (*store.User, error)
	GetSessionByTokenHash(ctx context.Context, tokenHashHex string) (*store.Session, error)
}

// Resolver authenticates a presented key into a Principal.
type Resolver struct {
	dir            Directory
	apiKey         []byte
	breakGlassHash []byte
}

// NewResolver builds a Resolver. breakGlassHashHex may be empty to disable the
// break-glass path; otherwise it must be a hex-encoded SHA-256.
func NewResolver(dir Directory, apiKey, breakGlassHashHex string) (*Resolver, error) {
	r := &Resolver{dir: dir, apiKey: []byte(apiKey)}
	if breakGlassHashHex != "" {
		b, err := hex.DecodeString(breakGlassHashHex)
		if err != nil || len(b) != sha256.Size {
			return nil, errors.New("auth: PAM_BREAK_GLASS_KEY_HASH must be a hex-encoded SHA-256")
		}
		r.breakGlassHash = b
	}
	return r, nil
}

// Resolve maps a presented key to a Principal, or ErrUnauthorized.
func (r *Resolver) Resolve(ctx context.Context, key string) (*Principal, error) {
	kb := []byte(key)
	if len(kb) == 0 {
		return nil, ErrUnauthorized
	}
	if len(r.apiKey) != 0 && subtle.ConstantTimeCompare(kb, r.apiKey) == 1 {
		return &Principal{Name: "bootstrap-admin", Role: RoleAdmin}, nil
	}
	sum := sha256.Sum256(kb)
	if len(r.breakGlassHash) != 0 && subtle.ConstantTimeCompare(sum[:], r.breakGlassHash) == 1 {
		return &Principal{Name: "break-glass", Role: RoleAdmin, BreakGlass: true}, nil
	}
	hash := hex.EncodeToString(sum[:])
	if r.dir != nil {
		// Per-user access token (local identity).
		if u, err := r.dir.GetUserByTokenHash(ctx, hash); err == nil {
			if role, perr := ParseRole(u.Role); perr == nil {
				return &Principal{Name: u.Username, Role: role}, nil
			}
			return nil, ErrUnauthorized
		}
		// Login session token (e.g. Active Directory).
		if s, err := r.dir.GetSessionByTokenHash(ctx, hash); err == nil {
			if role, perr := ParseRole(s.Role); perr == nil {
				return &Principal{Name: s.Username, Role: role}, nil
			}
			return nil, ErrUnauthorized
		}
	}
	return nil, ErrUnauthorized
}
