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
	"strings"

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
	// RoleAgent is an AI agent identity: it may call brokered tools and read
	// inventory, nothing else. It is assigned by the broker's agent-auth path, not
	// via ParseRole (agents are never provisioned as human/user tokens).
	RoleAgent Role = "agent"
)

// ParseRole validates s and returns the corresponding Role, or an error if it is
// not one of the four known roles.
func ParseRole(s string) (Role, error) {
	switch Role(s) {
	case RoleAdmin, RoleUser, RoleAuditor, RoleApprover:
		return Role(s), nil
	default:
		return "", fmt.Errorf("auth: invalid role %q (want admin|user|auditor|approver)", s)
	}
}

// ParseGrantRole validates a role name usable as a target-grant subject. Unlike
// ParseRole it also accepts RoleAgent, so a target can be scoped to AI agents
// (a "role:agent" grant), without letting an agent be provisioned as a human
// user or session token.
func ParseGrantRole(s string) (Role, error) {
	if Role(s) == RoleAgent {
		return RoleAgent, nil
	}
	return ParseRole(s)
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
	CapCallTool                            // invoke a brokered tool call (AI agents)
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
	RoleAgent: {
		CapReadInventory: true, CapCallTool: true,
	},
}

// Can reports whether the role is granted the capability.
func (r Role) Can(c Capability) bool {
	return roleCaps[r][c]
}

// CapabilitySet returns the concrete capability set a built-in role confers.
func (r Role) CapabilitySet() CapSet {
	out := make(CapSet)
	for c := CapReadInventory; c <= CapCallTool; c++ {
		if r.Can(c) {
			out[c] = true
		}
	}
	return out
}

// capNames maps each capability to a stable snake_case name. The portal keys its
// role-aware menu off these, so they are part of the /api/me contract — do not
// rename without updating the portal.
var capNames = map[Capability]string{
	CapReadInventory:     "read_inventory",
	CapManageTargets:     "manage_targets",
	CapManageCredentials: "manage_credentials",
	CapRevealSecret:      "reveal_secret",
	CapConnect:           "connect",
	CapReadAudit:         "read_audit",
	CapManageUsers:       "manage_users",
	CapApprove:           "approve",
	CapCallTool:          "call_tool",
}

// String returns the capability's stable snake_case name.
func (c Capability) String() string {
	if s, ok := capNames[c]; ok {
		return s
	}
	return "unknown"
}

// Capabilities returns the stable names of every capability the role is granted,
// in capability-enum order.
func (r Role) Capabilities() []string {
	out := make([]string, 0, len(capNames))
	for c := CapReadInventory; c <= CapCallTool; c++ {
		if r.Can(c) {
			out = append(out, c.String())
		}
	}
	return out
}

// CanConnectTarget reports whether the principal may connect to a target given
// its grants. A target with no grants is open to any connect-capable principal;
// admins may always connect; otherwise a grant must match the user or its role.
func CanConnectTarget(p *Principal, grants []store.TargetGrant) bool {
	if p.Role == RoleAdmin {
		return true
	}
	if len(grants) == 0 {
		return true
	}
	for _, g := range grants {
		switch g.SubjectType {
		case "role":
			if g.Subject == string(p.Role) {
				return true
			}
		case "user":
			if g.Subject == p.Name {
				return true
			}
		}
	}
	return false
}

// HighestRole maps directory claims (group DNs, group ids or app-role values) to
// a role via m (keys compared lower-cased) and returns the highest-privilege
// match. Shared by the LDAP, Entra and OIDC identity sources.
func HighestRole(claims []string, m map[string]Role) (Role, bool) {
	have := make(map[Role]bool)
	for _, c := range claims {
		if r, ok := m[strings.ToLower(c)]; ok {
			have[r] = true
		}
	}
	for _, r := range []Role{RoleAdmin, RoleApprover, RoleAuditor, RoleUser} {
		if have[r] {
			return r, true
		}
	}
	return "", false
}

// SessionScopeEnroll marks a login session that may only be used to complete
// MFA enrollment (issued when a policy requires MFA but the user has none).
const SessionScopeEnroll = "enroll"

// SessionScopeBreakGlass marks a short-lived emergency session issued after a
// successful M-of-N quorum unseal; it grants admin and is audited loudly.
const SessionScopeBreakGlass = "breakglass"

// CapSet is a resolved set of capabilities (used for custom profiles).
type CapSet map[Capability]bool

// Principal is an authenticated identity for the duration of a request or
// session.
type Principal struct {
	Name       string
	Role       Role
	Caps       CapSet // resolved custom-profile capabilities; nil for a built-in role
	BreakGlass bool   // authenticated via the emergency key; use is audited loudly
	EnrollOnly bool   // session may only complete MFA enrollment, nothing else
}

// Can reports whether the principal holds capability c. A custom profile carries
// its own Caps; a built-in role falls back to the role→capability matrix, so
// existing role behavior is unchanged.
func (p *Principal) Can(c Capability) bool {
	if p.Caps != nil {
		return p.Caps[c]
	}
	return p.Role.Can(c)
}

// Covers reports whether the principal holds every capability in want. It backs
// the "you cannot grant more than you have" rule when minting users or profiles,
// so a delegated user-admin can never escalate past its own capabilities. The
// bootstrap/break-glass admin holds every capability, so it is unconstrained.
func (p *Principal) Covers(want CapSet) bool {
	for c, needed := range want {
		if needed && !p.Can(c) {
			return false
		}
	}
	return true
}

// CapabilityNames returns the stable names of the principal's capabilities
// (from its custom profile, or its built-in role).
func (p *Principal) CapabilityNames() []string {
	if p.Caps == nil {
		return p.Role.Capabilities()
	}
	out := make([]string, 0, len(p.Caps))
	for c := CapReadInventory; c <= CapCallTool; c++ {
		if p.Caps[c] {
			out = append(out, c.String())
		}
	}
	return out
}

// ParseCapabilities resolves stable capability names into a CapSet, erroring on
// any unknown name. An empty list yields an empty (no-capability) set.
func ParseCapabilities(names []string) (CapSet, error) {
	byName := make(map[string]Capability, len(capNames))
	for c, n := range capNames {
		byName[n] = c
	}
	caps := make(CapSet, len(names))
	for _, n := range names {
		c, ok := byName[n]
		if !ok {
			return nil, fmt.Errorf("auth: unknown capability %q", n)
		}
		caps[c] = true
	}
	return caps, nil
}

// Directory is the slice of the store the resolver needs: per-user tokens and
// login sessions, both looked up by token hash.
type Directory interface {
	GetUserByTokenHash(ctx context.Context, tokenHashHex string) (*store.User, error)
	GetSessionByTokenHash(ctx context.Context, tokenHashHex string) (*store.Session, error)
}

// ProfileSource looks up a custom permission profile by name. Optional: nil
// means only the four built-in roles are recognized.
type ProfileSource interface {
	GetProfile(ctx context.Context, name string) (*store.Profile, error)
}

// Resolver authenticates a presented key into a Principal.
type Resolver struct {
	dir            Directory
	profiles       ProfileSource
	apiKey         []byte
	breakGlassHash []byte
}

// WithProfiles enables custom-profile resolution for identities whose stored role
// is not one of the four built-in roles. It returns the resolver for chaining.
func (r *Resolver) WithProfiles(ps ProfileSource) *Resolver {
	r.profiles = ps
	return r
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
			return r.principalFor(ctx, u.Username, u.Role, false)
		}
		// Login session token (e.g. Active Directory / Entra ID / break-glass).
		if s, err := r.dir.GetSessionByTokenHash(ctx, hash); err == nil {
			if s.Scope == SessionScopeBreakGlass {
				return &Principal{Name: s.Username, Role: RoleAdmin, BreakGlass: true}, nil
			}
			return r.principalFor(ctx, s.Username, s.Role, s.Scope == SessionScopeEnroll)
		}
	}
	return nil, ErrUnauthorized
}

// principalFor builds a Principal from a stored role string: a built-in role uses
// the role→capability matrix, otherwise the string is resolved as a custom
// profile (its capabilities become the principal's CapSet). An unresolvable role
// is unauthorized (fail-closed).
func (r *Resolver) principalFor(ctx context.Context, name, roleOrProfile string, enrollOnly bool) (*Principal, error) {
	if role, err := ParseRole(roleOrProfile); err == nil {
		return &Principal{Name: name, Role: role, EnrollOnly: enrollOnly}, nil
	}
	if r.profiles != nil {
		if p, err := r.profiles.GetProfile(ctx, roleOrProfile); err == nil {
			caps, cerr := ParseCapabilities(p.Capabilities)
			if cerr != nil {
				return nil, ErrUnauthorized
			}
			return &Principal{Name: name, Role: Role(p.Name), Caps: caps, EnrollOnly: enrollOnly}, nil
		}
	}
	return nil, ErrUnauthorized
}
