package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
)

// TestRoleCapabilities checks the role→capability matrix across all four roles.
func TestRoleCapabilities(t *testing.T) {
	cases := []struct {
		role Role
		cap  Capability
		want bool
	}{
		{RoleAdmin, CapManageUsers, true},
		{RoleAdmin, CapRevealSecret, true},
		{RoleUser, CapConnect, true},
		{RoleUser, CapReadInventory, true},
		{RoleUser, CapRevealSecret, false},
		{RoleUser, CapReadAudit, false},
		{RoleUser, CapManageTargets, false},
		{RoleAuditor, CapReadAudit, true},
		{RoleAuditor, CapReadInventory, true},
		{RoleAuditor, CapConnect, false},
		{RoleAuditor, CapManageTargets, false},
		{RoleAuditor, CapRevealSecret, false},
		{RoleAuditor, CapApprove, false},
		{RoleApprover, CapApprove, true},
		{RoleApprover, CapReadAudit, true},
		{RoleApprover, CapReadInventory, true},
		{RoleApprover, CapConnect, false},
		{RoleApprover, CapManageTargets, false},
		{RoleApprover, CapRevealSecret, false},
		{RoleAdmin, CapApprove, true},
		{RoleUser, CapApprove, false},
	}
	for _, c := range cases {
		if got := c.role.Can(c.cap); got != c.want {
			t.Errorf("%s.Can(%d) = %v, want %v", c.role, c.cap, got, c.want)
		}
	}
}

// TestCanConnectTarget checks target-grant logic: open when ungranted, admins
// always allowed, and user/role grants matched or denied.
func TestCanConnectTarget(t *testing.T) {
	admin := &Principal{Name: "boss", Role: RoleAdmin}
	user := &Principal{Name: "alice", Role: RoleUser}
	other := &Principal{Name: "bob", Role: RoleUser}

	// No grants on an ungated target → open to any connect-capable principal.
	if !CanConnectTarget(user, nil, false) {
		t.Fatal("no grants on an ungated target should be open")
	}
	grants := []store.TargetGrant{
		{SubjectType: "user", Subject: "alice"},
		{SubjectType: "role", Subject: "approver"},
	}
	if !CanConnectTarget(admin, grants, false) {
		t.Fatal("admin should always connect")
	}
	if !CanConnectTarget(user, grants, false) {
		t.Fatal("granted user should connect")
	}
	if CanConnectTarget(other, grants, false) {
		t.Fatal("ungranted user must be denied")
	}
	if !CanConnectTarget(&Principal{Name: "x", Role: RoleApprover}, grants, false) {
		t.Fatal("granted role should connect")
	}
}

// TestCanConnectSafeScoped verifies that a target placed in a safe is
// default-DENY when its effective grants yield no match — an empty safe must not
// fall through to the ungated "open to all" behavior. Admins are still allowed.
func TestCanConnectSafeScoped(t *testing.T) {
	user := &Principal{Name: "alice", Role: RoleUser}
	admin := &Principal{Name: "boss", Role: RoleAdmin}

	// Safe-scoped target with no members/grants: closed to a normal user.
	if CanConnectTarget(user, nil, true) {
		t.Fatal("safe-scoped target with no grants must be default-deny")
	}
	// ...but an admin may always connect.
	if !CanConnectTarget(admin, nil, true) {
		t.Fatal("admin should connect to a safe-scoped target")
	}
	// A matching safe member is allowed.
	grants := []store.TargetGrant{{SubjectType: "user", Subject: "alice"}}
	if !CanConnectTarget(user, grants, true) {
		t.Fatal("safe member should connect")
	}
	// A non-matching principal on a safe-scoped target is denied.
	if CanConnectTarget(&Principal{Name: "bob", Role: RoleUser}, grants, true) {
		t.Fatal("non-member must be denied on a safe-scoped target")
	}
}

// TestParseRole checks that the four valid roles parse and an unknown one errors.
func TestParseRole(t *testing.T) {
	for _, ok := range []string{"admin", "user", "auditor", "approver"} {
		if _, err := ParseRole(ok); err != nil {
			t.Errorf("ParseRole(%q) unexpected error: %v", ok, err)
		}
	}
	if _, err := ParseRole("root"); err == nil {
		t.Error("ParseRole(root) should fail")
	}
}

// fakeDir implements auth.Directory for tests.
type fakeDir struct {
	users    map[string]*store.User    // tokenHashHex -> user
	sessions map[string]*store.Session // tokenHashHex -> session
}

// GetUserByTokenHash returns the seeded user for hash h, or store.ErrNotFound.
func (f fakeDir) GetUserByTokenHash(_ context.Context, h string) (*store.User, error) {
	if u, ok := f.users[h]; ok {
		return u, nil
	}
	return nil, store.ErrNotFound
}

// GetSessionByTokenHash returns the seeded session for hash h, or store.ErrNotFound.
func (f fakeDir) GetSessionByTokenHash(_ context.Context, h string) (*store.Session, error) {
	if s, ok := f.sessions[h]; ok {
		return s, nil
	}
	return nil, store.ErrNotFound
}

// hashOf returns the hex SHA-256 of tok, matching how the resolver keys tokens.
func hashOf(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// TestResolve exercises every accepted key kind (bootstrap admin, break-glass,
// per-user token, login session) and rejection of empty/unknown/bad-role keys.
func TestResolve(t *testing.T) {
	bg := sha256.Sum256([]byte("emergency"))
	dir := fakeDir{
		users: map[string]*store.User{
			hashOf("alice-token"): {Username: "alice", Role: "user"},
			hashOf("theo-token"):  {Username: "theo", Role: "auditor"},
			hashOf("broken"):      {Username: "bad", Role: "wizard"},
		},
		sessions: map[string]*store.Session{
			hashOf("ad-session"): {Username: "ad-alice", Role: "approver"},
		},
	}
	r, err := NewResolver(dir, "bootstrap", hex.EncodeToString(bg[:]))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	check := func(key, name string, role Role, breakglass bool) {
		t.Helper()
		p, err := r.Resolve(ctx, key)
		if err != nil {
			t.Fatalf("Resolve(%q) error: %v", key, err)
		}
		if p.Name != name || p.Role != role || p.BreakGlass != breakglass {
			t.Fatalf("Resolve(%q) = %+v, want name=%s role=%s bg=%v", key, p, name, role, breakglass)
		}
	}
	check("bootstrap", "bootstrap-admin", RoleAdmin, false)
	check("emergency", "break-glass", RoleAdmin, true)
	check("alice-token", "alice", RoleUser, false)
	check("theo-token", "theo", RoleAuditor, false)
	check("ad-session", "ad-alice", RoleApprover, false) // login session token

	for _, bad := range []string{"", "nope", "broken"} {
		if _, err := r.Resolve(ctx, bad); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("Resolve(%q) = %v, want ErrUnauthorized", bad, err)
		}
	}
}
