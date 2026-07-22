package auth_test

import (
	"testing"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

// TestMatchedRoles maps a multi-group membership to the highest role plus the
// full matched set, in precedence order.
func TestMatchedRoles(t *testing.T) {
	m := map[string]auth.Role{"g-users": auth.RoleUser, "g-auditors": auth.RoleAuditor}
	display, all, ok := auth.MatchedRoles([]string{"g-users", "g-auditors"}, m)
	if !ok || display != auth.RoleAuditor {
		t.Fatalf("display = %q ok=%v; want auditor", display, ok)
	}
	if len(all) != 2 || all[0] != auth.RoleAuditor || all[1] != auth.RoleUser {
		t.Fatalf("matched set = %v; want [auditor user]", all)
	}
	if _, _, ok := auth.MatchedRoles([]string{"g-nothing"}, m); ok {
		t.Fatal("no-match should return ok=false")
	}
}

// TestMultiGroupUnion proves an identity in multiple mapped groups gets the UNION
// of their capabilities and role-grants (the reported bug: losing connect), while
// a single-role principal is unchanged.
func TestMultiGroupUnion(t *testing.T) {
	// user (read_inventory, connect) + auditor (read_inventory, read_audit).
	p := &auth.Principal{Name: "alice", Role: auth.RoleAuditor, Roles: []auth.Role{auth.RoleAuditor, auth.RoleUser}}
	if !p.Can(auth.CapConnect) {
		t.Fatal("multi-group user lost connect")
	}
	if !p.Can(auth.CapReadAudit) {
		t.Fatal("multi-group user lost read_audit")
	}
	if p.Can(auth.CapManageUsers) {
		t.Fatal("multi-group user gained manage_users it shouldn't have")
	}
	// A role:user grant is honored even though the display role is auditor.
	if !auth.CanConnectTarget(p, []store.TargetGrant{{SubjectType: "role", Subject: "user"}}, true) {
		t.Fatal("role:user grant not matched for a user+auditor member")
	}
	// A plain single-role principal (nil Roles) is unchanged: an auditor can't connect.
	single := &auth.Principal{Name: "bob", Role: auth.RoleAuditor}
	if single.Can(auth.CapConnect) {
		t.Fatal("a plain auditor must not have connect")
	}
}
