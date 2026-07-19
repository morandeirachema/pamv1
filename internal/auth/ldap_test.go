package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// fakeLDAP implements ldapConn for tests.
type fakeLDAP struct {
	binds      map[string]string // dn -> password that succeeds
	userDN     string
	memberOf   []string
	uac        string // userAccountControl value returned by Search
	searchErr  error
	notFound   bool
	lastModify *ldap.ModifyRequest
}

// Bind succeeds when dn/password match a seeded entry, else returns an error.
func (f *fakeLDAP) Bind(dn, password string) error {
	if pw, ok := f.binds[dn]; ok && pw == password {
		return nil
	}
	return errors.New("ldap: invalid credentials")
}

// Search returns the configured error, an empty result (notFound), or a single
// entry carrying the fixture's DN and memberOf values.
func (f *fakeLDAP) Search(_ *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	if f.notFound {
		return &ldap.SearchResult{}, nil
	}
	entry := &ldap.Entry{
		DN: f.userDN,
		Attributes: []*ldap.EntryAttribute{
			{Name: "memberOf", Values: f.memberOf},
			{Name: "userAccountControl", Values: []string{f.uac}},
		},
	}
	return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
}

// Modify records the modify request for assertions.
func (f *fakeLDAP) Modify(req *ldap.ModifyRequest) error {
	f.lastModify = req
	return nil
}

// Close is a no-op for the fake connection.
func (f *fakeLDAP) Close() error { return nil }

// newLDAPAuth builds an LDAPAuthenticator whose dialer returns the given fake conn.
func newLDAPAuth(t *testing.T, conn *fakeLDAP) *LDAPAuthenticator {
	t.Helper()
	a, err := NewLDAPAuthenticator(LDAPConfig{
		URL:          "ldaps://dc.example.com:636",
		BindDN:       "CN=svc,DC=example,DC=com",
		BindPassword: "svc-pw",
		BaseDN:       "DC=example,DC=com",
		GroupRoleMap: map[string]Role{
			"cn=pam-admins,dc=example,dc=com":   RoleAdmin,
			"cn=pam-users,dc=example,dc=com":    RoleUser,
			"cn=pam-auditors,dc=example,dc=com": RoleAuditor,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	a.dial = func(context.Context) (ldapConn, error) { return conn, nil }
	return a
}

// TestLDAPAuthenticateSuccess proves a valid user binds and gets its mapped role.
func TestLDAPAuthenticateSuccess(t *testing.T) {
	conn := &fakeLDAP{
		binds: map[string]string{
			"CN=svc,DC=example,DC=com":            "svc-pw",
			"CN=alice,OU=Users,DC=example,DC=com": "alice-pw",
		},
		userDN:   "CN=alice,OU=Users,DC=example,DC=com",
		memberOf: []string{"CN=PAM-Users,DC=example,DC=com"},
	}
	a := newLDAPAuth(t, conn)
	p, err := a.Authenticate(context.Background(), "alice", "alice-pw")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if p.Name != "alice" || p.Role != RoleUser {
		t.Fatalf("got %+v, want alice/user", p)
	}
}

// TestLDAPHighestPrivilegeWins proves the highest-privilege group role is chosen.
func TestLDAPHighestPrivilegeWins(t *testing.T) {
	conn := &fakeLDAP{
		binds:  map[string]string{"CN=svc,DC=example,DC=com": "svc-pw", "CN=bob,DC=example,DC=com": "bob-pw"},
		userDN: "CN=bob,DC=example,DC=com",
		memberOf: []string{
			"CN=PAM-Users,DC=example,DC=com",
			"CN=PAM-Admins,DC=example,DC=com",
		},
	}
	a := newLDAPAuth(t, conn)
	p, err := a.Authenticate(context.Background(), "bob", "bob-pw")
	if err != nil || p.Role != RoleAdmin {
		t.Fatalf("got %+v err %v, want admin", p, err)
	}
}

// TestLDAPWrongPassword proves a failed user bind returns ErrUnauthorized.
func TestLDAPWrongPassword(t *testing.T) {
	conn := &fakeLDAP{
		binds:    map[string]string{"CN=svc,DC=example,DC=com": "svc-pw"}, // user bind will fail
		userDN:   "CN=alice,DC=example,DC=com",
		memberOf: []string{"CN=PAM-Users,DC=example,DC=com"},
	}
	a := newLDAPAuth(t, conn)
	if _, err := a.Authenticate(context.Background(), "alice", "wrong"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong password: got %v, want ErrUnauthorized", err)
	}
}

// TestLDAPNoMappedGroup proves a user in no pamv1 group returns ErrUnauthorized.
func TestLDAPNoMappedGroup(t *testing.T) {
	conn := &fakeLDAP{
		binds:    map[string]string{"CN=svc,DC=example,DC=com": "svc-pw", "CN=eve,DC=example,DC=com": "eve-pw"},
		userDN:   "CN=eve,DC=example,DC=com",
		memberOf: []string{"CN=SomeoneElse,DC=example,DC=com"},
	}
	a := newLDAPAuth(t, conn)
	if _, err := a.Authenticate(context.Background(), "eve", "eve-pw"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("no mapped group: got %v, want ErrUnauthorized", err)
	}
}

// TestLDAPUserNotFound proves an absent user returns ErrUnauthorized.
func TestLDAPUserNotFound(t *testing.T) {
	conn := &fakeLDAP{
		binds:    map[string]string{"CN=svc,DC=example,DC=com": "svc-pw"},
		notFound: true,
	}
	a := newLDAPAuth(t, conn)
	if _, err := a.Authenticate(context.Background(), "ghost", "pw"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unknown user: got %v, want ErrUnauthorized", err)
	}
}

// TestLDAPEmptyCreds proves an empty password is rejected before dialing.
func TestLDAPEmptyCreds(t *testing.T) {
	a := newLDAPAuth(t, &fakeLDAP{})
	if _, err := a.Authenticate(context.Background(), "alice", ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("empty password should be rejected")
	}
}

// TestNewLDAPAuthenticatorValidation proves the constructor rejects an empty
// config and accepts a minimal valid one.
func TestNewLDAPAuthenticatorValidation(t *testing.T) {
	if _, err := NewLDAPAuthenticator(LDAPConfig{}); err == nil {
		t.Fatal("empty config should error")
	}
	if _, err := NewLDAPAuthenticator(LDAPConfig{
		URL: "ldaps://x", BaseDN: "DC=x", GroupRoleMap: map[string]Role{"g": RoleUser},
	}); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	// A plaintext ldap:// URL must be rejected — it would send bind passwords in
	// the clear.
	if _, err := NewLDAPAuthenticator(LDAPConfig{
		URL: "ldap://x", BaseDN: "DC=x", GroupRoleMap: map[string]Role{"g": RoleUser},
	}); err == nil {
		t.Fatal("plaintext ldap:// URL should be rejected")
	}
}

// TestUserStatus proves enabled/disabled/missing directory accounts are reported
// correctly (AD userAccountControl ACCOUNTDISABLE bit); missing is distinguished
// from disabled so orphaned local accounts aren't mistaken for revoked users.
func TestUserStatus(t *testing.T) {
	ctx := context.Background()

	enabled := newLDAPAuth(t, &fakeLDAP{binds: map[string]string{"CN=svc,DC=example,DC=com": "svc-pw"}, userDN: "CN=alice,DC=example,DC=com", uac: "512"})
	if exists, en, err := enabled.UserStatus(ctx, "alice"); err != nil || !exists || !en {
		t.Fatalf("enabled: exists=%v enabled=%v err=%v", exists, en, err)
	}

	disabled := newLDAPAuth(t, &fakeLDAP{binds: map[string]string{"CN=svc,DC=example,DC=com": "svc-pw"}, userDN: "CN=bob,DC=example,DC=com", uac: "514"}) // 512|2
	if exists, en, _ := disabled.UserStatus(ctx, "bob"); !exists || en {
		t.Fatalf("disabled: exists=%v enabled=%v (want exists,disabled)", exists, en)
	}

	missing := newLDAPAuth(t, &fakeLDAP{binds: map[string]string{"CN=svc,DC=example,DC=com": "svc-pw"}, notFound: true})
	if exists, _, _ := missing.UserStatus(ctx, "ghost"); exists {
		t.Fatal("missing account must report not-exists")
	}
}

// TestChangePassword proves the AD unicodePwd modify carries the UTF-16LE,
// double-quoted password for the resolved DN.
func TestChangePassword(t *testing.T) {
	f := &fakeLDAP{binds: map[string]string{"CN=svc,DC=example,DC=com": "svc-pw"}, userDN: "CN=carol,DC=example,DC=com"}
	a := newLDAPAuth(t, f)
	if err := a.ChangePassword(context.Background(), "carol", "N3w-Pass"); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if f.lastModify == nil || f.lastModify.DN != "CN=carol,DC=example,DC=com" {
		t.Fatalf("modify DN wrong: %+v", f.lastModify)
	}
	got := f.lastModify.Changes[0].Modification
	if got.Type != "unicodePwd" || got.Vals[0] != encodeADPassword("N3w-Pass") {
		t.Fatalf("unexpected modify: type=%q", got.Type)
	}
	// Sanity: the encoding is quoted + UTF-16LE (2 bytes per rune).
	if want := 2 * len(`"N3w-Pass"`); len(encodeADPassword("N3w-Pass")) != want {
		t.Fatalf("encoded length = %d, want %d", len(encodeADPassword("N3w-Pass")), want)
	}
}
