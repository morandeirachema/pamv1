package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// fakeLDAP implements ldapConn for tests.
type fakeLDAP struct {
	binds     map[string]string // dn -> password that succeeds
	userDN    string
	memberOf  []string
	searchErr error
	notFound  bool
}

func (f *fakeLDAP) Bind(dn, password string) error {
	if pw, ok := f.binds[dn]; ok && pw == password {
		return nil
	}
	return errors.New("ldap: invalid credentials")
}

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
		},
	}
	return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
}

func (f *fakeLDAP) Close() error { return nil }

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

func TestLDAPEmptyCreds(t *testing.T) {
	a := newLDAPAuth(t, &fakeLDAP{})
	if _, err := a.Authenticate(context.Background(), "alice", ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("empty password should be rejected")
	}
}

func TestNewLDAPAuthenticatorValidation(t *testing.T) {
	if _, err := NewLDAPAuthenticator(LDAPConfig{}); err == nil {
		t.Fatal("empty config should error")
	}
	if _, err := NewLDAPAuthenticator(LDAPConfig{
		URL: "ldaps://x", BaseDN: "DC=x", GroupRoleMap: map[string]Role{"g": RoleUser},
	}); err != nil {
		t.Fatalf("valid config: %v", err)
	}
}
