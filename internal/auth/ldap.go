package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Authenticator verifies a username + password and returns a Principal. The
// Active Directory / LDAP implementation is the production identity source;
// the returned Principal's role comes from the user's directory groups.
type Authenticator interface {
	Authenticate(ctx context.Context, username, password string) (*Principal, error)
}

// LDAPConfig configures binding against Active Directory over LDAPS.
type LDAPConfig struct {
	URL          string // ldaps://dc.example.com:636 (LDAPS strongly preferred)
	BindDN       string // service account used to search for users
	BindPassword string
	BaseDN       string // search base, e.g. DC=example,DC=com
	UserFilter   string // e.g. (sAMAccountName=%s); %s is the escaped username
	// GroupRoleMap maps a group DN (lower-cased) to a pamv1 role. A user in
	// several mapped groups gets the highest-privilege role.
	GroupRoleMap map[string]Role
	// InsecureSkipVerify disables TLS verification — dev only.
	InsecureSkipVerify bool
}

// ldapConn is the minimal LDAP surface used, so tests can inject a fake.
type ldapConn interface {
	Bind(username, password string) error
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

// LDAPAuthenticator authenticates against Active Directory / LDAP.
type LDAPAuthenticator struct {
	cfg  LDAPConfig
	dial func(ctx context.Context) (ldapConn, error)
}

// NewLDAPAuthenticator validates cfg (URL, base DN and at least one group→role
// mapping are required), defaults the user filter, and wires the real dialer.
func NewLDAPAuthenticator(cfg LDAPConfig) (*LDAPAuthenticator, error) {
	switch {
	case cfg.URL == "":
		return nil, errors.New("ldap: PAM_LDAP_URL is required")
	case cfg.BaseDN == "":
		return nil, errors.New("ldap: PAM_LDAP_BASE_DN is required")
	case len(cfg.GroupRoleMap) == 0:
		return nil, errors.New("ldap: at least one group→role mapping is required")
	}
	if cfg.UserFilter == "" {
		cfg.UserFilter = "(sAMAccountName=%s)"
	}
	a := &LDAPAuthenticator{cfg: cfg}
	a.dial = a.realDial
	return a, nil
}

// realDial opens the real LDAP connection, using TLS (with the configured verify
// policy) for ldaps:// URLs.
func (a *LDAPAuthenticator) realDial(_ context.Context) (ldapConn, error) {
	var opts []ldap.DialOpt
	if strings.HasPrefix(strings.ToLower(a.cfg.URL), "ldaps://") {
		opts = append(opts, ldap.DialWithTLSConfig(&tls.Config{
			InsecureSkipVerify: a.cfg.InsecureSkipVerify, //nolint:gosec // dev-only toggle
			MinVersion:         tls.VersionTLS12,
		}))
	}
	c, err := ldap.DialURL(a.cfg.URL, opts...)
	if err != nil {
		return nil, err
	}
	return realConn{c}, nil
}

// realConn adapts *ldap.Conn to ldapConn (normalizing Close to return error).
type realConn struct{ *ldap.Conn }

// Close closes the underlying *ldap.Conn, adapting its no-error signature.
func (c realConn) Close() error { c.Conn.Close(); return nil }

// Authenticate binds as the service account to find the user, verifies the
// password by binding as that user, then maps their groups to a role. A missing
// or ambiguous user, a failed user bind, or no mapped group all return
// ErrUnauthorized; infrastructure failures return a wrapped error.
func (a *LDAPAuthenticator) Authenticate(ctx context.Context, username, password string) (*Principal, error) {
	if username == "" || password == "" {
		return nil, ErrUnauthorized
	}
	c, err := a.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("ldap: dial: %w", err)
	}
	defer c.Close()

	// 1. Bind as the service account to search the directory.
	if err := c.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("ldap: service bind failed: %w", err)
	}

	// 2. Find the user and read their group memberships.
	req := ldap.NewSearchRequest(
		a.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		fmt.Sprintf(a.cfg.UserFilter, ldap.EscapeFilter(username)),
		[]string{"memberOf"}, nil,
	)
	res, err := c.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ldap: search: %w", err)
	}
	if len(res.Entries) != 1 {
		return nil, ErrUnauthorized // no such user or ambiguous
	}
	userDN := res.Entries[0].DN
	groups := res.Entries[0].GetAttributeValues("memberOf")

	// 3. Verify the password by binding as the user.
	if err := c.Bind(userDN, password); err != nil {
		return nil, ErrUnauthorized
	}

	// 4. Map groups → role (highest privilege wins).
	role, ok := a.roleForGroups(groups)
	if !ok {
		return nil, fmt.Errorf("%w: user is in no pamv1 group", ErrUnauthorized)
	}
	return &Principal{Name: username, Role: role}, nil
}

// roleForGroups returns the highest-privilege role among the user's groups.
func (a *LDAPAuthenticator) roleForGroups(groups []string) (Role, bool) {
	return HighestRole(groups, a.cfg.GroupRoleMap)
}
