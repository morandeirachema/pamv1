package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"
)

// DirectorySource reports a directory account's status, so pamv1 can revoke
// access for disabled users and surface orphaned local accounts (identity
// reconciliation).
type DirectorySource interface {
	// UserStatus reports whether username exists in the directory and, if so,
	// whether it is enabled. This lets the caller revoke disabled directory users
	// while leaving absent local-only accounts untouched.
	UserStatus(ctx context.Context, username string) (exists, enabled bool, err error)
}

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
	Modify(req *ldap.ModifyRequest) error
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
	case !strings.HasPrefix(strings.ToLower(cfg.URL), "ldaps://"):
		// Bind passwords (service account and per-user) travel over this URL — a
		// plaintext ldap:// would expose them. Require LDAP over TLS.
		return nil, errors.New("ldap: PAM_LDAP_URL must use ldaps:// (LDAP over TLS)")
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
	// Normalize the login to lower-case: AD/LDAP binds are case-insensitive, so
	// "Alice" and "alice" authenticate identically — canonicalizing keeps one actor
	// spelling in the audit trail and makes user grants match consistently.
	return &Principal{Name: strings.ToLower(username), Role: role}, nil
}

// roleForGroups returns the highest-privilege role among the user's groups.
func (a *LDAPAuthenticator) roleForGroups(groups []string) (Role, bool) {
	return HighestRole(groups, a.cfg.GroupRoleMap)
}

// adAccountDisable is the ACCOUNTDISABLE bit in AD's userAccountControl.
const adAccountDisable = 0x0002

// UserStatus reports whether username exists in the directory and, if so, whether
// it is enabled (AD userAccountControl without the ACCOUNTDISABLE bit). A missing
// user returns (false, false, nil); a directory that omits userAccountControl is
// treated as enabled.
func (a *LDAPAuthenticator) UserStatus(ctx context.Context, username string) (bool, bool, error) {
	c, err := a.dial(ctx)
	if err != nil {
		return false, false, fmt.Errorf("ldap: dial: %w", err)
	}
	defer c.Close()
	if err := c.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
		return false, false, fmt.Errorf("ldap: service bind failed: %w", err)
	}
	req := ldap.NewSearchRequest(
		a.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		fmt.Sprintf(a.cfg.UserFilter, ldap.EscapeFilter(username)),
		[]string{"userAccountControl"}, nil,
	)
	res, err := c.Search(req)
	if err != nil {
		return false, false, fmt.Errorf("ldap: search: %w", err)
	}
	if len(res.Entries) != 1 {
		return false, false, nil // deleted or ambiguous
	}
	uac := res.Entries[0].GetAttributeValue("userAccountControl")
	if uac == "" {
		return true, true, nil
	}
	n, err := strconv.Atoi(uac)
	if err != nil {
		return true, true, nil
	}
	return true, n&adAccountDisable == 0, nil
}

// ChangePassword sets username's AD password to newPassword over LDAPS (a Modify
// of unicodePwd). AD rejects password changes over plain LDAP, so the URL must be
// ldaps://. A missing/ambiguous user returns ErrUnauthorized.
func (a *LDAPAuthenticator) ChangePassword(ctx context.Context, username, newPassword string) error {
	c, err := a.dial(ctx)
	if err != nil {
		return fmt.Errorf("ldap: dial: %w", err)
	}
	defer c.Close()
	if err := c.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
		return fmt.Errorf("ldap: service bind failed: %w", err)
	}
	req := ldap.NewSearchRequest(
		a.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		fmt.Sprintf(a.cfg.UserFilter, ldap.EscapeFilter(username)),
		[]string{"distinguishedName"}, nil,
	)
	res, err := c.Search(req)
	if err != nil {
		return fmt.Errorf("ldap: search: %w", err)
	}
	if len(res.Entries) != 1 {
		return fmt.Errorf("%w: user not found", ErrUnauthorized)
	}
	mod := ldap.NewModifyRequest(res.Entries[0].DN, nil)
	mod.Replace("unicodePwd", []string{encodeADPassword(newPassword)})
	if err := c.Modify(mod); err != nil {
		return fmt.Errorf("ldap: password change failed: %w", err)
	}
	return nil
}

// encodeADPassword formats a password as AD's unicodePwd requires: wrapped in
// double quotes and UTF-16LE encoded, returned as a raw byte string.
func encodeADPassword(pw string) string {
	u := utf16.Encode([]rune(`"` + pw + `"`))
	b := make([]byte, 0, len(u)*2)
	for _, r := range u {
		b = append(b, byte(r), byte(r>>8))
	}
	return string(b)
}
