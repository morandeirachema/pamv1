package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// EntraConfig configures login against Microsoft Entra ID (Azure AD).
type EntraConfig struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	// Scope requested from the token endpoint; defaults to "<ClientID>/.default"
	// so the access token carries the app roles assigned to the user.
	Scope string
	// RoleMap maps an Entra **app role value** or **group object id** (lower-cased)
	// to a pamv1 role. A user with several mapped claims gets the highest one.
	RoleMap map[string]Role
	// AuthorityHost overrides the login host for sovereign clouds
	// (e.g. login.microsoftonline.us); default login.microsoftonline.com.
	AuthorityHost string
	// tokenEndpoint overrides the full endpoint (tests only).
	tokenEndpoint string
}

// EntraAuthenticator authenticates users against Entra ID using the OAuth2
// resource-owner-password (ROPC) grant, which fits pamv1's username+password
// login. The access token is received over TLS in a direct back-channel call
// (not via the browser), so its claims are read to derive the role.
//
// NOTE: ROPC does not exercise Entra Conditional Access or IdP-side MFA — use
// pamv1's own TOTP MFA on top, and prefer the OIDC auth-code flow for
// production (a hardening item). JWKS signature validation is also a TODO.
type EntraAuthenticator struct {
	cfg      EntraConfig
	hc       *http.Client
	endpoint string
}

// NewEntraAuthenticator validates cfg (tenant, client id/secret and at least one
// role mapping are required) and applies defaults for scope, authority host and
// the token endpoint.
func NewEntraAuthenticator(cfg EntraConfig) (*EntraAuthenticator, error) {
	switch {
	case cfg.TenantID == "":
		return nil, fmt.Errorf("entra: PAM_ENTRA_TENANT_ID is required")
	case cfg.ClientID == "":
		return nil, fmt.Errorf("entra: PAM_ENTRA_CLIENT_ID is required")
	case cfg.ClientSecret == "":
		return nil, fmt.Errorf("entra: PAM_ENTRA_CLIENT_SECRET is required")
	case len(cfg.RoleMap) == 0:
		return nil, fmt.Errorf("entra: at least one app-role/group → role mapping is required")
	}
	if cfg.Scope == "" {
		cfg.Scope = cfg.ClientID + "/.default"
	}
	if cfg.AuthorityHost == "" {
		cfg.AuthorityHost = "login.microsoftonline.com"
	}
	endpoint := cfg.tokenEndpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://%s/%s/oauth2/v2.0/token", cfg.AuthorityHost, cfg.TenantID)
	}
	return &EntraAuthenticator{cfg: cfg, hc: &http.Client{Timeout: 10 * time.Second}, endpoint: endpoint}, nil
}

type entraClaims struct {
	Roles             []string `json:"roles"`
	Groups            []string `json:"groups"`
	PreferredUsername string   `json:"preferred_username"`
	UPN               string   `json:"upn"`
}

// Authenticate performs the ROPC token request, parses the access token's app
// role and group claims, and maps them to a Principal. Bad credentials return
// ErrUnauthorized; a user with no mapped role also returns ErrUnauthorized.
func (a *EntraAuthenticator) Authenticate(ctx context.Context, username, password string) (*Principal, error) {
	if username == "" || password == "" {
		return nil, ErrUnauthorized
	}
	form := url.Values{
		"grant_type":    {"password"},
		"client_id":     {a.cfg.ClientID},
		"client_secret": {a.cfg.ClientSecret},
		"scope":         {a.cfg.Scope},
		"username":      {username},
		"password":      {password},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("entra: token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		// invalid_grant = bad credentials; treat as unauthorized.
		return nil, ErrUnauthorized
	}

	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return nil, fmt.Errorf("entra: malformed token response")
	}
	claims, err := parseJWTClaims(tok.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("entra: parse token: %w", err)
	}
	role, ok := a.roleFor(claims.Roles, claims.Groups)
	if !ok {
		return nil, fmt.Errorf("%w: user has no mapped Entra app role or group", ErrUnauthorized)
	}
	name := firstNonEmpty(claims.PreferredUsername, claims.UPN, username)
	return &Principal{Name: name, Role: role}, nil
}

// roleFor maps the combined app-role and group claims to the highest role.
func (a *EntraAuthenticator) roleFor(roles, groups []string) (Role, bool) {
	return HighestRole(append(append([]string{}, roles...), groups...), a.cfg.RoleMap)
}

// parseJWTClaims decodes the (unverified) payload of a JWT. Safe here because
// the token is received directly from Entra over TLS in a back-channel call.
func parseJWTClaims(jwt string) (entraClaims, error) {
	var c entraClaims
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return c, fmt.Errorf("not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, err
	}
	return c, json.Unmarshal(payload, &c)
}

// firstNonEmpty returns the first non-empty string in vals, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
