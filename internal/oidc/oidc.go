// Package oidc implements the OpenID Connect Authorization Code flow with PKCE
// for browser-based login (e.g. Microsoft Entra ID). Unlike the ROPC grant, the
// user authenticates directly with the IdP (so Conditional Access and IdP-side
// MFA apply); pamv1 only receives an authorization code, exchanges it, and
// **validates the ID token's RS256 signature against the IdP's JWKS**.
package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GeneratePKCE returns a PKCE code_verifier and its S256 code_challenge.
func GeneratePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// RandomString returns a URL-safe random token (for state / nonce).
func RandomString() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AuthURL      string
	TokenURL     string
	JWKSURL      string
	Scopes       []string
	HTTPClient   *http.Client
}

type Provider struct {
	cfg Config
	hc  *http.Client
}

// NewProvider validates cfg (issuer, client id, redirect, auth/token/JWKS URLs
// are all required), defaults the scopes and HTTP client, and returns a Provider.
func NewProvider(cfg Config) (*Provider, error) {
	for name, v := range map[string]string{
		"issuer": cfg.Issuer, "client id": cfg.ClientID, "redirect url": cfg.RedirectURL,
		"auth url": cfg.AuthURL, "token url": cfg.TokenURL, "jwks url": cfg.JWKSURL,
	} {
		if v == "" {
			return nil, fmt.Errorf("oidc: %s is required", name)
		}
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile"}
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Provider{cfg: cfg, hc: hc}, nil
}

// AuthCodeURL builds the IdP authorize redirect with PKCE, state and nonce.
func (p *Provider) AuthCodeURL(state, nonce, challenge string) string {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.cfg.ClientID},
		"redirect_uri":          {p.cfg.RedirectURL},
		"scope":                 {strings.Join(p.cfg.Scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	return p.cfg.AuthURL + "?" + q.Encode()
}

// Claims are the validated fields pamv1 reads from the ID token.
type Claims struct {
	Subject           string
	PreferredUsername string
	Roles             []string
	Groups            []string
}

// Exchange swaps an authorization code for tokens and returns the validated
// ID-token claims (signature, issuer, audience, nonce and expiry all checked).
func (p *Provider) Exchange(ctx context.Context, code, verifier, nonce string) (*Claims, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.cfg.RedirectURL},
		"client_id":     {p.cfg.ClientID},
		"client_secret": {p.cfg.ClientSecret},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("oidc: token endpoint status %s", resp.Status)
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.IDToken == "" {
		return nil, errors.New("oidc: no id_token in response")
	}
	return p.verifyIDToken(ctx, tok.IDToken, nonce)
}

// verifyIDToken validates an ID token end to end: it requires RS256, verifies the
// signature against the JWKS key named by the header kid, then checks the issuer,
// audience, nonce and expiry (with 60s leeway) before returning the claims.
func (p *Provider) verifyIDToken(ctx context.Context, idToken, nonce string) (*Claims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("oidc: malformed id_token")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return nil, err
	}
	if hdr.Alg != "RS256" {
		return nil, fmt.Errorf("oidc: unsupported id_token alg %q", hdr.Alg)
	}
	pub, err := p.publicKey(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return nil, errors.New("oidc: id_token signature invalid")
	}

	var c struct {
		Iss               string          `json:"iss"`
		Aud               json.RawMessage `json:"aud"`
		Exp               int64           `json:"exp"`
		Nonce             string          `json:"nonce"`
		Sub               string          `json:"sub"`
		PreferredUsername string          `json:"preferred_username"`
		Roles             []string        `json:"roles"`
		Groups            []string        `json:"groups"`
	}
	if err := decodeSegment(parts[1], &c); err != nil {
		return nil, err
	}
	switch {
	case c.Iss != p.cfg.Issuer:
		return nil, errors.New("oidc: issuer mismatch")
	case !audienceContains(c.Aud, p.cfg.ClientID):
		return nil, errors.New("oidc: audience mismatch")
	case c.Nonce != nonce:
		return nil, errors.New("oidc: nonce mismatch")
	case time.Now().After(time.Unix(c.Exp, 0).Add(60 * time.Second)):
		return nil, errors.New("oidc: id_token expired")
	}
	return &Claims{Subject: c.Sub, PreferredUsername: c.PreferredUsername, Roles: c.Roles, Groups: c.Groups}, nil
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// publicKey fetches the provider's JWKS and returns the RSA public key whose kid
// matches, erroring if none is found.
func (p *Provider) publicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	return keyFromJWKS(ctx, p.hc, p.cfg.JWKSURL, kid)
}

// keyFromJWKS fetches the JWKS at jwksURL and returns the RSA public key whose
// kid matches, erroring if none is found.
func keyFromJWKS(ctx context.Context, hc *http.Client, jwksURL, kid string) (*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: jwks: %w", err)
	}
	defer resp.Body.Close()
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}
	for _, k := range set.Keys {
		if k.Kid == kid && k.Kty == "RSA" {
			return rsaKeyFromJWK(k)
		}
	}
	return nil, fmt.Errorf("oidc: no JWKS key for kid %q", kid)
}

// VerifyRS256 validates a JWT's RS256 signature against the JWKS at jwksURL,
// enforces expiry (60s leeway), optionally requires wantAudience in the "aud"
// claim, and unmarshals the now-trusted payload into out. It performs no issuer
// or nonce checks — the caller adds those. This backs token paths without a
// nonce, such as the Entra ROPC id_token. A nil hc uses a default client.
func VerifyRS256(ctx context.Context, hc *http.Client, jwksURL, token, wantAudience string, out any) error {
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("oidc: malformed token")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return err
	}
	if hdr.Alg != "RS256" {
		return fmt.Errorf("oidc: unsupported token alg %q", hdr.Alg)
	}
	pub, err := keyFromJWKS(ctx, hc, jwksURL, hdr.Kid)
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return errors.New("oidc: token signature invalid")
	}
	var std struct {
		Exp int64           `json:"exp"`
		Aud json.RawMessage `json:"aud"`
	}
	if err := decodeSegment(parts[1], &std); err != nil {
		return err
	}
	if std.Exp != 0 && time.Now().After(time.Unix(std.Exp, 0).Add(60*time.Second)) {
		return errors.New("oidc: token expired")
	}
	if wantAudience != "" && !audienceContains(std.Aud, wantAudience) {
		return errors.New("oidc: audience mismatch")
	}
	if out != nil {
		return decodeSegment(parts[1], out)
	}
	return nil
}

// rsaKeyFromJWK reconstructs an RSA public key from a JWK's base64url modulus (n)
// and exponent (e).
func rsaKeyFromJWK(k jwk) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
}

// decodeSegment base64url-decodes a JWT segment and unmarshals its JSON into v.
func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// audienceContains reports whether the "aud" claim (a single string or an array)
// contains want.
func audienceContains(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}

// Discover fetches the OIDC well-known configuration and returns the authorize,
// token and JWKS endpoints for an issuer.
func Discover(ctx context.Context, hc *http.Client, issuer string) (authURL, tokenURL, jwksURL string, err error) {
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return "", "", "", err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	var d struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		JwksURI               string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return "", "", "", err
	}
	return d.AuthorizationEndpoint, d.TokenEndpoint, d.JwksURI, nil
}
