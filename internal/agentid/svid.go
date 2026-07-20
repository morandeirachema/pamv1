package agentid

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

// jwk is a JSON Web Key covering the SPIFFE-relevant key types: RSA (n,e), EC
// (crv,x,y), and OKP/Ed25519 (crv,x).
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// actClaim is an RFC 8693 "act" (actor) claim, optionally nested to express a
// delegation chain (the current actor acting on behalf of an inner actor).
type actClaim struct {
	Sub string    `json:"sub"`
	Act *actClaim `json:"act"`
}

// SVIDVerifier verifies SPIFFE JWT-SVIDs against a trust-domain JWKS loaded from
// a file (SPIRE publishes the bundle; we verify SVIDs against it, we do not run a
// SPIRE agent). It requires the subject to be a SPIFFE ID in the configured trust
// domain, the audience to match, and the token to be unexpired (fail-closed).
// RFC 8693 nested "act" claims become a delegation actor chain bounded by maxDepth.
type SVIDVerifier struct {
	trustDomain string // e.g. "example.org" (the host of spiffe://example.org/...)
	audience    string
	maxDepth    int
	keys        map[string]crypto.PublicKey // kid -> public key
}

// NewSVIDVerifier loads the trust-domain JWKS from jwksPath and returns a
// verifier. trustDomain is the SPIFFE trust domain host, audience the required
// aud, maxDepth the delegation-depth cap (<=0 becomes 1).
func NewSVIDVerifier(jwksPath, trustDomain, audience string, maxDepth int) (*SVIDVerifier, error) {
	if trustDomain == "" {
		return nil, errors.New("agentid: svid trust domain is required")
	}
	data, err := os.ReadFile(jwksPath)
	if err != nil {
		return nil, fmt.Errorf("agentid: read svid jwks: %w", err)
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("agentid: parse svid jwks: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		pub, err := publicKeyFromJWK(k)
		if err != nil {
			return nil, err
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("agentid: svid jwks has no usable keys")
	}
	if maxDepth <= 0 {
		maxDepth = 1
	}
	return &SVIDVerifier{trustDomain: trustDomain, audience: audience, maxDepth: maxDepth, keys: keys}, nil
}

// Verify validates a JWT-SVID and returns the delegated Identity, or
// ErrUnauthenticated. Every failure path is fail-closed and indistinguishable
// (no oracle about why a token was rejected).
func (v *SVIDVerifier) Verify(_ context.Context, bearer string) (*Identity, error) {
	bearer = strings.TrimSpace(bearer)
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return nil, ErrUnauthenticated
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return nil, ErrUnauthenticated
	}
	pub, ok := v.keys[hdr.Kid]
	if !ok {
		return nil, ErrUnauthenticated
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrUnauthenticated
	}
	if !verifySignature(hdr.Alg, pub, parts[0]+"."+parts[1], sig) {
		return nil, ErrUnauthenticated
	}

	var claims struct {
		Sub string          `json:"sub"`
		Exp int64           `json:"exp"`
		Aud json.RawMessage `json:"aud"`
		Act *actClaim       `json:"act"`
	}
	if err := decodeSegment(parts[1], &claims); err != nil {
		return nil, ErrUnauthenticated
	}
	// Expiry is mandatory and enforced with a small leeway (fail closed).
	if claims.Exp == 0 || time.Now().After(time.Unix(claims.Exp, 0).Add(60*time.Second)) {
		return nil, ErrUnauthenticated
	}
	if v.audience != "" && !audienceContains(claims.Aud, v.audience) {
		return nil, ErrUnauthenticated
	}
	// The subject must be a SPIFFE ID in our trust domain.
	if !v.inTrustDomain(claims.Sub) {
		return nil, ErrUnauthenticated
	}
	chain, ok := v.actorChain(claims.Sub, claims.Act)
	if !ok {
		return nil, ErrUnauthenticated // delegation too deep, or a delegate outside the trust domain
	}
	id := &Identity{AgentName: claims.Sub, SPIFFEID: claims.Sub, ActorChain: chain}
	// The accountable party is the outermost actor (the human/service the chain
	// bottoms out at), else the subject itself.
	id.OnBehalfOf = chain[len(chain)-1]
	return id, nil
}

// inTrustDomain reports whether sub is a SPIFFE ID under this verifier's trust
// domain (spiffe://<trustDomain>/<path>).
func (v *SVIDVerifier) inTrustDomain(sub string) bool {
	return strings.HasPrefix(sub, "spiffe://"+v.trustDomain+"/")
}

// actorChain builds the delegation chain from the subject plus any nested RFC
// 8693 act claims: [subject, act.sub, act.act.sub, ...]. Every delegate must be a
// SPIFFE ID in this verifier's trust domain — an out-of-domain or malformed
// act.sub is rejected (fail-closed), so a signed token can't inject a spoofed or
// foreign "accountable party" into the audit chain or the approver UI. A chain
// (counting the subject) beyond maxDepth is likewise rejected.
func (v *SVIDVerifier) actorChain(subject string, act *actClaim) ([]string, bool) {
	chain := []string{subject}
	for a := act; a != nil; a = a.Act {
		if a.Sub == "" {
			break
		}
		if !v.inTrustDomain(a.Sub) {
			return nil, false
		}
		chain = append(chain, a.Sub)
		if len(chain) > v.maxDepth {
			return nil, false
		}
	}
	return chain, true
}

// verifySignature checks a JWT signature for the SPIFFE-supported algorithms
// against the JWS signing input (header.payload). JWT ECDSA signatures are raw
// r||s (not ASN.1); Ed25519 signs the input directly (no prehash).
func verifySignature(alg string, pub crypto.PublicKey, signingInput string, sig []byte) bool {
	switch alg {
	case "RS256":
		rp, ok := pub.(*rsa.PublicKey)
		if !ok {
			return false
		}
		digest := sha256.Sum256([]byte(signingInput))
		return rsa.VerifyPKCS1v15(rp, crypto.SHA256, digest[:], sig) == nil
	case "ES256":
		ep, ok := pub.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 {
			return false
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		digest := sha256.Sum256([]byte(signingInput))
		return ecdsa.Verify(ep, digest[:], r, s)
	case "EdDSA":
		ep, ok := pub.(ed25519.PublicKey)
		if !ok {
			return false
		}
		return ed25519.Verify(ep, []byte(signingInput), sig)
	default:
		return false
	}
}

// publicKeyFromJWK reconstructs a public key from a JWK (RSA, EC P-256, or
// Ed25519 OKP).
func publicKeyFromJWK(k jwk) (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
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
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("agentid: unsupported EC curve %q", k.Crv)
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("agentid: unsupported OKP curve %q", k.Crv)
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		if len(xb) != ed25519.PublicKeySize {
			return nil, errors.New("agentid: bad Ed25519 key length")
		}
		return ed25519.PublicKey(xb), nil
	default:
		return nil, fmt.Errorf("agentid: unsupported key type %q", k.Kty)
	}
}

// decodeSegment base64url-decodes a JWT segment and unmarshals its JSON into v.
func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// audienceContains reports whether the "aud" claim (a string or array of strings)
// includes want.
func audienceContains(raw json.RawMessage, want string) bool {
	if len(raw) == 0 {
		return false
	}
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

// MultiVerifier tries each verifier in order and returns the first success, so a
// deployment can accept both static agent keys and SPIFFE SVIDs.
type MultiVerifier []Verifier

// Verify returns the first verifier's success, or ErrUnauthenticated if none
// recognize the bearer.
func (m MultiVerifier) Verify(ctx context.Context, bearer string) (*Identity, error) {
	for _, v := range m {
		if id, err := v.Verify(ctx, bearer); err == nil {
			return id, nil
		}
	}
	return nil, ErrUnauthenticated
}
