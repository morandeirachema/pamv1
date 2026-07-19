// Package web embeds the management portal (a single self-contained page).
package web

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"net/http"
)

//go:embed static/index.html
var indexHTML []byte

// noncePlaceholder is the token in index.html's <script> tag that Index rewrites
// to the per-request CSP nonce.
var noncePlaceholder = []byte("__CSP_NONCE__")

// nonce returns a fresh base64 CSP nonce, or "" if the system RNG fails — in
// which case the emitted policy matches no script and the page fails closed
// (blank) rather than falling back to a weaker CSP.
func nonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// Index serves the embedded single-page 5250-style portal under a per-request
// nonce-based CSP. The page's one inline <script> carries the nonce, so an
// injected inline script (the only real XSS sink here) cannot execute even if a
// field ever escaped the template's esc(). style-src keeps 'unsafe-inline'
// because the page uses inline style attributes, which nonces cannot cover.
func Index(w http.ResponseWriter, _ *http.Request) {
	n := nonce()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; style-src 'unsafe-inline'; script-src 'nonce-"+n+"'; "+
			"connect-src 'self'; base-uri 'none'; form-action 'self'; "+
			"frame-ancestors 'none'; object-src 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(bytes.Replace(indexHTML, noncePlaceholder, []byte(n), 1))
}
