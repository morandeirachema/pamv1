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

// guacamoleJS is the vendored Apache Guacamole JavaScript client (an unmodified
// ESM build of guacamole-common-js, Apache-2.0 — see the repo NOTICE). It powers
// the in-portal RDP viewer, rendering guacd's protocol stream to a canvas. It is
// loaded on demand via a dynamic import() from the portal's one inline script.
//
//go:embed static/guacamole-common.min.js
var guacamoleJS []byte

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
	// script-src adds 'self' so the portal may dynamic-import() the vendored,
	// same-origin Guacamole client; img-src/media-src add data:/blob: because the
	// RDP viewer paints guacd's PNG instructions (data: URIs) and audio (blobs)
	// onto a canvas. Everything remains same-origin — no third-party host is
	// allowed, and script-src still forbids inline scripts without the nonce.
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; style-src 'unsafe-inline'; script-src 'nonce-"+n+"' 'self'; "+
			"img-src 'self' data: blob:; media-src 'self' data: blob:; "+
			"connect-src 'self'; base-uri 'none'; form-action 'self'; "+
			"frame-ancestors 'none'; object-src 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(bytes.Replace(indexHTML, noncePlaceholder, []byte(n), 1))
}

// GuacamoleJS serves the vendored guacamole-common-js ESM module (immutable, so
// it is cached aggressively). It is public, like the portal page itself; the RDP
// tunnel and token endpoints — not this static asset — enforce authorization.
func GuacamoleJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	_, _ = w.Write(guacamoleJS)
}
