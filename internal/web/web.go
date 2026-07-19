// Package web embeds the management portal (a single self-contained page).
package web

import (
	_ "embed"
	"net/http"
)

//go:embed static/index.html
var indexHTML []byte

// Index serves the embedded single-page 5250-style portal with a strict CSP.
func Index(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(indexHTML)
}
