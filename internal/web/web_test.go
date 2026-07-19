package web

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// TestIndexNonceCSP proves the portal is served under a per-request nonce-based
// script-src (no 'unsafe-inline'), that the same nonce appears in the header and
// the page's <script> tag, that the placeholder is substituted, and that each
// request mints a fresh nonce.
func TestIndexNonceCSP(t *testing.T) {
	get := func() (csp, body string) {
		rec := httptest.NewRecorder()
		Index(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		return rec.Header().Get("Content-Security-Policy"), rec.Body.String()
	}
	csp, body := get()

	if strings.Contains(csp, "script-src 'unsafe-inline'") {
		t.Fatalf("script-src still allows unsafe-inline: %q", csp)
	}
	m := regexp.MustCompile(`script-src 'nonce-([A-Za-z0-9+/=]+)'`).FindStringSubmatch(csp)
	if m == nil {
		t.Fatalf("no nonce in script-src: %q", csp)
	}
	nonce := m[1]
	if !strings.Contains(body, `<script nonce="`+nonce+`">`) {
		t.Fatalf("served <script> tag does not carry the CSP nonce %q", nonce)
	}
	if strings.Contains(body, "__CSP_NONCE__") {
		t.Fatal("nonce placeholder was not substituted in the served page")
	}
	for _, dir := range []string{"base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'", "object-src 'none'"} {
		if !strings.Contains(csp, dir) {
			t.Errorf("CSP missing %q: %s", dir, csp)
		}
	}

	if csp2, _ := get(); csp == csp2 {
		t.Fatal("CSP nonce was reused across requests")
	}
}
