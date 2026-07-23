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
	// The RDP viewer paints guacd's PNG instructions (data: URIs) onto a canvas and
	// dynamic-import()s the same-origin Guacamole client, so img-src must allow
	// data:/blob: and script-src must allow 'self' (in ADDITION to the nonce) —
	// without these the viewer is silently blank. Guard them so a CSP tightening
	// cannot regress the viewer.
	if !strings.Contains(csp, "img-src 'self' data: blob:") {
		t.Errorf("CSP missing RDP-viewer img-src (data:/blob:): %s", csp)
	}
	// Assert the nonce AND 'self' both sit in script-src, so dropping 'self' (which
	// would block the dynamic import and blank the viewer) actually fails this test.
	if !regexp.MustCompile(`script-src 'nonce-[A-Za-z0-9+/=]+' 'self'`).MatchString(csp) {
		t.Errorf("script-src must carry both the nonce and 'self': %s", csp)
	}

	if csp2, _ := get(); csp == csp2 {
		t.Fatal("CSP nonce was reused across requests")
	}
}

// TestIndexExposesConsole checks the served portal is the full management
// console: the expanded main menu and the key management screens are present.
func TestIndexExposesConsole(t *testing.T) {
	rec := httptest.NewRecorder()
	Index(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	body := rec.Body.String()

	// Every management area the console must surface (screen titles / menu items).
	for _, marker := range []string{
		"PAMV1 Main Menu",
		"Work with Targets",
		"Work with Target Grants",
		"Work with Vaulted Credentials",
		"Credential Check-out / Check-in",
		"Work with Active Sessions",
		"Work with Access Requests",
		"Work with Users & Profiles",
		"Multi-Factor Authentication",
		"Discovery Scan",
		"Credential Reconciliation",
		"Display Audit Trail",
		"Break-Glass Unseal",
		"/api/me", // role-aware menu source
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("portal is missing management surface %q", marker)
		}
	}
}
