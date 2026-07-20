package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/morandeirachema/pamv1/internal/config"
	"github.com/morandeirachema/pamv1/internal/store"
)

// effectiveConfig reports the read-only runtime status of the identity/SSO/policy
// backends (which are wired, and the operational-policy toggles in force) plus
// whether configuration changes hot-swap or need a restart. It reads the live
// runtime snapshot, so it reflects any override applied since startup.
func (s *Server) effectiveConfig(w http.ResponseWriter, r *http.Request) {
	rt := s.rt()
	writeJSON(w, http.StatusOK, map[string]any{
		"backends": map[string]bool{
			"password_login":      rt.authn != nil,
			"oidc_login":          rt.oidc != nil,
			"directory_reconcile": rt.directory != nil,
			"mfa_required":        rt.mfaRequired,
			"reveal_disabled":     rt.revealDisabled,
			"approval_required":   rt.approvalRequired,
			"broker_enabled":      s.broker != nil,
		},
		"hot_swap": s.hotSwap(),
		"note":     "Identity, SSO and API-enforced policy hot-swap; the SSH proxy's protocol/approval gates and networking/TLS apply on restart. Use the IaC export to codify console changes back into env/Helm/Terraform.",
	})
}

// iacConfig renders the current DB-persisted configuration overrides as
// deployable infrastructure-as-code (env file, Helm values, or Terraform
// locals), so console changes can be committed back to the IaC that owns the
// deployment. Secret values are never emitted — they render as placeholders
// wired to a secret store.
func (s *Server) iacConfig(w http.ResponseWriter, r *http.Request) {
	settings, err := s.store.ListSettings(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	sort.Slice(settings, func(i, j int) bool { return settings[i].Key < settings[j].Key })
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "env"
	}
	var content string
	switch format {
	case "env":
		content = renderEnv(settings)
	case "helm":
		content = renderHelm(settings)
	case "terraform", "tf":
		format = "terraform"
		content = renderTerraform(settings)
	default:
		writeError(w, http.StatusUnprocessableEntity, `format must be "env", "helm", or "terraform"`)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"format": format, "content": content})
}

// iacSecretPlaceholder is emitted in place of a secret override's value so the
// export never carries plaintext; the operator wires it to their secret store.
const iacSecretPlaceholder = "CHANGE_ME__set_from_secret_store"

// renderEnv renders the overrides as a dotenv file.
func renderEnv(settings []store.Setting) string {
	var b strings.Builder
	b.WriteString("# pamv1 configuration overrides (exported from the console).\n")
	b.WriteString("# Networking/TLS/bootstrap stay in your existing env — these are identity/SSO/policy.\n")
	for _, st := range settings {
		if config.IsSecretKey(st.Key) {
			fmt.Fprintf(&b, "%s=%s\n", st.Key, iacSecretPlaceholder)
			continue
		}
		fmt.Fprintf(&b, "%s=%s\n", st.Key, st.Value)
	}
	return b.String()
}

// renderHelm renders the overrides as a Helm values.yaml env block, wiring
// secrets to a secretKeyRef instead of an inline value.
func renderHelm(settings []store.Setting) string {
	var b strings.Builder
	b.WriteString("# pamv1 configuration overrides (exported from the console).\n")
	b.WriteString("env:\n")
	for _, st := range settings {
		if config.IsSecretKey(st.Key) {
			fmt.Fprintf(&b, "  - name: %s\n    valueFrom:\n      secretKeyRef:\n        name: pamv1-secrets\n        key: %s\n", st.Key, strings.ToLower(st.Key))
			continue
		}
		fmt.Fprintf(&b, "  - name: %s\n    value: %q\n", st.Key, st.Value)
	}
	return b.String()
}

// renderTerraform renders the overrides as a Terraform locals map, keeping
// secret values out of state via a placeholder.
func renderTerraform(settings []store.Setting) string {
	var b strings.Builder
	b.WriteString("# pamv1 configuration overrides (exported from the console).\n")
	b.WriteString("locals {\n  pam_config = {\n")
	for _, st := range settings {
		val := st.Value
		if config.IsSecretKey(st.Key) {
			val = iacSecretPlaceholder
		}
		fmt.Fprintf(&b, "    %s = %q\n", st.Key, val)
	}
	b.WriteString("  }\n}\n")
	return b.String()
}
