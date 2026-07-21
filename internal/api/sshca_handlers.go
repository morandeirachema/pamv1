package api

import "net/http"

// sshCAPublicKey publishes the Zero Standing Privilege SSH certificate-authority
// public key (Phase 22) so an operator can trust it on their targets. Installing
// this key as the target's OpenSSH TrustedUserCAKeys lets the account accept the
// short-lived certificates pamv1 mints just-in-time — no standing secret is ever
// stored for the account. Returns 404 when ZSP is not enabled (no CA configured).
func (s *Server) sshCAPublicKey(w http.ResponseWriter, r *http.Request) {
	if s.sshCA == nil {
		writeError(w, http.StatusNotFound, "zero standing privilege is not enabled (set PAM_SSH_CA_KEY)")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"type":        "ssh_ca",
		"public_key":  s.sshCA.AuthorizedKey(),
		"fingerprint": s.sshCA.Fingerprint(),
		"install_hint": "Install on each target: write this line to /etc/ssh/pamv1_ca.pub, " +
			"add `TrustedUserCAKeys /etc/ssh/pamv1_ca.pub` to sshd_config, and reload sshd. " +
			"Then create an ssh_ca credential for the account and connect through the proxy.",
	})
}
