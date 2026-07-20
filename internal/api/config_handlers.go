package api

import (
	"net/http"

	"github.com/morandeirachema/pamv1/internal/config"
	"github.com/morandeirachema/pamv1/internal/store"
)

// listConfig returns the overridable configuration keys with their current DB
// override (secret values masked). The effective value is env-merged at startup;
// this shows what an admin has overridden and may edit.
func (s *Server) listConfig(w http.ResponseWriter, r *http.Request) {
	stored, err := s.store.ListSettings(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	byKey := make(map[string]store.Setting, len(stored))
	for _, st := range stored {
		byKey[st.Key] = st
	}
	type item struct {
		Key        string `json:"key"`
		Secret     bool   `json:"secret"`
		Overridden bool   `json:"overridden"`
		Value      string `json:"value"`
	}
	out := make([]item, 0, len(config.OverridableKeys()))
	for _, key := range config.OverridableKeys() {
		it := item{Key: key, Secret: config.IsSecretKey(key)}
		if st, ok := byKey[key]; ok {
			it.Overridden = true
			if it.Secret {
				it.Value = "********"
			} else {
				it.Value = st.Value
			}
		}
		out = append(out, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"settings": out,
		"note":     "Overrides " + s.reloadNote() + ". Bootstrap/transport settings (database, master key, listen/TLS) stay environment-only.",
	})
}

// reloadNote describes when a configuration change becomes effective, depending
// on whether hot-swap (a wired reconfigure closure) is enabled.
func (s *Server) reloadNote() string {
	if s.hotSwap() {
		return "take effect immediately for identity, SSO and API-enforced policy; " +
			"the SSH proxy's protocol/approval gates and networking/TLS apply on restart"
	}
	return "take effect on restart"
}

type configIn struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// putConfig stores a configuration override; secret values are vault-encrypted.
func (s *Server) putConfig(w http.ResponseWriter, r *http.Request) {
	var in configIn
	if !readJSON(w, r, &in) {
		return
	}
	if !config.IsOverridable(in.Key) {
		writeError(w, http.StatusUnprocessableEntity, "key is not an overridable configuration setting")
		return
	}
	if in.Value == "" {
		writeError(w, http.StatusUnprocessableEntity, "value is required (use DELETE to clear an override)")
		return
	}
	setting := store.Setting{Key: in.Key, Value: in.Value, Secret: config.IsSecretKey(in.Key)}
	if setting.Secret {
		enc, err := s.vault.Encrypt(r.Context(), in.Value, store.ConfigAAD(in.Key))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encryption failed")
			return
		}
		setting.Value = enc
	}
	// Capture the prior override so a rejected hot-swap can be rolled back rather
	// than leaving a bad value that would also break the next restart.
	prev, prevErr := s.store.GetSetting(r.Context(), in.Key)
	if err := s.store.PutSetting(r.Context(), &setting); err != nil {
		storeError(w, err)
		return
	}
	if err := s.applyReconfigure(r.Context()); err != nil {
		if prevErr == nil {
			_ = s.store.PutSetting(r.Context(), prev)
		} else {
			_ = s.store.DeleteSetting(r.Context(), in.Key)
		}
		writeError(w, http.StatusUnprocessableEntity, "configuration rejected: "+err.Error())
		return
	}
	s.audit(r.Context(), "config.update", in.Key)
	writeJSON(w, http.StatusOK, map[string]any{"key": in.Key, "updated": true, "note": "changes " + s.reloadNote()})
}

// deleteConfig clears a configuration override, reverting to the environment.
func (s *Server) deleteConfig(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if err := s.store.DeleteSetting(r.Context(), key); err != nil {
		storeError(w, err)
		return
	}
	// Reverting to the env baseline, which was valid at startup, so a reconfigure
	// failure here is unexpected; surface it but leave the override cleared.
	if err := s.applyReconfigure(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "override cleared but reload failed: "+err.Error())
		return
	}
	s.audit(r.Context(), "config.revert", key)
	w.WriteHeader(http.StatusNoContent)
}
