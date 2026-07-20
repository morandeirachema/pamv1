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
		"note":     "Overrides take effect on restart. Bootstrap/transport settings (database, master key, listen/TLS) stay environment-only.",
	})
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
	if err := s.store.PutSetting(r.Context(), &setting); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "config.update", in.Key)
	writeJSON(w, http.StatusOK, map[string]any{"key": in.Key, "updated": true, "note": "takes effect on restart"})
}

// deleteConfig clears a configuration override, reverting to the environment.
func (s *Server) deleteConfig(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if err := s.store.DeleteSetting(r.Context(), key); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "config.revert", key)
	w.WriteHeader(http.StatusNoContent)
}
