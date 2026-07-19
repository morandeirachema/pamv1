package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestDecryptFailureIsAudited proves that a failed secret-use (a credential whose
// vault token can no longer be decrypted) is recorded as credential.decrypt_failed
// rather than silently returning a 500.
func TestDecryptFailureIsAudited(t *testing.T) {
	srv, st := newTestServerStore(t)

	// Seed a target + credential, then corrupt the stored ciphertext so decrypt
	// fails on the next reveal.
	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "web-01", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	targetID := int64(jsonMap(t, data)["id"].(float64))
	_, data = do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": targetID, "username": "root", "secret": secretPassword,
	})
	credID := int64(jsonMap(t, data)["id"].(float64))

	if err := st.UpdateCredentialSecretEnc(context.Background(), credID, "v2:corrupted-token"); err != nil {
		t.Fatal(err)
	}

	status, _ := do(t, srv, http.MethodPost, "/api/credentials/"+itoa(credID)+"/reveal", testAPIKey, nil)
	if status != http.StatusInternalServerError {
		t.Fatalf("reveal of a corrupt credential: want 500, got %d", status)
	}

	_, data = do(t, srv, http.MethodGet, "/api/audit", testAPIKey, nil)
	var events []map[string]any
	if err := json.Unmarshal(data, &events); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e["action"] == "credential.decrypt_failed" && strings.Contains(e["detail"].(string), "op:reveal") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a credential.decrypt_failed audit event, got %s", data)
	}
}
