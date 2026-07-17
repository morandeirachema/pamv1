package api_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

const (
	testAPIKey     = "test-api-key"
	breakGlassKey  = "sealed-emergency-key"
	secretPassword = "S3cret-P@ssw0rd!"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	masterKey, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	bgHash := sha256.Sum256([]byte(breakGlassKey))
	handler, err := api.New(memstore.New(), v, testAPIKey, hex.EncodeToString(bgHash[:]))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func do(t *testing.T, srv *httptest.Server, method, path, apiKey string, body any) (int, []byte) {
	t.Helper()
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		buf = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, srv.URL+path, buf)
	if err != nil {
		t.Fatal(err)
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

func jsonMap(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal %q: %v", data, err)
	}
	return m
}

func TestHealthzIsOpen(t *testing.T) {
	srv := newTestServer(t)
	status, _ := do(t, srv, http.MethodGet, "/healthz", "", nil)
	if status != http.StatusOK {
		t.Fatalf("healthz status = %d", status)
	}
}

func TestAuthRequired(t *testing.T) {
	srv := newTestServer(t)
	for _, key := range []string{"", "wrong-key"} {
		status, _ := do(t, srv, http.MethodGet, "/api/targets", key, nil)
		if status != http.StatusUnauthorized {
			t.Fatalf("key %q: status = %d, want 401", key, status)
		}
	}
}

func TestFullFlow(t *testing.T) {
	srv := newTestServer(t)

	status, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "web-01", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	if status != http.StatusCreated {
		t.Fatalf("create target: %d %s", status, data)
	}
	targetID := int64(jsonMap(t, data)["id"].(float64))

	status, data = do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": targetID, "username": "root", "secret": secretPassword,
	})
	if status != http.StatusCreated {
		t.Fatalf("create credential: %d %s", status, data)
	}
	if strings.Contains(string(data), secretPassword) || strings.Contains(string(data), "secret_enc") {
		t.Fatalf("credential response leaks secret material: %s", data)
	}
	credID := int64(jsonMap(t, data)["id"].(float64))

	status, data = do(t, srv, http.MethodGet, "/api/credentials?target_id=1", testAPIKey, nil)
	if status != http.StatusOK || strings.Contains(string(data), secretPassword) {
		t.Fatalf("list credentials: %d %s", status, data)
	}

	status, data = do(t, srv, http.MethodPost,
		"/api/credentials/"+itoa(credID)+"/reveal", testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("reveal: %d %s", status, data)
	}
	if jsonMap(t, data)["secret"] != secretPassword {
		t.Fatalf("revealed secret mismatch: %s", data)
	}

	status, data = do(t, srv, http.MethodGet, "/api/audit", testAPIKey, nil)
	if status != http.StatusOK || !strings.Contains(string(data), "credential.reveal") {
		t.Fatalf("audit must record the reveal: %d %s", status, data)
	}

	status, _ = do(t, srv, http.MethodDelete, "/api/targets/"+itoa(targetID), testAPIKey, nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete target: %d", status)
	}
	status, data = do(t, srv, http.MethodGet, "/api/credentials", testAPIKey, nil)
	if status != http.StatusOK || strings.TrimSpace(string(data)) != "[]" {
		t.Fatalf("credentials must cascade on target delete: %s", data)
	}
}

func TestBreakGlass(t *testing.T) {
	srv := newTestServer(t)
	status, _ := do(t, srv, http.MethodGet, "/api/targets", breakGlassKey, nil)
	if status != http.StatusOK {
		t.Fatalf("break-glass key rejected: %d", status)
	}
	status, data := do(t, srv, http.MethodGet, "/api/audit", testAPIKey, nil)
	if status != http.StatusOK || !strings.Contains(string(data), "breakglass.access") ||
		!strings.Contains(string(data), "break-glass") {
		t.Fatalf("break-glass use must be audited: %d %s", status, data)
	}
}

func TestValidationAndConflicts(t *testing.T) {
	srv := newTestServer(t)
	status, _ := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "x", "host": "h", "os_type": "solaris", "protocol": "ssh",
	})
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("bad os_type: %d, want 422", status)
	}
	payload := map[string]any{"name": "dup", "host": "h", "os_type": "linux", "protocol": "ssh"}
	if status, _ = do(t, srv, http.MethodPost, "/api/targets", testAPIKey, payload); status != http.StatusCreated {
		t.Fatalf("create: %d", status)
	}
	if status, _ = do(t, srv, http.MethodPost, "/api/targets", testAPIKey, payload); status != http.StatusConflict {
		t.Fatalf("duplicate name: %d, want 409", status)
	}
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
