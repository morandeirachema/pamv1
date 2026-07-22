package store_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
)

// secretFields lists every struct field that carries secret or
// tamper-evidence-internal material and MUST be tagged `json:"-"` so it can never
// be serialized to a client. This is security invariant §6.1 / §6.7 from
// docs/ARCHITECTURE-LOW-LEVEL.md, encoded as an executable test: adding a
// secret-bearing field without `json:"-"` (or renaming one of these) fails here.
var secretFields = []struct {
	typ   any
	field string
}{
	{store.Credential{}, "SecretEnc"},
	{store.User{}, "TokenHash"},
	{store.AgentKey{}, "TokenHash"},
	{store.AppKey{}, "TokenHash"},
	{store.Session{}, "TokenHash"},
	{store.BrokerToken{}, "JTI"},
	{store.MFAEnrollment{}, "SecretEnc"},
	{store.MFAEnrollment{}, "LastTOTPStep"},
	{store.BrokerAuditEvent{}, "PrevHash"},
}

// TestSecretFieldsAreNeverSerialized asserts each secret-bearing field is
// `json:"-"`, so it is structurally impossible to leak it through the JSON API.
func TestSecretFieldsAreNeverSerialized(t *testing.T) {
	for _, c := range secretFields {
		rt := reflect.TypeOf(c.typ)
		f, ok := rt.FieldByName(c.field)
		if !ok {
			t.Errorf("%s.%s: field no longer exists — update secretFields (and check the secret is still protected)", rt.Name(), c.field)
			continue
		}
		if tag := f.Tag.Get("json"); tag != "-" {
			t.Errorf("%s.%s must be `json:\"-\"` (secret material), got json:%q", rt.Name(), c.field, tag)
		}
	}
}

// TestSecretValuesDoNotAppearInJSON is the behavioral counterpart: marshal fully
// populated records and confirm the secret material is absent from the output,
// so a future serialization change can't silently start leaking it.
func TestSecretValuesDoNotAppearInJSON(t *testing.T) {
	const marker = "S3CRET-MARKER-DO-NOT-LEAK"
	records := []any{
		store.Credential{ID: 1, Username: "root", SecretEnc: "v2:" + marker},
		store.User{ID: 1, Username: "alice", TokenHash: marker},
		store.AgentKey{ID: 1, Name: "agent", TokenHash: marker},
		store.AppKey{ID: 1, Name: "app", TokenHash: marker},
		store.Session{ID: 1, Username: "alice", TokenHash: marker},
		store.MFAEnrollment{Username: "alice", SecretEnc: "v2:" + marker},
		store.BrokerToken{JTI: marker, CallID: "call_1"},
	}
	for _, rec := range records {
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal %T: %v", rec, err)
		}
		if strings.Contains(string(b), marker) {
			t.Errorf("%T serialized its secret material: %s", rec, b)
		}
	}
}
