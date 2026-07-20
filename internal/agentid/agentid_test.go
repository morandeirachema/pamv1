package agentid

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// TestStaticVerifier proves a valid agent bearer resolves to a RoleAgent
// identity, and that empty / unknown / disabled bearers all fail closed and
// indistinguishably.
func TestStaticVerifier(t *testing.T) {
	st := memstore.New()
	ctx := context.Background()
	hash := func(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }

	if err := st.CreateAgentKey(ctx, &store.AgentKey{Name: "bot", Owner: "alice", TokenHash: hash("good-bearer")}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAgentKey(ctx, &store.AgentKey{Name: "off", TokenHash: hash("disabled-bearer"), Disabled: true}); err != nil {
		t.Fatal(err)
	}
	v := NewStaticVerifier(st)

	id, err := v.Verify(ctx, "good-bearer")
	if err != nil {
		t.Fatalf("valid bearer: %v", err)
	}
	if id.AgentName != "bot" || id.OnBehalfOf != "alice" {
		t.Fatalf("identity = %+v", id)
	}
	if p := id.Principal(); p.Name != "bot" || p.Role != auth.RoleAgent {
		t.Fatalf("principal = %+v, want name=bot role=agent", p)
	}

	for _, bad := range []string{"", "   ", "wrong", "disabled-bearer"} {
		if _, err := v.Verify(ctx, bad); err != ErrUnauthenticated {
			t.Errorf("bearer %q: want ErrUnauthenticated, got %v", bad, err)
		}
	}
}
