package memstore

import (
	"context"
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
)

// TestAuditChainDetectsTampering proves the chain catches an edited event: it is
// an in-package test because it mutates the stored slice directly to simulate a
// database-level tamper (the interface offers no way to alter a written event).
func TestAuditChainDetectsTampering(t *testing.T) {
	m := New()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	m.EnableAuditChain(key)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if err := m.AppendAudit(ctx, &store.AuditEvent{Actor: "a", Action: "credential.reveal", Detail: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	if ok, _, _ := m.VerifyAuditChain(ctx); !ok {
		t.Fatal("freshly built chain should verify")
	}

	// Tamper with a stored event's detail (a DB-level edit an attacker might make).
	m.audit[1].Detail = "TAMPERED"
	ok, brokeAt, err := m.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("tampering was not detected")
	}
	if brokeAt != m.audit[1].ID {
		t.Fatalf("brokeAt = %d, want the tampered event id %d", brokeAt, m.audit[1].ID)
	}
}

// TestVerifyAuditChainDisabled confirms verify errors when chaining is off.
func TestVerifyAuditChainDisabled(t *testing.T) {
	m := New()
	if _, _, err := m.VerifyAuditChain(context.Background()); err == nil {
		t.Fatal("VerifyAuditChain should error when the chain is not enabled")
	}
}
