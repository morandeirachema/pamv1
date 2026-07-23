package memstore

import (
	"testing"

	"github.com/morandeirachema/pamv1/internal/store/storetest"
)

// TestMemstoreContract runs the shared store conformance suite against memstore.
func TestMemstoreContract(t *testing.T) {
	storetest.RunStoreContract(t, New())
}

// TestMemstoreAuditChainContract runs the shared audit-chain conformance suite.
func TestMemstoreAuditChainContract(t *testing.T) {
	storetest.RunAuditChainContract(t, New())
}
