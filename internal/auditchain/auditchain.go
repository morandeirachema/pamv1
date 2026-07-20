// Package auditchain implements the broker's tamper-evident, keyed-HMAC
// hash-chained audit log. Each appended event's HMAC covers the previous event's
// HMAC and the event's semantic content, so any content edit, reorder, or
// mid-history deletion breaks the chain; tail truncation is caught by an
// ed25519-signed head checkpoint. The broker is the sole writer, and a mutex
// serializes appends so rows chain in a deterministic order.
//
// The event timestamp is recorded but deliberately NOT part of the HMAC input,
// so the chain survives a database timestamp-precision round-trip; content,
// ordering, and truncation are all still covered.
package auditchain

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// KeySize is the required HMAC key length in bytes.
const KeySize = 32

// Chain appends and verifies broker audit events against a store.
type Chain struct {
	mu      sync.Mutex
	key     []byte
	signKey ed25519.PrivateKey
	st      store.Store
	head    []byte // last event's HMAC, kept in memory
}

// New builds a Chain, seeding its in-memory head from the store's latest event.
// The HMAC key must be KeySize bytes and signKey a valid ed25519 private key.
func New(ctx context.Context, key []byte, signKey ed25519.PrivateKey, st store.Store) (*Chain, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("auditchain: HMAC key must be %d bytes, got %d", KeySize, len(key))
	}
	if len(signKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("auditchain: invalid ed25519 signing key")
	}
	c := &Chain{key: key, signKey: signKey, st: st}
	head, err := st.GetBrokerAuditHead(ctx)
	if err != nil {
		return nil, err
	}
	if head != nil {
		c.head = head.HMAC
	}
	return c, nil
}

// Append chains and persists ev; its PrevHash/HMAC (and ID/TS from the store) are
// set on the returned copy. The HMAC is computed from the head the store reads
// back under its append lock, not from c.head, so concurrent writers (rolling
// deploy, HA) can't fork the chain; c.head is kept only as an advisory hint.
func (c *Chain) Append(ctx context.Context, ev store.BrokerAuditEvent) (store.BrokerAuditEvent, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out, err := c.st.AppendBrokerAuditLinked(ctx, func(head *store.BrokerAuditEvent) store.BrokerAuditEvent {
		var prev []byte
		if head != nil {
			prev = head.HMAC
		}
		ev.HMAC = c.mac(prev, ev)
		// Store an empty (non-nil) prev_hash at genesis so a NOT NULL column
		// accepts it; verify recomputes from the running head, so the value is
		// informational.
		ev.PrevHash = prev
		if ev.PrevHash == nil {
			ev.PrevHash = []byte{}
		}
		return ev
	})
	if err != nil {
		return store.BrokerAuditEvent{}, err
	}
	c.head = out.HMAC
	return out, nil
}

// Verify walks the whole chain oldest-first, recomputing each HMAC. It returns
// ok=false and the id of the first event whose HMAC does not reproduce (a
// content edit or a mid-history deletion).
func (c *Chain) Verify(ctx context.Context) (ok bool, brokeAtID int64, err error) {
	events, err := c.st.ListBrokerAudit(ctx, 0)
	if err != nil {
		return false, 0, err
	}
	var head []byte
	for i := range events {
		ev := events[i]
		if !hmac.Equal(c.mac(head, ev), ev.HMAC) {
			return false, ev.ID, nil
		}
		head = ev.HMAC
	}
	return true, 0, nil
}

// Checkpoint is a signed anchor of the chain at a point in time. An auditor
// stores it and later detects tail truncation if the current chain no longer
// reproduces this (LastID, Head), verified against the broker's ed25519 public key.
type Checkpoint struct {
	LastID    int64     `json:"last_id"`
	Count     int64     `json:"count"`
	Head      []byte    `json:"head"`      // last event's HMAC (base64 in JSON)
	TS        time.Time `json:"ts"`        // when the checkpoint was produced
	Signature []byte    `json:"signature"` // ed25519 over (last_id || head)
	PublicKey []byte    `json:"public_key"`
}

// Head returns a freshly signed checkpoint of the chain's current head.
func (c *Chain) Head(ctx context.Context, now time.Time) (Checkpoint, error) {
	head, err := c.st.GetBrokerAuditHead(ctx)
	if err != nil {
		return Checkpoint{}, err
	}
	cp := Checkpoint{TS: now.UTC(), PublicKey: c.signKey.Public().(ed25519.PublicKey)}
	if head != nil {
		cp.LastID = head.ID
		cp.Count = head.ID // highest row id (a BIGSERIAL upper bound; rolled-back inserts can leave gaps, so this is not an exact row count — truncation detection relies on the signed LastID/Head, not Count)
		cp.Head = head.HMAC
	}
	cp.Signature = ed25519.Sign(c.signKey, checkpointMsg(cp.LastID, cp.Head))
	return cp, nil
}

// mac computes HMAC-SHA256(key, prev || canonical(ev)).
func (c *Chain) mac(prev []byte, ev store.BrokerAuditEvent) []byte {
	m := hmac.New(sha256.New, c.key)
	m.Write(prev)
	m.Write(canonical(ev))
	return m.Sum(nil)
}

// canonical is the deterministic serialization of an event's semantic content
// (not id/ts/prev_hash/hmac) that the chain protects.
func canonical(ev store.BrokerAuditEvent) []byte {
	b, _ := json.Marshal(struct {
		Actor      string `json:"actor"`
		OnBehalfOf string `json:"on_behalf_of"`
		ActorChain string `json:"actor_chain"`
		Action     string `json:"action"`
		Detail     string `json:"detail"`
		Scope      string `json:"scope"`
	}{ev.Actor, ev.OnBehalfOf, ev.ActorChain, ev.Action, ev.Detail, ev.Scope})
	return b
}

// checkpointMsg is the ed25519-signed message: big-endian last_id followed by head.
func checkpointMsg(lastID int64, head []byte) []byte {
	msg := make([]byte, 8, 8+len(head))
	binary.BigEndian.PutUint64(msg, uint64(lastID))
	return append(msg, head...)
}
