package session

import "sync"

// Hub fans out live session output to subscribed watchers, keyed by session id.
// The proxy publishes each recorded output chunk; the API's live-stream endpoint
// subscribes a supervisor to watch a session as it happens (Phase 16). Delivery
// is non-blocking: a slow watcher drops frames rather than stalling the session
// it is observing. A nil Hub is a no-op, so callers can hold one unconditionally.
type Hub struct {
	mu   sync.Mutex
	subs map[string]map[chan []byte]struct{}
}

// NewHub returns an empty, ready-to-use live-output hub.
func NewHub() *Hub { return &Hub{subs: make(map[string]map[chan []byte]struct{})} }

// Publish delivers a copy of b to every current subscriber of session id. It
// never blocks the caller: a watcher whose buffer is full drops the frame.
func (h *Hub) Publish(id string, b []byte) {
	if h == nil || id == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	subs := h.subs[id]
	if len(subs) == 0 {
		return
	}
	cp := append([]byte(nil), b...) // the caller may reuse its buffer
	for ch := range subs {
		select {
		case ch <- cp:
		default: // slow watcher: drop this frame rather than stall the session
		}
	}
}

// Subscribe registers a watcher for session id, returning a channel of output
// frames and a cancel func that unsubscribes it. The channel is never closed
// (so a concurrent Publish can never panic); the caller stops reading when its
// own context ends and calls cancel to release the subscription.
func (h *Hub) Subscribe(id string) (<-chan []byte, func()) {
	ch := make(chan []byte, 256)
	h.mu.Lock()
	if h.subs[id] == nil {
		h.subs[id] = make(map[chan []byte]struct{})
	}
	h.subs[id][ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if m := h.subs[id]; m != nil {
			delete(m, ch)
			if len(m) == 0 {
				delete(h.subs, id)
			}
		}
		h.mu.Unlock()
	}
}
