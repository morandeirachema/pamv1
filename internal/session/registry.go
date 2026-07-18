// Package session tracks live brokered sessions so operators can see who is
// connected and terminate a session. The registry is shared between the SSH
// proxy (which registers sessions) and the API (which lists and kills them).
package session

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync"
	"time"
)

// Info describes a live session (safe to serialize to auditors).
type Info struct {
	ID       string    `json:"id"`
	Actor    string    `json:"actor"`
	Target   string    `json:"target"`
	Protocol string    `json:"protocol"` // ssh | rdp
	Remote   string    `json:"remote"`
	Started  time.Time `json:"started"`
}

type entry struct {
	info Info
	kill func()
}

// Registry is a thread-safe set of live sessions.
type Registry struct {
	mu sync.Mutex
	m  map[string]entry
}

func NewRegistry() *Registry { return &Registry{m: make(map[string]entry)} }

// Register records a session and returns its id; kill terminates it when called
// (e.g. closes the underlying connection).
func (r *Registry) Register(info Info, kill func()) string {
	id := randID()
	info.ID = id
	r.mu.Lock()
	r.m[id] = entry{info: info, kill: kill}
	r.mu.Unlock()
	return id
}

// Remove drops a session (call when it ends).
func (r *Registry) Remove(id string) {
	r.mu.Lock()
	delete(r.m, id)
	r.mu.Unlock()
}

// List returns the live sessions, oldest first.
func (r *Registry) List() []Info {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Info, 0, len(r.m))
	for _, e := range r.m {
		out = append(out, e.info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.Before(out[j].Started) })
	return out
}

// Kill terminates a session by id, returning whether it was found.
func (r *Registry) Kill(id string) bool {
	r.mu.Lock()
	e, ok := r.m[id]
	r.mu.Unlock()
	if !ok {
		return false
	}
	if e.kill != nil {
		e.kill()
	}
	return true
}

func randID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
