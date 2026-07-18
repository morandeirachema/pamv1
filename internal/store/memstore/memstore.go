// Package memstore is an in-memory store.Store used by tests and the
// "memory" demo mode. Data is lost on restart; production runs on pgstore.
package memstore

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

type Memstore struct {
	mu       sync.Mutex
	nextID   int64
	targets  map[int64]store.Target
	creds    map[int64]store.Credential
	users    map[int64]store.User
	sessions map[int64]store.Session
	mfa      map[string]store.MFAEnrollment
	recovery map[string]map[string]bool // username -> set of code hashes
	audit    []store.AuditEvent
}

func New() *Memstore {
	return &Memstore{
		targets:  make(map[int64]store.Target),
		creds:    make(map[int64]store.Credential),
		users:    make(map[int64]store.User),
		sessions: make(map[int64]store.Session),
		mfa:      make(map[string]store.MFAEnrollment),
		recovery: make(map[string]map[string]bool),
	}
}

func (m *Memstore) id() int64 {
	m.nextID++
	return m.nextID
}

func (m *Memstore) CreateTarget(_ context.Context, t *store.Target) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.targets {
		if existing.Name == t.Name {
			return store.ErrConflict
		}
	}
	t.ID = m.id()
	t.CreatedAt = time.Now().UTC()
	m.targets[t.ID] = *t
	return nil
}

func (m *Memstore) ListTargets(_ context.Context) ([]store.Target, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.Target, 0, len(m.targets))
	for _, t := range m.targets {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memstore) GetTarget(_ context.Context, id int64) (*store.Target, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.targets[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &t, nil
}

func (m *Memstore) DeleteTarget(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.targets[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.targets, id)
	for cid, c := range m.creds {
		if c.TargetID == id {
			delete(m.creds, cid)
		}
	}
	return nil
}

func (m *Memstore) CreateCredential(_ context.Context, c *store.Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.targets[c.TargetID]; !ok {
		return store.ErrNotFound
	}
	c.ID = m.id()
	c.CreatedAt = time.Now().UTC()
	m.creds[c.ID] = *c
	return nil
}

func (m *Memstore) ListCredentials(_ context.Context, targetID int64) ([]store.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.Credential, 0, len(m.creds))
	for _, c := range m.creds {
		if targetID == 0 || c.TargetID == targetID {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memstore) GetCredential(_ context.Context, id int64) (*store.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.creds[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &c, nil
}

func (m *Memstore) DeleteCredential(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.creds[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.creds, id)
	return nil
}

func (m *Memstore) AppendAudit(_ context.Context, e *store.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e.ID = m.id()
	e.TS = time.Now().UTC()
	m.audit = append(m.audit, *e)
	return nil
}

func (m *Memstore) ListAudit(_ context.Context, limit int) ([]store.AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.audit)
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]store.AuditEvent, 0, limit)
	for i := n - 1; i >= n-limit; i-- {
		out = append(out, m.audit[i])
	}
	return out, nil
}

func (m *Memstore) CreateUser(_ context.Context, u *store.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.users {
		if existing.Username == u.Username {
			return store.ErrConflict
		}
	}
	u.ID = m.id()
	u.CreatedAt = time.Now().UTC()
	m.users[u.ID] = *u
	return nil
}

func (m *Memstore) ListUsers(_ context.Context) ([]store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memstore) GetUserByTokenHash(_ context.Context, tokenHashHex string) (*store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.TokenHash == tokenHashHex {
			return &u, nil
		}
	}
	return nil, store.ErrNotFound
}

func (m *Memstore) DeleteUser(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.users, id)
	return nil
}

func (m *Memstore) CreateSession(_ context.Context, s *store.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s.ID = m.id()
	s.CreatedAt = time.Now().UTC()
	m.sessions[s.ID] = *s
	return nil
}

func (m *Memstore) GetSessionByTokenHash(_ context.Context, tokenHashHex string) (*store.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for _, s := range m.sessions {
		if s.TokenHash == tokenHashHex {
			if now.After(s.ExpiresAt) {
				return nil, store.ErrNotFound
			}
			return &s, nil
		}
	}
	return nil, store.ErrNotFound
}

func (m *Memstore) DeleteSession(_ context.Context, tokenHashHex string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if s.TokenHash == tokenHashHex {
			delete(m.sessions, id)
			return nil
		}
	}
	return store.ErrNotFound
}

func (m *Memstore) UpsertMFAEnrollment(_ context.Context, e *store.MFAEnrollment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	m.mfa[e.Username] = *e
	return nil
}

func (m *Memstore) GetMFAEnrollment(_ context.Context, username string) (*store.MFAEnrollment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.mfa[username]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &e, nil
}

func (m *Memstore) DeleteMFAEnrollment(_ context.Context, username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.mfa[username]; !ok {
		return store.ErrNotFound
	}
	delete(m.mfa, username)
	delete(m.recovery, username)
	return nil
}

func (m *Memstore) ReplaceMFARecoveryCodes(_ context.Context, username string, codeHashes []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	set := make(map[string]bool, len(codeHashes))
	for _, h := range codeHashes {
		set[h] = true
	}
	m.recovery[username] = set
	return nil
}

func (m *Memstore) ConsumeMFARecoveryCode(_ context.Context, username, codeHash string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	set := m.recovery[username]
	if set == nil || !set[codeHash] {
		return false, nil
	}
	delete(set, codeHash)
	return true, nil
}

func (m *Memstore) CountMFARecoveryCodes(_ context.Context, username string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.recovery[username]), nil
}

func (m *Memstore) Close() {}
