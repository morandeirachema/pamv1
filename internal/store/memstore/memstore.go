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
	mu         sync.Mutex
	nextID     int64
	targets    map[int64]store.Target
	creds      map[int64]store.Credential
	users      map[int64]store.User
	sessions   map[int64]store.Session
	mfa        map[string]store.MFAEnrollment
	recovery   map[string]map[string]bool // username -> set of code hashes
	grants     map[int64]store.TargetGrant
	accessReq  map[int64]store.AccessRequest
	checkouts  map[int64]store.Checkout
	oidcStates map[string]oidcState
	audit      []store.AuditEvent
}

// New returns an empty in-memory store ready for use.
func New() *Memstore {
	return &Memstore{
		targets:   make(map[int64]store.Target),
		creds:     make(map[int64]store.Credential),
		users:     make(map[int64]store.User),
		sessions:  make(map[int64]store.Session),
		mfa:       make(map[string]store.MFAEnrollment),
		recovery:  make(map[string]map[string]bool),
		grants:    make(map[int64]store.TargetGrant),
		accessReq: make(map[int64]store.AccessRequest),
		checkouts: make(map[int64]store.Checkout),
	}
}

// id returns the next monotonically increasing identity; the caller holds the lock.
func (m *Memstore) id() int64 {
	m.nextID++
	return m.nextID
}

// CreateTarget inserts a target, assigning its ID and CreatedAt; ErrConflict if the name is taken.
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

// ListTargets returns all targets ordered by ID.
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

// GetTarget returns the target with the given ID, or ErrNotFound.
func (m *Memstore) GetTarget(_ context.Context, id int64) (*store.Target, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.targets[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &t, nil
}

// DeleteTarget removes a target and cascades to its credentials, grants, and
// access requests; ErrNotFound if the target is absent.
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
	for gid, g := range m.grants {
		if g.TargetID == id {
			delete(m.grants, gid)
		}
	}
	for aid, ar := range m.accessReq {
		if ar.TargetID == id {
			delete(m.accessReq, aid)
		}
	}
	// pgstore FKs cascade checkouts on target delete — match it so an orphaned
	// active lease can't survive only in the demo store.
	for coid, co := range m.checkouts {
		if co.TargetID == id {
			delete(m.checkouts, coid)
		}
	}
	return nil
}

// CreateTargetGrant adds a grant for an existing target; ErrNotFound if the
// target is missing, ErrConflict if an identical grant already exists.
func (m *Memstore) CreateTargetGrant(_ context.Context, g *store.TargetGrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.targets[g.TargetID]; !ok {
		return store.ErrNotFound
	}
	for _, ex := range m.grants {
		if ex.TargetID == g.TargetID && ex.SubjectType == g.SubjectType && ex.Subject == g.Subject {
			return store.ErrConflict
		}
	}
	g.ID = m.id()
	m.grants[g.ID] = *g
	return nil
}

// ListTargetGrants returns the grants for a target, ordered by ID.
func (m *Memstore) ListTargetGrants(_ context.Context, targetID int64) ([]store.TargetGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.TargetGrant, 0)
	for _, g := range m.grants {
		if g.TargetID == targetID {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// DeleteTargetGrant removes a grant by ID; ErrNotFound if absent.
func (m *Memstore) DeleteTargetGrant(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.grants[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.grants, id)
	return nil
}

// CreateAccessRequest records a new request (defaulting status to pending) for
// an existing target; ErrNotFound if the target is missing.
func (m *Memstore) CreateAccessRequest(_ context.Context, ar *store.AccessRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.targets[ar.TargetID]; !ok {
		return store.ErrNotFound
	}
	ar.ID = m.id()
	ar.CreatedAt = time.Now().UTC()
	if ar.Status == "" {
		ar.Status = "pending"
	}
	m.accessReq[ar.ID] = *ar
	return nil
}

// GetAccessRequest returns the access request with the given ID, or ErrNotFound.
func (m *Memstore) GetAccessRequest(_ context.Context, id int64) (*store.AccessRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ar, ok := m.accessReq[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	ar.DecidedAt = cloneTimePtr(ar.DecidedAt)
	return &ar, nil
}

// ListAccessRequests returns requests with the given status (all when status is
// ""), ordered by ID.
func (m *Memstore) ListAccessRequests(_ context.Context, status string) ([]store.AccessRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.AccessRequest, 0, len(m.accessReq))
	for _, ar := range m.accessReq {
		if status == "" || ar.Status == status {
			ar.DecidedAt = cloneTimePtr(ar.DecidedAt)
			out = append(out, ar)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// DecideAccessRequest records an approve/deny decision, approver, and decision
// time; ErrNotFound if the request is missing.
func (m *Memstore) DecideAccessRequest(_ context.Context, id int64, status, approver string, decidedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ar, ok := m.accessReq[id]
	if !ok {
		return store.ErrNotFound
	}
	ar.Status = status
	ar.Approver = approver
	at := decidedAt.UTC()
	ar.DecidedAt = &at
	m.accessReq[id] = ar
	return nil
}

// HasActiveApproval reports whether requester has an approved, unexpired request
// for targetID as of now.
func (m *Memstore) HasActiveApproval(_ context.Context, requester string, targetID int64, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ar := range m.accessReq {
		if ar.Requester == requester && ar.TargetID == targetID &&
			ar.Status == "approved" && now.Before(ar.ExpiresAt) {
			return true, nil
		}
	}
	return false, nil
}

// activeCheckoutLocked returns the credential's active (unreturned, unexpired)
// checkout, if any; the caller holds the lock.
func (m *Memstore) activeCheckoutLocked(credentialID int64, now time.Time) (store.Checkout, bool) {
	for _, co := range m.checkouts {
		if co.CredentialID == credentialID && co.ReturnedAt == nil && now.Before(co.ExpiresAt) {
			return co, true
		}
	}
	return store.Checkout{}, false
}

// CreateCheckout leases a credential; ErrNotFound if the credential is missing,
// ErrConflict if it already has an active checkout as of now.
func (m *Memstore) CreateCheckout(_ context.Context, co *store.Checkout, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.creds[co.CredentialID]; !ok {
		return store.ErrNotFound
	}
	if _, active := m.activeCheckoutLocked(co.CredentialID, now); active {
		return store.ErrConflict
	}
	co.ID = m.id()
	co.CheckedOutAt = now.UTC()
	m.checkouts[co.ID] = *co
	return nil
}

// GetActiveCheckout returns the credential's active checkout as of now, or ErrNotFound.
func (m *Memstore) GetActiveCheckout(_ context.Context, credentialID int64, now time.Time) (*store.Checkout, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if co, active := m.activeCheckoutLocked(credentialID, now); active {
		co.ReturnedAt = cloneTimePtr(co.ReturnedAt)
		return &co, nil
	}
	return nil, store.ErrNotFound
}

// CheckinCheckout marks a checkout returned; ErrNotFound if missing or already returned.
func (m *Memstore) CheckinCheckout(_ context.Context, id int64, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	co, ok := m.checkouts[id]
	if !ok || co.ReturnedAt != nil {
		return store.ErrNotFound
	}
	t := at.UTC()
	co.ReturnedAt = &t
	m.checkouts[id] = co
	return nil
}

// ListCheckouts returns checkouts ordered by ID; activeOnly limits to
// unreturned, unexpired ones as of now.
func (m *Memstore) ListCheckouts(_ context.Context, activeOnly bool, now time.Time) ([]store.Checkout, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.Checkout, 0, len(m.checkouts))
	for _, co := range m.checkouts {
		if activeOnly && (co.ReturnedAt != nil || !now.Before(co.ExpiresAt)) {
			continue
		}
		co.ReturnedAt = cloneTimePtr(co.ReturnedAt)
		out = append(out, co)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// CreateCredential inserts a credential for an existing target, assigning its ID
// and CreatedAt; ErrNotFound if the target is missing.
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

// ListCredentials returns credentials for one target, or all when targetID is 0,
// ordered by ID.
func (m *Memstore) ListCredentials(_ context.Context, targetID int64) ([]store.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.Credential, 0, len(m.creds))
	for _, c := range m.creds {
		if targetID == 0 || c.TargetID == targetID {
			c.RotatedAt = cloneTimePtr(c.RotatedAt)
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// GetCredential returns the credential with the given ID, or ErrNotFound.
func (m *Memstore) GetCredential(_ context.Context, id int64) (*store.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.creds[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	c.RotatedAt = cloneTimePtr(c.RotatedAt)
	return &c, nil
}

// cloneTimePtr returns a fresh copy of a *time.Time so a caller can't mutate the
// value the store still holds in its map (pgstore hands back independent values).
func cloneTimePtr(p *time.Time) *time.Time {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// UpdateCredentialSecretEnc replaces a credential's encrypted secret without
// touching rotated_at; ErrNotFound if absent.
func (m *Memstore) UpdateCredentialSecretEnc(_ context.Context, id int64, secretEnc string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.creds[id]
	if !ok {
		return store.ErrNotFound
	}
	c.SecretEnc = secretEnc
	m.creds[id] = c
	return nil
}

// RotateCredentialSecret replaces the encrypted secret and stamps rotated_at;
// ErrNotFound if absent.
func (m *Memstore) RotateCredentialSecret(_ context.Context, id int64, secretEnc string, rotatedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.creds[id]
	if !ok {
		return store.ErrNotFound
	}
	c.SecretEnc = secretEnc
	at := rotatedAt.UTC()
	c.RotatedAt = &at
	m.creds[id] = c
	return nil
}

// DeleteCredential removes a credential by ID; ErrNotFound if absent.
func (m *Memstore) DeleteCredential(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.creds[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.creds, id)
	// pgstore FKs cascade checkouts on credential delete — match it.
	for coid, co := range m.checkouts {
		if co.CredentialID == id {
			delete(m.checkouts, coid)
		}
	}
	return nil
}

// AppendAudit appends an audit event, assigning its ID and timestamp.
func (m *Memstore) AppendAudit(_ context.Context, e *store.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e.ID = m.id()
	e.TS = time.Now().UTC()
	m.audit = append(m.audit, *e)
	return nil
}

// ListAudit returns up to limit audit events, newest first (all when limit <= 0).
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

// ExportAudit returns audit events with since <= ts < until, oldest-first; a
// zero since means from the beginning and a zero until means up to now.
func (m *Memstore) ExportAudit(_ context.Context, since, until time.Time) ([]store.AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if until.IsZero() {
		until = time.Now()
	}
	out := make([]store.AuditEvent, 0, len(m.audit))
	for _, e := range m.audit {
		if (since.IsZero() || !e.TS.Before(since)) && e.TS.Before(until) {
			out = append(out, e)
		}
	}
	return out, nil
}

// CreateUser inserts a user, assigning its ID and CreatedAt; ErrConflict if the username is taken.
func (m *Memstore) CreateUser(_ context.Context, u *store.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.users {
		// pgstore has UNIQUE constraints on both columns; match it so identity
		// resolution (GetUserByTokenHash) can't become ambiguous in the demo store.
		if existing.Username == u.Username || existing.TokenHash == u.TokenHash {
			return store.ErrConflict
		}
	}
	u.ID = m.id()
	u.CreatedAt = time.Now().UTC()
	m.users[u.ID] = *u
	return nil
}

// ListUsers returns all users ordered by ID.
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

// GetUserByTokenHash returns the user whose token hash matches, or ErrNotFound.
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

// DeleteUser removes a user by ID; ErrNotFound if absent.
func (m *Memstore) DeleteUser(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.users, id)
	return nil
}

// CreateSession inserts a session, assigning its ID and CreatedAt.
func (m *Memstore) CreateSession(_ context.Context, s *store.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s.ID = m.id()
	s.CreatedAt = time.Now().UTC()
	m.sessions[s.ID] = *s
	return nil
}

// GetSessionByTokenHash returns a non-expired session matching the token hash,
// or ErrNotFound.
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

// DeleteSession removes the session with the given token hash; ErrNotFound if absent.
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

// UpsertMFAEnrollment creates or replaces a user's TOTP enrollment.
func (m *Memstore) UpsertMFAEnrollment(_ context.Context, e *store.MFAEnrollment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	m.mfa[e.Username] = *e
	return nil
}

// GetMFAEnrollment returns a user's TOTP enrollment, or ErrNotFound.
func (m *Memstore) GetMFAEnrollment(_ context.Context, username string) (*store.MFAEnrollment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.mfa[username]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &e, nil
}

// ConsumeTOTPStep records step as the user's last-used TOTP step, returning true
// only if it is newer than the stored one (else it is a replay).
func (m *Memstore) ConsumeTOTPStep(_ context.Context, username string, step int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.mfa[username]
	if !ok {
		return false, nil
	}
	if step > e.LastTOTPStep {
		e.LastTOTPStep = step
		m.mfa[username] = e
		return true, nil
	}
	return false, nil
}

// ListMFAEnrollments returns all enrollments ordered by username.
func (m *Memstore) ListMFAEnrollments(_ context.Context) ([]store.MFAEnrollment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.MFAEnrollment, 0, len(m.mfa))
	for _, e := range m.mfa {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

// DeleteMFAEnrollment removes a user's enrollment and any recovery codes;
// ErrNotFound if the enrollment is absent.
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

// ReplaceMFARecoveryCodes stores a fresh set of recovery-code hashes for a user,
// discarding any previous set.
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

// ConsumeMFARecoveryCode removes a matching unused recovery code and reports
// whether one was consumed.
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

// CountMFARecoveryCodes returns how many recovery codes remain for a user.
func (m *Memstore) CountMFARecoveryCodes(_ context.Context, username string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.recovery[username]), nil
}

type oidcState struct {
	verifier, nonce string
	expiresAt       time.Time
}

// PutOIDCState stores PKCE verifier/nonce state for an OIDC login, sweeping
// expired entries first.
func (m *Memstore) PutOIDCState(_ context.Context, state, verifier, nonce string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.oidcStates == nil {
		m.oidcStates = make(map[string]oidcState)
	}
	now := time.Now()
	for k, v := range m.oidcStates { // opportunistic expiry sweep
		if now.After(v.expiresAt) {
			delete(m.oidcStates, k)
		}
	}
	m.oidcStates[state] = oidcState{verifier: verifier, nonce: nonce, expiresAt: expiresAt.UTC()}
	return nil
}

// TakeOIDCState atomically fetches and deletes an unexpired state; ok is false
// if it is missing or expired.
func (m *Memstore) TakeOIDCState(_ context.Context, state string, now time.Time) (string, string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.oidcStates[state]
	if ok {
		delete(m.oidcStates, state)
	}
	if !ok || now.After(s.expiresAt) {
		return "", "", false, nil
	}
	return s.verifier, s.nonce, true, nil
}

// Ping always succeeds for the in-memory store.
func (m *Memstore) Ping(_ context.Context) error { return nil }

// Close is a no-op for the in-memory store.
func (m *Memstore) Close() {}
