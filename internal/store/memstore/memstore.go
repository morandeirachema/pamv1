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
	mu            sync.Mutex
	nextID        int64
	targets       map[int64]store.Target
	creds         map[int64]store.Credential
	users         map[int64]store.User
	sessions      map[int64]store.Session
	mfa           map[string]store.MFAEnrollment
	recovery      map[string]map[string]bool // username -> set of code hashes
	grants        map[int64]store.TargetGrant
	accessReq     map[int64]store.AccessRequest
	checkouts     map[int64]store.Checkout
	oidcStates    map[string]oidcState
	audit         []store.AuditEvent
	agentKeys     map[int64]store.AgentKey
	brokerLog     []store.BrokerAuditEvent
	brokerTok     map[string]store.BrokerToken
	settings      map[string]store.Setting
	profiles      map[int64]store.Profile
	safes         map[int64]store.Safe
	safeMembers   map[int64]store.SafeMember
	credDeps      map[int64]store.CredentialDependency
	campaigns     map[int64]store.Campaign
	campaignItems map[int64]store.CampaignItem
}

// New returns an empty in-memory store ready for use.
func New() *Memstore {
	return &Memstore{
		targets:       make(map[int64]store.Target),
		creds:         make(map[int64]store.Credential),
		users:         make(map[int64]store.User),
		sessions:      make(map[int64]store.Session),
		mfa:           make(map[string]store.MFAEnrollment),
		recovery:      make(map[string]map[string]bool),
		grants:        make(map[int64]store.TargetGrant),
		accessReq:     make(map[int64]store.AccessRequest),
		checkouts:     make(map[int64]store.Checkout),
		agentKeys:     make(map[int64]store.AgentKey),
		brokerTok:     make(map[string]store.BrokerToken),
		settings:      make(map[string]store.Setting),
		profiles:      make(map[int64]store.Profile),
		safes:         make(map[int64]store.Safe),
		safeMembers:   make(map[int64]store.SafeMember),
		credDeps:      make(map[int64]store.CredentialDependency),
		campaigns:     make(map[int64]store.Campaign),
		campaignItems: make(map[int64]store.CampaignItem),
	}
}

// cloneProfile deep-copies a profile so callers can't mutate the stored slice.
func cloneProfile(p store.Profile) store.Profile {
	p.Capabilities = append([]string(nil), p.Capabilities...)
	return p
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

// EffectiveTargetGrants unions a target's direct grants with grants derived from
// its safe's membership (Phase 17).
func (m *Memstore) EffectiveTargetGrants(_ context.Context, targetID int64) ([]store.TargetGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.TargetGrant, 0)
	for _, g := range m.grants {
		if g.TargetID == targetID {
			out = append(out, g)
		}
	}
	if t, ok := m.targets[targetID]; ok && t.SafeID != nil {
		for _, sm := range m.safeMembers {
			if sm.SafeID == *t.SafeID {
				out = append(out, store.TargetGrant{ID: sm.ID, TargetID: targetID, SubjectType: sm.SubjectType, Subject: sm.Subject})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// CreateSafe inserts a safe, assigning ID and CreatedAt.
func (m *Memstore) CreateSafe(_ context.Context, sf *store.Safe) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ex := range m.safes {
		if ex.Name == sf.Name {
			return store.ErrConflict
		}
	}
	sf.ID = m.id()
	sf.CreatedAt = time.Now().UTC()
	m.safes[sf.ID] = *sf
	return nil
}

// ListSafes returns all safes ordered by name.
func (m *Memstore) ListSafes(_ context.Context) ([]store.Safe, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.Safe, 0, len(m.safes))
	for _, sf := range m.safes {
		out = append(out, sf)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// GetSafe returns a safe by ID, or ErrNotFound.
func (m *Memstore) GetSafe(_ context.Context, id int64) (*store.Safe, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sf, ok := m.safes[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &sf, nil
}

// DeleteSafe removes a safe, cascading its members and unassigning its targets.
func (m *Memstore) DeleteSafe(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.safes[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.safes, id)
	for mid, sm := range m.safeMembers {
		if sm.SafeID == id {
			delete(m.safeMembers, mid)
		}
	}
	for tid, t := range m.targets {
		if t.SafeID != nil && *t.SafeID == id {
			t.SafeID = nil
			m.targets[tid] = t
		}
	}
	return nil
}

// AddSafeMember adds a member to a safe.
func (m *Memstore) AddSafeMember(_ context.Context, mem *store.SafeMember) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.safes[mem.SafeID]; !ok {
		return store.ErrNotFound
	}
	for _, ex := range m.safeMembers {
		if ex.SafeID == mem.SafeID && ex.SubjectType == mem.SubjectType && ex.Subject == mem.Subject {
			return store.ErrConflict
		}
	}
	mem.ID = m.id()
	m.safeMembers[mem.ID] = *mem
	return nil
}

// ListSafeMembers returns a safe's members ordered by id.
func (m *Memstore) ListSafeMembers(_ context.Context, safeID int64) ([]store.SafeMember, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.SafeMember, 0)
	for _, sm := range m.safeMembers {
		if sm.SafeID == safeID {
			out = append(out, sm)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// DeleteSafeMember removes a safe member by ID, or ErrNotFound.
func (m *Memstore) DeleteSafeMember(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.safeMembers[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.safeMembers, id)
	return nil
}

// AssignTargetSafe sets (or clears, when safeID is nil) a target's safe.
func (m *Memstore) AssignTargetSafe(_ context.Context, targetID int64, safeID *int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.targets[targetID]
	if !ok {
		return store.ErrNotFound
	}
	if safeID != nil {
		if _, ok := m.safes[*safeID]; !ok {
			return store.ErrNotFound
		}
	}
	t.SafeID = safeID
	m.targets[targetID] = t
	return nil
}

// CreateCredentialDependency declares a consumer of a credential.
func (m *Memstore) CreateCredentialDependency(_ context.Context, d *store.CredentialDependency) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.creds[d.CredentialID]; !ok {
		return store.ErrNotFound
	}
	if d.Port == 0 {
		d.Port = 5985
	}
	d.ID = m.id()
	m.credDeps[d.ID] = *d
	return nil
}

// ListCredentialDependencies returns a credential's declared consumers.
func (m *Memstore) ListCredentialDependencies(_ context.Context, credentialID int64) ([]store.CredentialDependency, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.CredentialDependency, 0)
	for _, d := range m.credDeps {
		if d.CredentialID == credentialID {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// DeleteCredentialDependency removes a dependency by ID, or ErrNotFound.
func (m *Memstore) DeleteCredentialDependency(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.credDeps[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.credDeps, id)
	return nil
}

// CreateCampaign inserts a certification campaign, assigning ID and CreatedAt.
func (m *Memstore) CreateCampaign(_ context.Context, c *store.Campaign) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c.Status == "" {
		c.Status = "open"
	}
	c.ID = m.id()
	c.CreatedAt = time.Now().UTC()
	m.campaigns[c.ID] = *c
	return nil
}

// ListCampaigns returns all campaigns, newest first.
func (m *Memstore) ListCampaigns(_ context.Context) ([]store.Campaign, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.Campaign, 0, len(m.campaigns))
	for _, c := range m.campaigns {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// GetCampaign returns a campaign by ID, or ErrNotFound.
func (m *Memstore) GetCampaign(_ context.Context, id int64) (*store.Campaign, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.campaigns[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &c, nil
}

// CloseCampaign marks a campaign closed at the given time.
func (m *Memstore) CloseCampaign(_ context.Context, id int64, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.campaigns[id]
	if !ok {
		return store.ErrNotFound
	}
	c.Status = "closed"
	t := at.UTC()
	c.ClosedAt = &t
	m.campaigns[id] = c
	return nil
}

// AddCampaignItem adds one access item to a campaign.
func (m *Memstore) AddCampaignItem(_ context.Context, item *store.CampaignItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.campaigns[item.CampaignID]; !ok {
		return store.ErrNotFound
	}
	if item.Decision == "" {
		item.Decision = "pending"
	}
	item.ID = m.id()
	m.campaignItems[item.ID] = *item
	return nil
}

// ListCampaignItems returns a campaign's items ordered by id.
func (m *Memstore) ListCampaignItems(_ context.Context, campaignID int64) ([]store.CampaignItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.CampaignItem, 0)
	for _, it := range m.campaignItems {
		if it.CampaignID == campaignID {
			out = append(out, it)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// GetCampaignItem returns one item by ID, or ErrNotFound.
func (m *Memstore) GetCampaignItem(_ context.Context, id int64) (*store.CampaignItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.campaignItems[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &it, nil
}

// DecideCampaignItem records a certify/revoke decision on an item.
func (m *Memstore) DecideCampaignItem(_ context.Context, id int64, decision, decidedBy string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.campaignItems[id]
	if !ok {
		return store.ErrNotFound
	}
	it.Decision = decision
	it.DecidedBy = decidedBy
	t := at.UTC()
	it.DecidedAt = &t
	m.campaignItems[id] = it
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
	if ar.RequiredApprovals < 1 {
		ar.RequiredApprovals = 1
	}
	m.accessReq[ar.ID] = *ar
	return nil
}

// SetApprovalState records a multi-approver decision (Phase 21).
func (m *Memstore) SetApprovalState(_ context.Context, id int64, approvedBy, status, approver string, decidedAt *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ar, ok := m.accessReq[id]
	if !ok {
		return store.ErrNotFound
	}
	ar.ApprovedBy = approvedBy
	ar.Status = status
	ar.Approver = approver
	if decidedAt != nil {
		t := decidedAt.UTC()
		ar.DecidedAt = &t
	}
	m.accessReq[id] = ar
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
			ar.Status == "approved" && now.Before(ar.ExpiresAt) &&
			(ar.NotBefore == nil || !now.Before(*ar.NotBefore)) {
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
// ErrConflict if it already has an active (unexpired, unreturned) checkout as of
// now. An expired-but-unreturned lease is auto-closed rather than blocking the new
// checkout, mirroring pgstore's expire-then-insert so at most one unreturned lease
// per credential exists in either store.
func (m *Memstore) CreateCheckout(_ context.Context, co *store.Checkout, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.creds[co.CredentialID]; !ok {
		return store.ErrNotFound
	}
	for id, existing := range m.checkouts {
		if existing.CredentialID != co.CredentialID || existing.ReturnedAt != nil {
			continue
		}
		if now.Before(existing.ExpiresAt) {
			return store.ErrConflict // an active lease still holds the credential
		}
		t := now.UTC() // expired: close it so it neither blocks nor lingers unreturned
		existing.ReturnedAt = &t
		m.checkouts[id] = existing
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
	// pgstore FKs cascade checkouts and dependencies on credential delete — match it.
	for coid, co := range m.checkouts {
		if co.CredentialID == id {
			delete(m.checkouts, coid)
		}
	}
	for did, d := range m.credDeps {
		if d.CredentialID == id {
			delete(m.credDeps, did)
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

// CreateAgentKey inserts an agent key, assigning its ID and CreatedAt; ErrConflict
// if the token hash is taken.
func (m *Memstore) CreateAgentKey(_ context.Context, k *store.AgentKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.agentKeys {
		if existing.TokenHash == k.TokenHash {
			return store.ErrConflict
		}
	}
	k.ID = m.id()
	k.CreatedAt = time.Now().UTC()
	m.agentKeys[k.ID] = *k
	return nil
}

// GetAgentKeyByTokenHash returns the enabled agent key whose token hash matches,
// or ErrNotFound (a disabled key is treated as not found).
func (m *Memstore) GetAgentKeyByTokenHash(_ context.Context, tokenHashHex string) (*store.AgentKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range m.agentKeys {
		if k.TokenHash == tokenHashHex && !k.Disabled {
			out := k
			return &out, nil
		}
	}
	return nil, store.ErrNotFound
}

// ListAgentKeys returns all agent keys ordered by ID.
func (m *Memstore) ListAgentKeys(_ context.Context) ([]store.AgentKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.AgentKey, 0, len(m.agentKeys))
	for _, k := range m.agentKeys {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// DeleteAgentKey removes an agent key by ID; ErrNotFound if absent.
func (m *Memstore) DeleteAgentKey(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.agentKeys[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.agentKeys, id)
	return nil
}

// GetAgentKey returns an agent key by ID (regardless of disabled), or ErrNotFound.
func (m *Memstore) GetAgentKey(_ context.Context, id int64) (*store.AgentKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.agentKeys[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &k, nil
}

// CreateBrokerToken stores a single-use resume token for a parked tool call.
func (m *Memstore) CreateBrokerToken(_ context.Context, t *store.BrokerToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.brokerTok[t.JTI]; exists {
		return store.ErrConflict // match pgstore's PK-violation semantics
	}
	m.brokerTok[t.JTI] = *t
	return nil
}

// ConsumeBrokerToken spends a token under the lock, so only the first caller
// wins; a used, expired, or unknown jti returns ErrNotFound.
func (m *Memstore) ConsumeBrokerToken(_ context.Context, jti string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.brokerTok[jti]
	if !ok || t.UsedAt != nil || time.Now().After(t.ExpiresAt) {
		return "", store.ErrNotFound
	}
	now := time.Now().UTC()
	t.UsedAt = &now
	m.brokerTok[jti] = t
	return t.CallID, nil
}

// PeekBrokerToken returns a token's bound call id without spending it.
func (m *Memstore) PeekBrokerToken(_ context.Context, jti string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.brokerTok[jti]
	if !ok || t.UsedAt != nil || time.Now().After(t.ExpiresAt) {
		return "", store.ErrNotFound
	}
	return t.CallID, nil
}

// DeleteExpiredBrokerTokens removes spent or expired tokens (periodic GC).
func (m *Memstore) DeleteExpiredBrokerTokens(_ context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	now := time.Now()
	for jti, t := range m.brokerTok {
		if t.UsedAt != nil || now.After(t.ExpiresAt) {
			delete(m.brokerTok, jti)
			n++
		}
	}
	return n, nil
}

// PutSetting upserts a configuration override, stamping UpdatedAt.
func (m *Memstore) PutSetting(_ context.Context, s *store.Setting) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s.UpdatedAt = time.Now().UTC()
	m.settings[s.Key] = *s
	return nil
}

// GetSetting returns the override for key, or ErrNotFound.
func (m *Memstore) GetSetting(_ context.Context, key string) (*store.Setting, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.settings[key]; ok {
		out := s
		return &out, nil
	}
	return nil, store.ErrNotFound
}

// ListSettings returns all configuration overrides ordered by key.
func (m *Memstore) ListSettings(_ context.Context) ([]store.Setting, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.Setting, 0, len(m.settings))
	for _, s := range m.settings {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// DeleteSetting removes the override for key; ErrNotFound if absent.
func (m *Memstore) DeleteSetting(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.settings[key]; !ok {
		return store.ErrNotFound
	}
	delete(m.settings, key)
	return nil
}

// CreateProfile inserts a custom permission profile; ErrConflict on a duplicate name.
func (m *Memstore) CreateProfile(_ context.Context, p *store.Profile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.profiles {
		if e.Name == p.Name {
			return store.ErrConflict
		}
	}
	p.ID = m.id()
	p.CreatedAt = time.Now().UTC()
	m.profiles[p.ID] = cloneProfile(*p)
	return nil
}

// GetProfile returns the profile with the given name, or ErrNotFound.
func (m *Memstore) GetProfile(_ context.Context, name string) (*store.Profile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.profiles {
		if p.Name == name {
			out := cloneProfile(p)
			return &out, nil
		}
	}
	return nil, store.ErrNotFound
}

// ListProfiles returns all custom profiles ordered by name.
func (m *Memstore) ListProfiles(_ context.Context) ([]store.Profile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.Profile, 0, len(m.profiles))
	for _, p := range m.profiles {
		out = append(out, cloneProfile(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// DeleteProfile removes a profile by ID; ErrNotFound if absent.
func (m *Memstore) DeleteProfile(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.profiles[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.profiles, id)
	return nil
}

// AppendBrokerAuditLinked links the event to the current head and appends it
// under the store mutex — the single-process analogue of pgstore's advisory
// lock — assigning ID and TS. Reading the head and appending are one atomic
// step, so an appender's cached head is only advisory.
func (m *Memstore) AppendBrokerAuditLinked(_ context.Context, link func(head *store.BrokerAuditEvent) store.BrokerAuditEvent) (store.BrokerAuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var head *store.BrokerAuditEvent
	if n := len(m.brokerLog); n > 0 {
		h := cloneBrokerEvent(m.brokerLog[n-1])
		head = &h
	}
	ev := link(head)
	ev.ID = m.id()
	ev.TS = time.Now().UTC()
	// Deep-copy the hash-chain byte slices so the stored row can't alias (and be
	// mutated through) the returned event — parity with pgstore's fresh scans.
	m.brokerLog = append(m.brokerLog, cloneBrokerEvent(ev))
	return ev, nil
}

// cloneBrokerEvent returns a copy whose PrevHash/HMAC byte slices are independent
// of the argument, so stored and returned rows never alias.
func cloneBrokerEvent(e store.BrokerAuditEvent) store.BrokerAuditEvent {
	e.PrevHash = append([]byte(nil), e.PrevHash...)
	e.HMAC = append([]byte(nil), e.HMAC...)
	return e
}

// ListBrokerAudit returns broker audit events oldest-first; limit <= 0 returns
// the whole chain, limit > 0 the most recent limit events (still in chain order).
func (m *Memstore) ListBrokerAudit(_ context.Context, limit int) ([]store.BrokerAuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.brokerLog)
	start := 0
	if limit > 0 && limit < n {
		start = n - limit
	}
	out := make([]store.BrokerAuditEvent, 0, n-start)
	for _, e := range m.brokerLog[start:] {
		out = append(out, cloneBrokerEvent(e))
	}
	return out, nil
}

// GetBrokerAuditHead returns the most recent broker audit event, or (nil, nil)
// when the log is empty.
func (m *Memstore) GetBrokerAuditHead(_ context.Context) (*store.BrokerAuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.brokerLog) == 0 {
		return nil, nil
	}
	out := cloneBrokerEvent(m.brokerLog[len(m.brokerLog)-1])
	return &out, nil
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
