package registry

import (
	"maps"
	"sort"
	"sync"
	"time"
)

// compile-time check that InMemory implements Repository.
var _ Repository = (*InMemory)(nil)

// InMemory is a thread-safe, in-memory implementation of Repository.
type InMemory struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	now   func() time.Time
	// connected is the live Tunnel set, fed by the transport. Deliberately a
	// separate map from nodes: it is not part of a Node's record and must not
	// survive a restart, and keeping it beside the record would invite somebody
	// to persist it.
	connected        map[string]struct{}
	maxNodes         int    // 0 = unlimited
	minDaemonVersion string // ADR-0014 gate; empty = off. Never mutable via any API.
}

// Option is a functional option for NewInMemory.
type Option func(*InMemory)

// WithClock overrides the clock used to record LastSeen timestamps. Use this
// in tests to get deterministic time values.
func WithClock(now func() time.Time) Option {
	return func(r *InMemory) {
		r.now = now
	}
}

// WithMaxNodes sets a cap on the number of Nodes the registry will accept via
// INSERT. When the cap is reached, Upsert returns ErrAtCapacity for new Nodes;
// updates to existing Nodes are always allowed. Pass 0 (the default) to leave
// the registry unbounded.
func WithMaxNodes(n int) Option {
	return func(r *InMemory) {
		r.maxNodes = n
	}
}

// WithMinDaemonVersion sets the minimum relay-daemon version (ADR-0014) used
// to derive each Node's Outdated flag. Pass "" (the default) to leave the
// gate off — every Node is then always non-outdated. This is a Relay-side
// config value only; it is never settable through Report or any API.
func WithMinDaemonVersion(v string) Option {
	return func(r *InMemory) {
		r.minDaemonVersion = v
	}
}

// NewInMemory returns an empty InMemory registry. Pass WithClock to override
// the clock (defaults to time.Now).
func NewInMemory(opts ...Option) *InMemory {
	r := &InMemory{
		nodes:     make(map[string]*Node),
		connected: make(map[string]struct{}),
		now:       time.Now,
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Upsert registers or updates a Node from a daemon's report.
//
// On insert: stores all report fields; EnrollingTokenID is set from the report
// and RelayLabels is initialized to an empty map.
//
// On update: overwrites CertFingerprint, Facts, NodeLabels, PolicyFingerprint,
// DaemonVersion, TemplateSetFingerprint, and LastSeen.
// RelayLabels is never touched (the node side cannot reach it). EnrollingTokenID
// is preserved from the first enrollment — a reconnecting Hello cannot rewrite
// provenance.
//
// Returns ErrEmptyNodeID if r.NodeID is empty. Returns a deep copy of the
// stored Node.
func (r *InMemory) Upsert(rep Report) (Node, error) {
	if rep.NodeID == "" {
		return Node{}, ErrEmptyNodeID
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	existing, ok := r.nodes[rep.NodeID]
	if !ok {
		// Insert path. Check the cap before allocating anything.
		if r.maxNodes > 0 && len(r.nodes) >= r.maxNodes {
			return Node{}, ErrAtCapacity
		}
		nl := maps.Clone(rep.nodeLabels)
		if nl == nil {
			nl = map[string]string{}
		}
		n := &Node{
			NodeID:                 rep.NodeID,
			CertFingerprint:        rep.CertFingerprint,
			Facts:                  cloneFacts(rep.Facts),
			NodeLabels:             nl,
			RelayLabels:            map[string]string{},
			LastSeen:               r.now(),
			EnrollingTokenID:       rep.EnrollingTokenID,
			PolicyFingerprint:      rep.PolicyFingerprint,
			DaemonVersion:          rep.DaemonVersion,
			TemplateSetFingerprint: rep.TemplateSetFingerprint,
		}
		r.nodes[rep.NodeID] = n
		return r.copyNode(n), nil
	}

	// Update path: overwrite node-rooted fields; leave relay-space untouched.
	nl := maps.Clone(rep.nodeLabels)
	if nl == nil {
		nl = map[string]string{}
	}
	existing.CertFingerprint = rep.CertFingerprint
	existing.Facts = cloneFacts(rep.Facts)
	existing.NodeLabels = nl
	existing.LastSeen = r.now()
	existing.PolicyFingerprint = rep.PolicyFingerprint
	existing.DaemonVersion = rep.DaemonVersion
	existing.TemplateSetFingerprint = rep.TemplateSetFingerprint
	// existing.RelayLabels: unchanged — node report cannot overwrite relay space.
	// existing.EnrollingTokenID: unchanged — provenance is set once at first enrollment.
	return r.copyNode(existing), nil
}

// UpdateLastSeen records the most recent contact time for nodeID. Returns
// ErrNotFound if the Node is not in the registry.
func (r *InMemory) UpdateLastSeen(nodeID string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	n, ok := r.nodes[nodeID]
	if !ok {
		return ErrNotFound
	}
	n.LastSeen = at
	return nil
}

// SetRelayLabels replaces the relay-space label set for nodeID. Facts and
// NodeLabels are never touched. Returns ErrNotFound if the Node is not in the
// registry.
func (r *InMemory) SetRelayLabels(nodeID string, labels map[string]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	n, ok := r.nodes[nodeID]
	if !ok {
		return ErrNotFound
	}
	rl := maps.Clone(labels)
	if rl == nil {
		rl = map[string]string{}
	}
	n.RelayLabels = rl
	return nil
}

// SetRevoked records that nodeID is revoked as of at. Returns ErrNotFound if
// the Node is not in the registry.
func (r *InMemory) SetRevoked(nodeID string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	n, ok := r.nodes[nodeID]
	if !ok {
		return ErrNotFound
	}
	n.RevokedAt = at
	return nil
}

// SetRevokedAll is SetRevoked's chunked twin: it revokes every id in nodeIDs
// as of at under a single lock, the in-memory analogue of the store's single
// transaction. A missing row is not an error: it is appended to missing and
// the rest of the batch still applies. Never returns a non-nil error — there
// is no failure mode to model in memory; the transaction and rollback proofs
// live at the store level.
func (r *InMemory) SetRevokedAll(nodeIDs []string, at time.Time) ([]string, error) {
	if len(nodeIDs) == 0 {
		return nil, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	var missing []string
	for _, id := range nodeIDs {
		n, ok := r.nodes[id]
		if !ok {
			missing = append(missing, id)
			continue
		}
		n.RevokedAt = at
	}
	return missing, nil
}

// RecordEnrollment persists first-enrollment certificate provenance.
func (r *InMemory) RecordEnrollment(nodeID string, cert Certificate, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	n, ok := r.nodes[nodeID]
	if !ok {
		return ErrNotFound
	}
	n.CertNotAfter = cert.NotAfter
	// Written only if unset. Re-enrolling an existing node_id must not rewrite
	// the join date — the provenance chain is the point, and a Node that
	// re-enrolls after a daemon reinstall has not joined the fleet twice.
	if n.EnrolledAt.IsZero() {
		n.EnrolledAt = at
	}
	return nil
}

// RecordRenewal persists a reissued certificate. It never writes EnrolledAt.
func (r *InMemory) RecordRenewal(nodeID string, cert Certificate, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	n, ok := r.nodes[nodeID]
	if !ok {
		return ErrNotFound
	}
	n.CertNotAfter = cert.NotAfter
	n.RenewalCount++
	n.LastRenewedAt = at
	return nil
}

// SetConnected records a Tunnel opening or closing. Never persisted.
func (r *InMemory) SetConnected(nodeID string, connected bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if connected {
		r.connected[nodeID] = struct{}{}
		return
	}
	delete(r.connected, nodeID)
}

// RevokedNodeIDs returns the IDs of every Node with a non-zero RevokedAt.
func (r *InMemory) RevokedNodeIDs() ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var ids []string
	for _, n := range r.nodes {
		if !n.RevokedAt.IsZero() {
			ids = append(ids, n.NodeID)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// Count returns the total number of enrolled Nodes and the subset currently
// revoked (non-zero RevokedAt).
func (r *InMemory) Count() (int, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	total := len(r.nodes)
	revoked := 0
	for _, n := range r.nodes {
		if !n.RevokedAt.IsZero() {
			revoked++
		}
	}
	return total, revoked, nil
}

// Get returns a deep copy of the stored Node record. Returns (Node{}, false)
// if the Node is not in the registry.
func (r *InMemory) Get(nodeID string) (Node, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	n, ok := r.nodes[nodeID]
	if !ok {
		return Node{}, false
	}
	return r.copyNode(n), true
}

// List returns deep copies of all stored Node records, sorted by NodeID.
func (r *InMemory) List() []Node {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]Node, 0, len(r.nodes))
	for _, n := range r.nodes {
		out = append(out, r.copyNode(n))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].NodeID < out[j].NodeID
	})
	return out
}

// ListChecked returns List() and a nil error: an in-memory read cannot fail.
func (r *InMemory) ListChecked() ([]Node, error) {
	return r.List(), nil
}

// copyNode returns a deep copy of n so callers cannot mutate stored state
// through a returned value, with Outdated computed against the registry's
// configured minDaemonVersion (ADR-0014; derived on read, never stored).
//
// It is the single read-back path behind Upsert, Get and List, as getNode is
// for the SQLite store, and like getNode it serves both label namespaces
// through wellFormedLabels: a stored pair WellFormedLabel refuses is declined
// on read.
func (r *InMemory) copyNode(n *Node) Node {
	nl := wellFormedLabels(n.NodeLabels)
	rl := wellFormedLabels(n.RelayLabels)
	return Node{
		NodeID:                 n.NodeID,
		CertFingerprint:        n.CertFingerprint,
		Facts:                  cloneFacts(n.Facts),
		NodeLabels:             nl,
		RelayLabels:            rl,
		LastSeen:               n.LastSeen,
		EnrollingTokenID:       n.EnrollingTokenID,
		PolicyFingerprint:      n.PolicyFingerprint,
		DaemonVersion:          n.DaemonVersion,
		RevokedAt:              n.RevokedAt,
		Outdated:               Outdated(n.DaemonVersion, r.minDaemonVersion),
		TemplateSetFingerprint: n.TemplateSetFingerprint,
		CertNotAfter:           n.CertNotAfter,
		EnrolledAt:             n.EnrolledAt,
		RenewalCount:           n.RenewalCount,
		LastRenewedAt:          n.LastRenewedAt,
		// Derived on read from the live connection set, exactly as Outdated is
		// derived from the configured minimum. Never read off the stored record,
		// because there is no stored record — see Node.Connected.
		Connected: r.isConnected(n.NodeID),
	}
}

// wellFormedLabels returns a new, non-nil map holding only the pairs of
// labels that WellFormedLabel accepts. It mirrors the SQLite store's
// read-back filter of the same name pair for pair, so the fake declines
// exactly what production declines: "decline to serve, never write"
// (#504/#555). The stored map is never modified. Each namespace's own writer
// owns its storage (invariant 7, ADR-0006): the Relay declining to serve a
// value is not the same act as rewriting it. The store's filter also counts
// what it declines for /metrics. The fake has no metrics, so it only filters.
func wellFormedLabels(labels map[string]string) map[string]string {
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		if WellFormedLabel(k, v) {
			out[k] = v
		}
	}
	return out
}

// isConnected reports whether nodeID currently holds a Tunnel. Callers hold at
// least a read lock.
func (r *InMemory) isConnected(nodeID string) bool {
	_, ok := r.connected[nodeID]
	return ok
}

// cloneFacts returns a value copy of f with a cloned IPAddresses slice.
func cloneFacts(f Facts) Facts {
	var ips []string
	if f.IPAddresses != nil {
		ips = make([]string, len(f.IPAddresses))
		copy(ips, f.IPAddresses)
	}
	return Facts{
		Hostname:    f.Hostname,
		OS:          f.OS,
		Kernel:      f.Kernel,
		Arch:        f.Arch,
		IPAddresses: ips,
	}
}
