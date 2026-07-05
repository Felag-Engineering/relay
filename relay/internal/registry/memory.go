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
	mu       sync.RWMutex
	nodes    map[string]*Node
	now      func() time.Time
	maxNodes int // 0 = unlimited
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

// NewInMemory returns an empty InMemory registry. Pass WithClock to override
// the clock (defaults to time.Now).
func NewInMemory(opts ...Option) *InMemory {
	r := &InMemory{
		nodes: make(map[string]*Node),
		now:   time.Now,
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
// and LastSeen.
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
		nl := maps.Clone(rep.NodeLabels)
		if nl == nil {
			nl = map[string]string{}
		}
		n := &Node{
			NodeID:            rep.NodeID,
			CertFingerprint:   rep.CertFingerprint,
			Facts:             cloneFacts(rep.Facts),
			NodeLabels:        nl,
			RelayLabels:       map[string]string{},
			LastSeen:          r.now(),
			EnrollingTokenID:  rep.EnrollingTokenID,
			PolicyFingerprint: rep.PolicyFingerprint,
		}
		r.nodes[rep.NodeID] = n
		return copyNode(n), nil
	}

	// Update path: overwrite node-rooted fields; leave relay-space untouched.
	nl := maps.Clone(rep.NodeLabels)
	if nl == nil {
		nl = map[string]string{}
	}
	existing.CertFingerprint = rep.CertFingerprint
	existing.Facts = cloneFacts(rep.Facts)
	existing.NodeLabels = nl
	existing.LastSeen = r.now()
	existing.PolicyFingerprint = rep.PolicyFingerprint
	// existing.RelayLabels: unchanged — node report cannot overwrite relay space.
	// existing.EnrollingTokenID: unchanged — provenance is set once at first enrollment.
	return copyNode(existing), nil
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

// Get returns a deep copy of the stored Node record. Returns (Node{}, false)
// if the Node is not in the registry.
func (r *InMemory) Get(nodeID string) (Node, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	n, ok := r.nodes[nodeID]
	if !ok {
		return Node{}, false
	}
	return copyNode(n), true
}

// List returns deep copies of all stored Node records, sorted by NodeID.
func (r *InMemory) List() []Node {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]Node, 0, len(r.nodes))
	for _, n := range r.nodes {
		out = append(out, copyNode(n))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].NodeID < out[j].NodeID
	})
	return out
}

// copyNode returns a deep copy of n so callers cannot mutate stored state
// through a returned value.
func copyNode(n *Node) Node {
	nl := maps.Clone(n.NodeLabels)
	if nl == nil {
		nl = map[string]string{}
	}
	rl := maps.Clone(n.RelayLabels)
	if rl == nil {
		rl = map[string]string{}
	}
	return Node{
		NodeID:            n.NodeID,
		CertFingerprint:   n.CertFingerprint,
		Facts:             cloneFacts(n.Facts),
		NodeLabels:        nl,
		RelayLabels:       rl,
		LastSeen:          n.LastSeen,
		EnrollingTokenID:  n.EnrollingTokenID,
		PolicyFingerprint: n.PolicyFingerprint,
	}
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
