// Package policyview holds the Relay's in-memory, thread-safe, DISPLAY-ONLY
// cache of each Node's daemon-reported effective Policy.
//
// This is display only: Policy is locally-rooted and remotely-immutable
// (ADR-0002) and evaluated only by the daemon's live engine (ADR-0011,
// invariant 12). The Relay never evaluates Policy itself and never sets a
// Node's Policy — it only records what a daemon reports (DaemonMessage.policy
// / relayv1.PolicySnapshot) so describe_node (#117) can show it to an
// authorized caller. Nothing in this package parses argv, checks a regex, or
// makes an allow/deny decision; it is a passive cache, the read-side sibling
// of registry.Node.PolicyFingerprint.
//
// Proto-free domain mirror, following the registry.Facts / jobs precedent:
// this package carries no proto dependency. The caller (relay/cmd/relay's
// tunnel handler) converts relayv1.PolicySnapshot to Snapshot before
// calling Set.
//
// In-memory, not registry/store: keeping this thin-surface issue out of the
// registry.Repository interface and the SQLite migration path. A snapshot is
// refreshed on every (re)connect (see tunnel.go); a Relay restart empties the
// cache until each Node reconnects and re-reports, so describe_node correctly
// shows reported=false for any Node that hasn't reconnected yet — never a
// stale, possibly-wrong Policy view.
package policyview

import "sync"

// OperationRule is a proto-free mirror of relayv1.OperationRule: one
// [[operation]] allow rule from the daemon's loaded Policy file, verbatim.
// AllowedArgs[i] is the permitted-value set at argv position i; an empty
// slice means the Operation is allowed with zero arguments. Display-only —
// see package doc.
type OperationRule struct {
	Name        string
	AllowedArgs [][]string
}

// DenyRule is a proto-free mirror of relayv1.DenyRule: one [[deny]] rule from
// the daemon's loaded Policy file, verbatim. Args[i] is the denied-value set
// at argv position i; an empty slice denies the whole Operation regardless
// of arguments. Display-only — see package doc.
type DenyRule struct {
	Name string
	Args [][]string
}

// Snapshot is a proto-free mirror of relayv1.PolicySnapshot: the
// daemon-reported effective Policy for one Node, at the time it was last
// reported. Display-only (see package doc).
type Snapshot struct {
	RawExecEnabled    bool
	RawAllowPatterns  []string
	RawDenyPatterns   []string
	AllowedOperations []string
	PolicyFingerprint string
	OperationRules    []OperationRule
	DenyRules         []DenyRule
}

// cloneArgSets returns a deep copy of a [][]string so no shared backing
// array (outer or inner) escapes the cache.
func cloneArgSets(sets [][]string) [][]string {
	if sets == nil {
		return nil
	}
	out := make([][]string, len(sets))
	for i, s := range sets {
		out[i] = append([]string(nil), s...)
	}
	return out
}

// clone returns a deep copy of s so Set/Get never let a caller mutate cached
// state through a shared slice (registry.copyNode precedent).
func (s Snapshot) clone() Snapshot {
	out := s
	out.RawAllowPatterns = append([]string(nil), s.RawAllowPatterns...)
	out.RawDenyPatterns = append([]string(nil), s.RawDenyPatterns...)
	out.AllowedOperations = append([]string(nil), s.AllowedOperations...)
	if s.OperationRules != nil {
		out.OperationRules = make([]OperationRule, len(s.OperationRules))
		for i, r := range s.OperationRules {
			out.OperationRules[i] = OperationRule{
				Name:        r.Name,
				AllowedArgs: cloneArgSets(r.AllowedArgs),
			}
		}
	}
	if s.DenyRules != nil {
		out.DenyRules = make([]DenyRule, len(s.DenyRules))
		for i, r := range s.DenyRules {
			out.DenyRules[i] = DenyRule{
				Name: r.Name,
				Args: cloneArgSets(r.Args),
			}
		}
	}
	return out
}

// Cache is an in-memory, thread-safe store of the most recently reported
// Snapshot per node_id.
type Cache struct {
	mu sync.RWMutex
	m  map[string]Snapshot
}

// New returns an empty Cache.
func New() *Cache {
	return &Cache{m: make(map[string]Snapshot)}
}

// Set records the latest Snapshot reported for nodeID, replacing any
// previous value. s is deep-copied on entry so a later mutation by the
// caller cannot reach the cached value.
func (c *Cache) Set(nodeID string, s Snapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[nodeID] = s.clone()
}

// Get returns a deep copy of the most recently reported Snapshot for
// nodeID, or (Snapshot{}, false) if none has been captured yet — e.g. the
// Node hasn't (re)connected since the Relay last started, or the daemon
// doesn't yet emit PolicySnapshot (follow-up #151).
func (c *Cache) Get(nodeID string) (Snapshot, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.m[nodeID]
	if !ok {
		return Snapshot{}, false
	}
	return s.clone(), true
}
