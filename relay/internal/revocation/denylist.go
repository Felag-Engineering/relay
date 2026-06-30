// Package revocation holds the Relay-side Node denylist and the live-connection
// tracker that together implement instant Node revocation
// (ADR-0006: revocation is a Relay-side Node denylist, instant).
package revocation

import "sync"

// Denylist is a thread-safe set of revoked node IDs.
//
// It is keyed by node_id only. node_id equals the verified client-cert CN
// (ADR-0006); one cert per Node makes a separate fingerprint key redundant,
// and the CN is the sole authoritative identity source.
type Denylist struct {
	mu  sync.RWMutex
	ids map[string]struct{}
}

// NewDenylist returns an initialized, empty Denylist.
func NewDenylist() *Denylist {
	return &Denylist{ids: make(map[string]struct{})}
}

// Add marks nodeID as revoked. Empty nodeID is a no-op.
func (d *Denylist) Add(nodeID string) {
	if nodeID == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ids[nodeID] = struct{}{}
}

// IsRevoked reports whether nodeID is in the denylist. Empty nodeID returns false.
func (d *Denylist) IsRevoked(nodeID string) bool {
	if nodeID == "" {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.ids[nodeID]
	return ok
}
