package revocation

import (
	"context"
	"sync"
)

// entry holds the cancel function for one live Tunnel stream.
type entry struct {
	cancel context.CancelFunc
}

// Connections tracks live Tunnel streams so a Disconnect call can cancel them
// out-of-band. Keyed by node_id; multiple concurrent streams for the same
// node_id are all tracked and canceled together.
//
// Rationale: grpc.ServerStream.Recv() does not observe a cancelled context, so
// the Tunnel handler must run Recv in a goroutine and select on ctx.Done() to
// honor revocation cancellation (see tunnel.go). The cancel held here is that
// teardown signal, not a direct stream abort.
type Connections struct {
	mu    sync.Mutex
	conns map[string]map[*entry]struct{}
}

// NewConnections returns an initialized, empty Connections tracker.
func NewConnections() *Connections {
	return &Connections{conns: make(map[string]map[*entry]struct{})}
}

// Track registers a new live stream for nodeID. It derives a child context from
// parent and returns it together with a release func the handler must defer.
// Calling release cancels the derived context, removes the entry, and is
// idempotent — safe to call after Disconnect or more than once.
func (c *Connections) Track(parent context.Context, nodeID string) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	e := &entry{cancel: cancel}

	c.mu.Lock()
	if c.conns[nodeID] == nil {
		c.conns[nodeID] = make(map[*entry]struct{})
	}
	c.conns[nodeID][e] = struct{}{}
	c.mu.Unlock()

	// Idempotency guard: only act if the entry is still present in the map.
	// Disconnect may have already removed it and fired cancel; in that case
	// re-entering release is a no-op.
	release := func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		m := c.conns[nodeID]
		if m == nil {
			return
		}
		if _, present := m[e]; !present {
			return
		}
		cancel()
		delete(m, e)
		if len(m) == 0 {
			delete(c.conns, nodeID)
		}
	}
	return ctx, release
}

// Disconnect cancels every live stream for nodeID and removes all its entries.
// No-op for an unknown nodeID.
func (c *Connections) Disconnect(nodeID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for e := range c.conns[nodeID] {
		e.cancel()
	}
	delete(c.conns, nodeID)
}

// Count returns the number of distinct node_ids with at least one live Tunnel
// stream tracked. This is the "connected Nodes" gauge source for /metrics.
func (c *Connections) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.conns)
}
