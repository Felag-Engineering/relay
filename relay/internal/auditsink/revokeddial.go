package auditsink

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
)

// revokedDialWindow is the least time between two records for one Node.
const revokedDialWindow = time.Hour

// revokedDialAuditBudget bounds the write a refused handshake waits on.
const revokedDialAuditBudget = 5 * time.Second

// RevokedDialRecorder records a revoked Node's refused dials as
// audit.KindRevokedNodeDial, throttled per Node. It satisfies
// transport.RevokedDialObserver structurally; this package does not import
// transport.
//
// The first refused dial by a Node is recorded at once. Afterwards there is at
// most one record per Node per window, written on the first dial at or after
// one window from the previous attempt, and carrying the count of dials it
// suppressed. A failed write is not retried within its window. There is no timer and no goroutine. State is in-process and
// empty after a restart; it grows with the distinct revoked Node IDs that dial
// (only denylisted CNs on a Relay-CA-verified chain reach it, the
// Denylist's own order of growth). It never logs or records certificate
// material, fingerprints or remote addresses, and it holds no handle on the
// Node, so the Relay never reaches back to it.
type RevokedDialRecorder struct {
	sink *Sink
	now  func() time.Time

	mu    sync.Mutex
	nodes map[string]*revokedDialState
}

type revokedDialState struct {
	recorded   bool      // this process has written a record for the Node
	last       time.Time // when that record was written
	suppressed int       // refused dials since last, not yet carried by a record
}

// NewRevokedDialRecorder returns a recorder writing through s, which must not
// be nil. A nil now uses the real clock.
func NewRevokedDialRecorder(s *Sink, now func() time.Time) *RevokedDialRecorder {
	if now == nil {
		now = time.Now
	}
	return &RevokedDialRecorder{sink: s, now: now, nodes: map[string]*revokedDialState{}}
}

// RevokedDial records one refused dial by nodeID, or counts it when the Node
// was recorded within the window. It never returns an error and never panics
// on a failed write: the refusal must not depend on the trail.
func (r *RevokedDialRecorder) RevokedDial(nodeID string) {
	if nodeID == "" {
		return
	}

	// The window compares on the clock's own reading (monotonic for the real
	// clock); only the stored Timestamp is normalised to UTC.
	at := r.now()

	r.mu.Lock()
	e := r.nodes[nodeID]
	if e == nil {
		e = &revokedDialState{}
		r.nodes[nodeID] = e
	}
	if e.recorded && at.Sub(e.last) < revokedDialWindow {
		e.suppressed++
		r.mu.Unlock()
		return
	}
	carried := e.suppressed
	e.recorded, e.last, e.suppressed = true, at, 0
	r.mu.Unlock()

	// Written outside the lock so one Node's slow write never stalls another
	// Node's handshake.
	ctx, cancel := context.WithTimeout(context.Background(), revokedDialAuditBudget)
	defer cancel()
	err := r.sink.append(ctx, audit.Record{
		Timestamp: at.UTC(),
		Kind:      audit.KindRevokedNodeDial,
		NodeID:    nodeID,
		Reason:    fmt.Sprintf("suppressed=%d", carried),
	})
	if err == nil {
		return
	}

	r.sink.log.Warn("revoked node dial not recorded",
		"node_id", nodeID, "suppressed", carried, "err", err)

	// The window stays closed after a failed write: a write that committed and
	// then returned an error is indistinguishable from one that did not, and
	// reopening it could record the Node twice within the window. A failing
	// store therefore costs one attempt and one warning per window, and the
	// count is carried into the next window's record.
	r.mu.Lock()
	e.suppressed += carried + 1
	r.mu.Unlock()
}
