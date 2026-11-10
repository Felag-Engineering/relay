package auditsink

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// connectionWindow is the least time between two records of one kind for one
// Node, and the least time between two sweeps.
const connectionWindow = 10 * time.Minute

// connectionAuditBudget bounds the write a connect waits on.
const connectionAuditBudget = 5 * time.Second

// PolicyChange is one change in what a Node reports of its Policy. An empty
// fingerprint and a nil Raw Exec state mean not reported.
type PolicyChange struct {
	FingerprintBefore, FingerprintAfter string
	RawExecBefore, RawExecAfter         *bool
}

// The renderers below are the only home of the Reason format of the Node
// connection kinds. A value that fails its bound renders "none", never
// sanitised, so no value can contain a space or "=" and the key=value grammar
// holds whatever a caller passes.

func policyChangedReason(c PolicyChange, n int) string {
	return fmt.Sprintf("policy_fingerprint_before=%s policy_fingerprint_after=%s raw_exec_before=%s raw_exec_after=%s changes=%d",
		reportedOrNone(c.FingerprintBefore, registry.WellFormedFingerprint),
		reportedOrNone(c.FingerprintAfter, registry.WellFormedFingerprint),
		rawExecText(c.RawExecBefore), rawExecText(c.RawExecAfter), n)
}

func daemonVersionChangedReason(before, after string, n int) string {
	downgrade := "unknown"
	if registry.WellFormedReportedDaemonVersion(before) && registry.WellFormedReportedDaemonVersion(after) {
		if lower, ok := registry.Downgrade(before, after); ok {
			downgrade = strconv.FormatBool(lower)
		}
	}
	return fmt.Sprintf("version_before=%s version_after=%s downgrade=%s changes=%d",
		reportedOrNone(before, registry.WellFormedReportedDaemonVersion),
		reportedOrNone(after, registry.WellFormedReportedDaemonVersion),
		downgrade, n)
}

func certChangedReason(before, after string, n int) string {
	return fmt.Sprintf("cert_fingerprint_before=%s cert_fingerprint_after=%s changes=%d",
		reportedOrNone(before, registry.WellFormedFingerprint),
		reportedOrNone(after, registry.WellFormedFingerprint), n)
}

func streamReplacedReason(n int) string {
	return fmt.Sprintf("replacements=%d", n)
}

func reportedOrNone(v string, wellFormed func(string) bool) string {
	if v == "" || !wellFormed(v) {
		return "none"
	}
	return v
}

func rawExecText(v *bool) string {
	if v == nil {
		return "unknown"
	}
	return strconv.FormatBool(*v)
}

// ConnectionRecorder records the Node connection kinds
// (audit.KindNodePolicyChanged, KindNodeDaemonVersionChanged,
// KindNodeCertChanged and KindNodeStreamReplaced), throttling each (Node,
// kind) independently.
//
// The first event is recorded at once. Afterwards there is at most one record
// per window, written on the first event at or after one window from the
// previous attempt. n counts the events since the previous record of that
// kind, including the one that writes it; before and after are that event's
// values, and a suppressed event adds only to the count. A failed write is not
// retried within its window and its count carries into the next record. There
// is no timer and no goroutine. State is in-process and empty after a restart.
// nodeID must be the Relay-CA-verified Node identity; the map grows with the
// distinct such IDs. A sweep, at most once per window and on a call, drops idle
// entries and keeps those with a pending count. It never logs before or after
// values, certificate material or remote addresses.
//
// It records what it is told: the caller decides that a change happened.
type ConnectionRecorder struct {
	sink *Sink
	now  func() time.Time

	mu        sync.Mutex
	entries   map[connectionKey]*connectionState
	lastSweep time.Time
}

type connectionKey struct{ nodeID, kind string }

type connectionState struct {
	recorded bool      // this process has attempted a record for the key
	last     time.Time // when that attempt was made
	pending  int       // events since last, not yet carried by a record
}

// NewConnectionRecorder returns a recorder writing through s, which must not
// be nil. A nil now uses the real clock.
func NewConnectionRecorder(s *Sink, now func() time.Time) *ConnectionRecorder {
	if now == nil {
		now = time.Now
	}
	return &ConnectionRecorder{
		sink:      s,
		now:       now,
		entries:   map[connectionKey]*connectionState{},
		lastSweep: now(),
	}
}

// PolicyChanged records one change in what nodeID reports of its Policy. It
// never returns an error: the connection must not depend on the trail.
func (r *ConnectionRecorder) PolicyChanged(nodeID string, c PolicyChange) {
	r.record(nodeID, audit.KindNodePolicyChanged, func(n int) string { return policyChangedReason(c, n) })
}

// DaemonVersionChanged records one change in the daemon version nodeID
// reports. It never returns an error.
func (r *ConnectionRecorder) DaemonVersionChanged(nodeID, before, after string) {
	r.record(nodeID, audit.KindNodeDaemonVersionChanged, func(n int) string { return daemonVersionChangedReason(before, after, n) })
}

// CertChanged records one change in nodeID's client certificate fingerprint.
// It never returns an error.
func (r *ConnectionRecorder) CertChanged(nodeID, before, after string) {
	r.record(nodeID, audit.KindNodeCertChanged, func(n int) string { return certChangedReason(before, after, n) })
}

// StreamReplaced records one stream opened for nodeID while another stream for
// the Node was live (NC-36). It never returns an error: the connection must
// not depend on the trail.
func (r *ConnectionRecorder) StreamReplaced(nodeID string) {
	r.record(nodeID, audit.KindNodeStreamReplaced, streamReplacedReason)
}

func (r *ConnectionRecorder) record(nodeID, kind string, reason func(n int) string) {
	if nodeID == "" {
		return
	}

	// The window compares on the clock's own reading (monotonic for the real
	// clock); only the stored Timestamp is normalised to UTC.
	at := r.now()
	key := connectionKey{nodeID, kind}

	r.mu.Lock()
	if at.Sub(r.lastSweep) >= connectionWindow {
		r.sweepLocked(at)
		r.lastSweep = at
	}
	e := r.entries[key]
	if e == nil {
		e = &connectionState{}
		r.entries[key] = e
	}
	if e.recorded && at.Sub(e.last) < connectionWindow {
		e.pending++
		r.mu.Unlock()
		return
	}
	n := e.pending + 1
	e.recorded, e.last, e.pending = true, at, 0
	r.mu.Unlock()

	// Written outside the lock so one Node's slow write never stalls another
	// Node's connect.
	ctx, cancel := context.WithTimeout(context.Background(), connectionAuditBudget)
	defer cancel()
	err := r.sink.append(ctx, audit.Record{
		Timestamp: at.UTC(),
		Kind:      kind,
		NodeID:    nodeID,
		Reason:    reason(n),
	})
	if err == nil {
		return
	}

	r.sink.log.Warn("node connection record not written",
		"node_id", nodeID, "kind", kind, "count", n, "err", err)

	// The window stays closed after a failed write: a write that committed and
	// then returned an error is indistinguishable from one that did not, and
	// reopening it could record twice. The count carries into the next record.
	r.mu.Lock()
	cur := r.entries[key]
	if cur == nil {
		cur = e
		r.entries[key] = cur
	}
	cur.pending += n
	r.mu.Unlock()
}

// sweepLocked deletes the entries whose window has passed with nothing
// pending. An entry with a pending count is kept, so no count is swept away.
func (r *ConnectionRecorder) sweepLocked(at time.Time) {
	for k, e := range r.entries {
		if e.pending == 0 && at.Sub(e.last) >= connectionWindow {
			delete(r.entries, k)
		}
	}
}
