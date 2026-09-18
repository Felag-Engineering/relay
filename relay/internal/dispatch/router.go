package dispatch

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	relayv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"
)

// ErrNotConnected is returned by Dispatch/Cancel when nodeID has no live
// Tunnel registered. ADR-0004's dispatch-time connectivity gate: a
// disconnected Node's Task is never sent, queued, or retried.
var ErrNotConnected = errors.New("dispatch: node not connected")

// ErrNodeDisconnected is returned by Dispatch when the Node's Tunnel goes
// away (unregister) while the call is still waiting for a Result. The Task
// itself is left Dispatched by the caller (capability.jobEngine never
// Resolves on this error), so it surfaces via TaskRepository.InFlight() for
// restart/reconnect reconciliation (Reconciler).
var ErrNodeDisconnected = errors.New("dispatch: node disconnected while waiting for result")

// conn is one Node's live registration. It is stored by pointer so a
// registration has a unique identity beyond its nodeID: a rapid
// disconnect/reconnect flap for the same cert nodeID produces two distinct
// *conn values, letting the OLD registration's unregister recognize (and
// refuse to clobber) a NEWER registration that has since taken nodeID's slot
// in conns. See Register's doc comment.
type conn struct {
	send func(*relayv1.RelayMessage) error
}

// waiter correlates one in-flight Dispatch call with the Result that will
// eventually arrive on the Node's Tunnel. ch is buffered(1) so Deliver's send
// never blocks the Tunnel's receive goroutine, and so unregister's close is
// never racing a blocked sender.
//
// nodeID is defense-in-depth, not the correlation key: task_id is minted
// globally-unique by capability.jobEngine ("task-" + 16 random bytes), so one
// flat waiters map (keyed by task_id) already disambiguates across every
// concurrent Task on every Node. The nodeID check in Deliver only guards
// against a Result arriving on the wrong Node's stream for a task_id it
// should never have seen.
//
// owner is the *conn the waiter was created under (the registration live at
// Dispatch time). It, not nodeID, is what unregister uses to decide whether
// this waiter belongs to it: during a connect/disconnect flap for the same
// nodeID, a stale (old) registration's unregister must fail only the waiters
// it owns, never a waiter a FRESH registration created after reusing the same
// nodeID (and possibly the same task_id, once the old Task's ID space is
// reused by a retry).
type waiter struct {
	nodeID string
	owner  *conn
	ch     chan *relayv1.TaskResult
}

// verdictWaiter is waiter's sibling for a Plan's PolicyQuery (#119,
// ADR-0011): correlates one in-flight Query call with the PolicyVerdict that
// will eventually arrive on the Node's Tunnel, keyed by query_id rather than
// task_id — a wholly separate ID space, so a query_id can never collide
// with, or be mistaken for, a real Task's dedup key. ch is buffered(1) for
// the same reason as waiter's: DeliverVerdict's send never blocks the
// Tunnel's receive goroutine, and is never racing a blocked close from
// unregister.
type verdictWaiter struct {
	nodeID string
	owner  *conn
	ch     chan *relayv1.PolicyVerdict
}

// Router is the production capability.Conduit: it sends Tasks down a
// connected Node's authenticated Tunnel (the existing mTLS stream and its
// cert-derived node_id — ADR-0005/0006; Router creates no new transport or
// trust) and correlates their Results. It is transport-only — it never
// touches the store; capability.jobEngine owns all Task persistence
// (MarkDispatched/Resolve), keeping the persist-then-dispatch discipline in
// one place (ADR-0004).
//
// Router satisfies capability.Conduit structurally (Connected/Dispatch/
// Cancel/Query on jobs.Task/jobs.Result/jobs.Verdict) without importing
// package capability, so there is no import cycle and capability's
// proto-free import lock (TestCapabilityImportsOnlyRegistryAndJobs) stays
// intact.
//
// Lock discipline: mu guards ONLY the conns, waiters, and verdictWaiters
// maps. It is taken only around map reads/writes, never around a network
// send or the blocking wait for a Result — a slow or stalled write to one
// Node's stream must never
// stall Connected()/Register()/Deliver() for every other Node (an
// availability hazard at fleet scale).
type Router struct {
	mu             sync.Mutex
	conns          map[string]*conn
	waiters        map[string]*waiter
	verdictWaiters map[string]*verdictWaiter

	// onConnect, if non-nil, is invoked (in its own goroutine, so it never
	// blocks the Tunnel handler) every time a Node registers a live send
	// function — including reconnects. It is the restart-reconciliation hook:
	// the composition root wires it to Reconciler.ReconcileNode.
	onConnect func(nodeID string)
}

// NewRouter returns a Router. onConnect may be nil (no reconciliation hook —
// used by hermetic tests that only exercise Dispatch/Deliver/Cancel).
func NewRouter(onConnect func(nodeID string)) *Router {
	return &Router{
		conns:          make(map[string]*conn),
		waiters:        make(map[string]*waiter),
		verdictWaiters: make(map[string]*verdictWaiter),
		onConnect:      onConnect,
	}
}

// Register records nodeID's live outbound send function and returns an
// unregister cleanup. It is called by the Tunnel handler once per connection,
// after the Hello/Ping handshake completes.
//
// Each call creates a fresh *conn, giving the registration a unique identity
// beyond nodeID. This is the node-flap fix: during a rapid disconnect/
// reconnect for the same cert nodeID, the OLD connection's deferred
// unregister must never evict a NEWER connection that has since re-registered
// under the same nodeID. unregister is a closure over its own *conn and only
// acts if conns[nodeID] still holds THAT *conn (identity compare, not a
// nodeID compare) — a stale unregister racing a fresh Register is a no-op.
//
// unregister is also the disconnect-mid-dispatch correctness point: under mu,
// it deletes the conn (if still current) AND fails every waiter it owns
// (waiter.owner == this *conn) by deleting it from waiters and closing its
// channel — and, identically, every verdictWaiter it owns (a blocked Query,
// #119). Scoping by owner rather than nodeID means a stale unregister can
// never close a FRESH waiter that a newer registration created after reusing
// the same nodeID (and potentially the same task_id/query_id). This
// guarantees any Dispatch or Query call blocked in its select on a waiter it
// truly owns unblocks (via the closed-channel case) rather than hanging
// until ctx expiry or forever on a deadline-less ctx.
func (r *Router) Register(nodeID string, send func(*relayv1.RelayMessage) error) (unregister func()) {
	c := &conn{send: send}

	r.mu.Lock()
	r.conns[nodeID] = c
	r.mu.Unlock()

	if r.onConnect != nil {
		go r.onConnect(nodeID)
	}

	return func() {
		r.mu.Lock()
		if r.conns[nodeID] == c {
			delete(r.conns, nodeID)
		}
		for taskID, w := range r.waiters {
			if w.owner == c {
				delete(r.waiters, taskID)
				close(w.ch)
			}
		}
		for queryID, w := range r.verdictWaiters {
			if w.owner == c {
				delete(r.verdictWaiters, queryID)
				close(w.ch)
			}
		}
		r.mu.Unlock()
	}
}

// Connected reports whether nodeID currently has a live Tunnel registered.
func (r *Router) Connected(nodeID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.conns[nodeID]
	return ok
}

// ConnectedNodes returns a snapshot of every Node currently registered with a
// live Tunnel. It is transport-only (mirrors Connected's locking) and exists
// for callers that need to enumerate the live fleet (e.g. the #103 devharness
// list_connected op) rather than test one Node at a time.
func (r *Router) ConnectedNodes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	nodeIDs := make([]string, 0, len(r.conns))
	for nodeID := range r.conns {
		nodeIDs = append(nodeIDs, nodeID)
	}
	return nodeIDs
}

// Dispatch sends task down nodeID's Tunnel and blocks for its Result.
//
// The map read (send func) and the waiter registration happen under mu; the
// network send and the blocking wait happen OUTSIDE mu (see the Router doc
// comment's lock-discipline note) so one slow Node never stalls another.
func (r *Router) Dispatch(ctx context.Context, nodeID string, t jobs.Task) (jobs.Result, error) {
	r.mu.Lock()
	c, ok := r.conns[nodeID]
	if !ok {
		r.mu.Unlock()
		return jobs.Result{}, ErrNotConnected
	}
	w := &waiter{nodeID: nodeID, owner: c, ch: make(chan *relayv1.TaskResult, 1)}
	r.waiters[t.ID] = w
	r.mu.Unlock()

	msg := &relayv1.RelayMessage{Body: &relayv1.RelayMessage_Task{Task: taskRequest(t)}}
	if err := c.send(msg); err != nil {
		r.removeWaiter(t.ID)
		return jobs.Result{}, fmt.Errorf("dispatch: send task %q to node %q: %w", t.ID, nodeID, err)
	}

	select {
	case tr, ok := <-w.ch:
		if !ok {
			// Channel closed by unregister: the Node's Tunnel went away while
			// we were waiting. The caller (jobEngine) leaves the Task
			// Dispatched — it surfaces via InFlight() for reconciliation.
			return jobs.Result{}, ErrNodeDisconnected
		}
		res, v := result(tr)
		if v.Violated() {
			slog.Warn("dispatch: node reported an outcome the wire contract forbids; recorded as a protocol violation",
				"node_id", nodeID, "task_id", t.ID, "reported_outcome", v.ReportedOutcome, "rule", v.Rule)
		}
		// The nil error is load-bearing: returning one here would leave the
		// Task Dispatched, so InFlight() hands it to the Reconciler, which
		// resends on the next reconnect and gets the same forged answer — an
		// attacker-controlled loop. Resolving failure is terminal and
		// truthful (invariant 4).
		return res, nil
	case <-ctx.Done():
		r.removeWaiter(t.ID)
		return jobs.Result{}, ctx.Err()
	}
}

// removeWaiter deletes taskID's waiter, if still present, under mu. It does
// NOT close the channel — the caller (Dispatch) is the only reader and is
// abandoning it, not signalling disconnect to some other reader.
func (r *Router) removeWaiter(taskID string) {
	r.mu.Lock()
	delete(r.waiters, taskID)
	r.mu.Unlock()
}

// Deliver routes an inbound TaskResult to the Dispatch call waiting on it.
// If tr.TaskId has no registered waiter, or the waiter belongs to a different
// nodeID (defense-in-depth; see the waiter doc comment), the Result is
// silently dropped — an uncorrelated Result is not a Router error.
//
// The waiter is deleted under mu before the (non-blocking, buffered(1)) send,
// which makes this delete-then-send mutually exclusive with unregister's
// delete-then-close: exactly one of the two ever touches a given waiter's
// channel, so Deliver can never send on an already-closed channel.
func (r *Router) Deliver(nodeID string, tr *relayv1.TaskResult) {
	r.mu.Lock()
	w, ok := r.waiters[tr.GetTaskId()]
	if ok && w.nodeID == nodeID {
		delete(r.waiters, tr.GetTaskId())
	}
	r.mu.Unlock()

	if ok && w.nodeID == nodeID {
		w.ch <- tr
	}
}

// newQueryID mints a unique query_id for one Query call: "query-" plus 16
// random bytes, hex-encoded, mirroring capability.defaultID's shape. It is
// deliberately unrelated to any task_id — a Plan's PolicyQuery can never
// collide with, or be mistaken for, a Task's at-most-once dedup key.
func newQueryID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("dispatch: generate query id: %w", err)
	}
	return "query-" + hex.EncodeToString(b), nil
}

// Query sends a PolicyQuery for act down nodeID's Tunnel and blocks for the
// daemon's PolicyVerdict (#119, ADR-0011) — capability.Conduit.Query's real
// implementation, mirroring Dispatch's shape exactly except for the
// query_id/task_id ID space and the waiter map it correlates through.
func (r *Router) Query(ctx context.Context, nodeID string, act jobs.Action) (jobs.Verdict, error) {
	queryID, err := newQueryID()
	if err != nil {
		return jobs.Verdict{}, err
	}

	r.mu.Lock()
	c, ok := r.conns[nodeID]
	if !ok {
		r.mu.Unlock()
		return jobs.Verdict{}, ErrNotConnected
	}
	w := &verdictWaiter{nodeID: nodeID, owner: c, ch: make(chan *relayv1.PolicyVerdict, 1)}
	r.verdictWaiters[queryID] = w
	r.mu.Unlock()

	msg := &relayv1.RelayMessage{Body: &relayv1.RelayMessage_PolicyQuery{PolicyQuery: policyQuery(queryID, act)}}
	if err := c.send(msg); err != nil {
		r.removeVerdictWaiter(queryID)
		return jobs.Verdict{}, fmt.Errorf("dispatch: send policy query %q to node %q: %w", queryID, nodeID, err)
	}

	select {
	case pv, ok := <-w.ch:
		if !ok {
			// Channel closed by unregister: the Node's Tunnel went away while
			// we were waiting.
			return jobs.Verdict{}, ErrNodeDisconnected
		}
		return verdict(pv), nil
	case <-ctx.Done():
		r.removeVerdictWaiter(queryID)
		return jobs.Verdict{}, ctx.Err()
	}
}

// removeVerdictWaiter deletes queryID's waiter, if still present, under mu.
// It does NOT close the channel — the caller (Query) is the only reader and
// is abandoning it, not signalling disconnect to some other reader (mirrors
// removeWaiter).
func (r *Router) removeVerdictWaiter(queryID string) {
	r.mu.Lock()
	delete(r.verdictWaiters, queryID)
	r.mu.Unlock()
}

// DeliverVerdict routes an inbound PolicyVerdict to the Query call waiting
// on it — Deliver's sibling for the plan-mode ID space. If pv.QueryId has no
// registered waiter, or the waiter belongs to a different nodeID
// (defense-in-depth; see waiter's doc comment), the PolicyVerdict is
// silently dropped — an uncorrelated verdict is not a Router error.
//
// The waiter is deleted under mu before the (non-blocking, buffered(1))
// send, which makes this delete-then-send mutually exclusive with
// unregister's delete-then-close: exactly one of the two ever touches a
// given waiter's channel, so DeliverVerdict can never send on an
// already-closed channel (mirrors Deliver).
func (r *Router) DeliverVerdict(nodeID string, pv *relayv1.PolicyVerdict) {
	r.mu.Lock()
	w, ok := r.verdictWaiters[pv.GetQueryId()]
	if ok && w.nodeID == nodeID {
		delete(r.verdictWaiters, pv.GetQueryId())
	}
	r.mu.Unlock()

	if ok && w.nodeID == nodeID {
		w.ch <- pv
	}
}

// Cancel sends TaskCancel for taskID down nodeID's Tunnel, best-effort
// (ADR-0013). It does not wait for or rewrite the Task's outcome — the
// daemon reports the true outcome (OUTCOME_CANCELLED, or the real result if
// the Task won the race) through the normal result path, delivered to the
// still-blocked Dispatch call for that Task via Deliver.
//
// An offline Node is not an error here: Cancel is inherently best-effort, so
// asking a disconnected Node to cancel a Task it never received is a no-op,
// not a failure the caller must handle.
func (r *Router) Cancel(_ context.Context, nodeID string, taskID string) error {
	r.mu.Lock()
	c, ok := r.conns[nodeID]
	r.mu.Unlock()
	if !ok {
		return nil
	}
	msg := &relayv1.RelayMessage{
		Body: &relayv1.RelayMessage_TaskCancel{TaskCancel: &relayv1.TaskCancel{TaskId: taskID}},
	}
	if err := c.send(msg); err != nil {
		return fmt.Errorf("dispatch: send cancel for task %q to node %q: %w", taskID, nodeID, err)
	}
	return nil
}

// WaitForNode polls until nodeID has a live Tunnel registered, or deadline
// elapses. It is a test/e2e sync point (mirrors dispatch_test.go's
// waitForNode), not used by production dispatch logic.
func (r *Router) WaitForNode(nodeID string, deadline time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	for {
		if r.Connected(nodeID) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("dispatch: WaitForNode(%q): timeout after %v", nodeID, deadline)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// WaitForAny polls until any Node has a live Tunnel registered, or deadline
// elapses, returning that Node's ID. It is a test/e2e sync point for
// scenarios that don't know the connecting Node's ID in advance (e.g. a
// freshly-enrolled daemon).
func (r *Router) WaitForAny(deadline time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	for {
		r.mu.Lock()
		for nodeID := range r.conns {
			r.mu.Unlock()
			return nodeID, nil
		}
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("dispatch: WaitForAny: timeout after %v", deadline)
		case <-time.After(5 * time.Millisecond):
		}
	}
}
