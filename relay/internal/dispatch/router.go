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

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/logctx"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
)

// ErrNotConnected is returned by Dispatch/Cancel when nodeID has no live
// Tunnel registered. ADR-0004's dispatch-time connectivity gate: a
// disconnected Node's Task is never sent, queued, or retried.
var ErrNotConnected = errors.New("dispatch: node not connected")

// ErrNodeDisconnected is returned by Dispatch when the Node's Tunnel goes
// away (unregister) while the call is still waiting for a Result. The Router
// resolves nothing. When the ending registration was the Node's current one,
// the offline hook (WithOnOffline) has already run, so the caller must read
// the store before treating the Task as still in flight: it may be Resolved.
var ErrNodeDisconnected = errors.New("dispatch: node disconnected while waiting for result")

// errStreamReplaced is what Dispatch returns when the ending registration was
// replaced by a newer Tunnel stream: it is an ErrNodeDisconnected, and also a
// jobs.ErrStreamReplaced, so the capability layer knows the Node is not
// offline and leaves the Task in flight.
var errStreamReplaced = fmt.Errorf("%w: %w", ErrNodeDisconnected, jobs.ErrStreamReplaced)

// conn is one Node's live registration. It is stored by pointer so a
// registration has a unique identity beyond its nodeID: a rapid
// disconnect/reconnect flap for the same cert nodeID produces two distinct
// *conn values, letting the OLD registration's unregister recognize (and
// refuse to clobber) a NEWER registration that has since taken nodeID's slot
// in conns. See Register's doc comment.
//
// A gRPC stream allows one SendMsg at a time, and Dispatch, Query and Cancel
// can all send to the same Node at once. Every send goes through conn.send,
// which holds sendMu for the call. sendMu is per Node and is never held with
// Router.mu, so a slow write to one Node stalls only that Node's senders.
//
// delivered holds the task IDs whose TaskResult was delivered to a waiter on
// this registration and whose result the caller has not yet settled
// (Router.Settled). The offline hook is handed the IDs so a result that
// arrived before the stream ended is never overwritten by the offline
// resolution. An entry stays until its Task's result is persisted, with no
// time horizon: a slow persistence, such as a degraded store, must not let the
// sweep replace a result that arrived. The set is therefore bounded by the
// Tasks whose results have arrived and are not yet persisted. superseded, when
// set, reports at unregister that a newer stream has replaced this one.
// delivered is guarded by Router.mu.
type conn struct {
	sendMu     sync.Mutex
	rawSend    func(*relayv1.RelayMessage) error
	delivered  map[string]struct{}
	superseded func() bool
}

// markDelivered records taskID as delivered on c. The caller holds Router.mu.
func (c *conn) markDelivered(taskID string) {
	if c.delivered == nil {
		c.delivered = make(map[string]struct{})
	}
	c.delivered[taskID] = struct{}{}
}

func (c *conn) send(msg *relayv1.RelayMessage) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return c.rawSend(msg)
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
//
// err is set under Router.mu before unregister closes ch, and says why the
// registration ended when a newer stream replaced it; nil means the Node went
// offline.
type waiter struct {
	nodeID string
	owner  *conn
	ch     chan *relayv1.TaskResult
	err    error
}

// verdictWaiter is waiter's sibling for a Plan's PolicyQuery
// (ADR-0011): correlates one in-flight Query call with the PolicyVerdict that
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

// violationAuditBudget bounds recordViolation's call to the ViolationRecorder.
// Matches the register reconcileDispatchTimeout uses for its own bounded
// call on this package's dispatching path (reconcile.go:18), and the
// revocation cascade's audit budget (controlplane/api/tokens.go,
// cascadeAuditBudget).
const violationAuditBudget = 5 * time.Second

// ViolationRecorder records a relay-daemon's protocol violation as a
// durable, queryable audit event. Structural, like Conduit in the
// other direction: *auditsink.Sink satisfies it, and this package imports
// neither internal/audit nor internal/capability to say so — the
// composition root wires them (cmd/relay/dispatch_wiring.go).
//
// It is a REQUIRED parameter of NewRouter, not an option, and that is
// the security property rather than a style choice: a production wiring
// that forgot it would give a deployment refused-and-unrecorded
// violations — audited dispatch with an unaudited refusal — and the
// capability layer's own fail-open guard cannot reach here to catch it
// (capability/seams.go:208-216 makes that argument for a sink method it
// COULD reach; see NewRouter). Making it positional moves the same
// guarantee from start-up to compile time. nil is permitted and means
// "log only", which is what every hermetic test in this package passes.
type ViolationRecorder interface {
	RecordProtocolViolation(ctx context.Context, ev jobs.ProtocolViolationEvent) error
}

// sendSlot is one task ID's send critical section. A worker's Dispatch and a
// Reconciler resend can run for the same Task at once; mu orders their guard
// decisions, and sent records that some caller has already handed the Task to
// a Tunnel, after which no later caller consults its guard: the Task has run
// or may run, so withholding it again would make the record untruthful. refs
// counts the Dispatch calls holding the slot; the last one out deletes it.
// refs and the map entry are guarded by Router.mu; mu and sent by mu.
type sendSlot struct {
	mu   sync.Mutex
	sent bool
	refs int
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
// Cancel/Query/Settled on jobs.Task/jobs.Result/jobs.Verdict) without importing
// package capability, so there is no import cycle and capability's
// proto-free import lock (.golangci.yml's capability-imports rule) stays
// intact.
//
// Router still never touches the store and decides nothing: it only evaluates
// a send guard its caller supplied in the ctx (jobs.WithSendGuard). The
// guard is a ctx value so that Conduit's domain-typed signature, and callers
// that set none, stay unchanged.
//
// Lock discipline: mu guards ONLY the conns, waiters, and verdictWaiters
// maps. It is taken only around map reads/writes, never around a network
// send or the blocking wait for a Result — a slow or stalled write to one
// Node's stream must never
// stall Connected()/Register()/Deliver() for every other Node (an
// availability hazard at fleet scale). Each conn's sendMu serialises writes
// to one Node's stream and is never held with mu or a send slot's lock.
type Router struct {
	mu             sync.Mutex
	conns          map[string]*conn
	waiters        map[string]*waiter
	verdictWaiters map[string]*verdictWaiter

	// sendSlots serialises, per task ID, the send guard's decision against
	// "this Task was handed to a Tunnel by some caller". Guarded by mu.
	sendSlots map[string]*sendSlot

	// onConnect, if non-nil, is invoked (in its own goroutine, so it never
	// blocks the Tunnel handler) every time a Node registers a live send
	// function — including reconnects. It is the restart-reconciliation hook:
	// the composition root wires it to Reconciler.ReconcileNode.
	onConnect func(nodeID string)

	// onOffline, if non-nil, runs synchronously when a Node's current
	// registration ends. See WithOnOffline.
	onOffline func(nodeID string, delivered map[string]struct{})

	// offlining holds, per Node, a channel closed when that Node's offline
	// hook has finished and its registration's waiters have failed. Register
	// waits on it. Guarded by mu.
	offlining map[string]chan struct{}

	// violations records a relay-daemon's protocol violation. See
	// ViolationRecorder and NewRouter's doc comment.
	violations ViolationRecorder

	// log is where the Router's operational problems go; nil means
	// slog.Default() (logger).
	log *slog.Logger
}

// NewRouter returns a Router. onConnect may be nil (no reconciliation
// hook — used by hermetic tests that only exercise Dispatch/Deliver/
// Cancel).
//
// violations is REQUIRED POSITIONALLY and may be nil. Nil is a real,
// supported mode — a Router that logs a refused TaskResult and records
// nothing — and every test in this package uses it deliberately, as a
// log-only fixture with no store to write to. It is a parameter rather
// than an option so that adding a second production assembly cannot
// silently inherit that mode: the compiler asks. Production must pass a
// real recorder; the compiler cannot enforce that a non-nil argument is
// the RIGHT one, so NewRouter logs a construction-time warning when
// violations is nil, which is what makes a mis-wired deployment announce
// itself instead of failing silently at the first refused TaskResult. The
// production wiring is asserted end to end by
// TestNewDispatchStack_AProtocolViolationOnAReadClassTaskIsRecordedWithNoOutput
// (cmd/relay).
func NewRouter(onConnect func(nodeID string), violations ViolationRecorder, opts ...RouterOption) *Router {
	r := &Router{
		conns:          make(map[string]*conn),
		waiters:        make(map[string]*waiter),
		verdictWaiters: make(map[string]*verdictWaiter),
		sendSlots:      make(map[string]*sendSlot),
		offlining:      make(map[string]chan struct{}),
		onConnect:      onConnect,
		violations:     violations,
	}
	for _, o := range opts {
		o(r)
	}
	if violations == nil {
		r.logger().Warn("dispatch: NewRouter called with no ViolationRecorder; this Router will not " +
			"record protocol violations durably — wire-boundary refusals will be log-only")
	}
	return r
}

// RouterOption configures a Router at construction.
type RouterOption func(*Router)

// WithLogger sets the logger the Router reports operational problems to.
// Observational only. Without it the Router logs through slog.Default().
func WithLogger(l *slog.Logger) RouterOption {
	return func(r *Router) { r.log = l }
}

// WithOnOffline sets the hook that resolves the Tasks in flight to a Node
// whose current registration has ended. It receives the IDs of the Tasks whose
// TaskResult was delivered on that registration and not yet settled
// (Settled): their callers are about to persist the real result, so the hook
// must leave them alone.
//
// The hook runs synchronously on the unregistering goroutine, only when the
// ending registration is still the Node's current one and no newer Tunnel
// stream has claimed the Node (WithSupersededCheck), after the conn is removed
// and before its waiters fail. It never runs for a replaced registration, nor
// for one whose stream a newer one has claimed but not yet registered: the
// Node is not offline then, and its Tasks follow the replaced-stream path,
// where the new registration re-sends them for their result. mu is not held
// across it.
//
// While it runs, Register for the same Node waits (see Register), so no new
// registration exists until the offline resolution has committed. The hook
// must bound its own work with a context: the wait is exactly as long as the
// hook, and database/sql calls honour a context.
//
// A graceful server shutdown that closed every stream would run the hook for
// every Node and resolve every in-flight Task, removing the re-send-for-result
// a Relay restart relies on. Adding one is a decision to revisit this hook.
func WithOnOffline(f func(nodeID string, delivered map[string]struct{})) RouterOption {
	return func(r *Router) { r.onOffline = f }
}

func (r *Router) logger() *slog.Logger { return logctx.Or(r.log) }

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
// unregister is also the disconnect-mid-dispatch correctness point, in this
// order. Under mu it deletes the conn (if still current). If it was current
// and a hook is set (WithOnOffline), it then runs the hook with mu released.
// Last, under mu, it fails every waiter it owns (waiter.owner == this *conn)
// by deleting it from waiters and closing its channel — and, identically,
// every verdictWaiter it owns (a blocked Query) — and releases any Register
// waiting behind the hook. Scoping by owner rather than nodeID means a stale
// unregister can never close a FRESH waiter that a newer registration created
// after reusing the same nodeID (and potentially the same task_id/query_id).
// This guarantees any Dispatch or Query call blocked in its select on a
// waiter it truly owns unblocks (via the closed-channel case) rather than
// hanging until ctx expiry or forever on a deadline-less ctx. The waiters
// fail even if the hook panics.
//
// Register waits while the same Node's offline hook is running. Without the
// wait, the hook could resolve a Task sent on the NEW registration, or the new
// registration's onConnect could re-send a Task before the hook commits its
// resolution. The wait is bounded by the hook's own context budget; the
// caller's liveness timer starts after Register returns, so the wait never
// counts against a stream's heartbeat deadline.
//
// A stream that a newer one has already claimed for the Node, but whose
// replacement has not yet registered here, is still the Router's current
// registration. WithSupersededCheck lets the caller say so at unregister: the
// registration is then removed and its waiters failed with
// jobs.ErrStreamReplaced, but the offline hook does not run, so a Task in
// flight is not resolved offline for a Node that is reconnecting.
func (r *Router) Register(nodeID string, send func(*relayv1.RelayMessage) error, opts ...RegisterOption) (unregister func()) {
	c := &conn{rawSend: send}
	for _, o := range opts {
		o(c)
	}

	r.mu.Lock()
	for {
		ch := r.offlining[nodeID]
		if ch == nil {
			break
		}
		r.mu.Unlock()
		<-ch
		r.mu.Lock()
	}
	r.conns[nodeID] = c
	r.mu.Unlock()

	if r.onConnect != nil {
		go r.onConnect(nodeID)
	}

	return func() {
		var (
			barrier   chan struct{}
			delivered map[string]struct{}
		)
		// Read before taking mu: the check belongs to the caller.
		superseded := c.superseded != nil && c.superseded()
		replaced := superseded
		r.mu.Lock()
		if r.conns[nodeID] != c {
			replaced = true
		} else {
			delete(r.conns, nodeID)
			if r.onOffline != nil && !superseded {
				barrier = make(chan struct{})
				r.offlining[nodeID] = barrier
				delivered = make(map[string]struct{}, len(c.delivered))
				for id := range c.delivered {
					delivered[id] = struct{}{}
				}
			}
		}
		r.mu.Unlock()

		defer func() {
			r.mu.Lock()
			for taskID, w := range r.waiters {
				if w.owner == c {
					delete(r.waiters, taskID)
					if replaced {
						w.err = errStreamReplaced
					}
					close(w.ch)
				}
			}
			for queryID, w := range r.verdictWaiters {
				if w.owner == c {
					delete(r.verdictWaiters, queryID)
					close(w.ch)
				}
			}
			if barrier != nil {
				delete(r.offlining, nodeID)
				close(barrier)
			}
			r.mu.Unlock()
		}()

		if barrier != nil {
			r.onOffline(nodeID, delivered)
		}
	}
}

// RegisterOption configures one Register call.
type RegisterOption func(*conn)

// WithSupersededCheck sets a predicate the registration's unregister evaluates
// to learn whether a newer Tunnel stream has claimed the Node since this one
// registered. See Register.
func WithSupersededCheck(superseded func() bool) RegisterOption {
	return func(c *conn) { c.superseded = superseded }
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
// for callers that need to enumerate the live fleet (e.g. the devharness
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
//
// The send guard (jobs.WithSendGuard) is evaluated after the waiter is
// registered and immediately before c.send, under the Task's send slot: the
// guard decision and "some caller handed this task ID to the Tunnel" are
// serialised per task ID. The first caller whose guard does not withhold marks
// the slot sent; a caller arriving after that never consults its guard and
// sends (a resend of an already-sent Task, deduped by the relay-daemon by
// task_id), so the Task resolves truthfully. On a withheld send nothing is
// written, only this call's own waiter is removed, and jobs.ErrSendWithheld is
// returned. A send already inside c.send is past the guard: that is the
// residual pre-send window under ADR-0013.
//
// Neither mu nor the slot's lock is held while the other is taken, and the
// slot's lock is never held across c.send.
func (r *Router) Dispatch(ctx context.Context, nodeID string, t jobs.Task) (jobs.Result, error) {
	r.mu.Lock()
	c, ok := r.conns[nodeID]
	if !ok {
		r.mu.Unlock()
		return jobs.Result{}, ErrNotConnected
	}
	w := &waiter{nodeID: nodeID, owner: c, ch: make(chan *relayv1.TaskResult, 1)}
	r.waiters[t.ID] = w
	slot := r.sendSlots[t.ID]
	if slot == nil {
		slot = &sendSlot{}
		r.sendSlots[t.ID] = slot
	}
	slot.refs++
	r.mu.Unlock()
	defer r.releaseSendSlot(t.ID, slot)

	// Outside mu on purpose: the guard may take the Job gate's mutex, commit
	// to the store, or read it, and mu guards map access only.
	slot.mu.Lock()
	if !slot.sent && jobs.SendWithheld(ctx) {
		slot.mu.Unlock()
		r.removeWaiterIfOwn(t.ID, w)
		return jobs.Result{}, jobs.ErrSendWithheld
	}
	slot.sent = true
	slot.mu.Unlock()

	msg := &relayv1.RelayMessage{Body: &relayv1.RelayMessage_Task{Task: taskRequest(t)}}
	if err := c.send(msg); err != nil {
		r.removeWaiter(t.ID)
		return jobs.Result{}, fmt.Errorf("dispatch: send task %q to node %q: %w", t.ID, nodeID, err)
	}

	select {
	case tr, ok := <-w.ch:
		if !ok {
			// Channel closed by unregister: the Node's Tunnel went away while
			// we were waiting. The Router resolves nothing; the caller reads
			// the store, where the offline hook may already have resolved the
			// Task (ErrNodeDisconnected). When a newer stream replaced this
			// one, w.err also carries jobs.ErrStreamReplaced; the close
			// orders this read after unregister's write.
			if w.err != nil {
				return jobs.Result{}, w.err
			}
			return jobs.Result{}, ErrNodeDisconnected
		}
		res, v := result(tr)
		if v.Violated() {
			r.logger().WarnContext(ctx, "dispatch: node reported an outcome the wire contract forbids; the Relay "+
				"refused the report and resolved the Task as a Relay-authored failure",
				"node_id", nodeID, "task_id", t.ID, "reported_outcome", v.ReportedOutcome, "rule", v.Rule)
			r.recordViolation(ctx, nodeID, t, v)
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

// releaseSendSlot drops one Dispatch call's reference on taskID's slot and
// deletes the slot when it was the last.
func (r *Router) releaseSendSlot(taskID string, slot *sendSlot) {
	r.mu.Lock()
	slot.refs--
	if slot.refs == 0 && r.sendSlots[taskID] == slot {
		delete(r.sendSlots, taskID)
	}
	r.mu.Unlock()
}

// removeWaiter deletes taskID's waiter, if still present, under mu. It does
// NOT close the channel — the caller (Dispatch) is the only reader and is
// abandoning it, not signalling disconnect to some other reader.
func (r *Router) removeWaiter(taskID string) {
	r.mu.Lock()
	delete(r.waiters, taskID)
	r.mu.Unlock()
}

// removeWaiterIfOwn deletes taskID's waiter only if it is still w. The waiters
// map is keyed by task ID, and a concurrent Reconciler resend can overwrite
// this call's entry (see ReconcileNode's doc); a withheld send must never
// delete another caller's waiter, or that caller would hang until its timeout.
func (r *Router) removeWaiterIfOwn(taskID string, w *waiter) {
	r.mu.Lock()
	if r.waiters[taskID] == w {
		delete(r.waiters, taskID)
	}
	r.mu.Unlock()
}

// recordViolation writes v as a durable, queryable audit event,
// before the caller sees the Relay-authored failure Dispatch resolves the
// Task with — so there is no window in which a surface shows the failure
// and the trail cannot explain it. It is a no-op when r.violations is nil
// (the supported "log only" mode; see NewRouter's doc comment).
//
// A record failure must NOT become a returned error. Dispatch's nil error
// is load-bearing (see the comment above its return): an error leaves the
// Task Dispatched, the Reconciler resends, and the attacker supplies the
// same forged answer again. An unrecorded violation is a logged one; an
// unresolved Task is an attacker-controlled loop (invariant 4).
//
// The residual of that choice is not swallowed: the composition root counts
// a failed write on relay_protocol_violations_unrecorded_total, so "the
// trail is missing violations" is an aggregate an operator can alert on
// rather than a log line nobody reads. Naming the counter here keeps the two
// halves of the decision readable together.
//
// The context is detached and re-bounded (violationAuditBudget) because the
// violation arrived — whether the caller's request context has since
// expired must not decide whether the evidence is kept. Same shape as the
// revocation cascade's audit budget (controlplane/api/tokens.go,
// cascadeAuditBudget). It runs on the dispatching goroutine and holds no
// lock — mu guards only the maps (Router's doc comment), and that stays
// true here.
func (r *Router) recordViolation(ctx context.Context, nodeID string, t jobs.Task, v jobs.ProtocolViolation) {
	if r.violations == nil {
		return
	}
	ev := jobs.ProtocolViolationEvent{
		NodeID:        nodeID,
		TaskID:        t.ID,
		JobID:         t.JobID,
		OperationName: t.Action.OperationName,
		Violation:     v,
	}
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), violationAuditBudget)
	defer cancel()
	if err := r.violations.RecordProtocolViolation(auditCtx, ev); err != nil {
		r.logger().ErrorContext(ctx, "dispatch: failed to record protocol violation; this violation has no durable row",
			"node_id", nodeID, "task_id", t.ID, "job_id", t.JobID, "rule", v.Rule, "err", err)
	}
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
		w.owner.markDelivered(tr.GetTaskId())
		// The result may arrive on a replacing stream; its skip set must
		// hold the delivery too.
		if cur, ok := r.conns[nodeID]; ok && cur != w.owner {
			cur.markDelivered(tr.GetTaskId())
		}
	}
	r.mu.Unlock()

	if ok && w.nodeID == nodeID {
		w.ch <- tr
	}
}

// Settled tells the Router that the caller of Dispatch for taskID has finished
// with the Task: whatever result it had to persist is persisted, or will never
// be. The Router then drops taskID from nodeID's delivered set, ending the
// protection it gave a delivered result against the offline resolution. The
// caller invokes it only after its Resolve returns, so removing the entry can
// never expose a Task whose result is still unwritten.
func (r *Router) Settled(nodeID, taskID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.conns[nodeID]; ok {
		delete(c.delivered, taskID)
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
// daemon's PolicyVerdict (ADR-0011) — capability.Conduit.Query's real
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
