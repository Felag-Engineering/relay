// Package capability is the Relay's single capability layer: the pipeline
// every control-path surface (MCP, the Control API, the Admin Console, any
// future CLI) must go through to act on Nodes — Selector -> authz ->
// blast-cap -> dispatch -> audit (ADR-0009/0010, ROADMAP invariant 10). No
// surface may build a parallel path to a Node: the dispatch type and its
// constructor are unexported, so a surface that tries to dispatch without
// going through Service.Run fails to compile (dispatch.go,
// dispatch_construction_test.go).
//
// v0.0.5 [3/8] wires this pipeline with seams and safe no-op/allow-all
// defaults only: no real Job engine (#99), no real blast-radius cap
// (#100/[5/8]), no real audit writes (#102/[7/8]). capability imports
// registry and jobs only — no database/sql, no audit, no relayv1 proto —
// preserving the store-swap and contract boundaries the rest of the Relay
// relies on.
package capability

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// Service is the exported facade over the capability pipeline. Construct it
// with New; the composition root (cmd/relay/main.go) owns the instance so
// later issues can swap in real seams via Option.
type Service struct {
	reg    registry.Repository
	authz  Authorizer
	cap    CapChecker
	disp   dispatcher
	audit  AuditSink
	freeze FreezeStore

	// metrics is best-effort observability only (MetricsSink, seams.go); it
	// never affects a dispatch, authz, cap, or Freeze decision.
	metrics MetricsSink

	// gate and approvals are the approval callout (ADR-0027). The defaults
	// gate nothing, which is a deployment with no approval rules — safe
	// because a gate can only add a reason to stop. approvals is only
	// consulted when gate says a dispatch is gated, so the nil store is
	// unreachable unless a real gate was wired without one, which New refuses.
	gate      ApprovalGate
	approvals ApprovalStore

	// grants is the batch/window Grant store (ADR-0027 decision 12). Nil means
	// no grant ever covers anything, which is both the default and the safe
	// direction.
	grants ApprovalGrantStore

	// approvalAuthz is the role floor on a DECISION (#270): deciding a Request
	// requires the role that Action would have needed to be requested. Nil only
	// on a Service built without WithApprovals, where there is nothing to
	// decide.
	approvalAuthz ApprovalAuthorizer

	// approvalNotifier pushes a parked dispatch to the operator's own
	// notification plumbing. Best-effort by construction — see ApprovalNotifier.
	approvalNotifier ApprovalNotifier

	// now and newApprovalID are seams so tests get deterministic parks.
	now           func() time.Time
	newApprovalID idGen

	// realDispatcher is set by WithExecution (execution.go) once a real Job
	// engine is wired. New's end-of-construction guard uses it to refuse a
	// real dispatcher riding the allow-all/no-op default seams — see the
	// contract note below.
	realDispatcher bool
}

// Option configures a Service built by New.
type Option func(*Service)

// WithAuthorizer overrides the default allow-all Authorizer.
func WithAuthorizer(a Authorizer) Option {
	if a == nil {
		panic("capability: WithAuthorizer: authorizer must not be nil")
	}
	return func(s *Service) { s.authz = a }
}

// WithCapChecker overrides the default no-op CapChecker.
func WithCapChecker(c CapChecker) Option {
	if c == nil {
		panic("capability: WithCapChecker: capChecker must not be nil")
	}
	return func(s *Service) { s.cap = c }
}

// WithAuditSink overrides the default no-op AuditSink.
func WithAuditSink(a AuditSink) Option {
	if a == nil {
		panic("capability: WithAuditSink: auditSink must not be nil")
	}
	return func(s *Service) { s.audit = a }
}

// WithFreeze overrides the default noopFreezeStore (ADR-0013).
func WithFreeze(f FreezeStore) Option {
	if f == nil {
		panic("capability: WithFreeze: freezeStore must not be nil")
	}
	return func(s *Service) { s.freeze = f }
}

// WithApprovals wires the approval callout (ADR-0027): gate decides which
// dispatches must wait for a human, store persists the parked Requests, and
// authorizer is the role floor on answering one (#270).
//
// All three are required together. A gate with no store could decide a dispatch
// needs approval and then have nowhere to record it — which would either drop
// the dispatch silently or, worse, let it through. A store with no gate is
// inert. A store with no authorizer would accept a decision from any
// authenticated caller, including a viewer releasing a Raw Exec, which is the
// approval mechanism handing out authority instead of withholding it. Passing
// an incomplete set is a composition-root bug, so it panics rather than
// degrading.
func WithApprovals(gate ApprovalGate, store ApprovalStore, authorizer ApprovalAuthorizer) Option {
	if gate == nil {
		panic("capability: WithApprovals: gate must not be nil")
	}
	if store == nil {
		panic("capability: WithApprovals: store must not be nil")
	}
	if authorizer == nil {
		panic("capability: WithApprovals: approval authorizer must not be nil; without it any authenticated caller could release a parked dispatch")
	}
	return func(s *Service) {
		s.gate = gate
		s.approvals = store
		s.approvalAuthz = authorizer
	}
}

// WithApprovalGrants wires the batch/window Grant store (ADR-0027 decision 12).
//
// Optional and separate from WithApprovals. Omitting it means no grant ever
// covers anything, which is the safe direction and the behaviour of every
// deployment that never creates one — a grant can only ever RELEASE a dispatch
// the gate already gated, so its absence can never let something through.
func WithApprovalGrants(g ApprovalGrantStore) Option {
	if g == nil {
		panic("capability: WithApprovalGrants: grant store must not be nil")
	}
	return func(s *Service) { s.grants = g }
}

// WithApprovalNotifier wires the out-of-band notification envelope (ADR-0027):
// where to push a freshly parked dispatch so an approver hears about it.
//
// Optional, and deliberately so. The notification is a delivery convenience;
// the guarantee is the authenticated decision endpoint, which stands alone. A
// deployment with no notifier configured still parks, still audits, and still
// waits — approvers just have to poll the queue.
func WithApprovalNotifier(n ApprovalNotifier) Option {
	if n == nil {
		panic("capability: WithApprovalNotifier: notifier must not be nil")
	}
	return func(s *Service) { s.approvalNotifier = n }
}

// WithClock overrides the Service's clock. Test seam only: approval expiry and
// park timestamps are time-dependent, and a test that sleeps is a test that
// flakes.
func WithClock(now func() time.Time) Option {
	if now == nil {
		panic("capability: WithClock: now must not be nil")
	}
	return func(s *Service) { s.now = now }
}

// WithMetrics overrides the default noopMetricsSink. Metrics are never
// security-relevant, so — unlike WithAuthorizer/WithCapChecker/WithAuditSink/
// WithFreeze — New's real-dispatcher fail-open guard does not require this
// option to have been supplied.
func WithMetrics(m MetricsSink) Option {
	return func(s *Service) { s.metrics = m }
}

// New returns a Service backed by reg, with allowAllAuthorizer,
// noopCapChecker, noopDispatcher, noopAuditSink, and noopFreezeStore
// defaults (functional-option pattern, mirroring registry.NewInMemory).
// There is deliberately no exported WithDispatcher: dispatcher is unexported
// (see dispatch.go), so only files inside this package can supply a real
// one. #99 adds the exported WithExecution(...) option (execution.go) that
// constructs the in-package sealed Job-engine dispatcher from its own
// collaborators.
//
// Contract enforced here: these allow-all/no-op defaults are safe ONLY
// because v0.0.5 has no consumer surface and the default dispatcher is a
// no-op — nothing is actually authorized, capped, audited, or stoppable.
// Once WithExecution (or any option wiring a real dispatcher) is used, New
// requires real Authorizer, CapChecker, AuditSink, and FreezeStore —
// WithAuthorizer, WithCapChecker, WithAuditSink, and WithFreeze must all
// have been supplied too — rather than silently letting a real dispatcher
// ride these defaults, and panics otherwise (a composition-root wiring bug,
// not a recoverable runtime condition). A real dispatcher paired with an
// allow-all Authorizer, a no-op CapChecker, or a no-op AuditSink is a
// fail-open: every Node would match, every Action would be permitted, and
// nothing would be recorded. A real dispatcher paired with a noopFreezeStore
// is the same class of bug: an un-stoppable executor, since "never frozen"
// means the emergency stop (ADR-0013) can never actually halt it. See
// dispatcher's doc comment in dispatch.go.
func New(reg registry.Repository, opts ...Option) *Service {
	s := &Service{
		reg:              reg,
		authz:            allowAllAuthorizer{},
		cap:              noopCapChecker{},
		disp:             noopDispatcher{},
		audit:            noopAuditSink{},
		freeze:           noopFreezeStore{},
		metrics:          noopMetricsSink{},
		gate:             noopApprovalGate{},
		approvalNotifier: noopApprovalNotifier{},

		now:           func() time.Time { return time.Now().UTC() },
		newApprovalID: defaultID,
	}
	for _, o := range opts {
		o(s)
	}
	if s.realDispatcher {
		if _, ok := s.authz.(allowAllAuthorizer); ok {
			panic("capability: New: a real dispatcher (WithExecution) requires a real Authorizer (WithAuthorizer); allowAllAuthorizer would fail open")
		}
		if _, ok := s.cap.(noopCapChecker); ok {
			panic("capability: New: a real dispatcher (WithExecution) requires a real CapChecker (WithCapChecker); noopCapChecker would fail open")
		}
		if _, ok := s.audit.(noopAuditSink); ok {
			panic("capability: New: a real dispatcher (WithExecution) requires a real AuditSink (WithAuditSink); noopAuditSink would record nothing")
		}
		if _, ok := s.freeze.(noopFreezeStore); ok {
			panic("capability: New: a real dispatcher (WithExecution) requires a real FreezeStore (WithFreeze); noopFreezeStore is never frozen, making the emergency stop unreachable")
		}
	}
	return s
}

// Run is the pipeline every surface must call to act on Nodes: check the
// Freeze, resolve the Selector, authorize the Principal, check the
// blast-radius cap, dispatch, then audit — in that order. The Freeze gate,
// authorize, and the cap check each short-circuit the remaining stages on
// error (no dispatch — nothing was executed), but each refusal is itself
// audited (recordRefusal) — refusals are the most interesting audit events
// (ROADMAP acceptance for #102). Once dispatch is attempted, the audit
// record is always written, even if the dispatcher itself returns an error:
// a dispatcher may execute some Nodes before failing on others, and a
// partially-executed dispatch must never go unaudited. In that case Run
// returns the dispatch error (joined with any audit-write error via
// errors.Join) alongside the partial results. Principal is threaded through
// to the AuditSink so every recorded entry attributes who asked, even before
// real authn exists.
//
// The Freeze check (ADR-0013) is the OUTERMOST gate, run before Selector
// resolution and before authz: a frozen Relay refuses all new dispatch,
// every risk class, regardless of who asks or how many Nodes would have
// matched — there is no reason to spend registry-resolution work whose
// result the refusal path would only discard. A Frozen read error fails
// closed (refuses dispatch); a guardrail must never fail open, even at the
// cost of availability during a store blip.
//
// Deliberate info-disclosure trade-off: because the Freeze gate runs before
// authz, a caller who is not authorized for act/sel still learns "the Relay
// is frozen" before being told "denied". This is acceptable because every
// caller reaching Run is already mTLS-authenticated (ADR-0005/0006) — there
// is no anonymous caller to leak the Freeze state to — and no real
// per-Principal Authorizer exists this milestone anyway.
func (s *Service) Run(ctx context.Context, p Principal, sel Selector, act jobs.Action) ([]NodeResult, error) {
	frozen, err := s.freeze.Frozen(ctx)
	if err != nil {
		return nil, s.recordRefusal(ctx, p, sel, act, RefusalInternal, fmt.Errorf("capability: read freeze state: %w", err))
	}
	if frozen {
		return nil, s.recordRefusal(ctx, p, sel, act, RefusalFrozen, &FrozenError{})
	}

	nodes := sel.Resolve(s.reg)

	// withoutAssertions: an authorization decision must not be able to read
	// anything the caller asserted (see assertions.go).
	if err := s.authz.Authorize(withoutAssertions(ctx), p, act, sel); err != nil {
		return nil, s.recordRefusal(ctx, p, sel, act, RefusalUnauthorized, err)
	}

	if err := s.cap.Check(act.RiskClass, len(nodes)); err != nil {
		return nil, s.recordRefusal(ctx, p, sel, act, RefusalBlastCap, err)
	}

	// The approval gate (ADR-0027) sits HERE — after Selector resolution,
	// authz, and the blast cap, and before any Task exists.
	//
	// After, because the approver must be shown the resolved fan-out: an
	// approval that did not know how many Nodes it covered would be the
	// approval-view fidelity gap by construction. Before the dispatcher,
	// because parking must leave no Job and no Pending Tasks behind — rows a
	// restart reconciler could mistake for interrupted work.
	//
	// A park is not a refusal, so it does not go through recordRefusal: nothing
	// was denied and nothing ran. It is audited as its own kind.
	ap, err := s.checkApproval(ctx, p, sel, act, nodeIDs(nodes))
	if err != nil {
		return nil, s.recordRefusal(ctx, p, sel, act, RefusalInternal, err)
	}
	if ap.parked != nil {
		s.metrics.IncRefusal(RefusalPendingApproval)
		// approval_requested means A REQUEST WAS CREATED (#379). A re-drive
		// that bounced off an already-pending Request — which is how a caller
		// polls while waiting — is recorded under its own kind, so the trail's
		// count of asks stays truthful while the polling stays visible.
		kind := AuditKindApprovalRequested
		if ap.created == nil {
			kind = AuditKindApprovalPendingObserved
		}
		entry := AuditEntry{
			Kind: kind, Principal: p, Selector: sel, Action: act,
			Reason: ap.parked.Error(), ApprovalID: ap.parked.RequestID, PlanHash: ap.parked.PlanHash,
			Asserted: AssertionsFromContext(ctx),
		}
		if auditErr := s.audit.Record(ctx, entry); auditErr != nil {
			// An unaudited park is a dispatch nobody can account for. Surface
			// the write failure alongside the park rather than swallowing it.
			return nil, errors.Join(ap.parked, fmt.Errorf("capability: record audit entry: %w", auditErr))
		}
		// Notify only on a park this call CREATED, and only after it is durably
		// recorded and audited: a notification about a request that failed to
		// persist would page a human towards nothing. Re-driving a dispatch that
		// is already waiting deliberately does not re-notify — see
		// approvalDecision.created.
		if ap.created != nil {
			s.approvalNotifier.NotifyParked(ctx, noticeFor(*ap.created))
		}
		return nil, ap.parked
	}

	d := newDispatch(p, sel, nodes, act)
	res, dispatchErr := s.disp.run(ctx, d)

	// Join the approval that released this dispatch to the Job it produced, so
	// audit can answer "who approved what actually ran" rather than leaving the
	// two records to be correlated by timestamp.
	//
	// ONLY for a single-Plan approval. A Request carries one job_id, which is
	// right when one approval releases one Job — but a batch/window Grant
	// (ADR-0027 decision 12) releases MANY, and binding each in turn would
	// leave the authorizing Request pointing at whichever Job happened to run
	// last, silently losing the rest. The grant-to-Jobs join is the audit
	// trail's GrantID, which is why that field exists; a Grant deliberately
	// does not reuse this one-to-one column.
	if ap.grantID == "" && ap.requestID != "" && res.jobID != "" {
		if err := s.approvals.BindJob(ctx, ap.requestID, res.jobID); err != nil {
			dispatchErr = errors.Join(dispatchErr, fmt.Errorf("capability: bind job to approval: %w", err))
		}
	}

	for _, r := range res.results {
		s.metrics.IncDispatch(r.Outcome)
	}

	// The AuditSink is recorded unconditionally, even when the dispatcher
	// errors: dispatch.run may execute some Nodes before failing on others
	// (the #99 contract), and a partially-executed dispatch must never be
	// unaudited. results-so-far are recorded whether or not dispatchErr is
	// nil.
	//
	// Residual risk (inherited from #97/#98, out of #102's scope): Args/
	// RawExecArgv below are copied verbatim from act, so a secret passed in
	// an Operation's arguments would land in the audit trail as-is. #102
	// does not close this — it is flagged here so it is not mistaken for a
	// gap in #102's redaction guarantee.
	entry := AuditEntry{Kind: AuditKindDispatch, Principal: p, Selector: sel, Action: act, JobID: res.jobID, Results: res.results, ApprovalID: ap.requestID, GrantID: ap.grantID, Asserted: AssertionsFromContext(ctx)}
	auditErr := s.audit.Record(ctx, entry)
	if auditErr != nil {
		// The dispatch itself already happened; a failed audit write must
		// not silently vanish, so it is surfaced as an error alongside the
		// (still valid) results rather than swallowed.
		auditErr = fmt.Errorf("capability: record audit entry: %w", auditErr)
	}

	if err := errors.Join(dispatchErr, auditErr); err != nil {
		return res.results, err
	}
	return res.results, nil
}

// recordRefusal audits a Freeze-engaged, authz-deny, or cap-reject
// short-circuit — the dispatcher was never reached, so there is no JobID or
// Results, only the refusal's Reason. It also increments the MetricsSink for
// kind. It returns refusalErr, joined with a wrapped audit-write error if the
// audit write itself failed, so a failed audit write is never silently
// swallowed.
func (s *Service) recordRefusal(ctx context.Context, p Principal, sel Selector, act jobs.Action, kind RefusalKind, refusalErr error) error {
	s.metrics.IncRefusal(kind)
	entry := AuditEntry{Kind: AuditKindRefusal, Principal: p, Selector: sel, Action: act, Reason: refusalErr.Error(), Asserted: AssertionsFromContext(ctx)}
	var auditErr error
	if err := s.audit.Record(ctx, entry); err != nil {
		auditErr = fmt.Errorf("capability: record audit entry: %w", err)
	}
	return errors.Join(refusalErr, auditErr)
}

// EngageFreeze sets the Relay-wide Freeze (ADR-0013), attributed to p:
// persisted first (so a crash after this call still leaves the Freeze
// engaged), then recorded via AuditSink.RecordFreeze. If persistence fails,
// the audit call is skipped — there is nothing true to record — and the
// persistence error is returned.
func (s *Service) EngageFreeze(ctx context.Context, p Principal) error {
	if err := s.freeze.Engage(ctx, p.Attribution()); err != nil {
		return fmt.Errorf("capability: engage freeze: %w", err)
	}
	return s.audit.RecordFreeze(ctx, FreezeEvent{Principal: p, Engage: true, Asserted: AssertionsFromContext(ctx)})
}

// ReleaseFreeze clears the Relay-wide Freeze (ADR-0013), attributed to p
// with reason recorded for why: persisted first, then recorded via
// AuditSink.RecordFreeze, mirroring EngageFreeze.
func (s *Service) ReleaseFreeze(ctx context.Context, p Principal, reason string) error {
	if err := s.freeze.Release(ctx, p.Attribution(), reason); err != nil {
		return fmt.Errorf("capability: release freeze: %w", err)
	}
	return s.audit.RecordFreeze(ctx, FreezeEvent{Principal: p, Engage: false, Reason: reason, Asserted: AssertionsFromContext(ctx)})
}

// CancelJob stops jobID's Tasks (#101, ADR-0013): undispatched Tasks are
// marked cancelled without ever being sent, in-flight Tasks are asked to
// cancel over their Tunnels, and already-resolved Tasks keep their truthful
// outcome. It delegates to the sealed dispatcher (see dispatch.go) so
// tasksRepo/Conduit stay inside the engine, mirroring how Run delegates to
// s.disp.run.
//
// p is recorded via AuditSink.RecordCancel (v0.0.6 [5/8], owner DECISION 2):
// cancellation is durably recorded on each affected Task via
// OutcomeCancelled regardless of who asked (ADR-0013), but the audit trail
// must still answer "who asked for the stop", so this call ADDS a
// principal-attributed audit row on top of that per-Task record. Mirroring
// EngageFreeze/ReleaseFreeze: the cancel itself is attempted first, and the
// audit write is skipped if it errors — there is nothing true to record
// (e.g. jobs.ErrJobNotFound: no Task was ever touched).
func (s *Service) CancelJob(ctx context.Context, p Principal, jobID string) error {
	if err := s.disp.cancel(ctx, jobID); err != nil {
		return err
	}
	return s.audit.RecordCancel(ctx, p, jobID)
}
