// Package capability is the Relay's single capability layer: the pipeline
// every control-path surface (MCP, the Control API, the Admin Console, any
// future CLI) must go through to act on Nodes — Selector -> authz ->
// blast-cap -> dispatch -> audit (ADR-0009/0010, invariant 10). No
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
	"log/slog"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
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

	// jobEvents is the event seam's Job-grained publisher (#416,
	// JobEventSink, seams.go) — the same "purely observational" contract as
	// metrics. propagated onto the real Job engine (jobEngine.events) at
	// the end of New, below, because both Service.CancelJob and
	// jobEngine.run need the same sink and option order must not matter.
	jobEvents JobEventSink

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

	// mcpTasks persists MCP task handles (#374, ADR-0028). Nil disables the
	// Tasks extension entirely, which is the pre-#374 behaviour and loses
	// nothing: the universal pending_approval result path does not use handles.
	mcpTasks MCPTaskStore

	// approvalAuthz is the role floor on a DECISION (#270): deciding a Request
	// requires the role that Action would have needed to be requested. Nil only
	// on a Service built without WithApprovals, where there is nothing to
	// decide.
	approvalAuthz ApprovalAuthorizer

	// approvalNotifier pushes a parked dispatch to the operator's own
	// notification plumbing. Best-effort by construction — see ApprovalNotifier.
	approvalNotifier ApprovalNotifier

	// auditQ and jobQ are the read lane (#441): filtered, paginated queries
	// over the audit trail and over Jobs/Tasks. Nil means the read lane is
	// not wired — readlane.go's methods return ErrQueriesUnavailable rather
	// than an empty page, since an empty page is a claim ("there is nothing
	// here") and a nil seam has not actually looked.
	auditQ AuditQuery
	jobQ   JobQuery

	// policyView and nodeVocab are the DISPLAY-ONLY Policy-view and Template-
	// vocabulary reads (#680, seams.go). Both nil by default: DescribeNode
	// and ListOperations report *Reported=false for a nil seam rather than an
	// empty Policy or vocabulary — absence is never rendered as "nothing
	// restricted" (QRY-7).
	policyView PolicyViewSource
	nodeVocab  TemplateVocabularySource

	// now and newApprovalID are seams so tests get deterministic parks.
	now           func() time.Time
	newApprovalID idGen

	// realDispatcher is set by WithExecution (execution.go) once a real Job
	// engine is wired. New's end-of-construction guard uses it to refuse a
	// real dispatcher riding the allow-all/no-op default seams — see the
	// contract note below.
	realDispatcher bool

	// certExpiringWithin is the state:cert-expiring warning window
	// (ADR-0034), threaded into every Selector resolution via stateEval.
	// Zero (the default) means the marker never fires — set only by
	// WithCertExpiringWindow, which the composition root always calls with a
	// real value (invariant 11: file-only, no API reads or sets it).
	certExpiringWithin time.Duration

	// accountsStore and apiTokens back Account and API-Token administration
	// (#653, accountadmin.go). Both nil means the surface is unconfigured:
	// every method in accountadmin.go returns ErrAccountsUnavailable rather
	// than a claim about state it never looked at. Wired together by
	// WithAccountAdmin, since one without the other is half a surface (an
	// Account with no way to issue it a credential, or a token store with no
	// way to look up whose credential it is).
	accountsStore AccountStore
	apiTokens     APITokenStore
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

// WithMCPTasks wires the MCP task-handle store (#374, ADR-0028), enabling the
// Tasks extension's server side.
//
// Optional, and its absence is not a degraded mode but the prior one: with no
// store, dispatches park and return the universal `pending_approval` result
// (#371) exactly as before. ADR-0028 requires that path to keep working with
// the shim deleted, so nothing below it may come to depend on a handle
// existing.
func WithMCPTasks(store MCPTaskStore) Option {
	if store == nil {
		panic("capability: WithMCPTasks: task handle store must not be nil")
	}
	return func(s *Service) { s.mcpTasks = store }
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

// WithQueries wires the read lane (#441): audit is the trail's filtered/
// paginated/aggregating seam, job is the same for Jobs/Tasks. Both required
// together — a Job lane with no audit lane would leave Activity able to list
// Jobs and unable to attribute them, mirroring WithApprovals' "all required
// together" reasoning.
//
// Optional overall: a Service built without WithQueries still dispatches
// exactly as before #441, and its own read-lane methods (readlane.go) return
// ErrQueriesUnavailable rather than degrading. Its own fail-closed property
// is RecordRead's "record first" ordering in readlane.go — but New's guard
// now ALSO requires a real AuditSink whenever WithQueries was used (F5,
// #441 cycle-2 security review): WithQueries sat outside the real-dispatcher
// fail-open guard, so a Service built with WithQueries but no WithAuditSink
// answered every trail query while auditing none of them — exactly the
// "unauditable read succeeded" state ADR-0025 forbids, and a composition-root
// footgun distinct from (and checked independently of) the real-dispatcher
// case. See New.
func WithQueries(audit AuditQuery, job JobQuery) Option {
	if audit == nil {
		panic("capability: WithQueries: audit query seam must not be nil")
	}
	if job == nil {
		panic("capability: WithQueries: job query seam must not be nil")
	}
	return func(s *Service) {
		s.auditQ = audit
		s.jobQ = job
	}
}

// WithPolicyView wires the DISPLAY-ONLY Policy-view read (#680): source is
// typically a *policyview.Cache, narrowed to Get only. Absence (the default)
// is the honest state of a Relay that has just restarted, before any Node
// reconnects — DescribeNode reports PolicyReported=false, never an empty
// Policy (QRY-7).
func WithPolicyView(source PolicyViewSource) Option {
	if source == nil {
		panic("capability: WithPolicyView: source must not be nil")
	}
	return func(s *Service) { s.policyView = source }
}

// WithTemplateVocabulary wires the DISPLAY-ONLY Template-vocabulary read
// (#680): source is typically a *nodevocab.Cache, narrowed to Get only.
// Absence (the default) means DescribeNode and ListOperations report
// Reported=false rather than an empty vocabulary.
func WithTemplateVocabulary(source TemplateVocabularySource) Option {
	if source == nil {
		panic("capability: WithTemplateVocabulary: source must not be nil")
	}
	return func(s *Service) { s.nodeVocab = source }
}

// WithAccountAdmin wires Account and API-Token administration (#653,
// accountadmin.go). store and tokens are required together — an Account
// store with no Token store can create identities with no way to issue them
// a credential, and a Token store with no Account store cannot resolve
// whose credential it is minting or revoking; passing an incomplete set is a
// composition-root bug, so it panics rather than degrading (mirrors
// WithApprovals' "all required together" reasoning).
//
// Optional overall: a Service built without this option answers every
// accountadmin.go method with ErrAccountsUnavailable, exactly the posture
// WithQueries' absence gives the read lane.
func WithAccountAdmin(store AccountStore, tokens APITokenStore) Option {
	if store == nil {
		panic("capability: WithAccountAdmin: account store must not be nil")
	}
	if tokens == nil {
		panic("capability: WithAccountAdmin: API token store must not be nil")
	}
	return func(s *Service) {
		s.accountsStore = store
		s.apiTokens = tokens
	}
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

// WithJobEvents overrides the default noopJobEventSink (#416). Like
// WithMetrics, this is never security-relevant — New's real-dispatcher
// fail-open guard does not require it.
func WithJobEvents(s JobEventSink) Option {
	return func(svc *Service) { svc.jobEvents = s }
}

// WithCertExpiringWindow sets the state:cert-expiring warning window
// (ADR-0034): a Node fires the marker once less than d of its certificate's
// remaining lifetime is left. d is a Duration rather than a fraction because
// this package must never import internal/ca (its own import allowlist bars
// it) — the composition root computes d once via
// nodestate.CertExpiringWindow(ca.LeafValidity, fraction) and hands every
// surface, including this one, the same value (invariant 11).
//
// Panics on d < 0: a negative window is a composition-root bug, not a
// runtime condition to degrade under. The zero value (never calling this
// option) is the safe default and means the marker never fires.
func WithCertExpiringWindow(d time.Duration) Option {
	if d < 0 {
		panic("capability: WithCertExpiringWindow: d must not be negative")
	}
	return func(s *Service) { s.certExpiringWithin = d }
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
//
// Separately, and regardless of s.realDispatcher: WithQueries also requires
// a real AuditSink (F5, #441 cycle-2 security review) — see WithQueries' doc
// comment.
func New(reg registry.Repository, opts ...Option) *Service {
	s := &Service{
		reg:              reg,
		authz:            allowAllAuthorizer{},
		cap:              noopCapChecker{},
		disp:             noopDispatcher{},
		audit:            noopAuditSink{},
		freeze:           noopFreezeStore{},
		metrics:          noopMetricsSink{},
		jobEvents:        noopJobEventSink{},
		gate:             noopApprovalGate{},
		approvalNotifier: noopApprovalNotifier{},

		now:           func() time.Time { return time.Now().UTC() },
		newApprovalID: defaultID,
	}
	for _, o := range opts {
		o(s)
	}
	// Propagate the Job-event sink onto the real Job engine, if one is
	// wired (WithExecution, execution.go). This is here — AFTER the option
	// loop, alongside this fail-open validation — rather than as an
	// ExecOption, because option order must not matter and both
	// Service.CancelJob (below) and jobEngine.run (execution.go) need the
	// same sink.
	if e, ok := s.disp.(*jobEngine); ok {
		e.events = s.jobEvents
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
	// WithQueries requires a real AuditSink (F5, #441 cycle-2 security
	// review), independent of s.realDispatcher and checked here — not inside
	// WithQueries itself — so the result does not depend on the order two
	// Options were passed to New. Without this, a Service built with
	// WithQueries but no WithAuditSink answers every trail query while
	// recording none of them: exactly the "unauditable read succeeded" state
	// ADR-0025 forbids, the read-lane analogue of the real-dispatcher guard
	// above.
	if s.auditQ != nil {
		if _, ok := s.audit.(noopAuditSink); ok {
			panic("capability: New: WithQueries requires a real AuditSink (WithAuditSink); noopAuditSink would answer every trail query while recording none of them")
		}
	}
	// WithAccountAdmin requires a real AuditSink AND a real Authorizer (#653),
	// independent of s.realDispatcher and checked here for the same reason
	// WithQueries' guard above is: the result must not depend on the order
	// two Options were passed to New. An un-floored Account-administration
	// surface is a fail-open no less serious than an un-floored dispatch —
	// every role would pass account_role/account_disable/api_token_mint —
	// and an unaudited one means "who created this Account" is unanswerable
	// after a compromise, exactly what ADR-0025 forbids for the read lane.
	//
	// Checked on EITHER field, not just accountsStore: WithAccountAdmin sets
	// both together and panics on a nil argument, so today the two can never
	// disagree — but a guard that keys on only one of two fields a future
	// option (or a hand-built Service literal in a test) could set
	// independently is exactly the kind of guard that silently stops
	// covering what it claims to (TestNewRefusesAccountAdminWithoutA...
	// falsifies this by construction, see accountadmin_test.go).
	if s.accountsStore != nil || s.apiTokens != nil {
		if _, ok := s.authz.(allowAllAuthorizer); ok {
			panic("capability: New: WithAccountAdmin requires a real Authorizer (WithAuthorizer); allowAllAuthorizer would fail open on every Account/API-Token administration act")
		}
		if _, ok := s.audit.(noopAuditSink); ok {
			panic("capability: New: WithAccountAdmin requires a real AuditSink (WithAuditSink); noopAuditSink would record no Account/API-Token administration act")
		}
	}
	return s
}

// stateEval is the StateEval every Selector resolution inside this Service
// evaluates against: the Service's own clock (the same seam WithClock
// overrides for deterministic tests) and its configured cert-expiring
// window. One method, so Run and Plan can never resolve the same Selector
// against two different instants.
//
// Falls back to time.Now().UTC() when now is unset, mirroring New's own
// default — a *Service built as a struct literal in a test (bypassing New)
// must stay callable rather than panic on a nil func field.
func (s *Service) stateEval() StateEval {
	now := s.now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return StateEval{Now: now(), CertExpiringWithin: s.certExpiringWithin}
}

// Run is the pipeline every surface must call to act on Nodes: check the
// Freeze, resolve the Selector, authorize the Principal, refuse a Selector
// that matched no Nodes, check the blast-radius cap, dispatch, then audit —
// in that order. The Freeze gate, authorize, the no-Nodes-matched check, and
// the cap check each short-circuit the remaining stages on error (no
// dispatch — nothing was executed), but each refusal is itself audited
// (recordRefusal) — refusals are the most interesting audit events
// (acceptance criterion for #102). Once dispatch is attempted, the audit
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

	nodes := sel.Resolve(s.reg, s.stateEval())

	// withoutAssertions: an authorization decision must not be able to read
	// anything the caller asserted (see assertions.go).
	if err := s.authz.Authorize(withoutAssertions(ctx), p, act, sel); err != nil {
		return nil, s.recordRefusal(ctx, p, sel, act, RefusalUnauthorized, err)
	}

	// A Selector that resolved to zero Nodes is refused HERE — after
	// authorization, before the blast cap, the approval gate and the
	// dispatcher — so:
	//   (a) no Job ID is minted, CreateJob is never called, and no zero-Node
	//       request is parked: there is no Node to show an approver and
	//       nothing for a dispatcher to run.
	//   (b) it deliberately comes AFTER authorization: a caller who may not
	//       ask gets the same "unauthorized" refusal whatever the fleet
	//       holds, and learns nothing about whether any Selector matches
	//       (AGENTS.md section 9: prefer the more restrictive option).
	//   (c) it is audited as a refusal (recordRefusal), not as a job-level
	//       dispatch row.
	//   (d) Service.Plan reports the same condition as NoNodesMatched rather
	//       than refusing it — ADR-0011: "A Plan never hard-fails on
	//       guardrails — it reports."
	if len(nodes) == 0 {
		return nil, s.recordRefusal(ctx, p, sel, act, RefusalNoNodesMatched, &NoNodesMatchedError{Selector: sel.String()})
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
	// The Request checkApproval found had ALREADY released a Job (AP-77): a
	// sequential re-drive of an already-answered approval. Re-attach and
	// dispatch nothing — see Service.reattach.
	if ap.reattachJobID != "" {
		return s.reattach(ctx, p, sel, nodes, ap.requestID, ap.reattachJobID)
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
			//
			// Askable is cleared here too: a surface must never render a
			// question about a park that was never durably audited — and,
			// below, never notified either, since NotifyParked is skipped on
			// this same error path.
			ap.parked.Askable = false
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
		// Attach an MCP task handle, if Tasks are wired. Last, and never
		// fatally: the park is already durable and already audited, and
		// ADR-0028 requires the universal result path to stay whole with the
		// shim deleted — so a handle store that is down costs a client its poll
		// handle and costs the dispatch nothing.
		ap.parked.TaskID, ap.parked.TaskExpiresAt = s.mintTaskHandle(ctx, p, ap.parked.RequestID)
		return nil, ap.parked
	}

	d := newDispatch(p, sel, nodes, act)

	// A single-Plan approval's release is now CLAIMED before dispatch, not
	// bound after it (AP-77). The join between the approval and the Job it
	// releases is made by this claim, before any Job or Task exists — so a
	// client timeout, a dropped connection, or a cancelled request after
	// dispatch starts can never leave the Job unbound: there is nothing
	// left to lose, because the bind already committed.
	//
	// Grant-released dispatches (ap.grantID non-empty) are never claimed here:
	// a Request carries one job_id, which is right when one approval releases
	// one Job, but a batch/window Grant (ADR-0027 decision 12) releases MANY,
	// and binding each in turn would leave the authorizing Request pointing at
	// whichever Job happened to run last, silently losing the rest. The
	// grant-to-Jobs join is the audit trail's GrantID, which is why that field
	// exists; a Grant deliberately does not reuse this one-to-one column.
	//
	// A Grant can never reach here for a plan an approval already released:
	// checkApproval's re-attach lookup (Satisfied && Released) runs BEFORE it
	// ever claims a Grant, so a Grant issued to cover a plan AFTER a
	// single-Plan approval released it does NOT authorize a second Job while
	// that approval is still in force — the re-drive re-attaches instead, and
	// the Grant's own uses are untouched
	// (TestRun_ReleasedApprovalReAttachesEvenWhenAGrantCoversThePlan). Once the
	// approval's deadline passes, Satisfied goes false, the released Request no
	// longer shadows the Grant, and the Grant releases the dispatch normally.
	if ap.grantID == "" && ap.requestID != "" {
		jobID, err := s.disp.reserveJobID()
		if err != nil {
			return nil, s.recordRefusal(ctx, p, sel, act, RefusalInternal, fmt.Errorf("capability: reserve job id for approval release: %w", err))
		}
		claimed, err := s.approvals.BindJob(ctx, ap.requestID, jobID, s.clock())
		switch {
		case err == nil:
			d.jobID = jobID
		case errors.Is(err, approval.ErrAlreadyReleased) && claimed.JobID != "":
			// Lost the claim to a concurrent dispatch of the same plan. Nothing
			// is dispatched here (AP-77) — re-attach to the winner's Job.
			return s.reattach(ctx, p, sel, nodes, ap.requestID, claimed.JobID)
		default:
			// ErrNotReleasable (the deadline passed between read and claim),
			// ErrNotFound, a store failure, or — defensively — ErrAlreadyReleased
			// with no JobID to re-attach to (the store's belt-and-braces
			// backstop should never produce this, but a re-attach to nothing
			// must never be attempted). Fail closed: nothing is dispatched, and
			// the next re-drive re-evaluates from scratch.
			return nil, s.recordRefusal(ctx, p, sel, act, RefusalInternal, fmt.Errorf("capability: claim approval release: %w", err))
		}
	}

	res, dispatchErr := s.disp.run(ctx, d)

	// And onto the MCP task handle that was waiting for it, so a poll after the
	// release reports `completed` rather than `working` forever. Unlike the
	// binding above this one covers grant-released dispatches too: a handle is
	// per parked dispatch, so there is exactly one Job to record against it.
	s.bindTaskHandleJob(ctx, ap.requestID, res.jobID)

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

// recordRefusal audits a Freeze-engaged, authz-deny, no-Nodes-matched, or
// cap-reject short-circuit — the dispatcher was never reached, so there is
// no JobID or Results, only the refusal's Reason. It also increments the
// MetricsSink for kind. It returns refusalErr, joined with a wrapped
// audit-write error if the audit write itself failed, so a failed audit
// write is never silently swallowed.
func (s *Service) recordRefusal(ctx context.Context, p Principal, sel Selector, act jobs.Action, kind RefusalKind, refusalErr error) error {
	s.metrics.IncRefusal(kind)
	entry := AuditEntry{Kind: AuditKindRefusal, Principal: p, Selector: sel, Action: act, Reason: refusalErr.Error(), Asserted: AssertionsFromContext(ctx)}
	var auditErr error
	if err := s.audit.Record(ctx, entry); err != nil {
		auditErr = fmt.Errorf("capability: record audit entry: %w", err)
	}
	return errors.Join(refusalErr, auditErr)
}

// ErrFreezeReasonRequired is returned by ReleaseFreeze when reason is empty
// or whitespace. ADR-0013's asymmetric activation is not decoration: engaging
// the emergency stop is cheap and reason-free, and releasing it is the
// deliberate act that must say why, because the reason is what a later reader
// has to reconstruct the incident from. Enforced here rather than per surface
// so a Console or a future CLI cannot release without one.
var ErrFreezeReasonRequired = errors.New("capability: releasing the Freeze requires a non-empty reason (ADR-0013)")

// localHostPrincipal attributes an engage/release performed by root on the
// Relay host itself (the signal lever, cmd/relay/freeze_signal.go). It is
// deliberately role-less and kind-less: it is not an Account, it holds no
// credential, and its authority is process-signal privilege on the box —
// which is strictly greater than any API credential's.
//
// Defined here, once, so the attribution string recorded for the host lever
// cannot drift from the two methods allowed to use it.
func localHostPrincipal() Principal { return Principal{Account: "local-host"} }

// EngageFreeze sets the Relay-wide Freeze (ADR-0013), attributed to p:
// authorized first, then persisted (so a crash after the store call still
// leaves the Freeze engaged), then recorded via AuditSink.RecordFreeze. If
// persistence fails, the audit call is skipped — there is nothing true to
// record — and the persistence error is returned.
//
// The floor is `operator`, AND the Principal must be a human Account (#397).
// The role half is ADR-0013's "engage cheap": anyone who may run anything may
// also pull the cord. The human half is the amendment #397 records, and it is
// not a role question at all — a machine Account at `operator` freezing the
// fleet is a jailbroken AI-agent switching off its own overseers, a denial of
// service the fire-alarm argument does not cover. Authority is still the Role
// (principal.go); Kind answers only the question authority cannot.
//
// A refusal is audited as a refusal, with the Principal, exactly like a
// refused dispatch — see refuseControl.
func (s *Service) EngageFreeze(ctx context.Context, p Principal) error {
	if err := s.authz.AuthorizeControl(ctx, p, ControlFreezeEngage); err != nil {
		return s.refuseControl(ctx, p, err)
	}
	return s.engageFreeze(ctx, p)
}

// EngageFreezeLocal engages the Freeze on behalf of root on the Relay host —
// ADR-0013's second activation path ("or locally on the Relay host"), which
// exists precisely for the case where the distrusted thing IS the API
// credential.
//
// It is a separate method rather than a Principal the role gate happens to
// wave through, because the two are different roots of authority and that
// difference should be visible at the call site. Authority-by-call-site is
// also what keeps it unreachable from any surface: the Control API holds a
// Freezer interface carrying only the gated pair (api.Freezer), so no route
// can reach this even by accident.
func (s *Service) EngageFreezeLocal(ctx context.Context) error {
	return s.engageFreeze(ctx, localHostPrincipal())
}

func (s *Service) engageFreeze(ctx context.Context, p Principal) error {
	if err := s.freeze.Engage(ctx, p.Attribution()); err != nil {
		return fmt.Errorf("capability: engage freeze: %w", err)
	}
	return s.audit.RecordFreeze(ctx, FreezeEvent{Principal: p, Engage: true, Asserted: AssertionsFromContext(ctx)})
}

// ReleaseFreeze clears the Relay-wide Freeze (ADR-0013), attributed to p with
// reason recorded for why: authorized first, then persisted, then recorded
// via AuditSink.RecordFreeze, mirroring EngageFreeze.
//
// The floor is `admin` and the reason is mandatory (#397, ADR-0013): the
// fire-alarm asymmetry is that anyone may pull the handle and the chief
// clears re-entry. Both refusals are audited with the Principal.
func (s *Service) ReleaseFreeze(ctx context.Context, p Principal, reason string) error {
	if err := s.authz.AuthorizeControl(ctx, p, ControlFreezeRelease); err != nil {
		return s.refuseControl(ctx, p, err)
	}
	if strings.TrimSpace(reason) == "" {
		return s.refuseControl(ctx, p, ErrFreezeReasonRequired)
	}
	return s.releaseFreeze(ctx, p, reason)
}

// ReleaseFreezeLocal is EngageFreezeLocal's counterpart: release by root on
// the Relay host. The reason stays mandatory — the local lever is a different
// root of authority, not an exemption from saying why the fleet is running
// again.
func (s *Service) ReleaseFreezeLocal(ctx context.Context, reason string) error {
	if strings.TrimSpace(reason) == "" {
		return ErrFreezeReasonRequired
	}
	return s.releaseFreeze(ctx, localHostPrincipal(), reason)
}

func (s *Service) releaseFreeze(ctx context.Context, p Principal, reason string) error {
	if err := s.freeze.Release(ctx, p.Attribution(), reason); err != nil {
		return fmt.Errorf("capability: release freeze: %w", err)
	}
	return s.audit.RecordFreeze(ctx, FreezeEvent{Principal: p, Engage: false, Reason: reason, Asserted: AssertionsFromContext(ctx)})
}

// refuseControl audits a refused ControlAction and returns the refusal.
//
// It is recordRefusal's sibling for the acts that carry no Selector and no
// Action: nothing was resolved, nothing was dispatched, and there is no
// fan-out to describe — only who was refused and why. It goes to the SAME
// AuditKindRefusal the dispatch path uses, so "show me everything this
// Account was refused" stays one query rather than two (invariant 10 applied
// to the trail, not only to the code path).
func (s *Service) refuseControl(ctx context.Context, p Principal, refusalErr error) error {
	return s.recordRefusal(ctx, p, Selector{}, jobs.Action{}, RefusalUnauthorized, refusalErr)
}

// ErrJobNotRequestedByCaller is CancelJob's refusal for a machine Account
// asking to cancel a Job that is not its own (owner decision 2026-09-17,
// execution.md §Cancellation, #614). Exported and typed so a surface can
// recognize the refusal via errors.Is without string-matching (mirrors
// FrozenError/CapExceededError).
//
// One message covers two different facts on purpose — "this Job was
// requested by a different Account" and "this Job's requester is not
// recorded at all" — and the caller must not be able to tell which. The
// requester is recorded on the Job at creation (#616), and a Job with no
// recorded requester (one created before that) is refused exactly like
// another Account's Job: distinguishing "not recorded" from "somebody
// else's" would let a machine Account learn that a Job it cannot cancel
// exists and is still in flight, one bit at a time. Never inferred: an
// unresolvable requester is refused exactly like a resolved one that does
// not match.
var ErrJobNotRequestedByCaller = errors.New(
	"capability: cancel refused: this Job was not requested by the caller, or its requester is not recorded")

// CancelJob stops jobID's Tasks (#101, ADR-0013): undispatched Tasks are
// marked cancelled without ever being sent, in-flight Tasks are asked to
// cancel over their Tunnels, and already-resolved Tasks keep their truthful
// outcome. It delegates to the sealed dispatcher (see dispatch.go) so
// tasksRepo/Conduit stay inside the engine, mirroring how Run delegates to
// s.disp.run.
//
// The floor is `operator` for every Account, human or machine — that half
// is unchanged. What differs by Kind is the SCOPE (owner decision
// 2026-09-17, execution.md §Cancellation, #614, narrowing #595's original
// "any Job" reading): a human Account may still cancel any Job, but a
// machine Account may cancel only a Job whose recorded requester is that
// same Account — see authorizeMachineCancel. AuthorizeControl runs FIRST,
// before disp.cancel, so a refused caller neither touches a Task nor learns
// whether the Job exists (see TestCancelJobRefusalDoesNotRevealWhetherTheJobExists).
// It reads the context with withoutAssertions, for the same reason Run and
// Plan do: an authorization decision must never be swayed by caller-asserted
// attribution (assertions.go).
//
// A deliberate asymmetry falls out of the SCOPE difference above: a human
// Account cancelling an unknown Job ID reaches disp.cancel directly and gets
// jobs.ErrJobNotFound, while a machine Account asking about that same id
// gets the uniform ErrJobNotRequestedByCaller instead — because only a
// machine Account's cancel is scoped at all, and GET /api/v1/jobs/{id}
// already answers "does this Job exist" for any authenticated caller, so
// neither answer discloses anything new.
//
// A refusal from the role floor is recorded through refuseControl with the
// Principal and the reason, and deliberately without the Job ID: the
// refusal precedes any existence check, so the id is caller-authored text,
// and the trail's job_id column is otherwise always a Relay-minted id that
// surfaces build links from. A refusal from the machine-scoping check is
// recorded through refuseCancel instead, and carries the Job ID ONLY when
// authorizeMachineCancel's lookup actually found jobID — an unknown id, a
// query error, or no job query wired all leave it empty, exactly like the
// role-floor case, because none of those confirm the id names a real Job
// (see authorizeMachineCancel).
//
// p is recorded via AuditSink.RecordCancel (v0.0.6 [5/8], owner DECISION 2):
// cancellation is durably recorded on each affected Task via
// OutcomeCancelled regardless of who asked (ADR-0013), but the audit trail
// must still answer "who asked for the stop", so this call ADDS a
// principal-attributed audit row on top of that per-Task record. Mirroring
// EngageFreeze/ReleaseFreeze: the cancel itself is attempted first, and the
// audit write is skipped if it errors — there is nothing true to record
// (e.g. jobs.ErrJobNotFound: no Task was ever touched).
//
// CancelTask (mcptask.go) calls this and inherits the gate for a Task that
// already has a Job. A still-parked task handle — one CreateTaskHandle
// created but no dispatch has claimed yet — is cancelled without ever
// reaching CancelJob, so that path stays owner-scoped and ungated; only a
// Job-backed cancel is gated here.
func (s *Service) CancelJob(ctx context.Context, p Principal, jobID string) error {
	if err := s.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlCancelJob); err != nil {
		return s.refuseControl(ctx, p, err)
	}
	if !p.Human() {
		auditJobID, err := s.authorizeMachineCancel(ctx, jobID, p.AccountID)
		if err != nil {
			return s.refuseCancel(ctx, p, auditJobID, err)
		}
	}
	if err := s.disp.cancel(ctx, jobID); err != nil {
		return err
	}
	// Published after the cancel succeeded, and never in a way that changes
	// the returned error (#416, JobEventSink) — observational only, exactly
	// like the MetricsSink calls elsewhere in this file. Nil-checked because
	// this package's own white-box tests construct &Service{} literals
	// directly, bypassing New's noopJobEventSink default.
	if s.jobEvents != nil {
		s.jobEvents.RecordJob(JobEvent{Transition: JobCancelled, JobID: jobID, Principal: p})
	}
	return s.audit.RecordCancel(ctx, p, jobID)
}

// authorizeMachineCancel decides CancelJob's machine-Account scope (owner
// decision 2026-09-17, execution.md §Cancellation, #614): may accountID
// cancel jobID? It queries s.jobQ directly rather than through
// Service.QueryJobs — this is an authorization decision, not a
// caller-invoked read, so it must not append its own entry to the read-lane
// trail (recordQueryRead); CancelJob's own refuseCancel/RecordCancel is what
// gets recorded for it.
//
// It returns (auditJobID, err): err is nil on success, and on refusal is
// always ErrJobNotRequestedByCaller — the caller-visible answer must not
// distinguish "no requester recorded" from "requested by somebody else" (see
// ErrJobNotRequestedByCaller's doc comment). auditJobID is the STORE's own
// echo of the Job it resolved (page.Jobs[0].JobID, never the caller-supplied
// jobID argument) when the lookup actually found that exact Job — whether or
// not its requester matched — and empty otherwise: jobID empty or failing
// validateJobID (refused before any query, see below), s.jobQ unwired, the
// query itself failing, no row returned, or a returned row whose OWN JobID
// does not echo what was asked for. Only CancelJob's refuseCancel reads
// auditJobID, and only to decide what — if anything — lands in the trail's
// job_id column: never caller-supplied text the Relay never validated, and
// never a different Job's id the store happened to return.
//
// jobID is rejected BEFORE it ever reaches s.jobQ if it is empty or fails
// validateJobID. Both matter for different reasons: JobFilter's zero value
// (empty JobID) matches EVERY Job, not none (JobQuery's own contract) — so
// an empty jobID would query "the newest Job" rather than "no Job", and
// authorize a cancel of some job the caller never named, as long as ITS
// requester happened to be the caller. validateJobID's length bound exists
// independently so the slog line below can never be handed an unbounded
// caller string.
//
// Fail CLOSED, and identically from the CALLER's perspective, in every case
// above: only auditJobID (an internal, unexported detail) tells them apart.
// Never infer ownership from anything short of an exact match, and never
// trust a query result for a Job other than the one that was asked about —
// requiring page.Jobs[0].JobID == jobID before any ownership comparison is
// what closes that off even if a JobQuery implementation (or a test spy)
// ever returned the wrong row for an exact-JobID filter.
func (s *Service) authorizeMachineCancel(ctx context.Context, jobID, accountID string) (auditJobID string, err error) {
	if jobID == "" || validateJobID(jobID) != nil {
		return "", ErrJobNotRequestedByCaller
	}
	if s.jobQ == nil {
		return "", ErrJobNotRequestedByCaller
	}
	page, queryErr := s.jobQ.QueryJobs(ctx, JobFilter{JobID: jobID}, PageRequest{Limit: 1})
	if queryErr != nil {
		// Logged here, not folded into the caller-facing reason: the query
		// failure is operational detail (a store blip, a malformed filter)
		// that must not change what a refused caller is told, and must not
		// require a caller to be trusted with it to diagnose the Relay.
		slog.ErrorContext(ctx, "capability: cancel: job-requester lookup failed",
			"job_id", jobID, "account_id", accountID, "error", queryErr)
		return "", ErrJobNotRequestedByCaller
	}
	if len(page.Jobs) != 1 || page.Jobs[0].JobID != jobID {
		return "", ErrJobNotRequestedByCaller
	}
	// The lookup resolved jobID to that exact Job — record ITS id (the
	// store's own echo, not the caller's argument) on a refusal from here on,
	// regardless of whether the requester below turns out to match.
	auditJobID = page.Jobs[0].JobID
	requester := page.Jobs[0].RequesterAccountID
	if requester == "" || requester != accountID {
		return auditJobID, ErrJobNotRequestedByCaller
	}
	return auditJobID, nil
}

// refuseCancel audits a CancelJob refusal from authorizeMachineCancel. It is
// refuseControl's sibling for the one refusal CancelJob can attribute to a
// real Job: jobID is authorizeMachineCancel's auditJobID, empty unless its
// lookup actually resolved the caller-supplied id to a Job that exists — see
// authorizeMachineCancel's doc comment for why an unresolved id is never
// recorded here either, exactly like refuseControl's role-floor refusal.
func (s *Service) refuseCancel(ctx context.Context, p Principal, jobID string, refusalErr error) error {
	s.metrics.IncRefusal(RefusalUnauthorized)
	entry := AuditEntry{Kind: AuditKindRefusal, Principal: p, JobID: jobID, Reason: refusalErr.Error(), Asserted: AssertionsFromContext(ctx)}
	var auditErr error
	if err := s.audit.Record(ctx, entry); err != nil {
		auditErr = fmt.Errorf("capability: record audit entry: %w", err)
	}
	return errors.Join(refusalErr, auditErr)
}
