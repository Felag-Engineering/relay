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
// registry and jobs only — no database/sql, no audit, no gleipnirv1 proto —
// preserving the store-swap and contract boundaries the rest of the Relay
// relies on.
package capability

import (
	"context"
	"errors"
	"fmt"

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
		reg:    reg,
		authz:  allowAllAuthorizer{},
		cap:    noopCapChecker{},
		disp:   noopDispatcher{},
		audit:  noopAuditSink{},
		freeze: noopFreezeStore{},
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
		return nil, s.recordRefusal(ctx, p, sel, act, fmt.Errorf("capability: read freeze state: %w", err))
	}
	if frozen {
		return nil, s.recordRefusal(ctx, p, sel, act, &FrozenError{})
	}

	nodes := sel.Resolve(s.reg)

	if err := s.authz.Authorize(ctx, p, act, sel); err != nil {
		return nil, s.recordRefusal(ctx, p, sel, act, err)
	}

	if err := s.cap.Check(act.RiskClass, len(nodes)); err != nil {
		return nil, s.recordRefusal(ctx, p, sel, act, err)
	}

	d := newDispatch(p, sel, nodes, act)
	res, dispatchErr := s.disp.run(ctx, d)

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
	entry := AuditEntry{Kind: AuditKindDispatch, Principal: p, Selector: sel, Action: act, JobID: res.jobID, Results: res.results}
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
// Results, only the refusal's Reason. It returns refusalErr, joined with a
// wrapped audit-write error if the audit write itself failed, so a failed
// audit write is never silently swallowed.
func (s *Service) recordRefusal(ctx context.Context, p Principal, sel Selector, act jobs.Action, refusalErr error) error {
	entry := AuditEntry{Kind: AuditKindRefusal, Principal: p, Selector: sel, Action: act, Reason: refusalErr.Error()}
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
	return s.audit.RecordFreeze(ctx, FreezeEvent{Principal: p, Engage: true})
}

// ReleaseFreeze clears the Relay-wide Freeze (ADR-0013), attributed to p
// with reason recorded for why: persisted first, then recorded via
// AuditSink.RecordFreeze, mirroring EngageFreeze.
func (s *Service) ReleaseFreeze(ctx context.Context, p Principal, reason string) error {
	if err := s.freeze.Release(ctx, p.Attribution(), reason); err != nil {
		return fmt.Errorf("capability: release freeze: %w", err)
	}
	return s.audit.RecordFreeze(ctx, FreezeEvent{Principal: p, Engage: false, Reason: reason})
}

// CancelJob stops jobID's Tasks (#101, ADR-0013): undispatched Tasks are
// marked cancelled without ever being sent, in-flight Tasks are asked to
// cancel over their Tunnels, and already-resolved Tasks keep their truthful
// outcome. It delegates to the sealed dispatcher (see dispatch.go) so
// tasksRepo/Conduit stay inside the engine, mirroring how Run delegates to
// s.disp.run. Principal/audit attribution for the cancel action itself is
// intentionally deferred to the surface milestone that calls this (v0.0.6):
// audit.Kind has no cancel value yet, and the cancellation is durably
// recorded in the tasks table (OutcomeCancelled) either way.
func (s *Service) CancelJob(ctx context.Context, jobID string) error {
	return s.disp.cancel(ctx, jobID)
}
