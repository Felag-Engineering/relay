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
	reg   registry.Repository
	authz Authorizer
	cap   CapChecker
	disp  dispatcher
	audit AuditSink
}

// Option configures a Service built by New.
type Option func(*Service)

// WithAuthorizer overrides the default allow-all Authorizer.
func WithAuthorizer(a Authorizer) Option {
	return func(s *Service) { s.authz = a }
}

// WithCapChecker overrides the default no-op CapChecker.
func WithCapChecker(c CapChecker) Option {
	return func(s *Service) { s.cap = c }
}

// WithAuditSink overrides the default no-op AuditSink.
func WithAuditSink(a AuditSink) Option {
	return func(s *Service) { s.audit = a }
}

// New returns a Service backed by reg, with allowAllAuthorizer,
// noopCapChecker, noopDispatcher, and noopAuditSink defaults (functional-
// option pattern, mirroring registry.NewInMemory). There is deliberately no
// exported WithDispatcher: dispatcher is unexported (see dispatch.go), so
// only files inside this package can supply a real one. #99 adds an
// exported WithExecution(...) option that constructs the in-package sealed
// Job-engine dispatcher from its own collaborators.
//
// Contract for that future option (and any exported option like it that
// enables real execution): these allow-all/no-op defaults are safe ONLY
// because v0.0.5 has no consumer surface and the default dispatcher is a
// no-op — nothing is actually authorized, capped, or audited. Once
// WithExecution (or any option wiring a real dispatcher) is added, it MUST
// require real Authorizer, CapChecker, and AuditSink — either by requiring
// them as its own parameters or by validating that WithAuthorizer,
// WithCapChecker, and WithAuditSink were also supplied — rather than
// silently riding these defaults. A real dispatcher paired with an
// allow-all Authorizer, a no-op CapChecker, or a no-op AuditSink is a
// fail-open: every Node would match, every Action would be permitted, and
// nothing would be recorded. See dispatcher's doc comment in dispatch.go.
func New(reg registry.Repository, opts ...Option) *Service {
	s := &Service{
		reg:   reg,
		authz: allowAllAuthorizer{},
		cap:   noopCapChecker{},
		disp:  noopDispatcher{},
		audit: noopAuditSink{},
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Run is the pipeline every surface must call to act on Nodes: resolve the
// Selector, authorize the Principal, check the blast-radius cap, dispatch,
// then audit — in that order. Authorize and the cap check short-circuit the
// remaining stages on error (no dispatch, no audit record — nothing
// happened yet). Once dispatch is attempted, though, the audit record is
// always written, even if the dispatcher itself returns an error: a
// dispatcher may execute some Nodes before failing on others, and a
// partially-executed dispatch must never go unaudited. In that case Run
// returns the dispatch error (joined with any audit-write error via
// errors.Join) alongside the partial results. Principal is threaded through
// to the AuditSink so every recorded entry attributes who asked, even
// before real authn exists.
func (s *Service) Run(ctx context.Context, p Principal, sel Selector, act jobs.Action) ([]NodeResult, error) {
	nodes := sel.Resolve(s.reg)

	if err := s.authz.Authorize(ctx, p, act, sel); err != nil {
		return nil, err
	}

	if err := s.cap.Check(act.RiskClass, len(nodes)); err != nil {
		return nil, err
	}

	d := newDispatch(p, sel, nodes, act)
	results, dispatchErr := s.disp.run(ctx, d)

	// The AuditSink is recorded unconditionally, even when the dispatcher
	// errors: dispatch.run may execute some Nodes before failing on others
	// (the #99 contract), and a partially-executed dispatch must never be
	// unaudited. results-so-far are recorded whether or not dispatchErr is
	// nil.
	entry := AuditEntry{Principal: p, Selector: sel, Action: act, Results: results}
	auditErr := s.audit.Record(ctx, entry)
	if auditErr != nil {
		// The dispatch itself already happened; a failed audit write must
		// not silently vanish, so it is surfaced as an error alongside the
		// (still valid) results rather than swallowed.
		auditErr = fmt.Errorf("capability: record audit entry: %w", auditErr)
	}

	if err := errors.Join(dispatchErr, auditErr); err != nil {
		return results, err
	}
	return results, nil
}
