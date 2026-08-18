package main

// control_surfaces.go defines the ControlSurface self-registration seam
// (#162): each control surface (MCP, the Control API) knows how to mount its
// own routes onto the shared, already-auth-wrapped mux, so newServer holds a
// list of surfaces instead of two inline mount stanzas. This must live in
// package main rather than beside mcp/api themselves: mcp/no_dispatch_test.go
// requires every non-test file in the mcp package to be classified as
// read-only or exec-strict, and api/api_imports_test.go forbids the api
// package from importing mcp — package main is the only seam both surfaces
// can be mounted from without tripping either guard.
//
// surfaceDeps is assembled exactly once per newServer call (invariant 10:
// capSvc is a single instance, delivered to every surface here — no surface
// constructs its own capability.Service or dispatcher). Mount takes
// *http.ServeMux (from controlplane.Server.Mux()), never *controlplane.Server:
// a surface can reach the routes it registers but never the listener, TLS
// config, or the Authenticator that wraps the mux.

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/api"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/metrics"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/revocation"
)

// surfaceDeps holds every collaborator a control surface's Mount may need.
// It is assembled once in newServer's ControlEnabled block and handed to
// every surface in defaultControlSurfaces() — most fields are unused by any
// single surface (e.g. apiSurface never touches ops), which is expected: the
// struct is a shared dependency bag, not a per-surface signature.
type surfaceDeps struct {
	registry     registry.Repository
	policy       *policyview.Cache
	vocab        *nodevocab.Cache
	ops          mcp.OperationLister
	capability   *capability.Service // one instance: mcp.Executor AND api.Freezer
	jobs         jobs.JobRepository
	tasks        jobs.TaskRepository
	tokens       *enroll.Service
	accountsRepo accounts.Repository
	apiTokens    *accounts.TokenService
	revocation   *revocation.Service
	audit        audit.Repository
	auditSink    *auditsink.Sink
	now          func() time.Time
	metrics      *metrics.Metrics
}

// controlSurface is a self-mounting control-plane surface: it knows how to
// register its own routes onto mux using d, and nothing else.
type controlSurface interface {
	Mount(mux *http.ServeMux, d surfaceDeps)
}

// mcpSurface mounts the MCP server (#117's read tools, #118's execution
// tools) at "/mcp" — reached only through the Authenticator.Middleware that
// already wraps mux (invariant 10: one control path).
type mcpSurface struct{}

func (mcpSurface) Mount(mux *http.ServeMux, d surfaceDeps) {
	// The last argument is the MCP Tasks resolver (#374, ADR-0028) — the SAME
	// *capability.Service once more. Resolving a task handle reads an approval
	// Request and may cancel a Job, so it goes through the one capability layer
	// like everything else (invariant 10) rather than reaching a store.
	mux.Handle("/mcp", mcp.New(d.registry, d.policy, d.vocab, d.ops, d.capability,
		jobResultReader{jobsRepo: d.jobs, tasksRepo: d.tasks},
		readAuditor{sink: d.auditSink}, d.capability,
		// The in-band approval rung (#391, ADR-0029): the SAME
		// *capability.Service the API's decision endpoint uses. One decision
		// model, two delivery envelopes — a decision made through the tool is
		// the same act, recorded by the same code, differing only in the
		// channel it is stamped with and the fact that its approver is
		// asserted rather than verified.
		//
		// Passing it here is what makes rules configured `channel: "in-band"`
		// reachable at all. A deployment that wants the previous posture
		// changes nothing in code: leave its gate rules `out-of-band` and
		// ErrWeakChannel refuses every tool-delivered answer.
		mcp.WithApprovalDecider(d.capability)))
}

// apiSurface mounts the /api/v1 Control API slice (#116) onto the same mux —
// no new listener, no new auth (invariant 10). It never touches Relay Config
// or a blast cap (invariant 11).
type apiSurface struct{}

func (apiSurface) Mount(mux *http.ServeMux, d surfaceDeps) {
	api.Register(mux, api.Deps{
		Tokens:       d.tokens,
		TokenRevoker: d.revocation,
		Nodes:        d.revocation,
		Freeze:       d.capability,
		Audit:        d.audit,
		Accounts:     d.accountsRepo,
		APITokens:    d.apiTokens,
		Now:          d.now,
		// Execution (#356): the SAME *capability.Service instance the MCP
		// surface dispatches through — one capability layer, two thin surfaces
		// (invariant 10), so Freeze/authz/blast-cap/audit and at-most-once carry
		// over identically rather than being re-proven per surface.
		Exec: d.capability,
		Jobs: jobResultReader{jobsRepo: d.jobs, tasksRepo: d.tasks},
		// The out-of-band approval decision channel (#270, ADR-0027) — the same
		// *capability.Service again. The decision is the same act however it
		// arrives, so the API endpoint, the MCP elicitation envelope, and the
		// Console's approval queue all reach it through this one object.
		Approvals: d.capability,
		// Batch/window approval grants (#378, ADR-0027 decision 12) — the same
		// object once more. Requesting a grant creates an ordinary approval
		// Request answered through the decision route above, so the two share
		// one quorum implementation rather than each carrying its own.
		ApprovalGrants: d.capability,
		// Read auditing for the Job read route (#357, ADR-0025). *auditsink.Sink
		// satisfies api.ReadAuditor directly — no adapter needed here, unlike
		// mcp's readAuditor below, because package api may name capability
		// types on its own routes.
		//
		// Assigned only when non-nil: putting a nil *Sink into the interface
		// would make api's `Reads == nil` check false (a typed nil is a non-nil
		// interface) and turn every audited read into a nil-receiver panic
		// instead of the documented skip.
		Reads: readAuditorOrNil(d.auditSink),
	})
}

// metricsSurface mounts the Prometheus text /metrics endpoint (#182) onto the
// same mux — no new listener, no new auth (invariant 10). It is
// observability-only, reached solely through the Authenticator.Middleware
// wrapping mux: it never calls capability.Service.Run and has no execution
// capability whatsoever (invariant 10, ADR-0009/0010).
type metricsSurface struct{}

func (metricsSurface) Mount(mux *http.ServeMux, d surfaceDeps) {
	mux.Handle("GET /metrics", d.metrics.Handler())
}

// defaultControlSurfaces returns every control surface newServer mounts when
// Config.ControlEnabled. An explicit slice (not init()-registration): adding
// a surface is an obvious, greppable one-line edit here, with no global
// mutable registration state.
func defaultControlSurfaces() []controlSurface {
	return []controlSurface{mcpSurface{}, apiSurface{}, metricsSurface{}}
}

// readAuditor adapts the audit sink to mcp.ReadAuditor (#288, ADR-0025).
//
// It lives here, in the composition root, for the same reason every other
// surface adapter does: the mcp package must not name a capability type on its
// read path (no_dispatch_test.go), so resolving the acting Account from the
// request context happens on this side of the seam.
//
// Fail closed on a missing Principal. Every /mcp request passes through
// Authenticator.Middleware, so an absent Principal is unreachable in
// production — but "record an unattributed read" is not an acceptable
// fallback for an access trail, and a silent one would be worse.
type readAuditor struct{ sink *auditsink.Sink }

func (a readAuditor) RecordRead(ctx context.Context, e mcp.ReadEvent) error {
	if a.sink == nil {
		return nil
	}
	p, ok := controlplane.PrincipalFromContext(ctx)
	if !ok {
		return errors.New("read audit: no authenticated principal in context; refusing to record an unattributed read")
	}
	return a.sink.RecordRead(ctx, p, e.Tool, e.Selector, e.NodeID, e.JobID)
}

// readAuditorOrNil returns s as an api.ReadAuditor, or an untyped nil when s
// is nil.
//
// Go's typed-nil trap in one place: assigning a nil *auditsink.Sink straight
// into an interface field yields a NON-nil interface holding a nil pointer, so
// the consumer's `== nil` guard passes it through and the first method call
// panics on the nil receiver. Returning an untyped nil keeps the guard honest.
func readAuditorOrNil(s *auditsink.Sink) api.ReadAuditor {
	if s == nil {
		return nil
	}
	return s
}
