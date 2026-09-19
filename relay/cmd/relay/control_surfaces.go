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
	"log/slog"
	"net/http"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/ca"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/api"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/console"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/events"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/eventsink"
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
	registry   registry.Repository
	policy     *policyview.Cache
	vocab      *nodevocab.Cache
	ops        mcp.OperationLister
	capability *capability.Service // one instance: mcp.Executor AND api.Freezer
	jobs       jobs.JobRepository
	tasks      jobs.TaskRepository
	tokens     *enroll.Service
	revocation *revocation.Service
	audit      audit.Repository
	auditSink  *auditsink.Sink
	// roleGate is the ONE authz.RoleGate the process holds — the same object
	// the capability layer authorizes dispatches and Freeze with. The Control
	// API needs it directly for the administrative routes that never reach the
	// capability layer at all (enrollment-token mint/revoke, Node revoke —
	// #397), so that their floor is read from the same table rather than a
	// second one kept per surface (invariant 10).
	roleGate *authz.RoleGate
	now      func() time.Time
	metrics  *metrics.Metrics

	// consoleAuth is the Console's sign-in service (#418). Nil when the
	// Console is not enabled, in which case consoleSurface is not in the
	// surface list at all — the routes are unmounted, not disabled.
	consoleAuth *consoleauth.Service

	// freeze is the read half of the Relay-wide Freeze, for the Console's
	// control-plane banner. Deliberately the store's repository rather than the
	// capability layer: this seam must not carry Engage or Release.
	freeze console.FreezeReader

	// events is the event seam (#416). consoleSurface mounts the Console's
	// one live-read route over it, narrowed to console.EventReader — which
	// has no Publish method on it at all. mcpSurface wires the SAME bus
	// into the MCP server's tool-call observer below, on the writing side.
	events *events.Bus

	// trust is the CA and control-plane server-certificate fingerprints for
	// day one (spec 10, #427): two strings, so the Console never holds a CA.
	// Nil leaves that block on the screen saying it is not wired.
	trust console.TrustReader

	// certExpiringWithin is the state:cert-expiring warning window (#414,
	// ADR-0034), computed once in newServer from ca.LeafValidity and handed
	// to every surface below — MCP, the Control API, and the Console all
	// resolve `state:` against the SAME window (invariant 11).
	certExpiringWithin time.Duration
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
		mcp.WithApprovalDecider(d.capability),
		// The tool-call event publisher (#416, D9) — every tools/call
		// invocation, read and execution alike, feeds the Console's live
		// view via toolCallObserver below.
		mcp.WithToolCallObserver(toolCallObserver{bus: d.events}),
		// state:cert-expiring's warning window (#414, ADR-0034) — the same
		// value every other surface resolves `state:` against.
		mcp.WithCertExpiringWindow(d.certExpiringWithin)))
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
		// The role floor for mint/revoke (#397). Same *authz.RoleGate the
		// capability layer holds — one ladder, consulted from both places,
		// never re-derived here.
		Authz: d.roleGate,
		// Account and API-Token administration (#653) — the SAME
		// *capability.Service instance every other surface here holds: the
		// same floor, the same self-target/last-admin refusals, and the same
		// audit row as every other administrative act, rather than this
		// surface re-deriving any of them (invariant 10).
		AccountAdmin: d.capability,
		// The Node read route (#440). The same registry every other surface
		// reads, narrowed to a single Get on the way in.
		NodeReader: d.registry,
		Now:        d.now,
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
		// state:cert-expiring's warning window (#414, ADR-0034) — the same
		// value every other surface resolves `state:` against.
		CertExpiringWithin: d.certExpiringWithin,
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

// consoleSurface mounts the Admin Console (ADR-0009) onto the same mux — no
// new listener, no new auth (invariant 10). The Console is internal-only and
// shares the control-plane listener's exposure posture, which is one of the
// stacked mitigations that made ADR-0026's execution surface acceptable.
//
// It mounts the route table inside console.Secure (the content security
// policy, the companion headers, CSRF on every unsafe method) and hands that
// to the shared mux, which controlplane.Server has already wrapped in
// Authenticator.Middleware. Secure sits INSIDE the authenticator on purpose:
// CSRF verification on an unauthenticated request is meaningless.
//
// A sub-mux rather than registering onto the shared one directly, because
// Secure must wrap the Console's routes and only those: net/http passes the
// full path through a nested mux, so the "/console/..." patterns still match.
type consoleSurface struct{}

func (consoleSurface) Mount(mux *http.ServeMux, d surfaceDeps) {
	consoleMux := http.NewServeMux()
	console.Register(consoleMux, console.Deps{
		Auth: d.consoleAuth,
		// Execution is v0.7.0 (spec 05, issue #438). Until it lands there is
		// no execution route for console_execution to gate, and shipping the
		// flag ahead of the surface would be a knob that turns nothing off.
		Execution: false,
		// The read seams. registry.Repository arrives as console.FleetReader,
		// which has no Upsert, no SetRelayLabels and no SetRevoked. That is
		// what makes "the Console cannot change the fleet" a fact about the
		// types rather than a promise about the handlers, and it is the
		// property console/no_dispatch_test.go's registry.Repository
		// assertion guard exists to keep from being undone by a type switch.
		//
		// There is no separate Liveness seam (#414): registry.Node.Connected
		// is itself derived from the same live-Tunnel set, so the fleet view
		// and a state:offline Selector now read one fact instead of two.
		Fleet:     d.registry,
		Policy:    d.policy,
		Audit:     d.audit,
		Approvals: d.capability,
		Freeze:    d.freeze,
		Now:       d.now,
		// The two fingerprints day one renders. Digests over public
		// certificate DER, computed at startup and at read time from
		// certificates this Relay's own CA minted — not configuration, and
		// no CA object crosses the seam (console/seams.go).
		Trust: d.trust,
		// The live-read seam. This is the SAME *events.Bus the MCP surface
		// publishes tool calls into above; the Console is handed it through
		// console.EventReader, which carries Subscribe, Recent and
		// RetentionWindow and no Publish method of any kind, so this surface
		// can watch the seam's history and can never author it.
		//
		// Through the helper, never `Events: d.events` — see
		// consoleEventsOrNil for Go's typed-nil trap and what it would cost
		// here.
		Events: consoleEventsOrNil(d.events),
		// The read lane (#441). d.capability (*capability.Service) already
		// implements console.QueryReader's eight methods (#450 added the
		// registry half; #539 added RecordEventSubscription). Job detail
		// (#423) reads Jobs and Tasks through it and through nothing else,
		// which is why the Console is handed no Job repository of its own.
		Queries: d.capability,
		// state:cert-expiring's warning window (#414, ADR-0034) — the same
		// value every other surface resolves `state:` against.
		CertExpiringWithin: d.certExpiringWithin,
		// Cancel (#595): one of the Console's two write seams. d.capability
		// already implements CancelJob — the same method the Control API and
		// MCP call — so no adapter is built for it; the role floor is
		// operator, the scope beyond it differs by Account kind (human: any
		// Job, machine: only a Job it requested — #614), and both that and
		// the audit row live in the capability layer, not here. Execution
		// stays false, unchanged: Cancel cannot run anything, only ask
		// something already running to stop.
		Cancel: d.capability,
		// Decide (#453): the Console's other write seam, and the same
		// *capability.Service the Control API's out-of-band decision
		// endpoint (POST /api/v1/approvals/{id}/decision) and MCP's
		// approve_request call — so quorum, audience, requester exclusion,
		// channel strength and the audit record stay one implementation.
		// Execution stays false, unchanged: this route composes nothing, it
		// answers a Plan the Relay already built (decide.go's header).
		// d.consoleAuth is already wired above as Auth, so step-up needs no
		// new wiring.
		Decide: d.capability,
	})
	mux.Handle("/console/", console.Secure(consoleMux))
}

// defaultControlSurfaces returns every control surface newServer mounts when
// Config.ControlEnabled. An explicit slice (not init()-registration): adding
// a surface is an obvious, greppable one-line edit here, with no global
// mutable registration state.
//
// The Console is appended by the caller only when it is enabled, so with it
// off there is no /console/ route on the listener at all — absent, not
// refusing.
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

// toolCallObserver adapts the event bus to mcp.ToolCallObserver (#416, D9).
//
// It lives here, beside readAuditor, for the same reason: the mcp package
// must not name a capability type on its read path (no_dispatch_test.go),
// so the Principal is resolved on THIS side of the seam.
//
// Unlike readAuditor, it does NOT fail closed on a missing Principal — it
// publishes with an empty Account and logs a warning instead. Dropping the
// event would hide a tool call from the trust surface entirely (spec 03),
// which is worse than rendering it unattributed; and /mcp is always behind
// Authenticator.Middleware, so the missing-Principal branch is unreachable
// in production.
//
// The warning below logs e.Tool, which is caller-supplied — safe only
// because ToolCallEvent.Tool is already capped at maxToolNameBytes by the
// publishing middleware (S3, review-feedback.md cycle 2) before it ever
// reaches this observer.
type toolCallObserver struct{ bus *events.Bus }

func (o toolCallObserver) ToolCall(ctx context.Context, e mcp.ToolCallEvent) {
	p, ok := controlplane.PrincipalFromContext(ctx)
	if !ok {
		slog.Warn("tool-call event published with no authenticated principal in context", "tool", e.Tool)
	}
	eventsink.ToolCall(o.bus, p.Account, p.AccountID, e)
}

// consoleEventsOrNil returns b as a console.EventReader, or an untyped nil when
// b is nil — the same typed-nil guard readAuditorOrNil exists for, below, and
// needed here for a sharper reason.
//
// Assigning a nil *events.Bus straight into the interface field yields a
// NON-nil interface holding a nil pointer, so console's `d.Events == nil`
// guards all pass: day one would call Recent on a nil Bus while rendering, and
// the SSE route would call Subscribe on one instead of answering its 503. Three
// written promises — Deps.Events' doc, the route's unavailable branch, and the
// test that covers it — would be false, and the failure would be a nil-pointer
// panic on the Console's first screen.
func consoleEventsOrNil(b *events.Bus) console.EventReader {
	if b == nil {
		return nil
	}
	return b
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

// consoleTrustReader adapts the CA and the control-plane server certificate to
// console.TrustReader.
//
// It lives in the composition root, like every other surface adapter in this
// file, and that placement is what keeps package console from importing
// internal/ca — so no screen can reach a CA, a private key, or the issuance
// path. Two strings cross the boundary and nothing else.
//
// caFingerprint is captured once at startup because the CA certificate does not
// change while the process runs. serverCert is held live because its leaf is
// re-issued about daily, and Fingerprint reads the published pointer without
// ever triggering a re-issuance (ca.ServerCertificate.Fingerprint).
type consoleTrustReader struct {
	caFingerprint string
	serverCert    *ca.ServerCertificate
}

func (r consoleTrustReader) CAFingerprint() string { return r.caFingerprint }

func (r consoleTrustReader) ServerFingerprint() string {
	if r.serverCert == nil {
		return ""
	}
	return r.serverCert.Fingerprint()
}
