package main

// control_surfaces.go defines the ControlSurface self-registration seam:
// each control surface (MCP, the Control API) knows how to mount its
// own routes onto the shared, already-auth-wrapped mux, so newServer holds a
// list of surfaces instead of two inline mount stanzas. This must live in
// package main rather than beside mcp/api themselves: mcp/no_dispatch_test.go
// holds every non-test file in the mcp package to a strict capability
// allowlist unless it is listed as an execution file, and .golangci.yml's
// api-imports rule forbids the api package from importing mcp — package main
// is the only seam both surfaces can be mounted from without tripping either
// guard.
//
// surfaceDeps is assembled exactly once per newServer call (invariant 10:
// the capability services are single instances, delivered to every surface
// here — no surface constructs its own capability service or dispatcher). Mount takes
// *http.ServeMux (from controlplane.Server.Mux()), never *controlplane.Server:
// a surface can reach the routes it registers but never the listener, TLS
// config, or the Authenticator that wraps the mux.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/ca"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/api"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/console"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/relay/relay/internal/enroll"
	"github.com/Felag-Engineering/relay/relay/internal/events"
	"github.com/Felag-Engineering/relay/relay/internal/eventsink"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/metrics"
	"github.com/Felag-Engineering/relay/relay/internal/revocation"
)

// surfaceDeps holds every collaborator a control surface's Mount may need.
// It is assembled once in newServer's ControlEnabled block and handed to
// every surface in defaultControlSurfaces() — most fields are unused by any
// single surface (e.g. apiSurface never touches ops), which is expected: the
// struct is a shared dependency bag, not a per-surface signature.
//
// No surface is handed the registry or a display-only cache directly: every registry, Policy-view and Template-vocabulary read goes
// through d.readLane, the capability read lane, which records the read
// before it answers and fails closed (invariant 10, QRY-28). The registry,
// the Policy-view cache and the Template-vocabulary cache are wired only
// into d.readLane itself (main.go) and into the Tunnel handler, which
// remains their only writer.
//
// Each capability service is handed to a surface as the narrow type that
// surface uses, never as one value that carries every method: the Freeze
// (d.freezeControl), Account administration (d.accountAdmin) and the read lane
// (d.readLane) are separate services over one Recorder, so an adapter seam
// cannot reach a method it was not given.
type surfaceDeps struct {
	logger *slog.Logger // the process logger (main.go); nil means slog.Default()
	ops    mcp.OperationLister
	// execution is Execution: mcp Executor and TaskResolver; api Exec; console
	// Cancel.
	execution *capability.Execution
	// approvals is the approval callout: mcp ApprovalDecider; api Approvals and
	// ApprovalGrants; console Approvals and Decide.
	approvals *capability.Approvals
	// freezeControl is the Freeze and its role floor (api.Freezer).
	freezeControl *capability.Control
	// readLane backs the MCP read tools (through mcpReadLane), api.NodeReader
	// and console.Queries.
	readLane *capability.ReadLane
	// accountAdmin backs api.AccountAdmin, console.Accounts and
	// console.AccountAdmin.
	accountAdmin     *capability.AccountAdmin
	jobs             jobs.JobRepository
	tasks            jobs.TaskRepository
	enrollmentMinter *enroll.Minter
	revocation       *revocation.Service
	audit            audit.Repository
	auditSink        *auditsink.Sink
	// roleGate is the ONE authz.RoleGate the process holds — the same object
	// the capability layer authorizes dispatches and Freeze with. The Control
	// API needs it directly for the administrative routes that never reach the
	// capability layer at all (enrollment-token mint/revoke, Node revoke),
	// so that their floor is read from the same table rather than a
	// second one kept per surface (invariant 10).
	roleGate *authz.RoleGate
	now      func() time.Time
	metrics  *metrics.Metrics

	// consoleAuth is the Console's sign-in service. Nil when the
	// Console is not enabled, in which case consoleSurface is not in the
	// surface list at all — the routes are unmounted, not disabled.
	consoleAuth *consoleauth.Service

	// freeze is the read half of the Relay-wide Freeze, for the Console's
	// control-plane banner. Deliberately the store's repository rather than the
	// capability layer: this seam must not carry Engage or Release.
	freeze console.FreezeReader

	// events is the event seam. consoleSurface mounts the Console's
	// one live-read route over it, narrowed to console.EventReader — which
	// has no Publish method on it at all. mcpSurface wires the SAME bus
	// into the MCP server's tool-call observer below, on the writing side.
	events *events.Bus

	// trust is the CA and control-plane server-certificate fingerprints for
	// day one (spec 10): two strings, so the Console never holds a CA.
	// Nil leaves that block on the screen saying it is not wired.
	trust console.TrustReader

	// certExpiringWithin is the state:cert-expiring warning window
	// (ADR-0034), computed once in newServer from ca.LeafValidity and handed
	// to every surface below — MCP, the Control API, and the Console all
	// resolve `state:` against the SAME window (invariant 11).
	certExpiringWithin time.Duration

	// testMCPOptions are appended AFTER the production mcp.New options below,
	// so a test can construct the real MCP surface with an option the
	// composition root does not itself pass. See serverHooks, below: this
	// field is populated only through newServerWithHooks (main.go), and only
	// a test ever supplies it a non-empty serverHooks.
	testMCPOptions []mcp.Option
}

// serverHooks are seams into newServer that ONLY tests populate. The zero
// value is production: the production entry point reaches
// newServerWithHooks only through newServer, which passes an empty
// serverHooks. Never a Config field, env var or flag — invariant 11
// keeps what bounds acceptance operator-set on the host.
// TestControlSurfaces_TestOnlyMCPOptionHookIsEmptyInProduction and
// TestControlSurfaces_TestOnlyRevokedDialClockIsNilInProduction pin that.
type serverHooks struct {
	// testMCPOptions are appended AFTER the production mcp.New options of
	// mcpSurface, so a test can construct the real MCP surface with an
	// option the composition root does not itself pass.
	testMCPOptions []mcp.Option

	// testRevokedDialClock replaces the revoked-dial recorder's clock so a
	// test can cross the hourly throttle window. Nil in production: the real
	// clock.
	testRevokedDialClock func() time.Time
}

// controlSurface is a self-mounting control-plane surface: it knows how to
// register its own routes onto mux using d, and nothing else.
type controlSurface interface {
	Mount(mux *http.ServeMux, d surfaceDeps)
}

// mcpSurface mounts the MCP server (its read and execution tools) at "/mcp" — reached only through the Authenticator.Middleware that
// already wraps mux (invariant 10: one control path).
type mcpSurface struct{}

func (mcpSurface) Mount(mux *http.ServeMux, d surfaceDeps) {
	// The last argument is the MCP Tasks resolver (ADR-0028) — the SAME
	// *capability.Execution once more. Resolving a task handle reads an approval
	// Request and may cancel a Job, so it goes through the one capability layer
	// like everything else (invariant 10) rather than reaching a store.
	//
	// There is no certificate-expiry window option: the MCP read tools
	// resolve and evaluate nothing — state: Labels arrive already evaluated
	// on the lane's StateEval, which d.readLane resolves against the same
	// root-owned window every other surface uses (invariant 11).
	// opts holds exactly the three production options, in this order, with
	// d.testMCPOptions appended after them — test-only
	// (serverHooks), empty in production. mcp.New applies options in order,
	// so a later option setting the same field wins: a test option can
	// override a production one (e.g. to observe or replace
	// WithToolCallObserver), but the production list itself is unchanged.
	opts := []mcp.Option{
		// The in-band approval rung (ADR-0029): the SAME
		// *capability.Approvals the API's decision endpoint uses. One decision
		// model, two delivery envelopes — a decision made through the tool is
		// the same act, recorded by the same code, differing only in the
		// channel it is stamped with and the fact that its approver is
		// asserted rather than verified.
		//
		// Passing it here is what makes rules configured `channel: "in-band"`
		// reachable at all. A deployment that wants the previous posture
		// changes nothing in code: leave its gate rules `out-of-band` and
		// ErrWeakChannel refuses every tool-delivered answer.
		mcp.WithApprovalDecider(d.approvals),
		// The MRTR envelope over the same decision seam (ADR-0029
		// decision 6; ADR-0028 as amended 2026-09-24): an askable in-band
		// park from a client that can be asked is answered with an approval
		// question instead of today's pending_approval result; a client
		// that cannot be asked still gets pending_approval (AP-70).
		// Effective only alongside WithApprovalDecider, above. No Config
		// field, flag or env var controls it — the seal key mcp.New mints
		// for it comes from crypto/rand inside the call, never from
		// configuration (invariant 11).
		mcp.WithApprovalElicitation(),
		// The tool-call event publisher (D9) — every tools/call
		// invocation, read and execution alike, feeds the Console's live
		// view via toolCallObserver below.
		mcp.WithToolCallObserver(toolCallObserver{bus: d.events}),
		mcp.WithLogger(d.logger),
	}
	opts = append(opts, d.testMCPOptions...)

	mux.Handle("/mcp", mcp.New(mcpReadLane{svc: d.readLane}, d.ops, d.execution,
		jobResultReader{jobsRepo: d.jobs, tasksRepo: d.tasks},
		readAuditor{sink: d.auditSink}, d.execution, opts...))
}

// apiSurface mounts the /api/v1 Control API slice onto the same mux —
// no new listener, no new auth (invariant 10). It never touches Relay Config
// or a blast cap (invariant 11).
type apiSurface struct{}

func (apiSurface) Mount(mux *http.ServeMux, d surfaceDeps) {
	api.Register(mux, api.Deps{
		Tokens:       d.enrollmentMinter,
		Logger:       d.logger,
		TokenRevoker: d.revocation,
		Nodes:        d.revocation,
		Freeze:       d.freezeControl,
		Audit:        d.audit,
		// The role floor for mint/revoke. Same *authz.RoleGate the
		// capability layer holds — one ladder, consulted from both places,
		// never re-derived here.
		Authz: d.roleGate,
		// Account and API-Token administration — the SAME
		// *capability.AccountAdmin instance every other surface here holds: the
		// same floor, the same self-target/last-admin refusals, and the same
		// audit row as every other administrative act, rather than this
		// surface re-deriving any of them (invariant 10).
		AccountAdmin: d.accountAdmin,
		// The Node read route. The capability read lane — the
		// same *capability.ReadLane every other surface holds — records the
		// read before it answers and fails closed, rather than reading the
		// registry directly.
		NodeReader: d.readLane,
		Now:        d.now,
		// Execution: the SAME *capability.Execution instance the MCP
		// surface dispatches through — one capability layer, two thin surfaces
		// (invariant 10), so Freeze/authz/blast-cap/audit and at-most-once carry
		// over identically rather than being re-proven per surface.
		Exec: d.execution,
		Jobs: jobResultReader{jobsRepo: d.jobs, tasksRepo: d.tasks},
		// The out-of-band approval decision channel (ADR-0027) — the same
		// *capability.Approvals again. The decision is the same act however it
		// arrives, so the API endpoint, the MCP elicitation envelope, and the
		// Console's approval queue all reach it through this one object.
		Approvals: d.approvals,
		// Batch/window approval grants (ADR-0027 decision 12) — the same
		// object once more. Requesting a grant creates an ordinary approval
		// Request answered through the decision route above, so the two share
		// one quorum implementation rather than each carrying its own.
		ApprovalGrants: d.approvals,
		// Read auditing for the Job read route (ADR-0025). *auditsink.Sink
		// satisfies api.ReadAuditor directly — no adapter needed here, unlike
		// mcp's readAuditor below, because package api may name capability
		// types on its own routes.
		//
		// Assigned only when non-nil: putting a nil *Sink into the interface
		// would make api's `Reads == nil` check false (a typed nil is a non-nil
		// interface) and turn every audited read into a nil-receiver panic
		// instead of the documented skip.
		Reads: readAuditorOrNil(d.auditSink),
		// state:cert-expiring's warning window (ADR-0034) — the same
		// value every other surface resolves `state:` against.
		CertExpiringWithin: d.certExpiringWithin,
	})
}

// metricsSurface mounts the Prometheus text /metrics endpoint onto the
// same mux — no new listener, no new auth (invariant 10). It is
// observability-only, reached solely through the Authenticator.Middleware
// wrapping mux: it never calls capability.Execution.Run and has no execution
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
		Auth:   d.consoleAuth,
		Logger: d.logger,
		// Execution is v0.7.0 (spec 05). Until it lands there is
		// no execution route for console_execution to gate, and shipping the
		// flag ahead of the surface would be a knob that turns nothing off.
		Execution: false,
		// Every registry and Policy-view read is Deps.Queries (QRY-28) —
		// there is no separate Fleet/Policy seam. There is
		// also no separate Liveness seam: registry.Node.Connected is
		// itself derived from the same live-Tunnel set, so the fleet view
		// and a state:offline Selector read one fact instead of two.
		Audit:     d.audit,
		Approvals: d.approvals,
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
		// The read lane. d.readLane (*capability.ReadLane) already
		// implements console.QueryReader's six methods. Job detail
		// reads Jobs and Tasks through it and through nothing else,
		// which is why the Console is handed no Job repository of its own.
		Queries: d.readLane,
		// The Accounts screen's read seam. d.accountAdmin already
		// carries Accounts and APITokens, so no adapter is built for
		// it, and console.AccountReader declares none of the account lane's
		// five write verbs (CreateAccount, SetAccountRole, SetAccountEnabled,
		// MintAPIToken, RevokeAPIToken). The admin floor on both reads is the capability
		// layer's (authz.go), as is the decision that a successful read
		// records nothing — the latter an open question, in front of a human.
		Accounts: d.accountAdmin,
		// state:cert-expiring's warning window (ADR-0034) — the same
		// value every other surface resolves `state:` against.
		CertExpiringWithin: d.certExpiringWithin,
		// Cancel: one of the Console's two write seams. d.execution
		// already implements CancelJob — the same method the Control API and
		// MCP call — so no adapter is built for it; the role floor is
		// operator, the scope beyond it differs by Account kind (human: any
		// Job, machine: only a Job it requested), and both that and
		// the audit row live in the capability layer, not here. Execution
		// stays false, unchanged: Cancel cannot run anything, only ask
		// something already running to stop.
		Cancel: d.execution,
		// Decide: the Console's other write seam, and the same
		// *capability.Approvals the Control API's out-of-band decision
		// endpoint (POST /api/v1/approvals/{id}/decision) and MCP's
		// approve_request call — so quorum, audience, requester exclusion,
		// channel strength and the audit record stay one implementation.
		// Execution stays false, unchanged: this route composes nothing, it
		// answers a Plan the Relay already built (decide.go's header).
		// d.consoleAuth is already wired above as Auth, so step-up needs no
		// new wiring.
		Decide: d.approvals,
		// AccountAdmin: the Console's third write seam. d.accountAdmin
		// already carries all five verbs — CreateAccount,
		// SetAccountRole, SetAccountEnabled, MintAPIToken and RevokeAPIToken
		// — so no adapter is built for it. The admin floor on every one, the
		// self-target refusal, the last-enabled-admin refusal and all six
		// audit rows are the capability layer's. d.consoleAuth is already
		// wired above as Auth and d.accountAdmin as Accounts, so the per-action
		// step-up and the role route's current-role read need no new wiring
		// either. Execution stays false, unchanged: none of these five
		// composes or dispatches anything.
		AccountAdmin: d.accountAdmin,
	})
	mux.Handle("/console/", console.Secure(consoleMux, d.logger))
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

// mcpReadLane adapts *capability.ReadLane to mcp.ReadLane (QRY-28): the
// ONE audited seam the MCP read tools call for every registry, Policy-view
// and Template-vocabulary read.
//
// It lives here, beside readAuditor, for the same reason: the mcp package
// must not name a capability type on its read path (no_dispatch_test.go), so
// mcp.ReadLane is deliberately Principal-free and the Principal is resolved
// on THIS side of the seam. Every error passes through unwrapped, so
// errors.Is(err, capability.ErrNodeNotFound) still works at the tool
// boundary (tools_nodes.go, tools_operations.go).
type mcpReadLane struct{ svc *capability.ReadLane }

func (l mcpReadLane) principal(ctx context.Context) (capability.Principal, error) {
	p, ok := controlplane.PrincipalFromContext(ctx)
	if !ok {
		return capability.Principal{}, errors.New(
			"mcp read lane: no authenticated principal in context; refusing to serve an unattributed read")
	}
	return p, nil
}

func (l mcpReadLane) ListNodes(ctx context.Context, selector string) (mcp.NodeListing, error) {
	p, err := l.principal(ctx)
	if err != nil {
		return mcp.NodeListing{}, err
	}
	listing, err := l.svc.ListNodes(ctx, p, selector)
	if err != nil {
		return mcp.NodeListing{}, err
	}
	return mcp.NodeListing{Nodes: listing.Nodes, Eval: listing.Eval}, nil
}

func (l mcpReadLane) DescribeNode(ctx context.Context, nodeID string) (mcp.NodeDescription, error) {
	p, err := l.principal(ctx)
	if err != nil {
		return mcp.NodeDescription{}, err
	}
	detail, err := l.svc.DescribeNode(ctx, p, nodeID)
	if err != nil {
		return mcp.NodeDescription{}, err
	}
	return mcp.NodeDescription{
		Node:              detail.Node,
		Eval:              detail.Eval,
		Policy:            detail.Policy,
		PolicyReported:    detail.PolicyReported,
		Templates:         detail.Templates,
		TemplatesReported: detail.TemplatesReported,
	}, nil
}

func (l mcpReadLane) ListOperations(ctx context.Context, nodeID string) (mcp.NodeVocabulary, error) {
	p, err := l.principal(ctx)
	if err != nil {
		return mcp.NodeVocabulary{}, err
	}
	vocab, err := l.svc.ListOperations(ctx, p, nodeID)
	if err != nil {
		return mcp.NodeVocabulary{}, err
	}
	return mcp.NodeVocabulary{Templates: vocab.Templates, Reported: vocab.Reported}, nil
}

// readAuditor adapts the audit sink to mcp.ReadAuditor (ADR-0025).
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
	// mcp.ReadEvent carries no Selector/NodeID (list_nodes/describe_node/
	// list_operations are on the capability read lane, which records those
	// itself) — this seam only ever reads back a Job's
	// own Task rows, so the sink's selector/nodeID columns are always empty
	// here.
	return a.sink.RecordRead(ctx, p, e.Tool, "", "", e.JobID)
}

// toolCallObserver adapts the event bus to mcp.ToolCallObserver (D9).
//
// It lives here, beside readAuditor, for the same reason: the mcp package
// must not name a capability type on its read path (no_dispatch_test.go),
// so the Principal is resolved on THIS side of the seam.
//
// Unlike readAuditor, it does NOT fail closed on a missing Principal — it
// publishes with an empty Account and logs a warning instead. Dropping the
// event would hide a tool call from the trust surface entirely (spec 04),
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
