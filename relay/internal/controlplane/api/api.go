// Package api is the REST/JSON Control API (ADR-0010): Enrollment Token
// mint/revoke, Node revoke, Freeze engage/release, Account and API-Token
// management, tag writes, and execution (run an Operation, Raw Exec, and
// plan mode), all mounted under /api/v1 on the control-plane's existing *http.ServeMux
// (relay/internal/controlplane.Server.Mux()) behind the single
// Authenticator.Middleware already wired there — no new listener, no new
// auth path (invariant 10, ADR-0009).
//
// Every handler is a thin adapter: decode -> validate -> call existing
// enroll/revocation/capability machinery -> render. No route reimplements
// domain logic, and no route can reach Relay configuration, a blast cap, the
// CA key, or a listener (invariant 11) — Deps below intentionally carries
// none of those, and this package's import list is structurally capped by
// .golangci.yml's api-imports rule.
//
// The execution routes hold to the same rule structurally, not just by
// convention: .golangci.yml's "adapter boundary" patterns fail any file here
// that names capability.Execution or capability.NewExecution, and
// no_dispatch_test.go any that names newDispatch, so the only path to a
// dispatch is the injected Executor interface (execution.go).
package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/enroll"
	"github.com/Felag-Engineering/relay/relay/internal/revocation"
)

// TokenMinter mints a scoped, expiring Enrollment Token together with its join
// string. *enroll.Minter satisfies this interface. The handler passes the result
// through and never assembles enrollment material (invariant 10).
type TokenMinter interface {
	Mint(ctx context.Context, scope []string, ttl time.Duration, limit enroll.UseLimit, opts ...enroll.Option) (enroll.Minted, error)
}

// TokenRevoker revokes an Enrollment Token by id. *revocation.Service
// satisfies this interface (RevokeToken cascade-revokes the token's already
// -enrolled Nodes too — see tokens.go).
//
// The cascade writes one KindNodeRevoke record per cascaded Node through the
// record callback this surface supplies — revocation.Service has no
// audit sink of its own, so tokens.go's handleRevokeToken builds the closure
// that authors each record's Principal and reason and hands it in. A
// returned ErrCascadeNotRecorded means the token and every Node it enrolled
// were revoked, but the trail is incomplete for one or more of them. A
// returned ErrCascadeIncomplete means the token was revoked but the registry
// could not be read completely, so Nodes it enrolled may still be trusted —
// never that every Node was revoked.
type TokenRevoker interface {
	RevokeToken(ctx context.Context, id string, record revocation.RevocationRecorder) error
}

// NodeRevoker revokes a single Node, tearing down its live Tunnel
// immediately. *revocation.Service satisfies this interface.
//
// The recorded variant is what serialises this route against a token
// cascade revoking the same Node: revocation.Service.RevokeNodeRecorded
// holds the Node's lock across recording and revoking, so this interface
// deliberately does not expose the unrecorded revocation.Service.RevokeNode
// primitive at all — the same narrowing rationale Freezer states for
// EngageFreezeLocal/ReleaseFreezeLocal. A returned error means the Node was
// NOT revoked; a nil error means it is revoked and attributed, either by
// this call's own record or by the cascade record this Relay already wrote
// for it.
type NodeRevoker interface {
	RevokeNodeRecorded(ctx context.Context, nodeID string, record revocation.RevocationRecorder) error
}

// Freezer engages and releases the Relay-wide Freeze (ADR-0013).
// *capability.Control satisfies this interface.
//
// Both methods are role-gated INSIDE the capability layer: engage
// needs a human `operator`+, release needs `admin` and a reason, and the
// refusal is audited there. This interface deliberately does not expose
// capability.Control's EngageFreezeLocal/ReleaseFreezeLocal — the host-signal
// lever is root-on-the-box authority (ADR-0013) and must not be reachable
// from an HTTP route, so the narrow interface is what keeps it out of reach.
type Freezer interface {
	EngageFreeze(ctx context.Context, p capability.Principal) error
	ReleaseFreeze(ctx context.Context, p capability.Principal, reason string) error
}

// Auditor appends a lifecycle audit.Record. audit.Repository satisfies this
// interface.
type Auditor interface {
	Append(ctx context.Context, r audit.Record) error

	// AppendAll persists every Record in rs atomically: on a nil error all of
	// them were written, on a non-nil error none were (audit.Repository's
	// contract). Used by the token-revocation cascade to record a chunk of
	// Nodes in one commit rather than one per Node.
	AppendAll(ctx context.Context, rs []audit.Record) error
}

// AccountAdmin is Account and API-Token administration: the identity
// routes' single collaborator, mirroring capability.AccountAdmin's own
// accountadmin.go methods exactly (each takes the acting Principal, since
// the role floor AND the self-targeting/last-admin refusals now live in the
// capability layer, not here) — so *capability.AccountAdmin satisfies this
// interface with no adapter, the same shape as Freezer/Executor/
// ApprovalService above.
//
// Every method here is authorized, and self-targeting/last-admin refused,
// inside the capability layer before this surface ever sees a result: a
// surface that gated role itself would be a second control path invariant
// 10 forbids.
type AccountAdmin interface {
	Accounts(ctx context.Context, p capability.Principal) ([]accounts.Account, error)
	Account(ctx context.Context, p capability.Principal, id string) (accounts.Account, error)
	CreateAccount(ctx context.Context, p capability.Principal, a accounts.Account) (accounts.Account, error)
	SetAccountRole(ctx context.Context, p capability.Principal, id string, role accounts.Role) error
	SetAccountEnabled(ctx context.Context, p capability.Principal, id string, enabled bool) error
	APITokens(ctx context.Context, p capability.Principal, accountID string) ([]accounts.APIToken, error)
	MintAPIToken(ctx context.Context, p capability.Principal, accountID, name string, ttl time.Duration) (accounts.APIToken, accounts.Plaintext, error)
	RevokeAPIToken(ctx context.Context, p capability.Principal, id string) error
}

// logger returns Deps.Logger, or slog.Default() when none was supplied.
func (d Deps) logger() *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return slog.Default()
}

// Deps are the collaborators Register wires into the /api/v1 route table.
// Deliberately narrow (invariant 11): no Relay Config, CA, blast cap, or
// listener field — every dependency here is a purpose-built interface over
// existing runtime-object machinery, never Relay configuration.
type Deps struct {
	Tokens       TokenMinter
	TokenRevoker TokenRevoker
	Nodes        NodeRevoker
	Freeze       Freezer
	Audit        Auditor
	// Logger is where this surface's operational errors go; nil means
	// slog.Default(). Wiring, not configuration (invariant 11); context
	// correlation comes from the handler the composition root builds.
	Logger *slog.Logger
	// Authz is the control plane's role ladder for the ADMINISTRATIVE acts
	// that never construct a jobs.Action and so never reach the capability
	// layer's dispatch pipeline: enrollment-token mint and revoke, and Node
	// revoke. The composition root passes the SAME *authz.RoleGate the
	// capability layer holds, so a floor is decided in one table for every
	// surface (invariant 10) — this package consults it and renders the
	// answer, it never decides one.
	//
	// Freeze is NOT gated here: it goes through Deps.Freeze into the
	// capability layer, which consults the same object itself. The split is
	// not a preference — capability's import allowlist bars internal/enroll
	// and internal/revocation, so mint and revoke have no capability-layer
	// method to be gated inside.
	//
	// Nil refuses every route that needs it with a 500 rather than proceeding
	// ungated: an unwired gate is a composition-root bug, and an ungated path
	// fails open silently.
	Authz capability.ControlAuthorizer
	// AccountAdmin backs the identity-management routes through the
	// capability layer. Nil refuses every identity route with a
	// 500, on the same unwired-gate posture Authz above documents.
	AccountAdmin AccountAdmin
	// Tags is the capability layer's tag write, behind both tag routes. Nil
	// answers them with a 500, on the same unwired-gate posture as AccountAdmin.
	Tags TagWriter
	// NodeReader is the capability read lane behind GET
	// /api/v1/nodes/{node_id}: it is not a registry narrowing
	// any more — it is the one door to the registry, which records the read
	// before it answers (invariant 10, ADR-0025). The revoke route reaches
	// revocation through Nodes above rather than through this seam. Nil
	// still 500s.
	NodeReader NodeReader
	// Exec and Jobs back the execution routes. Exec is the SAME
	// capability layer the MCP surface dispatches through — never a second
	// control path (invariant 10) — and Jobs is a read-only view used to render
	// per-Node results after a dispatch returns. Neither carries a blast cap or
	// any Relay configuration: the caps live inside the capability layer, above
	// this surface's reach (invariant 11).
	Exec Executor
	Jobs JobResultReader
	// Approvals backs the out-of-band decision channel (ADR-0027). It is
	// backed by *capability.Approvals, not the Service Exec uses: the approval
	// routes hold no path to Run, Start or CancelJob (invariant 10). Kept as a
	// separate interface so this package's seams stay named after what each
	// route needs.
	Approvals ApprovalService
	// ApprovalGrants backs the batch/window grant routes (ADR-0027
	// decision 12) — the same *capability.Approvals again, named separately for
	// the same reason Approvals is. Nil disables the routes with a 500 rather
	// than silently accepting requests that would grant nothing.
	ApprovalGrants ApprovalGrantService
	// Reads records read-access events for the Job read route (ADR-0025).
	// Nil skips recording, so tests and any unwired surface work; the
	// composition root always supplies it.
	Reads ReadAuditor
	// Now returns the current time, used to timestamp lifecycle audit
	// Records. Defaults to time.Now().UTC() when nil.
	Now func() time.Time
}

// Route is one /api/v1 route: its HTTP method, its path (in net/http
// ServeMux's `{name}` wildcard syntax), and the handler factory that binds it
// to a Deps.
//
// The route table is exported as DATA (see [Routes]) rather than being a list
// of mux.HandleFunc calls buried in Register, because the published OpenAPI
// spec has to be checkable against what the server actually serves. With the
// table as data, openapi_test.go compares the two mechanically and a route
// added, renamed, or removed without a matching spec edit fails CI — instead of
// the spec quietly becoming fiction, which is the normal fate of a hand-kept
// API document.
type Route struct {
	Method string
	Path   string
	// Handler builds the http.HandlerFunc for this route from d.
	Handler func(d Deps) http.HandlerFunc
}

// Pattern renders the route as a net/http ServeMux pattern ("GET /api/v1/...").
func (r Route) Pattern() string { return r.Method + " " + r.Path }

// Routes returns the complete /api/v1 route table, in registration order.
//
// This is the single source of truth for "what does the Control API serve".
// Register mounts exactly these; the OpenAPI drift gate reads exactly these.
func Routes() []Route {
	return []Route{
		// Enrollment Tokens, Node revocation, Freeze. Every route
		// here has a role floor, and every floor is decided by the ONE
		// authz.RoleGate: the enrollment and revocation routes consult
		// it through authorizeControl below, the Freeze routes inherit it
		// inside the capability layer. Which of the two applies to a given
		// route is asserted by TestEveryRouteIsRoleClassified, so a route
		// added to this group later cannot silently have neither.
		{"POST", "/api/v1/enrollment-tokens", handleMintToken},
		{"DELETE", "/api/v1/enrollment-tokens/{id}", handleRevokeToken},
		{"GET", "/api/v1/nodes/{node_id}", handleGetNode},
		{"POST", "/api/v1/nodes/{node_id}/revoke", handleRevokeNode},
		{"POST", "/api/v1/freeze/engage", handleFreezeEngage},
		{"POST", "/api/v1/freeze/release", handleFreezeRelease},

		// Tag writes (ADR-0050). The floor, a human Account at operator or
		// above, lives in the capability layer behind TagWriter; these handlers
		// decode and render and call no authorizeControl.
		{"POST", "/api/v1/nodes/{node_id}/tags", handleWriteNodeTag},
		{"POST", "/api/v1/tags", handleWriteTags},

		// Identity management (the floor lives in capability.Control
		// behind AuthorizeControl). Every route here is
		// admin-only in full. Deps carries no store for these routes at all —
		// only AccountAdmin, the capability seam — so this surface renders the
		// refusal and re-derives nothing (role_floor_test.go's
		// TestCapabilityFlooredRoutesDoNotReachASurfaceGate pins that as a
		// mechanical fact, not a comment).
		{"POST", "/api/v1/accounts", handleCreateAccount},
		{"GET", "/api/v1/accounts", handleListAccounts},
		{"GET", "/api/v1/accounts/{id}", handleGetAccount},
		{"POST", "/api/v1/accounts/{id}/role", handleSetAccountRole},
		{"POST", "/api/v1/accounts/{id}/enable", enableAccount(true)},
		{"POST", "/api/v1/accounts/{id}/disable", enableAccount(false)},
		{"POST", "/api/v1/accounts/{id}/tokens", handleMintAPIToken},
		{"GET", "/api/v1/accounts/{id}/tokens", handleListAPITokens},
		{"DELETE", "/api/v1/api-tokens/{token_id}", handleRevokeAPIToken},

		// Execution. Both routes dispatch through the shared capability
		// layer (Selector -> authz -> blast-cap -> dispatch -> audit); neither
		// re-implements a role check, a Policy decision, or a cap — see
		// execution.go's header for why Raw Exec's admin gate deliberately stays
		// in authz.RoleGate rather than being repeated here.
		{"POST", "/api/v1/operations", handleRunOperation},
		{"POST", "/api/v1/raw-exec", handleRawExec},

		// Job read + cancel. The read route is audited (ADR-0025): it
		// returns captured Task output, so it discloses material somebody else
		// produced. Cancel goes through the same capability layer as dispatch.
		{"GET", "/api/v1/jobs/{id}", handleGetJob},
		{"POST", "/api/v1/jobs/{id}/cancel", handleCancelJob},

		// The out-of-band approval decision channel (ADR-0027). This is
		// the universal envelope: it works for a harness with zero approval
		// features and for the API-control drive mode, which has no MCP session
		// at all — and it is the only channel that is a guarantee rather than a
		// delivery convenience, because a decision here rides a credential the
		// requesting session does not hold. See approvals.go.
		{"GET", "/api/v1/approvals", handleListApprovals},
		{"GET", "/api/v1/approvals/{id}", handleGetApproval},
		{"POST", "/api/v1/approvals/{id}/decision", handleDecideApproval},

		// Batch/window approvals (ADR-0027 decision 12). Note what is
		// NOT here: a route that approves a grant. Requesting one creates an
		// ordinary approval Request, answered through the decision route above
		// — so quorum, audience, requester exclusion, and channel strength are
		// the same code for a window as for a single dispatch, and cannot drift
		// apart. See approval_grants.go.
		{"POST", "/api/v1/approval-grants", handleCreateGrant},
		{"GET", "/api/v1/approval-grants", handleListGrants},
		{"GET", "/api/v1/approval-grants/{id}", handleGetGrant},
		{"POST", "/api/v1/approval-grants/{id}/revoke", handleRevokeGrant},
	}
}

// enableAccount adapts handleSetAccountEnabled's two-argument shape to the
// Route.Handler signature, so the enable/disable pair stays in the table
// alongside every other route rather than being a special case in Register.
//
// The go:noinline directive below is load-bearing, not a performance note:
// role_floor_test.go's handlerFuncName resolves a Route's handler back to a
// source-level function name via runtime.FuncForPC, and the Go compiler's
// inliner folds this function's returned closure into Routes() at the call
// site — which makes FuncForPC report the closure as belonging to Routes
// itself. Routes' own body references literally every handler in the table
// as a value, so a resolution of "Routes" makes the FORWARD guard
// (TestSurfaceGatedRoutesReachARoleCheck) trivially true for that route
// regardless of what its own handler actually does — a SILENT false pass —
// while the INVERSE guard (TestCapabilityFlooredRoutesDoNotReachASurfaceGate)
// fails, but spuriously: loud, yet for the wrong reason, not because the
// handler re-derives anything. handlerFuncName additionally fails the test
// outright if it ever sees this resolution, so a future closure-built route
// that forgets this directive cannot go silently vacuous either way. Keeping
// this un-inlined is what keeps handlerFuncName resolving "enableAccount"
// instead.
//
//go:noinline
func enableAccount(enabled bool) func(Deps) http.HandlerFunc {
	return func(d Deps) http.HandlerFunc { return handleSetAccountEnabled(d, enabled) }
}

// Register mounts the /api/v1 route table onto mux. mux is expected to be
// controlplane.Server.Mux() (or an equivalent already wrapped by
// Authenticator.Middleware in tests) — Register never constructs a listener
// or auth wrapper of its own.
func Register(mux *http.ServeMux, d Deps) {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	for _, r := range Routes() {
		mux.HandleFunc(r.Pattern(), r.Handler(d))
	}
}

// principal reads the Principal that Authenticator.Middleware injected into
// r's context. Every route registered by this package sits behind that
// Middleware (Register's contract), so ok is expected to always be true; the
// false path is a defensive 500, never a security decision made here.
func principal(w http.ResponseWriter, r *http.Request) (capability.Principal, bool) {
	p, ok := controlplane.PrincipalFromContext(r.Context())
	if !ok {
		writeProblem(w, http.StatusInternalServerError, "missing principal",
			"request reached the Control API without an authenticated principal")
		return capability.Principal{}, false
	}
	return p, true
}

// authorizeControl is the surface-side role gate for the
// administrative routes that never reach the capability layer's dispatch
// pipeline (enrollment-token mint/revoke, Node revoke).
//
// It DECIDES NOTHING. The floor lives in one table — authz.RoleGate's
// requiredControlRole — which the capability layer consults for the Freeze
// and the composition root hands to this package as Deps.Authz, so the same
// answer reaches MCP, the Control API, and the Console (invariant 10). This
// function's whole job is to ask, audit a refusal, and render it.
//
// A nil Authz refuses with 500. That is the deliberate direction: an ungated
// administrative route fails open and nothing says so, so an unwired gate
// must be loud and closed rather than quiet and open.
//
// The refusal is recorded as audit.KindRefusal with the acting Principal,
// matching how the capability layer records a refused dispatch — a refusal is
// the most interesting kind of audit event, and one that only appears for
// some refusal paths is worse than none.
func authorizeControl(w http.ResponseWriter, r *http.Request, d Deps, p capability.Principal, act capability.ControlAction) bool {
	if d.Authz == nil {
		writeProblem(w, http.StatusInternalServerError, "authorization unavailable",
			"no control-plane authorizer is wired; refusing rather than proceeding ungated")
		return false
	}
	if err := d.Authz.AuthorizeControl(r.Context(), p, act); err != nil {
		recordLifecycle(r.Context(), d, p, audit.KindRefusal, "", err.Error())
		writeProblem(w, http.StatusForbidden, "forbidden", err.Error())
		return false
	}
	return true
}

// newAuditID mints a unique audit.Record.ID. audit_id is the table's PRIMARY
// KEY (store/migrations/0001_init.sql); every recordLifecycle call must set a
// fresh one or the second lifecycle insert in a session fails a UNIQUE
// constraint. A package-level var (rather than a Deps field) so it stays out
// of the deliberately narrow Deps struct while still being overridable from
// this package's own tests.
//
// Its default is the same generator relay/internal/auditsink uses,
// audit.NewID — one implementation of the ordering property rather than two
// copies of a shape. The ids it mints are monotonic, so the trail's
// (ts, audit_id) tie-break orders rows by when they were appended.
//
// That is what recordLifecycleAllErr's AppendAll cascade needs: a
// mass-revocation writes its whole batch of Records at one clock reading, so
// every row in the batch shares a ts and their order IS the id order. That
// batch is exactly what an incident reviewer reads as a sequence.
//
// Used unwrapped: audit.NewID already says "audit: generate record id: ...",
// and a wrap here would announce one failure twice.
var newAuditID = audit.NewID

// recordLifecycle appends one lifecycle audit.Record (token mint/revoke, or
// a refusal of one — see authorizeControl) attributed to p. Freeze
// engage/release, and a refused Freeze, are audited intrinsically by
// capability.Control (RecordFreeze) and must never call this — doing so
// would double-audit (see freeze.go). reason must never carry an Enrollment
// Token plaintext.
//
// On an audit-write failure, this logs and returns without undoing the
// already-completed lifecycle action: the action happened; a failed audit
// write must not be papered over by rolling it back, nor may it block the
// caller from returning success for a mutation that already took effect.
//
// This is a BEST-EFFORT record, deliberately: every remaining caller has
// already completed its act by the time it calls this, and rolling that act
// back because the trail write failed would be worse than an incomplete
// trail. Node revoke does not call this — it needs a fail-closed record,
// so it goes through revocation.Service.RevokeNodeRecorded instead, the
// one place that ordering can be atomic against a concurrent cascade for the same Node.
func recordLifecycle(ctx context.Context, d Deps, p capability.Principal, kind, nodeID, reason string) {
	rec, err := newLifecycleRecord(ctx, d, p, kind, nodeID, reason)
	if err != nil {
		d.logger().ErrorContext(ctx, "control api: build lifecycle audit record", "kind", kind, "error", err)
		return
	}
	if err := d.Audit.Append(ctx, rec); err != nil {
		d.logger().ErrorContext(ctx, "control api: append lifecycle audit record", "kind", kind, "error", err)
	}
}

// newLifecycleRecord builds one lifecycle audit.Record attributed to p,
// carrying both the verified and asserted identity lanes and the derived
// reason — the same construction recordLifecycle uses for a single
// best-effort write and recordLifecycleAllErr uses for a cascaded chunk (and,
// through it, RevokeNodeRecorded's single-Node fail-closed write). Kept in
// one place so the attribution mapping cannot drift between the paths: a
// second copy is what a security review would flag, and it is how a lane
// gets dropped on one path only.
func newLifecycleRecord(ctx context.Context, d Deps, p capability.Principal, kind, nodeID, reason string) (audit.Record, error) {
	id, err := newAuditID()
	if err != nil {
		return audit.Record{}, fmt.Errorf("api: generate lifecycle audit record id: %w", err)
	}
	asserted := capability.AssertionsFromContext(ctx)
	return audit.Record{
		ID:        id,
		Timestamp: d.Now(),
		Kind:      kind,
		Principal: p.Attribution(),
		Attribution: audit.Attribution{
			Verified: audit.Verified{
				AccountID:   p.AccountID,
				AccountName: p.Account,
				Role:        p.Role,
				TokenID:     p.TokenID,
				Method:      string(p.AuthMethod),
			},
			Asserted: audit.Asserted{
				OnBehalfOf:  asserted.OnBehalfOf,
				Traceparent: asserted.Traceparent,
				SessionRef:  asserted.SessionRef,
				ChangeRef:   asserted.ChangeRef,
			},
		},
		NodeID: nodeID,
		Reason: reason,
	}, nil
}

// recordLifecycleAllErr is the recorder-side half of RevocationRecorder's
// all-or-nothing contract (revocation/service.go): it builds one lifecycle
// audit.Record per Node in nodeIDs, attributed identically to
// recordLifecycle, then writes all of them through a single
// Auditor.AppendAll call. handleRevokeNode's single-Node RevocationRecorder
// (nodes.go) calls this with a one-element nodeIDs, so the fail-closed
// single-Node write and the cascade's chunked write share this one
// construction rather than a second one.
//
// Every record is built with newLifecycleRecord before any write is
// attempted, so an ID-generation failure returns before any record for this
// chunk is persisted — keeping the all-or-nothing contract even on that path.
func recordLifecycleAllErr(ctx context.Context, d Deps, p capability.Principal, kind string, nodeIDs []string, reason string) error {
	recs := make([]audit.Record, len(nodeIDs))
	for i, nodeID := range nodeIDs {
		rec, err := newLifecycleRecord(ctx, d, p, kind, nodeID, reason)
		if err != nil {
			return err
		}
		recs[i] = rec
	}
	if err := d.Audit.AppendAll(ctx, recs); err != nil {
		return fmt.Errorf("api: append lifecycle audit records: %w", err)
	}
	return nil
}
