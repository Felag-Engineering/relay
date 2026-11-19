// Package api is the REST/JSON Control API (ADR-0010): Enrollment Token
// mint/revoke, Node revoke, Freeze engage/release, Account and API-Token
// management, tag writes, and execution (run an Operation, Raw Exec, and
// plan mode), all mounted under /api/v1 on the control-plane's existing *http.ServeMux
// (relay/internal/controlplane.Server.Mux()) behind the single
// Authenticator.Middleware already wired there — no new listener, no new
// auth path (invariant 10, ADR-0009).
//
// Every handler is a thin adapter: decode -> validate -> call the
// capability layer -> render. No route reimplements
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
	"log/slog"
	"net/http"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/harnesssetup"
)

// TokenMinter mints an Enrollment Token through the capability layer: the floor,
// the input bounds and the fail-closed token_mint record are decided there
// (invariant 10, EN-36). *capability.EnrollmentTokens satisfies it with no adapter.
type TokenMinter interface {
	MintEnrollmentToken(ctx context.Context, p capability.Principal, m capability.EnrollmentMint) (capability.MintedEnrollmentToken, error)
}

// Revocations revokes a Node or an Enrollment Token through the capability
// layer. *capability.Revocations satisfies it with no adapter. The floor, the
// reason rule, the act and its records are the layer's (invariant 10, EN-19,
// EN-20); this surface holds no revocation service, so it cannot reach the act
// without the gate.
type Revocations interface {
	RevokeNodeWithReason(ctx context.Context, p capability.Principal, nodeID, reason string) error
	RevokeEnrollmentToken(ctx context.Context, p capability.Principal, tokenID string) error
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

// ControlGate is the capability layer's early ask for the two routes that read
// a request body before they can call the layer: Enrollment Token mint and Node
// revoke. The entry point asks again. *capability.Control satisfies it. The
// floor, the mask (EX-7) and the refusal's record are the layer's. There is one
// method per act and no ControlAction parameter, so a route cannot ask about an
// act it does not perform. Like Freezer, it is a narrow seam; the unauthorized levers on
// *capability.Control stay out of reach because the astguard authorize rule
// forbids an adapter from naming them.
type ControlGate interface {
	AuthorizeEnrollmentTokenMint(ctx context.Context, p capability.Principal) error
	AuthorizeNodeRevoke(ctx context.Context, p capability.Principal) error
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
	MintAPIToken(ctx context.Context, p capability.Principal, accountID, name string, lifetime capability.APITokenLifetime) (accounts.APIToken, accounts.Plaintext, error)
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
	// Tokens mints through the capability layer. Nil answers the mint route
	// with a 500, on the same unwired-gate posture as AccountAdmin and Tags.
	Tokens TokenMinter
	// Revocations revokes Nodes and Enrollment Tokens through the capability
	// layer. Nil refuses both revoke routes with a 500, on the same
	// unwired-gate posture as AccountAdmin.
	Revocations Revocations
	Freeze      Freezer
	// Logger is where this surface's operational errors go; nil means
	// slog.Default(). Wiring, not configuration (invariant 11); context
	// correlation comes from the handler the composition root builds.
	Logger *slog.Logger
	// Gate asks the capability layer early for Enrollment Token mint and Node
	// revoke, which read a body first; the layer records each refusal. The
	// composition root passes the same *capability.Control the Freeze goes
	// through. Nil refuses those two routes with a 500, the same unwired-gate
	// posture as AccountAdmin.
	Gate ControlGate
	// AccountAdmin backs the identity-management routes through the
	// capability layer. Nil refuses every identity route with a
	// 500, on the same unwired-gate posture Gate above documents.
	AccountAdmin AccountAdmin
	// Tags is the capability layer's tag write, behind both tag routes. Nil
	// answers them with a 500, on the same unwired-gate posture as AccountAdmin.
	Tags TagWriter
	// NodeReader is the capability read lane behind GET
	// /api/v1/nodes/{node_id}: it is not a registry narrowing
	// any more — it is the one door to the registry, which records the read
	// before it answers (invariant 10, ADR-0025). Nil still 500s.
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
	// Reads records read-access events for the Job read route (ADR-0025).
	// Nil skips recording, so tests and any unwired surface work; the
	// composition root always supplies it.
	Reads ReadAuditor
	// HarnessSetup renders the MCP URL, the CA certificate and the Harness
	// blocks an API Token mint returns beside its plaintext. It carries public
	// data only (never the CA key), and the caller's own credential is added at
	// mint. The zero value renders no harness_setup.
	HarnessSetup harnesssetup.Target
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
		// Enrollment Tokens, Node revocation, Freeze. Every route here has a
		// role floor, and every floor is decided by the ONE authz.RoleGate: mint
		// and Node revoke consult it through Gate before they read the request
		// (gateControl), the token-revoke and Freeze routes inherit it inside
		// the capability layer. Which of the two applies to a given route is
		// asserted by TestEveryRouteIsRoleClassified, so a route added to this
		// group later cannot silently have neither.
		{"POST", "/api/v1/enrollment-tokens", handleMintToken},
		{"DELETE", "/api/v1/enrollment-tokens/{id}", handleRevokeToken},
		{"GET", "/api/v1/nodes/{node_id}", handleGetNode},
		{"POST", "/api/v1/nodes/{node_id}/revoke", handleRevokeNode},
		{"POST", "/api/v1/freeze/engage", handleFreezeEngage},
		{"POST", "/api/v1/freeze/release", handleFreezeRelease},

		// Tag writes (ADR-0050). The floor, a human Account at operator or
		// above, lives in the capability layer behind TagWriter; these handlers
		// decode and render and call no gateControl.
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
// (TestGatedRoutesReachTheirOwnControlGate) trivially true for that route
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

// gateControl asks the capability layer whether p may perform one of the
// administrative acts this surface performs outside a capability service, and
// renders the answer. It decides nothing and records nothing: the layer has
// already recorded the refusal. A refusal that could not be recorded arrives
// joined with the record failure, which is logged and never shown.
//
// A nil Gate refuses with 500. That is the deliberate direction: an ungated
// administrative route fails open and nothing says so, so an unwired gate
// must be loud and closed rather than quiet and open.
func gateControl(w http.ResponseWriter, r *http.Request, d Deps, authorize func(ControlGate) error) bool {
	if d.Gate == nil {
		writeProblem(w, http.StatusInternalServerError, "authorization unavailable",
			"no control-plane authorizer is wired; refusing rather than proceeding ungated")
		return false
	}
	err := authorize(d.Gate)
	if err == nil {
		return true
	}
	writeControlRefusal(w, r, d, err)
	return false
}

// writeControlRefusal renders a refusal the capability layer returned. The layer
// always returns a join: one element once the refusal is recorded, two when the
// record failed too, which is logged and never shown. A length check, never a
// FirstRefusal(err) != err comparison: comparing a non-comparable error value
// panics. The detail is the first refusal, so it equals the recorded Reason.
func writeControlRefusal(w http.ResponseWriter, r *http.Request, d Deps, err error) {
	if joined, ok := err.(interface{ Unwrap() []error }); ok && len(joined.Unwrap()) > 1 {
		d.logger().ErrorContext(r.Context(), "control api: control refusal not recorded", "error", err)
	}
	writeProblem(w, http.StatusForbidden, "forbidden", capability.FirstRefusal(err).Error())
}
