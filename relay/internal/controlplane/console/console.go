// Package console is the Relay's human web UI (ADR-0009): a thin adapter over
// the same control-plane capability layer the MCP surface and the Control API
// adapt. It renders and requests; it never decides.
//
// # What this package is not allowed to become
//
// Invariant 10 says there is one capability layer and three thin surfaces.
// This package is the third. It holds no dispatch, no authorization logic, and
// no Relay configuration — no_dispatch_test.go enforces the first two
// structurally, in the same shape as the Control API's and the MCP surface's
// guards, because a new execution surface is exactly when the temptation to
// shortcut appears (ADR-0026 decision 1).
//
// # Why this package's security middleware is not hygiene
//
// ADR-0026 gave the Console an execution surface, which moved browser security
// onto the critical path: CSP and CSRF here are controls with a fleet-RCE
// blast radius, because a forged click would counterfeit the strongest
// per-action credential in the system (the step-up apply). See security.go.
//
// # Specification
//
// docs/design/console/ carries the per-screen specifications; 11-console-shell.md
// is this package, and 00-foundations.md is the design language every screen
// assumes. Where this code and the spec disagree, the spec is the intent and
// the disagreement is a bug in one of them.
package console

import (
	"net/http"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
)

// Deps is everything the Console needs from the rest of the Relay.
//
// As with the Control API's Deps, every field here is a purpose-built seam over
// runtime-object machinery — never Relay configuration. The one field that
// looks like configuration, Execution, is not settable from here or from any
// API: it mirrors a root-owned value the composition root reads at startup, and
// this package can only be told what it is.
type Deps struct {
	// Execution mirrors the root-owned console_execution setting (ADR-0026
	// decision 5). When false the execution routes are NOT MOUNTED and the
	// composer is not rendered — an absent capability, not an RBAC refusal.
	//
	// This is load-bearing and easy to get wrong: shipping a disabled or
	// greyed-out composer gives away the exact property the flag exists to
	// preserve. ADR-0009's insight was that absent beats forbidden.
	Execution bool

	// Auth is the Console's sign-in service (#418). It can start a session,
	// end one, and re-prove human presence for step-up; it cannot RESOLVE
	// one, because resolving a credential belongs to the authentication
	// boundary (controlplane.Authenticator) and not to a screen.
	//
	// Nil only in tests that render the shell without a sign-in path.
	Auth Authenticator

	// The read seams (seams.go). Every one is satisfied by an object the
	// composition root already holds and already hands to another surface, and
	// every one is read-only by its type — see seams.go for why that is a
	// structural property and not a convention.
	//
	// A nil seam makes the screens that need it refuse with an explanation
	// rather than render an empty one. An empty fleet view is a claim about the
	// fleet ("you have no Nodes"), and a Console that makes it because nobody
	// wired the registry has lied about something an operator will act on.
	Fleet     FleetReader
	Policy    PolicyReader
	Audit     AuditReader
	Approvals ApprovalReader
	Jobs      JobReader
	Freeze    FreezeReader

	// Now timestamps rendered pages. Defaults to time.Now().UTC() when nil.
	Now func() time.Time

	// CertExpiringWithin is the state:cert-expiring warning window
	// (ADR-0034, #414): a mirror of a root-owned startup value (invariant
	// 11), same "told, never settable" posture as Execution above. Zero (the
	// default) means the marker never fires.
	CertExpiringWithin time.Duration
}

// now reads the clock, defaulting when the composition root left it unset.
//
// Handlers call this rather than d.Now directly so that a Deps built by hand in
// a test — which is most of them — never panics on a nil func. The zero value of
// a Deps has to be renderable, because the shell was built before any seam
// existed and must stay testable without them.
func (d Deps) now() time.Time {
	if d.Now == nil {
		return time.Now().UTC()
	}
	return d.Now()
}

// Route is one Console route: its method, its path, the navigation destination
// it presents (if any), and the handler factory that binds it to a Deps.
//
// The table is exported as DATA (see [Routes]) for the same reason the Control
// API's is: something other than a human has to be able to check what the
// server actually serves. Here that something is the navigation — see nav.go.
type Route struct {
	Method string
	Path   string

	// Nav, when its Label is non-empty, makes this route a navigation
	// destination. A route with no Nav entry is reachable but not advertised.
	Nav NavEntry

	// MinRole is the lowest role for which this destination appears in the
	// NAVIGATION. It is presentation, not authorization.
	//
	// Read that twice. Authorization is the capability layer's RoleGate, for
	// this surface exactly as for MCP and the Control API (ADR-0026 decision
	// 4); a surface that gated a role itself would be a second control path,
	// and the first one to be forgotten. This field decides only whether a
	// link is drawn, so that a viewer gets a structurally smaller Console
	// rather than a wall of controls that refuse them.
	MinRole accounts.Role

	Handler func(Deps) http.HandlerFunc
}

// Pattern renders the route in net/http ServeMux syntax.
func (r Route) Pattern() string { return r.Method + " " + r.Path }

// Link is the path a navigation entry should href. It differs from Path only
// where the pattern carries ServeMux's exact-match marker, which is routing
// syntax rather than a URL.
func (r Route) Link() string { return strings.TrimSuffix(r.Path, "{$}") }

// Routes returns the route table for d — that is, the routes this process will
// actually mount, which is not the same as every route this package can
// describe. With d.Execution false the execution routes are absent from the
// returned slice entirely, so they are unmounted, unreachable and (because the
// navigation is a projection of this slice) unadvertised, by construction
// rather than by three separate pieces of discipline.
func Routes(d Deps) []Route {
	rs := []Route{
		// "{$}" is an EXACT match. Without it, net/http's subtree rule makes
		// "/console/" match every unclaimed path beneath it — which quietly
		// undid the property console_execution exists to provide: with
		// execution off, /console/run fell through to this handler and
		// answered 200, so the composer was shadowed rather than absent.
		// TestConsole_ExecutionOffMakesTheComposerAbsent caught it.
		{"GET", "/console/{$}", NavEntry{NavObserve, "Fleet", 10}, accounts.RoleViewer, handleFleet},
		{"GET", "/console/nodes/{node_id}", NavEntry{}, accounts.RoleViewer, handleNode},
		{"GET", "/console/agents", NavEntry{NavObserve, "Agents", 20}, accounts.RoleViewer, handleAgents},
		{"GET", "/console/activity", NavEntry{NavObserve, "Activity", 30}, accounts.RoleViewer, handleActivity},
		{"GET", "/console/jobs/{job_id}", NavEntry{}, accounts.RoleViewer, handleJob},
		{"GET", "/console/reads", NavEntry{NavObserve, "Read egress", 40}, accounts.RoleViewer, handleReads},

		{"GET", "/console/policy", NavEntry{NavAct, "Policy", 20}, accounts.RoleOperator, placeholder("Policy Author", "06-policy-author.md")},
		{"GET", "/console/approvals", NavEntry{NavAct, "Approvals", 30}, accounts.RoleViewer, handleApprovals},
		{"GET", "/console/approvals/{approval_id}", NavEntry{}, accounts.RoleViewer, handleApproval},

		{"GET", "/console/nodes/add", NavEntry{NavAdminister, "Add Nodes", 10}, accounts.RoleAdmin, placeholder("Add Nodes", "09-add-nodes.md")},
		{"GET", "/console/accounts", NavEntry{NavAdminister, "Accounts", 20}, accounts.RoleAdmin, placeholder("Accounts", "15-accounts-and-tokens.md")},
		{"GET", "/console/incident", NavEntry{NavAdminister, "Incident", 30}, accounts.RoleOperator, placeholder("Incident", "16-incident-ladder.md")},

		// Not a destination: the stylesheet the content security policy forces
		// out of the layout, since style-src admits this origin and nothing
		// inline.
		{"GET", "/console/assets/{path...}", NavEntry{}, accounts.RoleViewer, assetHandler},

		// The sign-in surface (#418). GET renders the form and POST accepts
		// it; both are reachable without a credential, which is what
		// Unauthenticated names for the authentication boundary. Sign-out is
		// POST-only and authenticated like every other mutating route.
		//
		// Not navigation destinations: signing in is not somewhere an
		// operator navigates to, and the sign-out control belongs beside the
		// account chip rather than in the three groups, whose grouping is the
		// teaching (nav.go).
		{"GET", LoginPath, NavEntry{}, accounts.RoleViewer, handleLoginForm},
		{"POST", LoginPath, NavEntry{}, accounts.RoleViewer, handleLoginSubmit},
		{"POST", LogoutPath, NavEntry{}, accounts.RoleViewer, handleLogout},
	}

	if d.Execution {
		rs = append(rs, Route{
			"GET", "/console/run",
			NavEntry{NavAct, "Run", 10}, accounts.RoleOperator,
			placeholder("Run", "05-composer-and-plan.md"),
		})
	}
	return rs
}

// Register mounts the Console route table onto mux, which is expected to be
// already wrapped by controlplane.Authenticator.Middleware and by this
// package's own Secure middleware. Register never constructs a listener, an
// auth wrapper, or a TLS config of its own — the Console is served on the
// existing internal-only control-plane listener (ADR-0009), and where it is
// exposed is the composition root's decision, not this package's.
func Register(mux *http.ServeMux, d Deps) {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	for _, r := range Routes(d) {
		mux.HandleFunc(r.Pattern(), r.Handler(d))
	}
}

// principal reads the Principal that Authenticator.Middleware injected. Every
// route this package registers sits behind that Middleware (Register's
// contract), so the false path is a defensive 500 and never a security
// decision made here.
func principal(w http.ResponseWriter, r *http.Request) (capability.Principal, bool) {
	p, ok := controlplane.PrincipalFromContext(r.Context())
	if !ok {
		http.Error(w, "the Console was reached without an authenticated principal", http.StatusInternalServerError)
		return capability.Principal{}, false
	}
	return p, true
}
