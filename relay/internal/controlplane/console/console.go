// Package console is the Relay's human web UI (ADR-0009): a thin adapter over
// the same control-plane capability layer the MCP surface and the Control API
// adapt. It renders and requests; it never decides.
//
// # What this package is not allowed to become
//
// Invariant 10 says there is one capability layer and three thin surfaces.
// This package is the third. It holds no dispatch and no Relay configuration —
// no_dispatch_test.go enforces the first structurally, in the same shape as
// the Control API's and the MCP surface's guards, because a new execution
// surface is exactly when the temptation to shortcut appears (ADR-0026
// decision 1).
//
// This package does hold one role comparison: [Route.ReachableBy], applied at
// mount time by [gated]. It is SUBTRACTIVE ONLY — it can refuse to mount a
// route below a session's role, and it can never admit a request the
// capability layer's RoleGate would refuse, because every admitted request
// still reaches that RoleGate unchanged when its handler dispatches. It is
// mount-time absence, the same lever console_execution already is (ADR-0026
// decision 5), generalised from a config flag to a role; it is not
// authorization and not a second control path. See Route.MinRole.
//
// The absence has to hold for every METHOD, not only the one a route
// advertises: net/http's ServeMux answers a method mismatch on a registered
// pattern with 405 (and an Allow header) before any handler runs, which would
// let an OPTIONS probe confirm a gated route exists even though GET 404s for
// it. [methodMismatch] closes that oracle; see its doc and gated's.
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
	//
	// Fleet and Policy are the UNAUDITED registry doors, and they are down to
	// one screen: #450 moved the fleet listing and node detail onto Queries,
	// whose reads are audited by construction (ADR-0025), and the comparison
	// screen is what still reads these. A NEW screen must not reach for them —
	// read through Queries — and read_audit_test.go is what makes that choice
	// visible rather than silent. Node detail still reads Policy for its
	// reported-Policy panel, which is covered by the describe_node record it
	// already wrote for that Node.
	//
	// Audit is down to one screen too: #542 moved agent history onto Queries,
	// leaving node detail's Recent Tasks panel and its node_revoke lookup as
	// the only reader of the whole trail through this seam.
	Fleet     FleetReader
	Policy    PolicyReader
	Audit     AuditReader
	Approvals ApprovalReader
	Freeze    FreezeReader

	// Trust is the CA and server-certificate fingerprints day one renders
	// (spec 10). Nil renders that block as "not wired" rather than as two
	// blanks: an empty fingerprint field beside the words "compare this
	// before you trust the Relay" is worse than an admission.
	Trust TrustReader

	// Events is the in-process event seam (#416) behind the Console's ONE
	// live-read path, GET /console/events. Nil leaves day one on its honest
	// "rejected attempts are not shown yet" paragraph and mounts no script.
	Events EventReader

	// Now timestamps rendered pages. Defaults to time.Now().UTC() when nil.
	Now func() time.Time

	// Queries is the capability layer's read lane (#441/#450): filtered,
	// paginated queries over the audit trail and over Jobs/Tasks, plus the
	// registry reads the fleet listing and node detail make (seams.go).
	//
	// It is THE audited door. Every method on it writes the read's own access
	// record before it answers and fails closed when it cannot (ADR-0025),
	// which is why a screen that reads fleet or trail data asks here and never
	// through Fleet/Policy/Audit above.
	Queries QueryReader

	// CertExpiringWithin is the state:cert-expiring warning window
	// (ADR-0034, #414): a mirror of a root-owned startup value (invariant
	// 11), same "told, never settable" posture as Execution above. Zero (the
	// default) means the marker never fires.
	CertExpiringWithin time.Duration

	// Cancel is one of the Console's two write seams (#595, cancel.go): the
	// same capability.Service.CancelJob the Control API and MCP call. The role
	// floor is operator; the scope beyond that floor differs by Account kind
	// (human: any Job, machine: only a Job it requested — #614). Both the
	// floor and that scope, plus the audit row, are the capability layer's;
	// this package only renders what it decided. Nil means the control does
	// not render and the route answers unavailable — the same "not wired"
	// posture every other seam on this Deps takes.
	Cancel JobCanceller

	// Decide is the Console's other write seam (#453, decide.go): the same
	// capability.Service.DecideApproval the Control API's out-of-band
	// endpoint and MCP call. Quorum, audience, requester exclusion, the
	// machine-self-decision rule, channel strength and the audit row are all
	// the capability layer's; this package only renders what it decided.
	//
	// Decide is PAIRED with Auth: decideOffered refuses to offer the control
	// unless both are wired, because a decision that cannot be
	// step-up-verified must not be offered at all. Wiring one without the
	// other is a composition-root trap, not a supported configuration — see
	// decideOffered and TestDecide_UnwiredSeamsOfferNothing.
	Decide ApprovalDecider
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

	// MinRole is the lowest role that may REACH this route. Register refuses
	// every request below it with a 404 ([gated]), and Nav projects the same
	// predicate ([Route.ReachableBy]) onto the navigation, so a drawn link and
	// a reachable route are one fact, not two that happen to agree today.
	//
	// This gate can only REMOVE reach; it can never grant it. Authorization is
	// still the capability layer's RoleGate, for this surface exactly as for
	// MCP and the Control API (ADR-0026 decision 4): every route this field
	// admits still passes RoleGate when its handler calls one. A surface that
	// gated Raw Exec itself would be a second control path — this field never
	// does that; it only decides whether the request arrives at all, the same
	// mount-time-absence lever console_execution already is (ADR-0026 decision
	// 5), generalised from a config flag to a role.
	MinRole accounts.Role

	Handler func(Deps) http.HandlerFunc
}

// Pattern renders the route in net/http ServeMux syntax.
func (r Route) Pattern() string { return r.Method + " " + r.Path }

// Link is the path a navigation entry should href. It differs from Path only
// where the pattern carries ServeMux's exact-match marker, which is routing
// syntax rather than a URL.
func (r Route) Link() string { return strings.TrimSuffix(r.Path, "{$}") }

// ReachableBy reports whether role may reach r at all — the single predicate
// both Register ([gated]) and Nav ([routesFor]) apply. Nothing else in this
// package may re-derive this comparison.
func (r Route) ReachableBy(role accounts.Role) bool { return role.AtLeast(r.MinRole) }

// constrainsReach reports whether r's own MinRole excludes any valid role at
// all. RoleViewer is the lowest valid role, so if RoleViewer can already
// reach r, MinRole excludes nobody and neither [gated] nor [methodMismatch]
// have anything to do — this is the single predicate both use to decide
// whether they wrap a route at all.
func (r Route) constrainsReach() bool { return !r.ReachableBy(accounts.RoleViewer) }

// Routes returns the route table for d — that is, the routes this PROCESS will
// mount, which is not the same as every route this package can describe, and
// — since [Route.MinRole] became a mount-time gate — is now a SUPERSET of what
// any one SESSION can reach. [routesFor] narrows this slice to what a given
// role may reach; that is what Nav and Register's per-request gate consume.
//
// With d.Execution false the execution routes are absent from the returned
// slice entirely, so they are unmounted, unreachable and (because the
// navigation is a projection of this slice) unadvertised, by construction
// rather than by three separate pieces of discipline.
func Routes(d Deps) []Route {
	rs := []Route{
		// "{$}" is an EXACT match. Without it, net/http's subtree rule makes
		// "/console/" match every unclaimed path beneath it — which quietly
		// undid the property console_execution exists to provide: with
		// execution off, /console/run fell through to this handler and
		// answered 200, so the composer was shadowed rather than absent.
		// TestConsole_ExecutionOffMakesTheComposerAbsent caught it. Register
		// mounts its own "/console/" catch-all (method-less) for every path
		// this table does not claim; {$} is still required so an unclaimed
		// path reaches THAT catch-all's styled 404 rather than this handler.
		{"GET", "/console/{$}", NavEntry{NavObserve, "Fleet", 10}, accounts.RoleViewer, handleFleet},
		{"GET", "/console/nodes/{node_id}", NavEntry{}, accounts.RoleViewer, handleNode},
		{"GET", "/console/agents", NavEntry{NavObserve, "Agents", 20}, accounts.RoleViewer, handleAgents},
		{"GET", "/console/activity", NavEntry{NavObserve, "Activity", 30}, accounts.RoleViewer, handleActivity},
		{"GET", "/console/jobs/{job_id}", NavEntry{}, accounts.RoleViewer, handleJob},

		// Compare is deliberately NOT /console/nodes/compare. Node ids are
		// unvalidated — registry.Upsert takes what enrollment gives it — so a
		// literal segment under /console/nodes/ permanently shadows any Node
		// whose id is that word. /console/nodes/add already carries that
		// hazard; a second one is not worth a tidier URL.
		//
		// No Nav entry: it is reached from a pin bar, like node detail and Job
		// detail, not from the menu.
		{"GET", "/console/compare", NavEntry{}, accounts.RoleViewer, handleCompare},
		{"GET", "/console/reads", NavEntry{NavObserve, "Read egress", 40}, accounts.RoleViewer, handleReads},

		// Policy Author (spec 06), Add Nodes (spec 09), Accounts (spec 15) and
		// Incident (spec 16) are v0.7.0 screens, not built yet (#464). They do
		// not get a placeholder row: a v0.6.0 nav must not advertise a route
		// that answers "not built yet", and Register no longer needs a
		// mounted-but-refusing row to keep a session from reaching one — the
		// route is simply absent until its screen ships, and that issue adds
		// its own row with its own MinRole.
		//
		// Add Nodes was /console/nodes/add — a LITERAL segment under
		// GET /console/nodes/{node_id} (above). With that row gone, the path
		// now falls through to handleNode with node_id="add" and renders the
		// Console shell's ordinary "Node not found" page instead of a plain
		// absence — not a new disclosure (any /console/nodes/<anything>
		// unknown already renders that page). Whoever re-adds this screen
		// cannot accept the shadow knowingly, though: a route that
		// constrains reach gets a second, bare-path registration from
		// [methodMismatch], and a bare "/console/nodes/add" would collide
		// with the already-registered "GET /console/nodes/{node_id}" —
		// net/http panics at Register time rather than letting the shadow
		// through silently. That is fail-closed and loud (a startup panic,
		// caught by any test that calls Register with this table), not a
		// danger to guard against — it just means a route that constrains
		// reach must own its path exclusively. Pick a path outside
		// /console/nodes/ instead, as /console/compare, above, already did
		// for the same reason.
		{"GET", "/console/approvals", NavEntry{NavAct, "Approvals", 30}, accounts.RoleViewer, handleApprovals},
		{"GET", "/console/approvals/{approval_id}", NavEntry{}, accounts.RoleViewer, handleApproval},

		// Not a destination: the stylesheet the content security policy forces
		// out of the layout, since style-src admits this origin and nothing
		// inline, and the one external script file for the same reason.
		{"GET", "/console/assets/{path...}", NavEntry{}, accounts.RoleViewer, assetHandler},

		// Not a destination either: the Console's ONE live-read path (spec
		// 11 — one connection per session, multiplexing the kinds the
		// screens on it render). GET, so Secure's safe-method
		// short-circuit applies and no CSRF token is required, which is
		// correct because an EventSource cannot set a header.
		//
		// MinRole here is RoleViewer, so the mount gate ([gated]) passes this
		// route through unwrapped — it refuses nothing an authenticated
		// principal can be. The real control is the per-kind table in
		// events.go; every kind it admits today sits AT this route's
		// RoleViewer floor, and that table — not this route's MinRole — is
		// what must move when a kind needing more than Viewer is added.
		{"GET", "/console/events", NavEntry{}, accounts.RoleViewer, handleEvents},

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

		// Cancel (#595): the first of the Console's two write routes. NOT
		// gated behind d.Execution — ADR-0026 decision 5 scopes that flag to
		// the composer and to dispatch, and Cancel cannot run anything, only
		// ask something already running to stop. MinRole here is mount-time
		// absence for a viewer (a 404, the same "absent beats forbidden"
		// every other MinRole gives); the capability layer's RoleGate,
		// reached inside handleCancelJob, is the authority.
		{"POST", "/console/jobs/{job_id}/cancel", NavEntry{}, accounts.RoleOperator, handleCancelJob},

		// Decide (#453): the second write route, and the one that RELEASES
		// execution rather than only ever reducing it — decide.go's header
		// states that asymmetry rather than eliding it. Also NOT gated
		// behind d.Execution, for the same reason: this route composes
		// nothing, it answers a Plan the Relay already built, and
		// ADR-0026 decision 5 scopes console_execution to the composer and
		// the dispatch routes.
		//
		// MinRole is RoleOperator because that is the LOWEST floor
		// authz.requiredRole can ever return (ActionOperation -> operator,
		// ActionRawExec -> admin; authz.go), so this mount gate can never
		// hide the route from a principal AuthorizeApprovalDecision would
		// admit — subtractive only, never wider than the capability layer.
		//
		// The path owns itself exclusively: "GET /console/approvals/{id}"
		// is a three-segment pattern and never matches this four-segment
		// one, and because this route constrainsReach(), Register also
		// mounts methodMismatch on the bare path
		// "/console/approvals/{approval_id}/decision", which collides with
		// nothing else in this table (contrast the "/console/nodes/add"
		// hazard documented above).
		{"POST", "/console/approvals/{approval_id}/decision", NavEntry{}, accounts.RoleOperator, handleDecideApproval},
	}

	// This placeholder stays mounted, unlike the four below that were removed
	// (#464): it is only ever appended when d.Execution is true, the
	// composition root hard-codes Execution:false (control_surfaces.go), so it
	// is not mounted in any shipped v0.6.0 configuration and is not in a
	// v0.6.0 nav. It is also the ONLY fixture behind
	// TestConsole_ExecutionOffMakesTheComposerAbsent, the ADR-0026 decision-5
	// regression guard — removing it would leave that guard with nothing to
	// guard.
	if d.Execution {
		rs = append(rs, Route{
			"GET", "/console/run",
			NavEntry{NavAct, "Run", 10}, accounts.RoleOperator,
			placeholder("Run", "05-composer-and-plan.md"),
		})
	}
	return rs
}

// SessionScope reports whether r targets the Console — the surface a Console
// session cookie is a credential FOR, and the only surface the authentication
// boundary will resolve one on (#459).
//
// # Why this predicate has to exist
//
// The Console session cookie carries the `__Host-` prefix, which the browser
// enforces as Path=/ (consoleauth.SessionCookieName). That is the right
// trade — host-only beats path-scoped, because a sibling subdomain cannot
// plant a `__Host-` cookie — but it means the browser attaches the session to
// EVERY path on this listener, `/api/v1` and `/mcp` included. The
// authentication boundary picks its lane by request shape (no Authorization
// header + a Console mounted = the browser lane), so without a path predicate
// an operator's Console cookie authenticated the Control API's dispatch
// routes: a fleet-wide Raw Exec credential presented as a cookie. A credential
// binds to the surface that issued it; this is where that is said in code.
//
// Consulted by controlplane.Authenticator (ConsoleSessionOptions.Scope) and
// supplied from here for the same reason [Unauthenticated] is: the package
// that owns the routes owns the statement about their extent, and asserts it
// against the route table in a test rather than describing it and hoping.
//
// It matches on the CLEANED path, exactly as [Unauthenticated] does, so
// `/api/v1/../console/` cannot smuggle an API route into scope — and, in the
// same direction, `/console/../api/v1/operations` cannot smuggle one out of
// the refusal. The bare `/console` is in scope too: only `/console/` is
// registered, so net/http answers `/console` with a redirect to it, and
// refusing there would bounce a signed-in operator to the sign-in page, back
// to `/console`, and around again.
func SessionScope(r *http.Request) bool {
	p := cleanPath(r.URL.Path)
	return p == strings.TrimSuffix(PathPrefix, "/") || strings.HasPrefix(p, PathPrefix)
}

// routesFor narrows Routes(d) to the routes a session with role may reach —
// spec 11's "routes this process mounted for this Account's role". Nav
// consumes it to draw the navigation; the per-role reachability test iterates
// it directly. This is the ONLY place outside [Route.ReachableBy] itself that
// may decide reachability; nothing else in this package re-derives the
// comparison.
func routesFor(d Deps, role accounts.Role) []Route {
	var rs []Route
	for _, r := range Routes(d) {
		if r.ReachableBy(role) {
			rs = append(rs, r)
		}
	}
	return rs
}

// gated wraps r's handler with the mount-time reachability check
// [Route.MinRole] now names. It is SUBTRACTIVE ONLY: the only two things it
// can do are call h unmodified or call notFound instead of h. It never
// calls h with an altered request, an elevated principal, or any other
// changed semantics — so it has no admit-power, only not-call, and every
// admitted request still reaches the capability layer's RoleGate unchanged
// when its handler dispatches (ADR-0026 decision 4).
//
// If RoleViewer already satisfies r.MinRole, the route constrains no valid
// role, and gated returns h UNCHANGED — it does not even look at the request.
// This is what keeps the unauthenticated sign-in surface reachable (LoginPath
// GET/POST, the sign-out POST, and the assets prefix all carry RoleViewer):
// those requests arrive with no Principal in context at all, because
// Authenticator.Middleware's public-path branch calls next.ServeHTTP before
// authenticating (auth.go), and a gate that consulted the request would panic
// or refuse the sign-in page itself.
//
// Otherwise the returned handler reads the Principal that Middleware injected
// and calls notFound — the SAME not-found handler Register mounts on every
// unmatched /console/ path — unless r.ReachableBy(that Principal's role). A
// MISSING Principal on a gated route is unreachable in production (every
// gated route sits behind Authenticator.Middleware, Register's contract) and
// also refused here rather than the 500 [principal] returns elsewhere,
// because the refusal must stay byte-identical to a route that was never
// mounted, not merely present with a different number.
//
// A typo'd MinRole fails closed too: RoleViewer.AtLeast(<not a role>) is
// false, so an invalid MinRole is treated as gate-worthy, and
// accounts.Role.AtLeast then refuses every role including admin — the route
// 404s for everyone and Nav drops it, the same rank-zero behaviour
// accounts.Role and resolveEventKinds (events.go) already rely on.
//
// gated alone only protects r's own method-specific pattern
// ("GET /console/run"). It does not by itself make a gated route
// method-proof — see [methodMismatch], which Register mounts alongside it.
func gated(r Route, h http.HandlerFunc, notFound http.HandlerFunc) http.HandlerFunc {
	if !r.constrainsReach() {
		return h
	}
	return func(w http.ResponseWriter, req *http.Request) {
		p, ok := controlplane.PrincipalFromContext(req.Context())
		if !ok || !r.ReachableBy(accounts.Role(p.Role)) {
			notFound(w, req)
			return
		}
		h(w, req)
	}
}

// methodMismatch answers requests to r's PATH whose METHOD does not match
// r.Method — the case [gated]'s own registration (mounted on r.Pattern(), a
// method-specific pattern) never sees, because net/http's ServeMux resolves a
// method mismatch on a registered pattern itself, with a 405 and an Allow
// header, before any handler runs. Left alone that answer fires whether or
// not the caller may reach r at all, so a viewer's OPTIONS on an admin-only
// path would confirm the path is mounted even though its GET 404s — the exact
// oracle GET was gated to deny. Register mounts this on r.Path (no method) for
// every route where [Route.constrainsReach] is true, so the method-less
// pattern only ever receives a method OTHER than r.Method: ServeMux always
// prefers the more specific, method-matching pattern for r.Method itself
// (verified empirically; a method-specific pattern coexists with a
// method-less one on the same path and always wins its own method).
//
// Below MinRole it answers exactly like [gated]: notFound, the same
// not-found handler Register mounts on every unmatched /console/ path, so the
// method used to probe cannot distinguish a gated route from one never
// mounted.
//
// At or above MinRole it must not simply invent a 405: a hand-written Allow
// header could drift from what ServeMux would really have said, and drift
// here is a correctness bug on a route a legitimate caller uses. Instead it
// delegates to a private single-route ServeMux holding only r's own
// method-specific pattern — the exact mux net/http would build if r were the
// only thing ever registered for its path — so the 405 and its Allow header
// are the real stdlib computation, not a reimplementation of it. That holds
// for every route sharing r.Path in this table today, because they all carry
// the same MinRole; it is not a general guarantee. A path carrying two
// constrained routes with DIFFERENT floors (say GET at RoleViewer and POST
// at RoleAdmin) would break it: this probe only knows about r, so an in-role
// admin's OPTIONS would answer "Allow: POST" instead of the real
// "Allow: GET, HEAD, POST", and a viewer's OPTIONS would 404 on a path whose
// GET they legitimately reach. The direction is over-hiding, not disclosure,
// but the claim only holds because no such split exists yet.
func methodMismatch(r Route, notFound http.HandlerFunc) http.HandlerFunc {
	probe := http.NewServeMux()
	probe.HandleFunc(r.Pattern(), func(http.ResponseWriter, *http.Request) {
		panic("console: methodMismatch probe was asked to serve r's own method; " +
			"Register only mounts this handler on r.Path, which a method-matching " +
			"request never reaches — see methodMismatch's doc comment")
	})
	return func(w http.ResponseWriter, req *http.Request) {
		p, ok := controlplane.PrincipalFromContext(req.Context())
		if !ok || !r.ReachableBy(accounts.Role(p.Role)) {
			notFound(w, req)
			return
		}
		probe.ServeHTTP(w, req)
	}
}

// Register mounts the Console route table onto mux, which is expected to be
// already wrapped by controlplane.Authenticator.Middleware and by this
// package's own Secure middleware. Register never constructs a listener, an
// auth wrapper, or a TLS config of its own — the Console is served on the
// existing internal-only control-plane listener (ADR-0009), and where it is
// exposed is the composition root's decision, not this package's.
//
// Every route is mounted through [gated], the mount-time reachability check
// [Route.MinRole] now names. This is still ONE mux: gated wraps each route's
// own handler in place, it does not select among several muxes, and it never
// changes which pattern ServeMux matches — so a refused request finds no
// route registered for it, rather than falling through to a neighbour's
// handler with a role it should not have satisfied.
//
// For every route [Route.constrainsReach] reports true for, Register ALSO
// mounts [methodMismatch] on the route's bare path (no method): otherwise the
// method-specific pattern gated is mounted on would be the only registration
// for that path, and ServeMux would answer any OTHER method itself — 405
// before gated ever runs — which reveals the route exists to a role that
// cannot GET it. A route no MinRole constrains (RoleViewer and below) gets no
// second registration; an ordinary method mismatch on it discloses nothing,
// because every valid role could already reach it.
//
// Register also mounts ONE catch-all, "/console/" (deliberately method-less:
// a "GET /console/" pattern would conflict at registration with the
// method-less methodMismatch patterns above, and net/http panics on
// conflicting patterns). It is the least specific pattern under /console/, so
// every table route and every methodMismatch registration still wins; it only
// ever answers a path this table never claimed. gated and methodMismatch both
// call the SAME handler for their own refusals, so a route that exists but is
// out of role and a path that was never mounted render byte-identical
// responses — see [renderNotFound]. It is not added to [Routes]: it is not a
// route, and putting it there would make it a nav item and a read-audit
// classification entry it is neither of.
//
// By the time any request reaches this mux, authentication has already
// happened: Authenticator.Middleware redirects an unauthenticated /console/*
// request to sign-in before the mux is consulted (login.go's Unauthenticated
// admits only LoginPath and AssetsPrefix), so the catch-all enumerates
// nothing before sign-in — an unauthenticated probe of an unknown path gets
// the sign-in redirect, never this 404.
func Register(mux *http.ServeMux, d Deps) {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	nf := notFoundHandler(d)
	for _, r := range Routes(d) {
		mux.HandleFunc(r.Pattern(), gated(r, r.Handler(d), nf))
		if r.constrainsReach() {
			mux.HandleFunc(r.Path, methodMismatch(r, nf))
		}
	}
	mux.HandleFunc("/console/", nf)
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
