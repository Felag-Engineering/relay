// Package console is the Relay's human web UI (ADR-0009): a thin adapter over
// the same control-plane capability layer the MCP surface and the Control API
// adapt. It renders and requests; it never decides.
//
// # What this package is not allowed to become
//
// Invariant 10 says there is one capability layer and three thin surfaces.
// This package is the third. It holds no dispatch and no Relay configuration —
// no_dispatch_test.go enforces the first structurally, in the same shape as
// the Control API's and the MCP surface's guards, and covers this package with
// no exception, because no Console route dispatches (ADR-0052 decision 1).
//
// This package does hold one role comparison: [Route.ReachableBy], applied at
// mount time by [gated]. It is SUBTRACTIVE ONLY — it can refuse to mount a
// route below a session's role, and it can never admit a request the
// capability layer's RoleGate would refuse, because every admitted request
// still reaches that RoleGate unchanged when its handler dispatches. It is
// mount-time absence (ADR-0009's absent-beats-forbidden); it is not
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
// CSP and CSRF here are controls, not hygiene, because the Console grants
// roles and mints API Tokens, and a minted token reaches the Control API: a
// forged click would counterfeit a human Account's own privilege-granting act
// and the step-up that guards it (11-console-shell.md). See security.go.
//
// # Specification
//
// docs/design/console/ carries the per-screen specifications; 11-console-shell.md
// is this package, and 00-foundations.md is the design language every screen
// assumes. Where this code and the spec disagree, the spec is the intent and
// the disagreement is a bug in one of them.
package console

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/harnesssetup"
	"github.com/Felag-Engineering/relay/relay/internal/logctx"
)

// Deps is everything the Console needs from the rest of the Relay.
//
// As with the Control API's Deps, every field here is a purpose-built seam over
// runtime-object machinery — never Relay configuration. The one field that
// looks like configuration, OAuthConfigured, is not settable from here or
// from any API: it mirrors a startup value the composition root sets, and this
// package can only be told what it is.
type Deps struct {
	// Logger is where the Console's operational errors go; nil means
	// slog.Default(). Wiring, not configuration.
	Logger *slog.Logger

	// OAuthConfigured mirrors whether this Relay accepts OAuth bearer tokens
	// (ADR-0024). It is presentation only: Access says OAuth sign-ins are not
	// listed only where there can be some (20-access.md, D34).
	OAuthConfigured bool

	// Auth is the Console's sign-in service. It can start a session,
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
	// Every registry and Policy-view read is Deps.Queries now (QRY-28):
	// the Compare screen and the Node-detail Policy panel ask through
	// DescribeNode, the same audited door the fleet listing and node detail
	// use. There is no unaudited registry door.
	//
	// Audit has one screen too: AI-agent history reads through Queries,
	// leaving node detail's Recent Tasks panel and its node_revoke lookup as
	// the only reader of the whole trail through this seam.
	Audit AuditReader

	// Approvals is Job detail's read of a dispatch's approval record.
	Approvals ApprovalReader
	Freeze    FreezeReader

	// HarnessSetup renders the MCP URL, the CA certificate and the Harness
	// blocks an API Token mint shows beside its plaintext. It carries public
	// data only (never the CA key), and the minted credential is added at mint.
	// The zero value renders no harness setup.
	HarnessSetup harnesssetup.Target

	// Trust is the CA and server-certificate fingerprints day one renders
	// (spec 10). Nil renders that block as "not wired" rather than as two
	// blanks: an empty fingerprint field beside the words "compare this
	// before you trust the Relay" is worse than an admission.
	Trust TrustReader

	// Events is the in-process event seam behind the Console's ONE
	// live-read path, GET /console/events. Nil leaves day one on its honest
	// "rejected attempts are not shown yet" paragraph and mounts no script.
	Events EventReader

	// Now timestamps rendered pages. Defaults to time.Now().UTC() when nil.
	Now func() time.Time

	// Queries is the capability layer's read lane: filtered,
	// paginated queries over the audit trail and over Jobs/Tasks, plus the
	// registry reads the fleet listing and node detail make (seams.go).
	//
	// It is THE audited door. Every method on it writes the read's own access
	// record before it answers and fails closed when it cannot (ADR-0025),
	// which is why a screen that reads fleet, Policy or trail data asks here
	// and nowhere else.
	Queries QueryReader

	// Accounts is the Account registry and its API Tokens, read-only
	// (seams.go). It is satisfied by *capability.AccountAdmin, not the
	// *capability.ReadLane behind Queries above, and it is deliberately NOT
	// the same field: that comment is about the registry/Policy-view door and
	// says a new screen asks there, and this seam must not read as having
	// inherited that permission by sitting next to it.
	//
	// It is, though, a FOURTH door whose successful reads record nothing.
	// ControlAccountRead and ControlAPITokenRead are authorized and answered
	// and write no audit row unless they are refused (accountadmin.go), so
	// reading who holds an identity on this control plane leaves no trace.
	// That is not an ADR-0025 violation — decision 1 scopes to non-dispatching
	// read TOOLS, and these two are ControlActions — and it is not this
	// package's to fix: a RecordRead here is what read_audit_test.go forbids.
	// It is a known gap in internal/capability, where the fix belongs.
	//
	// Nil renders the screen unavailable rather than as an empty Account
	// list. "You have no Accounts" is a claim about identity, and a Console
	// that makes it because nobody wired the seam has lied about who can
	// reach this Relay — the same rule the read seams above follow, on the
	// one subject where being wrong is worst.
	Accounts AccountReader

	// Cancel is one of the Console's write seams (cancel.go): the
	// same capability.Execution.CancelJob the Control API and MCP call. The role
	// floor is operator; the scope beyond that floor differs by Account kind
	// (human: any Job, machine: only a Job it requested). Both the
	// floor and that scope, plus the audit row, are the capability layer's;
	// this package only renders what it decided. Nil means the control does
	// not render and the route answers unavailable — the same "not wired"
	// posture every other seam on this Deps takes.
	Cancel JobCanceller

	// AccountAdmin is the Console's second write seam (accounts_write.go): the
	// same five capability.AccountAdmin verbs the Control API calls —
	// CreateAccount, SetAccountRole, SetAccountEnabled, MintAPIToken and
	// RevokeAPIToken. The admin floor on all of them, the
	// self-target refusal, the last-enabled-admin refusal and every audit row
	// are the capability layer's; this package only renders what it decided.
	//
	// PAIRED with Auth AND with Accounts: accountsOffered refuses to offer
	// any of the five controls unless all three are wired — Auth because a
	// granting act that cannot be step-up-verified must not be offered at
	// all, Accounts because the role route
	// reads the target's current role to tell a raise from a lower. Nil, or
	// either partner nil, means the controls do not render and the routes
	// answer unavailable.
	AccountAdmin AccountAdministrator

	// Tags is the Console's third write seam (tags.go): the same
	// capability.TagWriter.WriteTag the Control API calls. The floor (a human
	// Account at operator or above, no step-up), the label rules, the
	// per-Node cap and the audit rows are the capability layer's; this package
	// only renders what it decided (invariant 10, ADR-0050). Nil means no tag
	// control renders and the routes answer unavailable.
	Tags TagWriter

	// AliasWriter is the Console's fourth write seam (policyaliases.go): the
	// same capability.PolicyAliasAdmin the capability layer owns. The admin and
	// human-Account floor, the name rules, uniqueness and the audit record are
	// its and never this package's (invariant 10). The control is offered only
	// to a human admin (policyAliasesOffered), and alias names are read and
	// drawn only for a human (readPolicyAliases). Nil means no control renders
	// and the route answers unavailable.
	AliasWriter PolicyAliasWriter

	// TemporaryPasswords is the Console's fifth write seam
	// (temporarypassword.go): the same capability.TemporaryPasswords the
	// Control API and MCP are never handed (ADR-0045 decision 11). Creating a
	// human Account issues its temporary password through it, so a human
	// create with this nil is refused as unavailable rather than made
	// passwordless. Nil also means no re-issue control renders.
	TemporaryPasswords TemporaryPasswordIssuer

	// EnrollmentTokens is the Console's sixth write seam (addnodes.go): the
	// same capability action and admin floor as the Control API's mint,
	// through capability.EnrollmentTokens. It is paired with Auth, because a
	// mint whose step-up cannot be verified is not offered. Nil means the
	// screen answers unavailable.
	EnrollmentTokens EnrollmentTokenMinter
}

// logger resolves Deps.Logger, falling back to slog.Default() when unset.
func (d Deps) logger() *slog.Logger { return logctx.Or(d.Logger) }

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
	// does that; it only decides whether the request arrives at all.
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
// No field of d adds or removes a route: d is what every route's Handler is
// bound to, and the table itself is fixed.
func Routes(d Deps) []Route {
	return []Route{
		// "{$}" is an EXACT match. Without it, net/http's subtree rule makes
		// "/console/" match every unclaimed path beneath it, so an unclaimed
		// path would answer with the Fleet screen. Register mounts its own
		// "/console/" catch-all (method-less) for every path this table does
		// not claim; {$} is still required so an unclaimed path reaches THAT
		// catch-all's styled 404 rather than this handler.
		{"GET", "/console/{$}", NavEntry{Group: NavObserve, Label: "Fleet", Order: 10, Under: []string{"/console/nodes", "/console/compare", "/console/tags", policyAliasesAction}}, accounts.RoleViewer, handleFleet},
		{"GET", "/console/nodes/{node_id}", NavEntry{}, accounts.RoleViewer, handleNode},
		{"GET", "/console/activity", NavEntry{Group: NavObserve, Label: "Activity", Order: 30, Under: []string{"/console/jobs"}}, accounts.RoleViewer, handleActivity},
		{"GET", "/console/jobs/{job_id}", NavEntry{}, accounts.RoleViewer, handleJob},

		// Compare is deliberately NOT /console/nodes/compare. Node ids are
		// unvalidated — registry.Upsert takes what enrollment gives it — so a
		// literal segment under /console/nodes/ permanently shadows any Node
		// whose id is that word. /console/nodes/add already carries that
		// hazard; a second one is not worth a tidier URL.
		//
		// No Nav entry of its own: it is reached from a pin bar, not from the
		// menu, and marks Fleet current (Fleet's Under).
		{"GET", "/console/compare", NavEntry{}, accounts.RoleViewer, handleCompare},

		// Policy Author and the Incident screen are cut from the MVP
		// (docs/design/console/README.md) and get no row.
		//
		// Add Nodes (spec 09, addnodes.go) lives outside /console/nodes/: a
		// constrained literal there collides with GET /console/nodes/{node_id}
		// at registration. The POST has its own path because two constrained
		// routes on one path panic. MinRole admin narrows to authz's
		// ControlMintEnrollmentToken floor and widens nothing. Order 10 puts it
		// before Accounts (20) and Access (30), as 00-foundations.md draws it;
		// Under makes the POST's reveal page mark Add Nodes current.
		{"GET", "/console/add-nodes", NavEntry{Group: NavAdminister, Label: "Add Nodes", Order: 10, Under: []string{"/console/add-nodes"}}, accounts.RoleAdmin, handleAddNodes},
		{"POST", "/console/add-nodes/tokens", NavEntry{}, accounts.RoleAdmin, handleMintEnrollmentToken},

		// Accounts, read half (spec 15). The first route in the
		// Administer group.
		//
		// MinRole is admin because ControlAccountRead is floored at admin on
		// every surface (authz.go): this gate narrows to exactly the
		// capability layer's own floor and widens nothing, and a viewer gets
		// the byte-identical 404 [gated] gives every other constrained route
		// rather than a 403 that would confirm the screen exists.
		//
		// THE PATH BELONGS TO THIS ROUTE ALONE, and that is a constraint on
		// what comes next rather than an observation. Because this route
		// constrainsReach(), Register mounts [methodMismatch] on the BARE
		// "/console/accounts" as well, which collides with nothing in this
		// table today. It did mean the write half could not add a
		// constrained "POST /console/accounts": Register would register the
		// bare path a second time and net/http panics at registration. The
		// write half used the distinct literals this comment predicted —
		// /console/accounts/create and so on — and they are below.
		//
		// The Account page, GET /console/accounts/{account_name}, is mounted
		// below. It owns the two-segment shape under /console/accounts/: a
		// constrained {account_name} route makes Register also mount the
		// method-less "/console/accounts/{account_name}", so a two-segment
		// LITERAL beside it panics at registration. Nothing may be added in that
		// shape; use a path outside /console/accounts/ instead.
		{"GET", "/console/accounts", NavEntry{Group: NavAdminister, Label: "Accounts", Order: 20, Under: []string{"/console/accounts", "/console/new-account", "/console/api-tokens"}}, accounts.RoleAdmin, handleAccounts},
		{"GET", "/console/accounts/{account_name}", NavEntry{}, accounts.RoleAdmin, handleAccount},
		{"GET", "/console/new-account", NavEntry{}, accounts.RoleAdmin, handleNewAccount},

		// Access (spec 20, D17): who signed in, who failed to, and who
		// changed an Account or minted it a credential — admin only. MinRole
		// admin is a Console-only narrowing (invariant 10, subtractive only):
		// the records stay on the audit read lane under its existing role
		// rules, and the handler sends every request to
		// capability.ReadLane.QueryAudit with the caller unchanged. The path
		// owns itself exclusively; because this route constrainsReach(),
		// Register also mounts methodMismatch on the bare "/console/access",
		// which collides with nothing else in this table
		// (TestConsole_RegisterMountsEveryRouteWithoutPatternConflict picks
		// it up).
		{"GET", "/console/access", NavEntry{Group: NavAdminister, Label: "Access", Order: 30}, accounts.RoleAdmin, handleAccess},

		// Accounts, write half (accounts_write.go): the Console's
		// third, fourth, fifth, sixth and seventh write routes. All five at
		// accounts.RoleAdmin, which is exactly the floor
		// authz.requiredControlRole returns for all eight account
		// ControlActions — so each MinRole narrows to the capability layer's
		// own floor and widens nothing. None is a navigation destination:
		// they are form targets on the screen above.
		//
		// THESE FIVE PATHS ARE FORCED, and were driven through a real
		// net/http.ServeMux — with the bare-path second registration Register
		// mounts for every constrainsReach() route — rather than reasoned
		// about. Two shapes panic at registration, which in production is a
		// process that does not start:
		//
		//   - a constrained "POST /console/accounts", because the GET route
		//     above already owns that bare path;
		//   - a two-segment literal under /console/accounts/, because the
		//     Account page's {account_name} route is more general than it.
		//
		// Create therefore lives at /console/new-account/create, which also
		// keeps an Account named "new" or "create" reachable. The old
		// /console/accounts/create now belongs to the Account page's
		// method-less twin and may never be re-added as a literal: an admin's
		// POST there is a 405 (Allow: GET, HEAD) and a lower role's is the
		// unmounted 404.
		//
		// TestConsole_RegisterMountsEveryRouteWithoutPatternConflict is the
		// standing guard and picks these rows up automatically.
		{"POST", "/console/new-account/create", NavEntry{}, accounts.RoleAdmin, handleCreateAccount},
		{"POST", "/console/accounts/{account_id}/role", NavEntry{}, accounts.RoleAdmin, handleSetAccountRole},
		{"POST", "/console/accounts/{account_id}/enabled", NavEntry{}, accounts.RoleAdmin, handleSetAccountEnabled},
		{"POST", "/console/accounts/{account_id}/tokens", NavEntry{}, accounts.RoleAdmin, handleMintAPIToken},
		{"POST", "/console/api-tokens/{token_id}/revoke", NavEntry{}, accounts.RoleAdmin, handleRevokeAPIToken},

		// Re-issuing a temporary password (temporarypassword.go): three
		// segments under /console/accounts/ like role, enabled and tokens.
		// MinRole admin narrows to authz.ControlTemporaryPasswordIssue's floor
		// and widens nothing; the human-only rule is the capability layer's.
		{"POST", "/console/accounts/{account_id}/temporary-password", NavEntry{}, accounts.RoleAdmin, handleIssueTemporaryPassword},

		// The confirmation pages for the three acts that reduce authority.
		// They are reads at the same admin floor as ControlAccountRead and
		// ControlAPITokenRead, so MinRole narrows to the capability layer's
		// floor and widens nothing. Their paths differ from the POST paths
		// because two constrained routes on one path panic at registration.
		{"GET", "/console/accounts/{account_id}/disable", NavEntry{}, accounts.RoleAdmin, handleConfirmDisable},
		{"GET", "/console/accounts/{account_id}/lower", NavEntry{}, accounts.RoleAdmin, handleConfirmLowerRole},
		{"GET", "/console/accounts/{account_id}/tokens/{token_id}/revoke", NavEntry{}, accounts.RoleAdmin, handleConfirmRevokeAPIToken},

		// Not a destination: the stylesheet, fonts, brand SVGs and external
		// script files the content security policy forces out of the layout,
		// since it admits this origin and nothing inline. Serves both the
		// hashed, immutable URLs and the unhashed, no-store ones.
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

		// The sign-in surface. GET renders the form and POST accepts
		// it; both are reachable without a credential, which is what
		// Unauthenticated names for the authentication boundary. Sign-out is
		// POST-only and authenticated like every other mutating route.
		//
		// Not navigation destinations: signing in is not somewhere an
		// operator navigates to, and the sign-out control belongs beside the
		// account chip rather than in the two groups, whose grouping is the
		// teaching (nav.go).
		{"GET", LoginPath, NavEntry{}, accounts.RoleViewer, handleLoginForm},
		{"POST", LoginPath, NavEntry{}, accounts.RoleViewer, handleLoginSubmit},
		{"POST", LogoutPath, NavEntry{}, accounts.RoleViewer, handleLogout},

		// Your account (password.go): a signed-in human changes only their own
		// password (ADR-0045). Every role may, so both are RoleViewer and the
		// proof of the current password is consoleauth's. /console/account is
		// not /console/accounts, and neither path is a literal beneath a
		// constrained wildcard. A session opened with a temporary password
		// reaches these two and sign-out and nothing else (PasswordChangeOnly).
		{"GET", yourAccountPath, NavEntry{}, accounts.RoleViewer, handleYourAccount},
		{"POST", changePasswordPath, NavEntry{}, accounts.RoleViewer, handleChangePassword},

		// Cancel: one of the Console's write routes. Cancel cannot run
		// anything, only ask something already running to stop. MinRole here
		// is mount-time absence for a viewer (a 404, the same "absent beats
		// forbidden" every other MinRole gives); the capability layer's
		// RoleGate, reached inside handleCancelJob, is the authority.
		{"POST", "/console/jobs/{job_id}/cancel", NavEntry{}, accounts.RoleOperator, handleCancelJob},

		// Tags (tags.go): edit one Node's tag: labels from Node detail, and a
		// filtered selection's from the Fleet view through a confirmation
		// page that lists the matched Nodes. MinRole operator narrows to
		// authz.ControlTagWrite's own floor and widens nothing; the
		// human-Account-only rule is the capability layer's, reached inside the
		// POST handlers. The confirmation page is a read that writes nothing.
		// Each path owns itself: a constrained route also mounts its bare path,
		// so none shares a path with another route and none is a literal beneath
		// a constrained wildcard.
		{"POST", "/console/nodes/{node_id}/tags", NavEntry{}, accounts.RoleOperator, handleWriteNodeTag},
		{"GET", "/console/tags/confirm", NavEntry{}, accounts.RoleOperator, handleConfirmTags},
		{"POST", "/console/tags", NavEntry{}, accounts.RoleOperator, handleWriteTags},

		// Policy aliases (policyaliases.go): set, rename or clear one alias from
		// Fleet's facet or Node detail. MinRole admin narrows to
		// authz.ControlPolicyAlias's own floor and widens nothing; the
		// human-Account-only rule is the capability layer's, the backstop behind
		// Secure's CSRF check, which refuses a bearer-lane POST before routing.
		// The path owns itself and sits outside /console/nodes/.
		{"POST", policyAliasesAction, NavEntry{}, accounts.RoleAdmin, handleWritePolicyAlias},
	}
}

// SessionScope reports whether r targets the Console — the surface a Console
// session cookie is a credential FOR, and the only surface the authentication
// boundary will resolve one on.
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
// MISSING Principal on a gated route is unreachable in production for gated
// ITSELF (every route gated wraps has constrainsReach() true, so its MinRole
// exceeds RoleViewer and it sits behind Authenticator.Middleware, Register's
// contract). But notFound is the SAME handler Register also mounts directly
// on the public, method-less catch-all ("/console/"), which a public,
// unauthenticated request CAN reach — an OPTIONS on a public path, or a path
// variant (a trailing slash) the route table never claimed — so notFound must
// handle a missing Principal safely on its own; see [renderNotFound]. gated
// refuses here, rather than deferring to the 500 [principal] returns
// elsewhere, because the refusal must stay byte-identical to a route that was
// never mounted, not merely present with a different number.
//
// A typo'd MinRole fails closed too: RoleViewer.AtLeast(<not a role>) is
// false, so an invalid MinRole is treated as gate-worthy, and
// accounts.Role.AtLeast then refuses every role including admin — the route
// 404s for everyone and Nav drops it, the same rank-zero behaviour
// accounts.Role and resolveEventKinds (events.go) already rely on.
//
// gated alone only protects r's own method-specific pattern
// ("POST /console/jobs/{job_id}/cancel"). It does not by itself make a gated
// route method-proof — see [methodMismatch], which Register mounts alongside
// it.
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
// By the time an ORDINARY request reaches this mux, authentication has
// already happened: Authenticator.Middleware redirects an unauthenticated
// /console/* request to sign-in before the mux is consulted, so an
// unauthenticated probe of an unknown path gets the sign-in redirect, never
// this 404. The exception is login.go's Unauthenticated surface itself
// (LoginPath and AssetsPrefix, exactly): a request that targets one of those
// but not with the method or exact path the route table claims — an
// unauthenticated OPTIONS on LoginPath, say — is still "public" by
// Middleware's own predicate, so it reaches the catch-all with no Principal
// in context at all. [renderNotFound] handles that case directly rather than
// assuming it cannot happen; see its doc comment.
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
