package console

// accounts.go is the Accounts screen, read half (spec 15): who holds an
// identity on this control plane, with what authority, and what credentials
// authenticate as them.
//
// # Why this screen is admin-only, and why a viewer gets a 404
//
// The route's MinRole is admin because ControlAccountRead and
// ControlAPITokenRead are floored at admin on EVERY surface (authz.go). The
// mount gate therefore narrows to exactly the capability layer's own floor and
// widens nothing (invariant 10) — it is mount-time absence, not a second
// opinion about authorization, and every request it admits still meets
// AuthorizeControl inside the capability layer.
//
// A viewer gets the byte-identical 404 [gated] gives every other constrained
// route, never a 403: a 403 would confirm the screen exists, which is itself
// the disclosure (ADR-0009's absent-beats-forbidden).
// Nothing in this file compares a role. If a read is refused, what renders is
// the capability layer's own refusal text.
//
// # The table renders unconditionally
//
// There is no "you have no Accounts" branch, because that Console cannot be
// reached: this route serves only a signed-in human Account, and the first is
// the admin `relay init` creates. So a Console that is serving this route is a
// Console with at least one Account, an else-branch here would be dead copy,
// and the honest first-boot shape is one row under a <thead> rather than an
// empty state. dayone_test.go carries the
// matching named skip, and TestAccounts_DayOneShowsTheFirstAdmin pins the
// shape that skip hands over.
//
// # The last tool call, and what it honestly cannot say
//
// Spec 15 asks for the time of a machine Account's last tool call. That is not
// on accounts.Account — LastSeenAt is last AUTHENTICATION, which the screen
// renders separately — so it comes from the audit trail: ONE QueryAudit over
// agentCallKinds, with the newest call per Account taken from that single
// page, one page, newest call per
// Account.
//
// The cost is stated on screen rather than hidden. An Account whose most
// recent call is older than the page renders "no tool call in the last N
// recorded calls" — never blank, never a zero, and never a claim that it has
// never called. Two alternatives were rejected: one QueryAudit per machine
// Account (correct for arbitrarily old calls, but it writes N read records per
// page view, inflating the very trail Activity renders), and a
// LastToolCallByAccount method on the read lane (the right answer, and not
// built).
//
// # What must not appear here (spec 15, "Must not appear")
//
// No token value and no SecretHash — tokenRow below has no field one could
// occupy, which is the structural half of that claim, and
// TestAccounts_NoConsoleFileNamesSecretHash is the other. No Relay
// configuration of any kind (invariant 11): the role block is prose about
// where the boundary falls, never an inventory of editable values.
//
// This file is the list (D35): one table, and each row carries Edit (a link to
// the Account page, accounts_page.go) and either Disable (a GET to its
// confirmation page, marked from=list so the act returns to the list) or Enable
// (a link to the Account page's state section). No row control posts. The
// forms for an existing Account live on its page. What stays absent is a role
// or PERMISSION editor of any kind — the three roles are ADR-0010's closed set
// and a custom-permission builder is a second authorization model — and any
// Relay configuration whatsoever. The one place a minted credential appears is
// accounts_write.go's mint response, never this screen.
//
// Edit, Enable and New account are links; with the Console's external script
// (accounts.js) they open the linked page's content in a dialog instead, and
// nothing else about them changes. A refused act from either page re-renders
// that page with the refusal above the act's button (accounts_write.go,
// createRefusal and editRefusal).

import (
	"net/http"
	"net/url"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

// accountsCallPage is how many recorded AI-agent calls this screen looks back
// over for each machine Account's last call. It is rendered into the copy, so
// the honest-absence sentence states the real number rather than a rounded
// one.
const accountsCallPage = 200

// selfPanelNote is why the signed-in Account's own panel carries no control.
// The refusal page's fuller sentence, selfTargetRefusal, is the capability
// layer's refusal; this is the panel's one-line rendering of the same rule.
const selfPanelNote = "This is your own Account; another admin must change its role or state."

// accountsView is the list.
type accountsView struct {
	Accounts []accountRow

	CallPage int

	// Done is the fixed result sentence for a done= key (doneSentence), or "".
	Done string

	// Write is nil when the write half is not wired (accounts_write.go):
	// no control of any kind renders, which is the honest-absence posture every
	// other seam on this Deps takes. accountsOffered decides it.
	Write *accountsWriteControls

	// NewAccountHref is the New account page; empty exactly when Write is nil.
	NewAccountHref string
}

// accountsWriteControls is everything the row and token forms need
// beyond the row itself: the CSRF token every Console POST carries, whether a
// recent step-up makes the password optional, and the mint form's closed
// lifetime options.
type accountsWriteControls struct {
	CSRFToken string
	// StepUpFresh renders the three granting forms' password field as
	// optional. Presentation only: requireStepUp re-decides on submit.
	StepUpFresh bool
	TTLs        []ttlOption
}

// accountCreateForm is the New account page's form. The same definition serves
// the plain page (no echo) and the refused re-render, which carries the caller's
// own submission back. The echoes are bounded by handleCreateAccount and
// escaped by html/template. handleCreateAccount never copies the password into
// the form.
//
// The option lists are built from accounts.RoleViewer/Operator/Admin and
// accounts.KindHuman/KindMachine rather than hand-typed strings, so a screen
// and the domain cannot come to disagree about what the closed sets are.
type accountCreateForm struct {
	CSRFToken    string
	CreateAction string
	// StepUpFresh renders the password field as optional; presentation only.
	StepUpFresh bool
	Roles       []string
	Kinds       []string
	// RoleLines is the "What this role may do" panel's text, one per role.
	RoleLines []roleLine
	Refusal   string
	Name      string
	Kind      string
	Role      string
}

// ttlOption is one entry in the mint form's closed lifetime select. The
// VALUE is what the handler parses (ttlFor, accounts_write.go); the label is
// what an operator reads.
type ttlOption struct {
	Value string
	Label string
	// Selected marks the default entry, offered only for a human Account.
	Selected bool
}

// accountRow is one Account.
//
// The two times are time.Time and not preformatted strings: the template calls
// {{stamp .LastAuthAt}}, and stamp (screen.go) owns the screen-wide rendering
// of a zero time as "—". Formatting either of them in Go here would be a
// SECOND rendering of "never", which is how two places on one Console come to
// disagree about what a blank cell means.
type accountRow struct {
	Name  string
	Kind  string
	Role  string
	State string

	LastAuthAt time.Time
	LastCallAt time.Time

	// LastCallHref points at Activity scoped to this Account by its verified
	// ID (spec 15 Rows; spec 04 ?account=; D18: an ID, never a name).
	LastCallHref string

	// EditHref is the Account page. EnableHref is its state section, set only
	// for a disabled Account when the write half is wired: Enable never acts
	// from the row, because it takes a password. DisableAction is the
	// confirmation page, set for an enabled Account that is not the caller's
	// own, when the write half is wired.
	EditHref      string
	EnableHref    string
	DisableAction string
	Self          bool

	// The accessible names of the three actions; each begins with the visible
	// text, so the name and the label agree.
	EditLabel, DisableLabel, EnableLabel string

	// Machine scopes the last-tool-call cell: spec 15 asks for it on machine
	// Accounts, and a human Account's empty cell is correct rather than
	// missing.
	Machine bool
}

// accountChange is the Account page's role and state controls. Built when the
// write half is wired; the list carries none.
//
// The ACTIONS, not the raw id, so an Account id never lands in a rendered form
// VALUE — the id is in the path, escaped once by the builder that made it.
type accountChange struct {
	// Role is the held role, shown as the disabled "(current)" option.
	Role string
	// State is the display word for the Account's state.
	State string
	// Enabled decides which form renders, Disable or Enable. The asymmetry
	// (Disable needs no password, Enable does) is in the markup, not here.
	Enabled       bool
	RoleAction    string
	EnabledAction string
	// LowerAction and DisableAction are the confirmation pages
	// (accounts_confirm.go) the two danger buttons GET; neither performs the act.
	LowerAction   string
	DisableAction string

	// RaiseRoles are the roles above the held one (Raise role: password,
	// .btn.grant); LowerRoles the roles below it (Lower role: no password,
	// .btn.danger, through a confirmation page). Presentation only:
	// handleSetAccountRole re-decides raise vs lower from the stored role.
	RaiseRoles []string
	LowerRoles []string

	// Self is capability.SelfTargeted(caller, the Account's ID): the capability layer
	// would refuse every change here, so no control renders and SelfNote says
	// why (spec 15 States, "Say why"). Narrowing only: the refusal stays the
	// capability layer's, and a hand-built POST is still refused there.
	Self     bool
	SelfNote string // = selfPanelNote
}

// tokenRow is one API Token, as far as a screen is ever allowed to see one.
//
// THERE IS NO FIELD A SECRET COULD OCCUPY: no []byte, no SecretHash, no
// Plaintext. accounts.APIToken carries a SecretHash and capability's mint
// carries a Plaintext; neither crosses into this type, so "no token value ever
// renders" is a property of the struct rather than a rule the template has to
// keep remembering. TestAccounts_ATokenRowHasNoFieldASecretCouldOccupy is the
// guard.
type tokenRow struct {
	ID   string
	Name string

	CreatedAt  time.Time
	LastUsedAt time.Time

	// ExpiresAt is zero for a token that does not expire, which the template
	// says in words. That is a different fact from "never used", so it does
	// not go through stamp's "—".
	ExpiresAt time.Time

	Revoked bool

	// RevokeAction is this token's confirmation page. Empty when the write
	// half is not wired. A NAME, an id and a path — still no field a secret
	// could occupy.
	RevokeAction string
}

func handleAccounts(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := principal(w, r)
		if !ok {
			return
		}
		p, ok := page(d, w, r, "Accounts")
		if !ok {
			return
		}
		p.Banner = banner(d, r)

		if d.Queries == nil {
			unavailable(w, queryLaneName)
			return
		}
		if d.Accounts == nil {
			unavailable(w, "Account administration")
			return
		}
		d, lane := latched(d)

		// The trail read is FIRST and UNCONDITIONAL, and the reason is what
		// the screen is rather than what a fixture contains: spec 15 asks for
		// a machine Account's last tool call by name, so that column is part
		// of this screen, and a page that read the trail only when it happened
		// to hold a machine Account would render a column whose absence looked
		// exactly like "this Account has made no calls".
		//
		// Two properties follow from making it unconditional. "Exactly one
		// query_audit per page view" becomes a property rather than a
		// coincidence of the Accounts the Relay holds; and the route stays
		// provably audited under the real-lane sweep, which a conditional read
		// could not be — against a fixture with no machine Account it would
		// record nothing and the sweep would have nothing to assert.
		//
		// The third option, rejected: classify the trail read as EXEMPT with a
		// why (read_audit_test.go). Rejected on properties, not on taste — an
		// exempt route is skipped by the real-lane sweep, so the read would go
		// unproven, and it drops out of
		// TestConsole_AnUnauditableReadRefusesTheScreen entirely, which would
		// leave a read this Relay cannot audit free to render the screen.
		pg, err := d.Queries.QueryAudit(r.Context(), caller,
			capability.AuditFilter{Kinds: agentCallKinds},
			capability.PageRequest{Limit: accountsCallPage})
		if err != nil {
			readFailed(w, err, "the AI-agent call trail")
			return
		}
		if refusedUnaudited(w, lane, "the AI-agent call trail") {
			return
		}

		// Keyed on the VERIFIED Account id, which is the join the trail
		// supports. The link below carries the same id, which is what
		// /console/activity?account= filters on (D18). The page is
		// newest-first by contract (capability.AuditPage), and this takes the
		// maximum anyway so the cell cannot come to depend on that ordering.
		lastCallByAccountID := map[string]time.Time{}
		for _, row := range pg.Rows {
			f := factsOfRow(row)
			if f.VerifiedAccountID == "" {
				continue
			}
			if at, seen := lastCallByAccountID[f.VerifiedAccountID]; !seen || f.Timestamp.After(at) {
				lastCallByAccountID[f.VerifiedAccountID] = f.Timestamp
			}
		}

		accts, err := d.Accounts.Accounts(r.Context(), caller)
		if err != nil {
			accountsReadFailed(w, p, err)
			return
		}

		v := accountsView{
			CallPage: accountsCallPage,
			Done:     doneSentence(r.URL.Query().Get("done")),
		}
		if accountsOffered(d) {
			v.Write = &accountsWriteControls{
				CSRFToken:   p.CSRFToken,
				StepUpFresh: stepUpFresh(d, r),
			}
			v.NewAccountHref = newAccountPath
		}

		for _, a := range accts {
			row := accountRow{
				Name: a.Name,
				Kind: string(a.Kind),
				Role: string(a.Role),
				// In words, never a bare boolean: "false" in a Status column is
				// a sentence nobody can read at a glance during an incident.
				State:      accountState(a.Enabled),
				LastAuthAt: a.LastSeenAt,
				Machine:    a.Kind == accounts.KindMachine,
				Self:       capability.SelfTargeted(caller, a.ID),
				// PathEscape, never concatenation: an Account name is not
				// constrained to be URL-safe by this package.
				EditHref:     accountPagePath(a.Name),
				EditLabel:    "Edit " + a.Name,
				DisableLabel: "Disable " + a.Name,
				EnableLabel:  "Enable " + a.Name,
				LastCallHref: "/console/activity?" + url.Values{"account": {a.ID}}.Encode(),
			}
			if v.Write != nil {
				switch {
				case !a.Enabled:
					row.EnableHref = row.EditHref + "#state"
				case !row.Self:
					row.DisableAction = confirmDisableAction(a.ID)
				}
			}
			if row.Machine {
				row.LastCallAt = lastCallByAccountID[a.ID]
			}
			v.Accounts = append(v.Accounts, row)
		}

		p.Scripts = []string{accountsScript}
		renderScreen(w, p, accountsTmpl, v)
	}
}

// accountsScript opens New account and Edit in a dialog; see accounts.js.
var accountsScript = assetURL("accounts.js")

// accountKinds is the closed Account kind set, from the domain's constants.
func accountKinds() []string {
	return []string{string(accounts.KindHuman), string(accounts.KindMachine)}
}

// allRoleNames is the closed role set, in ascending authority, built from the
// domain's own constants so this screen cannot drift from it.
func allRoleNames() []string {
	return []string{string(accounts.RoleViewer), string(accounts.RoleOperator), string(accounts.RoleAdmin)}
}

// roleTargets splits the closed role set, minus the one held, into the roles a
// change would RAISE to and the roles it would LOWER to. Presentation only —
// it decides which form offers which target, and handleSetAccountRole
// re-decides from the stored role. It reuses roleChangeCouldGrant, so an
// invalid held role fails closed: every target lands in raise and costs a
// password.
func roleTargets(held accounts.Role) (raise, lower []string) {
	for _, r := range allRoleNames() {
		if r == string(held) {
			continue
		}
		if roleChangeCouldGrant(held, accounts.Role(r)) {
			raise = append(raise, r)
		} else {
			lower = append(lower, r)
		}
	}
	return raise, lower
}

// ttlOptions projects the mint form's closed lifetime vocabulary
// (ttlChoices, accounts_write.go) onto the view, so the handler that PARSES a
// value and the template that OFFERS one read from a single list.
//
// The default entry is left out unless kind is human: a machine Account's
// lifetime has no default (capability.ErrAPITokenTTLRequired).
func ttlOptions(kind accounts.Kind) []ttlOption {
	out := make([]ttlOption, 0, len(ttlChoices))
	for _, c := range ttlChoices {
		if c.Default && kind != accounts.KindHuman {
			continue
		}
		out = append(out, ttlOption{Value: c.Value, Label: c.Label, Selected: c.Default})
	}
	return out
}

// accountState renders the durable off-switch in words.
func accountState(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

// accountsRefusedTmpl renders a refusal the capability layer made. It reuses
// cancelResultView (cancel.go) for the same reason that type is small: the
// interesting rendering is the layer's own sentence, and this page exists only
// to carry it.
var accountsRefusedTmpl = newScreen("accounts-refused", `
<div class="placeholder">
  <p>{{.Heading}}</p>
</div>
`)

var accountsTmpl = newScreen("accounts", `
<div class="pagehead">
  {{with .Done}}<p class="done" role="status">{{.}}</p>{{end}}
  {{with .NewAccountHref}}<a class="btn grant" href="{{.}}" data-modal-trigger data-modal-title="New account">New account</a>{{end}}
</div>

{{if not .Write}}<p class="note">Account and token changes are not wired into this Relay&#39;s Console.</p>{{end}}

<div class="tablescroll">
<table class="rows cards">
  <thead><tr><th scope="col">Name</th><th scope="col">Kind</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col">Last authentication</th><th scope="col">Last tool call</th><th scope="col"><span class="vh">Actions</span></th></tr></thead>
  <tbody>
  {{range .Accounts}}
    <tr>
      <td data-label="Name">{{.Name}}</td>
      <td data-label="Kind"><span class="kind" data-kind="{{.Kind}}">{{.Kind}}</span></td>
      <td data-label="Role">{{.Role}}</td>
      <td data-label="Status">{{.State}}</td>
      <td data-label="Last authentication">{{stamp .LastAuthAt}}</td>
      <td data-label="Last tool call">{{if .Machine}}{{if .LastCallAt.IsZero}}<span class="dim">no tool call in the last {{$.CallPage}} recorded calls</span>{{else}}<a href="{{.LastCallHref}}">{{stamp .LastCallAt}}</a>{{end}}{{end}}</td>
      <td data-label="Actions"><div class="rowacts">
        <a class="btn" href="{{.EditHref}}" aria-label="{{.EditLabel}}" data-modal-trigger data-modal-title="{{.Name}}">Edit</a>
        {{if .DisableAction}}<form class="ctlform" method="get" action="{{.DisableAction}}">
          <input type="hidden" name="from" value="list">
          <button class="btn danger" type="submit" aria-label="{{.DisableLabel}}">Disable</button>
        </form>{{end}}
        {{if .EnableHref}}<a class="btn" href="{{.EnableHref}}" aria-label="{{.EnableLabel}}" data-modal-trigger data-modal-title="{{.Name}}">Enable</a>{{end}}
      </div></td>
    </tr>
  {{end}}
  </tbody>
</table>
</div>

<dialog id="acctdlg" class="modal" aria-labelledby="acctdlg-title">
  <div class="modalbox">
    <div class="modalhead">
      <h2 id="acctdlg-title" data-modal-title></h2>
      <button type="button" class="modalx" data-modal-close aria-label="Close">&times;</button>
    </div>
    <div class="modalbody" data-modal-body></div>
    <div class="modalfoot"><button type="button" class="btn" data-modal-close>Cancel</button></div>
  </div>
</dialog>
`)

// isAgentCallKind reports whether an audit Kind describes a call somebody
// made THROUGH a control surface, as opposed to something the Relay did.
//
// It is the SOURCE of the last-tool-call read's kind filter (agentCallKinds
// below), not a per-row test: it runs once per audit Kind at var-init, and the
// Kinds filter does the selecting in SQL.
//
// Sign-ins, Freeze transitions and Account changes are control-plane events
// and belong on Activity. An approval expiring is the clock, not a caller.
//
// # The eight tools are six families
//
// `cancel_job` and the Preflight once matched neither arm and rendered NOWHERE,
// against the retired Agents screen's first acceptance criterion — every one
// of the eight tools renders with a request line and a result line. Both are calls in
// exactly the sense this function means: an Account asked a control surface for
// something and the Relay recorded the ask. They are now families of their own
// (rowCancel, rowPlan; spec 04, Row kinds), so they are admitted by family like
// the rest, and rowOther stays out: it is the catch-all for every audit kind
// nobody has classified yet, and admitting it would put a kind added to
// internal/audit next month on the trust surface with nobody having decided it
// belonged.
func isAgentCallKind(kind string) bool {
	switch kindOf(kind) {
	case rowDispatch, rowRead, rowRefusal, rowApproval, rowPlan, rowCancel:
		// The intent record is not a call: the last-tool-call read keeps
		// reading the outcome row.
		return kind != audit.KindApprovalExpired && kind != audit.KindDispatchIntent
	default:
		return false
	}
}

// agentCallKinds is the last-tool-call read's kind filter, DERIVED from audit.Kinds()
// through isAgentCallKind rather than hand-listed — the same derived-not-
// enumerated shape buildKindsByFamily (activity.go) uses. Deriving it means
// the filter and the predicate cannot drift, and a kind added to
// internal/audit is classified by isAgentCallKind rather than by a second
// hand-kept list nobody remembers to update.
//
// Eight kinds today, against AuditFilter.validate's cap of 32.
// approval_expired stays excluded exactly as isAgentCallKind decides.
var agentCallKinds = buildAgentCallKinds()

// buildAgentCallKinds panics if isAgentCallKind admits nothing.
//
// This is not a defensive nicety. capability.AuditFilter's documented
// zero-value semantics are that an EMPTY Kinds slice matches EVERY ROW, not
// none — the same trap noSuchAuditKind (activity.go) exists to prevent for
// row families. An empty agentCallKinds would therefore not narrow the filter
// to nothing, it would silently WIDEN it to the whole trail: login, token
// mint, Account and Freeze records — including login_failed's asserted
// submitted usernames — would land on this read's trust surface into the
// last-tool-call read. A future refactor of kindOf that
// renamed a row family and left isAgentCallKind's switch matching nothing
// would produce exactly that, silently, with every existing test still
// green. A Relay that cannot derive its own AI-agent-call kind set must not
// start serving this read with a filter that means "everything".
func buildAgentCallKinds() []string {
	var out []string
	for _, k := range audit.Kinds() {
		if isAgentCallKind(k) {
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		panic("console: isAgentCallKind admits no audit kind at all — an empty " +
			"agentCallKinds would match EVERY row (capability.AuditFilter's " +
			"empty-Kinds-matches-all semantics), putting login, token, Account " +
			"and Freeze records on the AI-agent call filter")
	}
	return out
}
