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
// the disclosure (ADR-0026 decision 5, ADR-0009's absent-beats-forbidden).
// Nothing in this file compares a role. If a read is refused, what renders is
// the capability layer's own refusal text.
//
// # The table renders unconditionally
//
// There is no "you have no Accounts" branch, because that Relay cannot exist.
// EnsureFoundingAdmin runs at startup (relay/cmd/relay/main.go) inside the
// same ControlEnabled branch that mounts the Console, and fails the boot
// closed if it cannot seed; it creates an enabled human admin. So a Console
// that is serving this route is a Console with at least one Account, an
// else-branch here would be dead copy, and the honest first-boot shape is one
// row under a <thead> rather than an empty state. dayone_test.go carries the
// matching named skip, and TestAccounts_DayOneShowsTheFoundingAdmin pins the
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
// The screen draws the selected Account's panel first, then the read-only
// list, then the create form behind "New account" (design spec 15, D32).
//
// The write half lives in accounts_write.go, and this file renders forms as
// well as rows. The three acts that reduce authority open their confirmation
// pages (accounts_confirm.go) instead of posting; this screen posts only the
// granting forms. The forms for an existing Account render only in the
// SELECTED Account's panel; the list is read-only. What stays absent is
// a role or PERMISSION editor of any kind — the three roles are ADR-0010's
// closed set and a custom-permission builder is a second authorization model —
// and any Relay configuration whatsoever. The one place a minted credential appears is
// accounts_write.go's mint response, never this screen.

import (
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

// accountsCallPage is how many recorded AI-agent calls this screen looks back
// over for each machine Account's last call. It is rendered into the copy, so
// the honest-absence sentence states the real number rather than a rounded
// one.
const accountsCallPage = 200

// policyCeilingNote is the sentence the screen must not lose: a role is a
// ceiling on what the RELAY will ask for, and every Node's own Policy is the
// ceiling on what actually runs (ADR-0002, invariant 2). What each role may do
// is ADR-0010's and GLOSSARY.md's, not this screen's.
const policyCeilingNote = "A role bounds what this Relay will ask of a Node; each Node's own Policy is the real ceiling."

// selfPanelNote is why the signed-in Account's own panel carries no control.
// The refusal page's fuller sentence, selfTargetRefusal, is the capability
// layer's refusal; this is the panel's one-line rendering of the same rule.
const selfPanelNote = "This is your own Account; another admin must change its role or state."

// accountsView is the whole screen.
type accountsView struct {
	Accounts []accountRow

	// Selected is the raw ?account= value, echoed only in the note that says
	// no such Account exists. SelectedName is the resolved Account's own name,
	// which is what the token panel is headed with.
	Selected      string
	SelectedName  string
	SelectedFound bool

	Tokens           []tokenRow
	TokensUnreadable bool

	// Change is the selected Account's role and state controls. Nil
	// when nothing is selected or the write half is not wired.
	Change *accountChange

	// SelectedMintAction is the selected Account's mint form action,
	// empty when nothing is selected or the write half is not wired. The
	// mint form lives in the token panel because minting is about ONE
	// Account, and the panel is the only part of this screen that is.
	SelectedMintAction string

	CallPage int
	Ceiling  string

	// Write is nil when the write half is not wired (accounts_write.go):
	// no form of any kind renders, which is the honest-absence posture every
	// other seam on this Deps takes. accountsOffered decides it.
	Write *accountsWriteControls

	// Create is the "New account" form; nil exactly when Write is.
	Create *accountCreateForm

	// LowerHint is drawn inside the Lower role form (lowerRoleHint).
	LowerHint string
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

// accountCreateForm is the "New account" form. One type serves the screen
// (Open false, no echo) and the refused re-render, which draws the same
// definition open with the caller's own submission echoed back. The echoes are
// bounded by handleCreateAccount and escaped by html/template. There is no
// password field, so a password cannot be echoed.
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
	Open        bool
	Refusal     string
	Name        string
	Kind        string
	Role        string
}

// ttlOption is one entry in the mint form's closed lifetime select. The
// VALUE is what the handler parses (ttlFor, accounts_write.go); the label is
// what an operator reads.
type ttlOption struct {
	Value string
	Label string
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
	// ID (spec 15 Rows; spec 04 ?account=; D18: an ID, never a name). Href
	// selects this Account on this screen.
	LastCallHref string
	Href         string

	// Machine scopes the last-tool-call cell: spec 15 asks for it on machine
	// Accounts, and a human Account's empty cell is correct rather than
	// missing. Current marks the Account the token panel is about.
	Machine bool
	Current bool
}

// accountChange is the selected Account's role and state controls. Built
// only for the SELECTED Account when the write half is wired; the list carries
// none.
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
	// .btn.danger, through a confirmation page). Presentation only: handleSetAccountRole re-decides raise
	// vs lower from the stored role.
	RaiseRoles []string
	LowerRoles []string

	// Self is capability.SelfTargeted(caller, selected.ID): the capability layer
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
		switch {
		case err == nil:
		case errors.Is(err, authz.ErrUnauthorized):
			// The capability layer decided this, and this screen renders what
			// it decided — it does not restate the rule, re-derive the floor,
			// or translate the sentence (invariant 10).
			w.WriteHeader(http.StatusForbidden)
			renderScreen(w, p, accountsRefusedTmpl, cancelResultView{
				Heading: "The Relay refused this read: " + err.Error() + ".",
			})
			return
		case errors.Is(err, capability.ErrAccountsUnavailable):
			unavailable(w, "Account administration")
			return
		default:
			unreadable(w, "the Account registry")
			return
		}

		v := accountsView{
			Selected: r.URL.Query().Get("account"),
			CallPage: accountsCallPage,
			Ceiling:  policyCeilingNote,
		}
		if accountsOffered(d) {
			fresh := stepUpFresh(d, r)
			v.Write = &accountsWriteControls{
				CSRFToken:   p.CSRFToken,
				StepUpFresh: fresh,
				TTLs:        ttlOptions(),
			}
			v.Create = &accountCreateForm{
				CSRFToken:    p.CSRFToken,
				CreateAction: createAccountAction(),
				StepUpFresh:  fresh,
				Roles:        allRoleNames(),
				Kinds:        accountKinds(),
			}
			v.LowerHint = lowerRoleHint
		}

		var selected accounts.Account
		for _, a := range accts {
			row := accountRow{
				Name: a.Name,
				Kind: string(a.Kind),
				Role: string(a.Role),
				// In words, never a bare boolean: "false" in a State column is
				// a sentence nobody can read at a glance during an incident.
				State:      accountState(a.Enabled),
				LastAuthAt: a.LastSeenAt,
				Machine:    a.Kind == accounts.KindMachine,
				Current:    a.Name == v.Selected,
				// url.Values, never concatenation: an Account name is not
				// constrained by this package, and "bob&co" concatenated
				// links to the wrong Account.
				Href:         "/console/accounts?" + url.Values{"account": {a.Name}}.Encode(),
				LastCallHref: "/console/activity?" + url.Values{"account": {a.ID}}.Encode(),
			}
			if row.Machine {
				row.LastCallAt = lastCallByAccountID[a.ID]
			}
			v.Accounts = append(v.Accounts, row)

			if a.Name == v.Selected {
				selected, v.SelectedFound, v.SelectedName = a, true, a.Name
			}
		}

		if v.SelectedFound {
			if v.Write != nil {
				v.SelectedMintAction = mintAPITokenAction(selected.ID)
				raise, lower := roleTargets(selected.Role)
				v.Change = &accountChange{
					Role:          string(selected.Role),
					State:         accountState(selected.Enabled),
					Enabled:       selected.Enabled,
					RoleAction:    setAccountRoleAction(selected.ID),
					EnabledAction: setAccountEnabledAction(selected.ID),
					LowerAction:   confirmLowerRoleAction(selected.ID),
					DisableAction: confirmDisableAction(selected.ID),
					RaiseRoles:    raise,
					LowerRoles:    lower,
					Self:          capability.SelfTargeted(caller, selected.ID),
					SelfNote:      selfPanelNote,
				}
			}
			tokens, tokErr := d.Accounts.APITokens(r.Context(), caller, selected.ID)
			switch {
			case tokErr == nil:
				for _, t := range tokens {
					row := tokenRow{
						ID:         t.ID,
						Name:       t.Name,
						CreatedAt:  t.CreatedAt,
						LastUsedAt: t.LastUsedAt,
						ExpiresAt:  t.ExpiresAt,
						Revoked:    t.Revoked(),
					}
					// Revoke is offered for any token not ALREADY revoked,
					// including an expired one: revoking an expired token is
					// harmless and idempotent (capability's RevokeAPIToken),
					// and refusing it would be a second opinion about token
					// state this screen must not hold.
					if v.Write != nil && !row.Revoked {
						row.RevokeAction = confirmRevokeAction(selected.ID, t.ID)
					}
					v.Tokens = append(v.Tokens, row)
				}
			case errors.Is(tokErr, authz.ErrUnauthorized):
				w.WriteHeader(http.StatusForbidden)
				renderScreen(w, p, accountsRefusedTmpl, cancelResultView{
					Heading: "The Relay refused this read: " + tokErr.Error() + ".",
				})
				return
			default:
				// A store that failed degrades one panel rather than refusing
				// the page: the Account table beside it IS readable, and
				// pretending otherwise would hide what this operator can
				// still see. An UNAUDITABLE read is the other case and is
				// handled above, where it refuses everything.
				v.TokensUnreadable = true
			}
		}

		renderScreen(w, p, accountsTmpl, v)
	}
}

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
func ttlOptions() []ttlOption {
	out := make([]ttlOption, 0, len(ttlChoices))
	for _, c := range ttlChoices {
		out = append(out, ttlOption{Value: c.Value, Label: c.Label})
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

// accountsCreateRefusedTmpl is the create form alone, open, with the refusal.
// It is parsed on a clone of accountsTmpl so it draws the one "account-create"
// definition the screen draws and the two cannot drift.
var accountsCreateRefusedTmpl = template.Must(template.Must(accountsTmpl.Clone()).New("accounts-create-refused").Parse(`
{{template "account-create" .}}
<p class="back"><a href="/console/accounts">Back to Accounts</a></p>
`))

var accountsTmpl = newScreen("accounts", `
{{define "account-create"}}
<details class="panel newaccount" id="new-account"{{if .Open}} open{{end}}>
  <summary>New account</summary>
  {{with .Refusal}}<p class="fielderr" role="alert">{{.}}</p>{{end}}
  <form class="ctlform ctlgrid" method="post" action="{{.CreateAction}}">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <div class="fld">
      <label class="fldlabel" for="create-name">Name</label>
      <input id="create-name" name="name" maxlength="64" required autocomplete="off"{{with .Name}} value="{{.}}"{{end}}>
    </div>
    <div class="fld">
      <label class="fldlabel" for="create-kind">Kind</label>
      <select id="create-kind" name="kind">
        {{range .Kinds}}<option value="{{.}}"{{if eq . $.Kind}} selected{{end}}>{{.}}</option>{{end}}
      </select>
    </div>
    <div class="fld">
      <label class="fldlabel" for="create-role">Role</label>
      <select id="create-role" name="role">
        {{range .Roles}}<option value="{{.}}"{{if eq . $.Role}} selected{{end}}>{{.}}</option>{{end}}
      </select>
    </div>
    <div class="fld">
      <label class="fldlabel" for="create-password">{{if .StepUpFresh}}Your password to create an Account &mdash; optional, you confirmed it recently{{else}}Your password &mdash; required to create an Account{{end}}</label>
      <input id="create-password" name="password" type="password" autocomplete="current-password"{{if not .StepUpFresh}} required{{end}}>
    </div>
    <button class="btn grant" type="submit">Create Account</button>
  </form>
  <p class="note">A <b>human</b> Account cannot sign in until a password is set with <code>relay console-password</code> on the Relay host.</p>
</details>
{{end}}

{{if not .Write}}<p class="note">Account and token changes are not wired into this Relay&#39;s Console.</p>{{end}}

{{if .Selected}}
{{with .Change}}{{$c := .}}
<section class="panel">
  <h3>Role and state &mdash; <span class="ident">{{$.SelectedName}}</span></h3>
  <p class="rolestate">Role <b>{{.Role}}</b>, {{.State}}.</p>
  {{if .Self}}
  <p class="note">{{.SelfNote}}</p>
  {{else}}
  <div class="acctchange">
    {{with .RaiseRoles}}
    <form class="ctlform ctlrow rolechange" method="post" action="{{$c.RoleAction}}" autocomplete="off">
      <input type="hidden" name="csrf_token" value="{{$.Write.CSRFToken}}">
      <label class="fld"><span class="fldlabel">Raise role to</span>
        <select name="role" required>
          <option value="" selected disabled>{{$c.Role}} (current)</option>
          {{range .}}<option value="{{.}}">{{.}}</option>{{end}}
        </select>
      </label>
      <label class="fld"><span class="fldlabel">{{if $.Write.StepUpFresh}}Your password to raise a role &mdash; optional, you confirmed it recently{{else}}Your password &mdash; required to raise a role{{end}}</span>
        <input name="password" type="password" autocomplete="current-password"{{if not $.Write.StepUpFresh}} required{{end}}>
      </label>
      <button class="btn grant" type="submit">Raise role</button>
    </form>
    {{end}}
    {{with .LowerRoles}}
    <form class="ctlform ctlrow rolechange" method="get" action="{{$c.LowerAction}}" autocomplete="off">
      <label class="fld"><span class="fldlabel">Lower role to</span>
        <select name="role" aria-describedby="lower-role-hint">
          <option value="" selected disabled>{{$c.Role}} (current)</option>
          {{range .}}<option value="{{.}}">{{.}}</option>{{end}}
        </select>
      </label>
      <button class="btn danger" type="submit">Lower role</button>
      <span class="note" id="lower-role-hint">{{$.LowerHint}}</span>
    </form>
    {{end}}
    {{if $c.Enabled}}
    <form class="ctlform ctlrow" method="get" action="{{$c.DisableAction}}">
      <button class="btn danger" type="submit">Disable</button>
    </form>
    {{else}}
    <form class="ctlform ctlrow" method="post" action="{{$c.EnabledAction}}">
      <input type="hidden" name="csrf_token" value="{{$.Write.CSRFToken}}">
      <input type="hidden" name="enabled" value="true">
      <label class="fld"><span class="fldlabel">{{if $.Write.StepUpFresh}}Password to re-enable &mdash; optional, you confirmed it recently{{else}}Password &mdash; required to re-enable{{end}}</span>
        <input name="password" type="password" autocomplete="current-password"{{if not $.Write.StepUpFresh}} required{{end}}>
      </label>
      <button class="btn grant" type="submit">Enable</button>
    </form>
    {{end}}
  </div>
  {{end}}
</section>
{{end}}
<section class="panel">
  {{if .SelectedFound}}
  <h3>API Tokens &mdash; <span class="ident">{{.SelectedName}}</span></h3>
  {{if .TokensUnreadable}}
  <p class="note">This Account&#39;s API Tokens could not be read; the Account list below is unaffected.</p>
  {{else if .Tokens}}
  <div class="tablescroll">
  <table class="rows">
    <thead><tr><th scope="col">Token</th><th scope="col">Name</th><th scope="col">Created</th><th scope="col">Last used</th><th scope="col">Expires</th><th scope="col">State</th>{{if $.Write}}<th scope="col">Revoke</th>{{end}}</tr></thead>
    <tbody>
    {{range .Tokens}}
      <tr>
        <td><code>{{.ID}}</code></td>
        <td>{{.Name}}</td>
        <td>{{stamp .CreatedAt}}</td>
        <td>{{stamp .LastUsedAt}}</td>
        <td>{{if .ExpiresAt.IsZero}}<span class="dim">does not expire</span>{{else}}{{stamp .ExpiresAt}}{{end}}</td>
        <td>{{if .Revoked}}revoked{{else}}live{{end}}</td>
        {{if $.Write}}
        <td>{{with .RevokeAction}}
          <form class="ctlform" method="get" action="{{.}}">
            <button class="btn danger" type="submit">Revoke</button>
          </form>
        {{end}}</td>
        {{end}}
      </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  <p class="note">Revocation is immediate and permanent; there is no un-revoke.</p>
  {{else}}
  <p class="dim">This Account has no API Tokens.</p>
  {{end}}
  {{if and .Write .SelectedMintAction}}
  <form class="ctlform ctlgrid" method="post" action="{{.SelectedMintAction}}">
    <input type="hidden" name="csrf_token" value="{{.Write.CSRFToken}}">
    <div class="fld">
      <label class="fldlabel" for="mint-name">Token name</label>
      <input id="mint-name" name="name" maxlength="128" required autocomplete="off">
    </div>
    <div class="fld">
      <label class="fldlabel" for="mint-ttl">Lifetime</label>
      <select id="mint-ttl" name="ttl">
        {{range .Write.TTLs}}<option value="{{.Value}}">{{.Label}}</option>{{end}}
      </select>
    </div>
    <div class="fld">
      <label class="fldlabel" for="mint-password">{{if .Write.StepUpFresh}}Your password to mint a token &mdash; optional, you confirmed it recently{{else}}Your password &mdash; required to mint a token{{end}}</label>
      <input id="mint-password" name="password" type="password" autocomplete="current-password"{{if not .Write.StepUpFresh}} required{{end}}>
    </div>
    <button class="btn grant" type="submit">Mint API Token</button>
  </form>
  <p class="note">The value is shown once, on the response to this form, and never again.</p>
  {{end}}
  {{else}}
  <div class="placeholder">
    <p>No Account on this Relay is named <code>{{.Selected}}</code>.</p>
    <p><a href="/console/accounts">Show every Account</a>.</p>
  </div>
  {{end}}
</section>
{{end}}

<div class="tablescroll">
<table class="rows cards">
  <thead><tr><th scope="col">Account</th><th scope="col">Kind</th><th scope="col">Role</th><th scope="col">State</th><th scope="col">Last authentication</th><th scope="col">Last tool call</th></tr></thead>
  <tbody>
  {{range .Accounts}}
    <tr>
      <td data-label="Account">{{if .Current}}<b>{{.Name}}</b>{{else}}<a href="{{.Href}}">{{.Name}}</a>{{end}}</td>
      <td data-label="Kind"><span class="kind" data-kind="{{.Kind}}">{{.Kind}}</span></td>
      <td data-label="Role">{{.Role}}</td>
      <td data-label="State">{{.State}}</td>
      <td data-label="Last authentication">{{stamp .LastAuthAt}}</td>
      <td data-label="Last tool call">{{if .Machine}}{{if .LastCallAt.IsZero}}<span class="dim">no tool call in the last {{$.CallPage}} recorded calls</span>{{else}}<a href="{{.LastCallHref}}">{{stamp .LastCallAt}}</a>{{end}}{{end}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
</div>
<p class="note">{{.Ceiling}}</p>

{{with .Create}}{{template "account-create" .}}{{end}}
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
