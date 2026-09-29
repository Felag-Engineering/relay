package console

// accounts.go is the Accounts screen, read half (#654, spec 15): who holds an
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
// page, which is the idiom agents.go already uses.
//
// The cost is stated on screen rather than hidden. An Account whose most
// recent call is older than the page renders "no tool call in the last N
// recorded calls" — never blank, never a zero, and never a claim that it has
// never called. Two alternatives were rejected in #654: one QueryAudit per
// machine Account (correct for arbitrarily old calls, but it writes N read
// records per page view, inflating the very trail Read egress renders), and a
// LastToolCallByAccount method on the read lane (the right answer, and scope
// this issue should not absorb).
//
// # What must not appear here (spec 15, "Must not appear")
//
// No token value and no SecretHash — tokenRow below has no field one could
// occupy, which is the structural half of that claim, and
// TestAccounts_NoConsoleFileNamesSecretHash is the other. No Relay
// configuration of any kind (invariant 11): the role block is prose about
// where the boundary falls, never an inventory of editable values.
//
// The write half landed in #655 (accounts_write.go), so this file now renders
// forms as well as rows. What stays absent is a role or PERMISSION editor of
// any kind — the three roles are ADR-0010's closed set and a custom-permission
// builder is a second authorization model — and any Relay configuration
// whatsoever. The one place a minted credential appears is
// accounts_write.go's mint response, never this screen.

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
)

// accountsCallPage is how many recorded agent calls this screen looks back
// over for each machine Account's last call. It is rendered into the copy, so
// the honest-absence sentence states the real number rather than a rounded
// one.
const accountsCallPage = 200

// policyCeilingNote is the sentence the role block must not lose: a role is a
// ceiling on what the RELAY will ask for, and every Node's own Policy is the
// ceiling on what actually runs (ADR-0002, invariant 2).
const policyCeilingNote = "A role bounds what this Relay will ask a Node to do. " +
	"It never widens what a Node will accept: each Node's own Policy is evaluated " +
	"on the Node, by the Node, and is always the real ceiling. No role on this " +
	"screen can raise it, and it cannot be changed from here."

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

	// SelectedMintAction is the selected Account's mint form action (#655),
	// empty when nothing is selected or the write half is not wired. The
	// mint form lives in the token panel because minting is about ONE
	// Account, and the panel is the only part of this screen that is.
	SelectedMintAction string

	CallPage  int
	RoleNotes []roleNote
	Ceiling   string

	// Write is nil when the write half is not wired (#655, accounts_write.go):
	// no form of any kind renders, which is the honest-absence posture every
	// other seam on this Deps takes. accountsOffered decides it.
	Write *accountsWriteControls
}

// accountsWriteControls is everything the write forms need that is not
// per-row: the CSRF token every Console POST carries, the create form's
// action, and the two CLOSED option lists its selects render from.
//
// The option lists are built from accounts.RoleViewer/Operator/Admin and
// accounts.KindHuman/KindMachine rather than hand-typed strings, so a screen
// and the domain cannot come to disagree about what the closed sets are.
type accountsWriteControls struct {
	CSRFToken    string
	CreateAction string
	Roles        []string
	Kinds        []string
	TTLs         []ttlOption
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

	// LastCallHref points at this Account's own slice of the agent stream
	// (spec 03). Href selects this Account on this screen.
	LastCallHref string
	Href         string

	// Machine scopes the last-tool-call cell: spec 15 asks for it on machine
	// Accounts, and a human Account's empty cell is correct rather than
	// missing. Current marks the Account the token panel is about.
	Machine bool
	Current bool

	// The per-row write actions (#655). The ACTIONS, not the raw id, so an
	// Account id never lands in a rendered form VALUE — the id is in the
	// path, escaped once by the builder that made it. Empty when the write
	// half is not wired.
	RoleAction    string
	EnabledAction string

	// Enabled drives which of the two state controls renders: an enabled row
	// gets a Disable button with no password field, a disabled row gets an
	// Enable form with a required one. The asymmetry is in the markup, not
	// only in the handler.
	Enabled bool

	// OtherRoles is the two roles this Account does not hold, so the per-row
	// role select offers a change and never a no-op.
	OtherRoles []string
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

	// RevokeAction is this token's revoke form action (#655). Empty when the
	// write half is not wired. A NAME, an id and a path — still no field a
	// secret could occupy.
	RevokeAction string
}

// roleNote is one role, described by the boundary it sits on.
type roleNote struct {
	Role  string
	Means string
}

// roleNotes is the "what a role means" block: boundaries, in prose.
//
// Deliberately not a permission matrix and deliberately not editable (spec
// 15's "Must not appear", invariant 11). It names where the two lines that
// matter fall — running an Operation at all, and Raw Exec plus the security
// lane's own label namespace — and stops there.
var roleNotes = []roleNote{
	{string(accounts.RoleViewer), "May read: the fleet, Jobs, the audit trail. It can ask this Relay " +
		"to show it things and can never ask a Node to do anything."},
	{string(accounts.RoleOperator), "May additionally run structured Operations — the typed vocabulary, " +
		"where the command is fixed by the Operation's author and an argument can never change " +
		"which command runs."},
	{string(accounts.RoleAdmin), "May additionally use Raw Exec — the caller-supplied, Policy-gated " +
		"exception to that vocabulary — and write the relay: labels the security lane targets. " +
		"It also administers this control plane, which is what makes this screen admin-only."},
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
			unavailable(w, "the audit and Job query lane")
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
		// why, which /console/approvals is precedent for
		// (read_audit_test.go). Rejected on properties, not on taste — an
		// exempt route is skipped by the real-lane sweep, so the read would go
		// unproven, and it drops out of
		// TestConsole_AnUnauditableReadRefusesTheScreen entirely, which would
		// leave a read this Relay cannot audit free to render the screen.
		pg, err := d.Queries.QueryAudit(r.Context(), caller,
			capability.AuditFilter{Kinds: agentCallKinds},
			capability.PageRequest{Limit: accountsCallPage})
		if err != nil {
			readFailed(w, err, "the agent call trail")
			return
		}
		if refusedUnaudited(w, lane, "the agent call trail") {
			return
		}

		// Keyed on the VERIFIED Account id, which is the join the trail
		// supports; the LINK below uses the name, which is what
		// /console/agents?account= filters on (agents.go). The page is
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
			Selected:  r.URL.Query().Get("account"),
			CallPage:  accountsCallPage,
			RoleNotes: roleNotes,
			Ceiling:   policyCeilingNote,
		}
		if accountsOffered(d) {
			v.Write = &accountsWriteControls{
				CSRFToken:    p.CSRFToken,
				CreateAction: createAccountAction(),
				Roles:        allRoleNames(),
				Kinds:        []string{string(accounts.KindHuman), string(accounts.KindMachine)},
				TTLs:         ttlOptions(),
			}
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
				// links to the wrong Account (#467).
				Href:         "/console/accounts?" + url.Values{"account": {a.Name}}.Encode(),
				LastCallHref: "/console/agents?" + url.Values{"account": {a.Name}}.Encode(),
				Enabled:      a.Enabled,
			}
			if row.Machine {
				row.LastCallAt = lastCallByAccountID[a.ID]
			}
			if v.Write != nil {
				row.RoleAction = setAccountRoleAction(a.ID)
				row.EnabledAction = setAccountEnabledAction(a.ID)
				row.OtherRoles = rolesOtherThan(a.Role)
			}
			v.Accounts = append(v.Accounts, row)

			if a.Name == v.Selected {
				selected, v.SelectedFound, v.SelectedName = a, true, a.Name
			}
		}

		if v.SelectedFound {
			if v.Write != nil {
				v.SelectedMintAction = mintAPITokenAction(selected.ID)
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
						row.RevokeAction = revokeAPITokenAction(t.ID)
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

// allRoleNames is the closed role set, in ascending authority, built from the
// domain's own constants so this screen cannot drift from it.
func allRoleNames() []string {
	return []string{string(accounts.RoleViewer), string(accounts.RoleOperator), string(accounts.RoleAdmin)}
}

// rolesOtherThan is the closed role set minus the one held, so a per-row role
// select offers a change and never a no-op.
func rolesOtherThan(held accounts.Role) []string {
	var out []string
	for _, r := range allRoleNames() {
		if r != string(held) {
			out = append(out, r)
		}
	}
	return out
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

var accountsTmpl = newScreen("accounts", `
<p class="lede">Every identity that can reach this control plane, and the credentials that
authenticate as one.{{if .Write}} Every act on this screen that could increase what a principal may
do &mdash; creating an Account, raising a role, re-enabling a disabled one, minting a token &mdash;
costs your password in the same request. Disabling, lowering a role and revoking a token only ever
reduce, so they do not.{{else}} Reading this page changes nothing: creating, disabling and re-roling
an Account, and minting or revoking a token, are not wired into this Relay's Console.{{end}}</p>

<div class="tablescroll">
<table class="rows">
  <thead><tr><th scope="col">Account</th><th scope="col">Kind</th><th scope="col">Role</th><th scope="col">State</th><th scope="col">Last authentication</th><th scope="col">Last tool call</th>{{if .Write}}<th scope="col">Change</th>{{end}}</tr></thead>
  <tbody>
  {{range .Accounts}}
    <tr>
      <td>{{if .Current}}<b>{{.Name}}</b>{{else}}<a href="{{.Href}}">{{.Name}}</a>{{end}}</td>
      <td><span class="kind" data-kind="{{.Kind}}">{{.Kind}}</span></td>
      <td>{{.Role}}</td>
      <td>{{.State}}</td>
      <td>{{stamp .LastAuthAt}}</td>
      <td>{{if .Machine}}{{if .LastCallAt.IsZero}}<span class="dim">no tool call in the last {{$.CallPage}} recorded calls</span>{{else}}<a href="{{.LastCallHref}}">{{stamp .LastCallAt}}</a>{{end}}{{end}}</td>
      {{if $.Write}}
      <td>
        <form method="post" action="{{.RoleAction}}">
          <input type="hidden" name="csrf_token" value="{{$.Write.CSRFToken}}">
          <label>Role
            <select name="role">
              {{range .OtherRoles}}<option value="{{.}}">{{.}}</option>{{end}}
            </select>
          </label>
          <label>Password &mdash; required to raise a role
            <input name="password" type="password" autocomplete="current-password">
          </label>
          <button type="submit">Set role</button>
        </form>
        {{if .Enabled}}
        <form method="post" action="{{.EnabledAction}}">
          <input type="hidden" name="csrf_token" value="{{$.Write.CSRFToken}}">
          <input type="hidden" name="enabled" value="false">
          <button type="submit">Disable</button>
        </form>
        {{else}}
        <form method="post" action="{{.EnabledAction}}">
          <input type="hidden" name="csrf_token" value="{{$.Write.CSRFToken}}">
          <input type="hidden" name="enabled" value="true">
          <label>Password &mdash; required to re-enable
            <input name="password" type="password" autocomplete="current-password" required>
          </label>
          <button type="submit">Enable</button>
        </form>
        {{end}}
      </td>
      {{end}}
    </tr>
  {{end}}
  </tbody>
</table>
</div>

{{with .Write}}
<section class="panel">
  <h3>Create an Account</h3>
  <form method="post" action="{{.CreateAction}}">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <label for="create-name">Name</label>
    <input id="create-name" name="name" maxlength="64" required>
    <label for="create-kind">Kind</label>
    <select id="create-kind" name="kind">
      {{range .Kinds}}<option value="{{.}}">{{.}}</option>{{end}}
    </select>
    <label for="create-role">Role</label>
    <select id="create-role" name="role">
      {{range .Roles}}<option value="{{.}}">{{.}}</option>{{end}}
    </select>
    <label for="create-password">Your password &mdash; creating an Account is a privilege-granting act</label>
    <input id="create-password" name="password" type="password" autocomplete="current-password" required>
    <button type="submit">Create Account</button>
  </form>
  <p class="note">A <b>human</b> Account created here cannot sign in until a password is set for it
  with <code>relay console-password</code> on the Relay host. Nothing on this screen can set one:
  that lever is local and root-owned on purpose, for the same reason
  <code>relay bootstrap-token</code> is.</p>
</section>
{{end}}
<p class="note">Last authentication is the most recent time this Account proved who it was — a
sign-in, or a token accepted. Last tool call is read from the agent call trail and looks back over
the last {{.CallPage}} recorded calls only, so an Account that called earlier than that reads as
absent from the window rather than as never having called.</p>

{{if .Selected}}
<section class="panel">
  {{if .SelectedFound}}
  <h3>API Tokens &mdash; {{.SelectedName}}</h3>
  {{if .TokensUnreadable}}
  <p class="note">The API Tokens for this Account could not be read. The table above is unaffected:
  it comes from a different read.</p>
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
          <form method="post" action="{{.}}">
            <input type="hidden" name="csrf_token" value="{{$.Write.CSRFToken}}">
            <button type="submit">Revoke</button>
          </form>
        {{end}}</td>
        {{end}}
      </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  <p class="note">A token&#39;s secret exists once, at the moment it is minted, and this Relay stores
  only a hash of it. Nothing on this screen can show it or recover it. Revocation is immediate and
  permanent — there is no un-revoke.</p>
  {{else}}
  <p class="dim">This Account has no API Tokens.</p>
  {{end}}
  {{if and .Write .SelectedMintAction}}
  <form method="post" action="{{.SelectedMintAction}}">
    <input type="hidden" name="csrf_token" value="{{.Write.CSRFToken}}">
    <label for="mint-name">Token name</label>
    <input id="mint-name" name="name" maxlength="128" required>
    <label for="mint-ttl">Lifetime</label>
    <select id="mint-ttl" name="ttl">
      {{range .Write.TTLs}}<option value="{{.Value}}">{{.Label}}</option>{{end}}
    </select>
    <label for="mint-password">Your password &mdash; minting brings a new credential into existence</label>
    <input id="mint-password" name="password" type="password" autocomplete="current-password" required>
    <button type="submit">Mint API Token</button>
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

<section class="panel">
  <h3>What a role means</h3>
  {{range .RoleNotes}}<p><b>{{.Role}}</b> &mdash; {{.Means}}</p>{{end}}
  <p class="note">{{.Ceiling}}</p>
</section>
`)
