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
// where the boundary falls, never an inventory of editable values. No editor
// and no permission matrix: the write half is #655.

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

	CallPage  int
	RoleNotes []roleNote
	Ceiling   string
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
			tokens, tokErr := d.Accounts.APITokens(r.Context(), caller, selected.ID)
			switch {
			case tokErr == nil:
				for _, t := range tokens {
					v.Tokens = append(v.Tokens, tokenRow{
						ID:         t.ID,
						Name:       t.Name,
						CreatedAt:  t.CreatedAt,
						LastUsedAt: t.LastUsedAt,
						ExpiresAt:  t.ExpiresAt,
						Revoked:    t.Revoked(),
					})
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
authenticate as one. Reading this page changes nothing: creating, disabling and re-roling an
Account, and minting or revoking a token, are not offered here.</p>

<div class="tablescroll">
<table class="rows">
  <thead><tr><th>Account</th><th>Kind</th><th>Role</th><th>State</th><th>Last authentication</th><th>Last tool call</th></tr></thead>
  <tbody>
  {{range .Accounts}}
    <tr>
      <td>{{if .Current}}<b>{{.Name}}</b>{{else}}<a href="{{.Href}}">{{.Name}}</a>{{end}}</td>
      <td><span class="chip" data-kind="{{.Kind}}">{{.Kind}}</span></td>
      <td>{{.Role}}</td>
      <td>{{.State}}</td>
      <td>{{stamp .LastAuthAt}}</td>
      <td>{{if .Machine}}{{if .LastCallAt.IsZero}}<span class="dim">no tool call in the last {{$.CallPage}} recorded calls</span>{{else}}<a href="{{.LastCallHref}}">{{stamp .LastCallAt}}</a>{{end}}{{end}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
</div>
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
    <thead><tr><th>Token</th><th>Name</th><th>Created</th><th>Last used</th><th>Expires</th><th>State</th></tr></thead>
    <tbody>
    {{range .Tokens}}
      <tr>
        <td><code>{{.ID}}</code></td>
        <td>{{.Name}}</td>
        <td>{{stamp .CreatedAt}}</td>
        <td>{{stamp .LastUsedAt}}</td>
        <td>{{if .ExpiresAt.IsZero}}<span class="dim">does not expire</span>{{else}}{{stamp .ExpiresAt}}{{end}}</td>
        <td>{{if .Revoked}}revoked{{else}}live{{end}}</td>
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
