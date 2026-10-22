package console

// accounts_page.go is the Account page and the New account page: the
// no-JavaScript pages spec 15 names for Edit and New account. Their forms post
// to the unchanged write routes (accounts_write.go) by Account ID; the name in
// the path only locates the page. Nothing here compares a role (invariant 10).

import (
	"errors"
	"net/http"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

// roleLine is one row of the "What this role may do" panel.
type roleLine struct {
	Role        string
	Description string
}

// accountPageView is the Account page.
//
// Every role-bearing field on an Accounts view model is a plain string, never
// accounts.Role, so no template can call .Role.Description where the module
// guard in internal/accounts cannot see it.
type accountPageView struct {
	Name  string
	Kind  string
	Role  string
	State string
	Done  string

	// Write is nil when the write half is not wired; no form renders then.
	Write *accountsWriteControls
	// Change is the role and state controls; nil exactly when Write is.
	Change     *accountChange
	MintAction string

	Tokens           []tokenRow
	TokensUnreadable bool

	// LowerHint is drawn inside the Lower role form (lowerRoleHint).
	LowerHint string
}

// roleLines is the role panel's text, one entry per role in ascending
// authority, from the one shared description (accounts.Role.Description). It
// describes and never decides.
func roleLines() []roleLine {
	var out []roleLine
	for _, r := range allRoleNames() {
		out = append(out, roleLine{Role: r, Description: accounts.Role(r).Description()})
	}
	return out
}

// newAccountForm is the New account page's form with nothing echoed.
func newAccountForm(csrf string, fresh bool) accountCreateForm {
	return accountCreateForm{
		CSRFToken:    csrf,
		StepUpFresh:  fresh,
		CreateAction: createAccountAction(),
		Roles:        allRoleNames(),
		Kinds:        accountKinds(),
		RoleLines:    roleLines(),
	}
}

// accountsReadFailed maps a failed Account-registry read to its page. The
// capability layer's refusal is rendered as it made it, not restated.
func accountsReadFailed(w http.ResponseWriter, p Page, err error) {
	switch {
	case errors.Is(err, authz.ErrUnauthorized):
		w.WriteHeader(http.StatusForbidden)
		renderScreen(w, p, accountsRefusedTmpl, cancelResultView{
			Heading: "The Relay refused this read: " + err.Error() + ".",
		})
	case errors.Is(err, capability.ErrAccountsUnavailable):
		unavailable(w, "Account administration")
	default:
		unreadable(w, "the Account registry")
	}
}

type accountMissingView struct {
	Name string
}

var accountMissingTmpl = newScreen("account-missing", `
<div class="placeholder">
  {{if .Name}}<p>No Account on this Relay is named <code>{{.Name}}</code>.</p>{{else}}<p>No Account on this Relay has that name.</p>{{end}}
  <p><a href="/console/accounts">Back to Accounts</a></p>
</div>
`)

// accountMissing is the one 404 for GET /console/accounts/{account_name}. name
// is echoed only when it is within the length an Account name can have.
func accountMissing(w http.ResponseWriter, p Page, name string) {
	w.WriteHeader(http.StatusNotFound)
	renderScreen(w, p, accountMissingTmpl, accountMissingView{Name: name})
}

// pageDoneSentence is doneSentence, except that the enabled and disabled lines
// show only when the Account is in the state they claim, so a crafted link
// cannot make the page assert a change that did not happen. The other lines are
// presentation only and cannot be checked against the Account.
func pageDoneSentence(raw string, enabled bool) string {
	switch doneKey(raw) {
	case doneEnabled:
		if !enabled {
			return ""
		}
	case doneDisabled:
		if enabled {
			return ""
		}
	}
	return doneSentence(raw)
}

// handleAccount implements GET /console/accounts/{account_name}.
func handleAccount(d Deps) http.HandlerFunc {
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

		name := r.PathValue("account_name")
		if name == "" || len(name) > maxAccountNameBytes {
			accountMissing(w, p, "")
			return
		}

		// The page records its read exactly as the list does: one query_audit
		// through the read lane, and a refusal to render when it cannot be
		// recorded. It is unconditional, so the route stays under the audited
		// sweeps rather than becoming an exemption. The Account and API Token
		// reads below record nothing on success; this is the row that does.
		if _, err := d.Queries.QueryAudit(r.Context(), caller,
			capability.AuditFilter{Kinds: agentCallKinds},
			capability.PageRequest{Limit: 1}); err != nil {
			readFailed(w, err, "the AI-agent call trail")
			return
		}
		if refusedUnaudited(w, lane, "the AI-agent call trail") {
			return
		}

		// AccountReader has no by-name read; the page resolves the name by
		// listing and taking the exact match.
		accts, err := d.Accounts.Accounts(r.Context(), caller)
		if err != nil {
			accountsReadFailed(w, p, err)
			return
		}
		var a accounts.Account
		found := false
		for _, candidate := range accts {
			if candidate.Name == name {
				a, found = candidate, true
				break
			}
		}
		if !found {
			accountMissing(w, p, name)
			return
		}

		p.Title = a.Name
		v := accountPageView{
			Name:  a.Name,
			Kind:  string(a.Kind),
			Role:  string(a.Role),
			State: accountState(a.Enabled),
			Done:  pageDoneSentence(r.URL.Query().Get("done"), a.Enabled),
		}
		if accountsOffered(d) {
			v.Write = &accountsWriteControls{
				CSRFToken:   p.CSRFToken,
				StepUpFresh: stepUpFresh(d, r),
				TTLs:        ttlOptions(),
			}
			v.MintAction = mintAPITokenAction(a.ID)
			v.LowerHint = lowerRoleHint
			raise, lower := roleTargets(a.Role)
			v.Change = &accountChange{
				Role:          string(a.Role),
				State:         accountState(a.Enabled),
				Enabled:       a.Enabled,
				RoleAction:    setAccountRoleAction(a.ID),
				EnabledAction: setAccountEnabledAction(a.ID),
				LowerAction:   confirmLowerRoleAction(a.ID),
				DisableAction: confirmDisableAction(a.ID),
				RaiseRoles:    raise,
				LowerRoles:    lower,
				Self:          capability.SelfTargeted(caller, a.ID),
				SelfNote:      selfPanelNote,
			}
		}

		tokens, tokErr := d.Accounts.APITokens(r.Context(), caller, a.ID)
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
				// harmless and idempotent (capability's RevokeAPIToken), and
				// refusing it would be a second opinion about token state this
				// screen must not hold.
				if v.Write != nil && !row.Revoked {
					row.RevokeAction = confirmRevokeAction(a.ID, t.ID)
				}
				v.Tokens = append(v.Tokens, row)
			}
		case errors.Is(tokErr, authz.ErrUnauthorized):
			accountsReadFailed(w, p, tokErr)
			return
		default:
			// A store that failed degrades one section rather than refusing
			// the page: the Account itself IS readable, and pretending
			// otherwise would hide what this operator can still see.
			v.TokensUnreadable = true
		}

		renderScreen(w, p, accountPageTmpl, v)
	}
}

// handleNewAccount implements GET /console/new-account. It reads no Account
// data.
func handleNewAccount(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := principal(w, r); !ok {
			return
		}
		p, ok := page(d, w, r, "Accounts")
		if !ok {
			return
		}
		p.Banner = banner(d, r)
		if !accountsOffered(d) {
			unavailable(w, "Account administration")
			return
		}
		renderScreen(w, p, newAccountTmpl, newAccountForm(p.CSRFToken, stepUpFresh(d, r)))
	}
}

var accountPageTmpl = newScreen("account", `
<p class="back"><a href="/console/accounts">Back to Accounts</a></p>
{{with .Done}}<p class="done" role="status">{{.}}</p>{{end}}
<p class="accthead"><span class="kind" data-kind="{{.Kind}}">{{.Kind}}</span></p>

{{if not .Write}}<p class="note">Account and token changes are not wired into this Relay&#39;s Console.</p>{{end}}

<section class="panel" id="role">
  <h2>Role</h2>
  <p class="rolestate">Role <b>{{.Role}}</b>.</p>
  {{with .Change}}{{$c := .}}
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
  </div>
  {{end}}
  {{end}}
</section>

<section class="panel" id="state">
  <h2>State</h2>
  <p class="rolestate">{{.State}}.</p>
  {{with .Change}}{{$c := .}}
  {{if not .Self}}
  <div class="acctchange">
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
  {{end}}
</section>

<section class="panel" id="tokens">
  <h2>API Tokens</h2>
  {{if .TokensUnreadable}}
  <p class="note">This Account&#39;s API Tokens could not be read.</p>
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
  {{if and .Write .MintAction}}
  <form class="ctlform ctlgrid" method="post" action="{{.MintAction}}">
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
  {{end}}
</section>
`)

var newAccountTmpl = newScreen("new-account", `
<p class="back"><a href="/console/accounts">Back to Accounts</a></p>
<form class="ctlform ctlgrid" method="post" action="{{.CreateAction}}">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <div class="fld">
    <label class="fldlabel" for="create-name">Name</label>
    <input id="create-name" name="name" maxlength="64" required autocomplete="off"{{with .Name}} value="{{.}}"{{end}}>
  </div>
  <fieldset class="fld">
    <legend class="fldlabel">Kind</legend>
    {{range .Kinds}}<input type="radio" id="create-kind-{{.}}" name="kind" value="{{.}}" required{{if eq . $.Kind}} checked{{end}}>
    <label for="create-kind-{{.}}">{{.}}</label>
    {{end}}
  </fieldset>
  <fieldset class="fld" aria-describedby="role-descriptions">
    <legend class="fldlabel">Role</legend>
    {{range .Roles}}<input type="radio" id="create-role-{{.}}" name="role" value="{{.}}" required{{if eq . $.Role}} checked{{end}}>
    <label for="create-role-{{.}}">{{.}}</label>
    {{end}}
  </fieldset>
  <div class="rolepanel" id="role-descriptions">
    <h2>What this role may do</h2>
    <dl>
      {{range .RoleLines}}<dt>{{.Role}}</dt><dd>{{.Description}}</dd>
      {{end}}
    </dl>
  </div>
  <div class="fld">
    <label class="fldlabel" for="create-password">{{if .StepUpFresh}}Your password to create an Account &mdash; optional, you confirmed it recently{{else}}Your password &mdash; required to create an Account{{end}}</label>
    <input id="create-password" name="password" type="password" autocomplete="current-password"{{if not .StepUpFresh}} required{{end}}>
  </div>
  {{with .Refusal}}<p class="fielderr" role="alert">{{.}}</p>{{end}}
  <button class="btn grant" type="submit">Create account</button>
</form>
`)
