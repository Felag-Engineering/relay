package console

// accounts_confirm.go is the confirmation step for the three acts that reduce
// authority: revoke a token, disable an Account, lower a role (design
// 00-foundations, "A destructive act asks a named confirmation"; spec 15, D24).
//
// It is a presentation step and not a control. It reads only through
// d.Accounts, calls no AccountAdmin method, adds no step-up, interprets no
// caller role and never reads an Account's kind. Pressing a danger button
// performs nothing: it GETs one of these pages, which names the target and the
// consequence and holds the single POST form. That form goes to the unchanged
// write route in accounts_write.go, where the capability layer decides exactly
// as it would without this page (invariant 10), so a hand-built POST needs
// only a valid CSRF token and never this page.
//
// The page offers its form under exactly the conditions the Accounts screen
// draws the button, and a page with no form and a link back otherwise. Those
// branches reuse existing presentation predicates (capability.SelfTargeted,
// roleTargets) and refuse nothing a POST would accept.
//
// The page carries the act's origin forward as a closed value (from=list, or
// the owning Account's ID on a revoke) so the act returns to the screen it was
// made from; neither is a URL.

import (
	"errors"
	"net/http"
	"net/url"
	"slices"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

// The three confirmation routes are GET /console/accounts/{account_id}/disable,
// .../{account_id}/lower and .../{account_id}/tokens/{token_id}/revoke. They
// cannot share the write routes' paths: Register mounts a bare-path
// registration for each constrained route, and two on one path panic. The
// revoke page carries the owning Account because AccountReader has no
// single-token read.

func confirmDisableAction(accountID string) string {
	return "/console/accounts/" + url.PathEscape(accountID) + "/disable"
}

func confirmLowerRoleAction(accountID string) string {
	return "/console/accounts/" + url.PathEscape(accountID) + "/lower"
}

func confirmRevokeAction(accountID, tokenID string) string {
	return "/console/accounts/" + url.PathEscape(accountID) + "/tokens/" + url.PathEscape(tokenID) + "/revoke"
}

// The consequence sentences, verbatim from spec 15's confirmation table.
const (
	revokeConsequence  = "Anything using it fails immediately; this cannot be undone."
	disableConsequence = "It can no longer sign in or call the Relay; re-enabling takes a password."
	lowerConsequence   = "Its API Tokens carry the lower role from their next request."
)

// hiddenField is one hidden input on the confirmation form.
type hiddenField struct {
	Name  string
	Value string
}

// accountConfirmView is one confirmation page.
type accountConfirmView struct {
	Act      string // "revoke" | "disable" | "lower": selects the question's shape
	Target   string // the token's name (revoke) or the Account's name
	From, To string // lower only
	// TokenID and Owner tell two equal token names apart; revoke only.
	TokenID     string
	Owner       string
	Consequence string
	// Action is the EXISTING write route the form posts to.
	Action    string
	CSRFToken string
	Hidden    []hiddenField
	Button    string
	Back      backLink
}

var accountsConfirmTmpl = newScreen("accounts-confirm", `
<section class="panel confirm">
  <p class="confirmq">{{if eq .Act "revoke"}}Revoke token <code>{{.Target}}</code>?{{else if eq .Act "disable"}}Disable <code>{{.Target}}</code>?{{else}}Lower <code>{{.Target}}</code> from <code>{{.From}}</code> to <code>{{.To}}</code>?{{end}} {{.Consequence}}</p>
  {{with .TokenID}}<p class="note">Token <code>{{.}}</code>, on <span class="ident">{{$.Owner}}</span>.</p>{{end}}
  <form class="ctlform ctlrow" method="post" action="{{.Action}}">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    {{range .Hidden}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">{{end}}
    <button class="btn danger" type="submit">{{.Button}}</button>
    <a href="{{.Back.Href}}">{{.Back.Label}}</a>
  </form>
</section>
`)

// confirmPrelude is the opening every confirmation handler shares: principal,
// nil-seam check, page. It reads no form, because these routes are GETs.
func confirmPrelude(d Deps, w http.ResponseWriter, r *http.Request) (capability.Principal, Page, bool) {
	caller, ok := principal(w, r)
	if !ok {
		return capability.Principal{}, Page{}, false
	}
	if !accountsOffered(d) {
		unavailable(w, "Account administration")
		return capability.Principal{}, Page{}, false
	}
	pg, ok := page(d, w, r, "Accounts")
	if !ok {
		return capability.Principal{}, Page{}, false
	}
	return caller, pg, true
}

// confirmRefusal renders a page with no form: what the confirmation cannot
// offer, and a link back.
func confirmRefusal(w http.ResponseWriter, pg Page, status int, heading string, back backLink) {
	renderWriteResult(w, pg, status, heading, back.Href, back.Label+".")
}

// confirmReadFailed maps a failed read to its page. writeFailed is not reused:
// its default sentence says a change may be partly recorded, which is false for
// a read.
func confirmReadFailed(w http.ResponseWriter, pg Page, err error, ident, what string) {
	switch {
	case errors.Is(err, authz.ErrUnauthorized):
		w.WriteHeader(http.StatusForbidden)
		renderScreen(w, pg, accountsRefusedTmpl, cancelResultView{
			Heading: "The Relay refused this read: " + err.Error() + ".",
		})
	case errors.Is(err, accounts.ErrNotFound):
		confirmRefusal(w, pg, http.StatusNotFound,
			"No Account matching "+ident+" appears in this Relay's records. Nothing was changed.",
			accountBack("", true))
	case errors.Is(err, accounts.ErrTokenNotFound):
		confirmRefusal(w, pg, http.StatusNotFound,
			"No API Token of this Account matches the request. Nothing was changed.",
			accountBack("", true))
	case errors.Is(err, capability.ErrAccountsUnavailable):
		unavailable(w, "Account administration")
	default:
		unreadable(w, what)
	}
}

func renderConfirm(w http.ResponseWriter, pg Page, v accountConfirmView) {
	v.CSRFToken = pg.CSRFToken
	renderScreen(w, pg, accountsConfirmTmpl, v)
}

// handleConfirmDisable implements GET /console/accounts/{account_id}/disable.
func handleConfirmDisable(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, pg, ok := confirmPrelude(d, w, r)
		if !ok {
			return
		}
		id, ok := pathID(w, r, "account_id", maxAccountIDBytes)
		if !ok {
			return
		}
		target, err := d.Accounts.Account(r.Context(), caller, id)
		if err != nil {
			confirmReadFailed(w, pg, err, id, "the Account registry")
			return
		}
		toList := cameFromList(r.URL.Query().Get(fromField))
		back := accountBack(target.Name, toList)
		if capability.SelfTargeted(caller, id) {
			confirmRefusal(w, pg, http.StatusConflict, selfTargetRefusal+" Nothing was changed.", back)
			return
		}
		if !target.Enabled {
			confirmRefusal(w, pg, http.StatusConflict, target.Name+" is already disabled. Nothing was changed.", back)
			return
		}
		hidden := []hiddenField{{Name: "enabled", Value: "false"}}
		if toList {
			hidden = append(hidden, hiddenField{Name: fromField, Value: fromList})
		}
		renderConfirm(w, pg, accountConfirmView{
			Act:         "disable",
			Target:      target.Name,
			Consequence: disableConsequence,
			Action:      setAccountEnabledAction(id),
			Hidden:      hidden,
			Button:      "Disable",
			Back:        back,
		})
	}
}

// handleConfirmLowerRole implements GET /console/accounts/{account_id}/lower?role=.
func handleConfirmLowerRole(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, pg, ok := confirmPrelude(d, w, r)
		if !ok {
			return
		}
		id, ok := pathID(w, r, "account_id", maxAccountIDBytes)
		if !ok {
			return
		}
		target, err := d.Accounts.Account(r.Context(), caller, id)
		if err != nil {
			confirmReadFailed(w, pg, err, id, "the Account registry")
			return
		}
		// Lower is only offered on the Account page.
		back := accountBack(target.Name, false)
		if capability.SelfTargeted(caller, id) {
			confirmRefusal(w, pg, http.StatusConflict, selfTargetRefusal+" The role was not changed.", back)
			return
		}

		// Valid comes before anything echoes the value.
		role := accounts.Role(r.URL.Query().Get("role"))
		switch {
		case role == "":
			confirmRefusal(w, pg, http.StatusBadRequest, noRoleRefusal, back)
			return
		case !role.Valid():
			confirmRefusal(w, pg, http.StatusBadRequest,
				"This form did not carry a recognisable role. The role was not changed.", back)
			return
		case role == target.Role:
			confirmRefusal(w, pg, http.StatusBadRequest,
				"That is already this Account's role. The role was not changed.", back)
			return
		}
		_, lower := roleTargets(target.Role)
		if !slices.Contains(lower, string(role)) {
			confirmRefusal(w, pg, http.StatusBadRequest,
				string(role)+" is not below this Account's role; Raise role takes your password. The role was not changed.", back)
			return
		}
		renderConfirm(w, pg, accountConfirmView{
			Act:         "lower",
			Target:      target.Name,
			From:        string(target.Role),
			To:          string(role),
			Consequence: lowerConsequence,
			Action:      setAccountRoleAction(id),
			Hidden:      []hiddenField{{Name: "role", Value: string(role)}},
			Button:      "Lower role",
			Back:        back,
		})
	}
}

// handleConfirmRevokeAPIToken implements
// GET /console/accounts/{account_id}/tokens/{token_id}/revoke. A token that is
// not on the named Account is a 404, so the page can never name one token and
// post another. There is no self check: a session may revoke its own tokens.
func handleConfirmRevokeAPIToken(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, pg, ok := confirmPrelude(d, w, r)
		if !ok {
			return
		}
		accountID, ok := pathID(w, r, "account_id", maxAccountIDBytes)
		if !ok {
			return
		}
		tokenID, ok := pathID(w, r, "token_id", maxTokenIDBytes)
		if !ok {
			return
		}
		owner, err := d.Accounts.Account(r.Context(), caller, accountID)
		if err != nil {
			confirmReadFailed(w, pg, err, accountID, "the Account registry")
			return
		}
		toks, err := d.Accounts.APITokens(r.Context(), caller, accountID)
		if err != nil {
			confirmReadFailed(w, pg, err, accountID, "this Account's API Tokens")
			return
		}
		back := accountBack(owner.Name, false)
		for _, t := range toks {
			if t.ID != tokenID {
				continue
			}
			if t.Revoked() {
				confirmRefusal(w, pg, http.StatusConflict, "Token "+t.Name+" is already revoked. Nothing was changed.", back)
				return
			}
			renderConfirm(w, pg, accountConfirmView{
				Act:         "revoke",
				Target:      t.Name,
				TokenID:     t.ID,
				Owner:       owner.Name,
				Consequence: revokeConsequence,
				Action:      revokeAPITokenAction(t.ID),
				Hidden:      []hiddenField{{Name: "account", Value: accountID}},
				Button:      "Revoke token",
				Back:        back,
			})
			return
		}
		confirmRefusal(w, pg, http.StatusNotFound,
			"No API Token matching "+tokenID+" appears on this Account. The token was not revoked.", back)
	}
}
