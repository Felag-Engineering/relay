package console

// accounts_write.go is the Accounts screen's write half (spec 15): the
// Console's THIRD write seam, after Cancel (cancel.go) and Decide
// (decide.go). It lives in its own file, exactly as those two do, so
// seams.go's "every seam here is read-only" claim stays true unqualified.
//
// # What this file decides: nothing
//
// The admin floor on all eight account ControlActions, the self-target rule
// (capability.ErrSelfTargeted), the last-enabled-admin rule
// (accounts.ErrLastAdmin, enforced in ONE guarded UPDATE in the store) and
// every audit row are the capability layer's, exactly as they are for the
// Control API — and they are re-decided NOWHERE here (invariant 10). Each
// route's MinRole is mount-time absence at exactly that layer's own admin
// floor: it subtracts reach and can never widen it.
//
// # Step-up: one password per window
//
// Every granting act goes through the shared requireStepUp (stepup.go) in
// stepUpWindowed mode. Owner decision 2026-10-05: a successful step-up
// stamps the session, and a later granting act inside the configured window
// proceeds without a password; outside it, or with no stamp, the prompt
// returns. The window is consoleauth's to decide, never this file's. A
// password, when submitted, is always verified in the request, and a
// successful step-up rotates the session id. Each granting act's form carries
// an inline `password` field, which is why the [StepUp] component cannot
// express it (components.go): StepUp models a STANDALONE confirmation with its
// own FormAction, and every granting act here is a form already carrying its
// own fields (name/kind/role; role; ttl/name), which a nested <form> cannot
// hold — invalid HTML.
//
// WHICH ACTS TAKE A PASSWORD is the owner's decision of 2026-09-19, not this
// file's derivation: an act that could INCREASE what some principal may do
// takes step-up (create an Account of any role or kind, RAISE a role,
// re-enable a disabled Account, mint an API Token); an act that can only
// REDUCE does not (disable, LOWER a role, revoke a Token), because an
// emergency brake that costs a password is one people route around.
//
// # The role route's read-then-write, closed by a compare-and-set
//
// handleSetAccountRole reads the target's current role, decides raise vs
// lower, then writes. The write is a compare-and-set on exactly the role that
// decision was made from (capability.SetAccountRoleFrom, one guarded UPDATE in
// the store), so a concurrent change between the read and the write is refused
// with accounts.ErrRoleChanged instead of turning an unstepped lower into a
// raise. The atomicity lives in the store and the capability layer; this
// adapter only passes back the role it read and decides nothing new.
//
//   - It can NEVER be used for self-elevation. capability.ErrSelfTargeted
//     (decided by capability.SelfTargeted) refuses a role change on the
//     caller's own Account unconditionally, before the store is touched —
//     and self-elevation by a hijacked admin session is precisely ADR-0009's
//     named risk.
//   - The last-admin guard is orthogonal to whether a change was a raise; it
//     is a count over enabled admins and says nothing about step-up.
//   - The compare applies to a stepped raise too: a refused stepped write is a
//     "review and retry", and inside the step-up window the retry costs no
//     password. One rule is simpler to audit than a conditional.
//
// The one unconditional write is the read-failure branch: with no observed
// role there is nothing to compare, and step-up was taken (a failed read
// counts as a possible raise), so every transition on that branch is a stepped
// one. That write still goes through capability.SetAccountRole, which itself
// reads the stored role before its own compare-and-set.
//
// roleChangeCouldGrant fails closed on an invalid role on either side, and a
// FAILED read demands step-up rather than skipping it. The unchanged-role
// refusal rides the same read and, like the raise/lower decision, does not
// apply when the read fails.
//
// # The mint response, and the one field a secret may occupy
//
// mintedView.Token is that field, and the moment accounts.Plaintext.Reveal()
// runs, every redaction that type provides is GONE — Token is a plain string.
// That is why mintedView carries its own LogValue, why mint is the ONE write
// route here that does not post-redirect-get, and why both the success and the
// audit-failure branch set Cache-Control: no-store explicitly. See mintedView
// and handleMintAPIToken.
//
// # Import-scope
//
// This file is the Console's FOURTH importer of internal/authz, and it names
// exactly one symbol from it — authz.ErrUnauthorized — to recognise a refusal
// the capability layer already made. The authz allowlist in no_dispatch_test.go
// is package-wide, not per-file, so this needs no change there.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

// AccountAdministrator is the write seam this file holds. Every method
// mirrors capability.AccountAdmin's signature EXACTLY, so
// *capability.AccountAdmin satisfies it with no adapter — the same shape
// JobCanceller and ApprovalDecider already take.
type AccountAdministrator interface {
	CreateAccount(ctx context.Context, p capability.Principal, a accounts.Account) (accounts.Account, error)
	SetAccountRole(ctx context.Context, p capability.Principal, id string, role accounts.Role) error
	SetAccountRoleFrom(ctx context.Context, p capability.Principal, id string, from, to accounts.Role) error
	SetAccountEnabled(ctx context.Context, p capability.Principal, id string, enabled bool) error
	MintAPIToken(ctx context.Context, p capability.Principal, accountID, name string, ttl time.Duration) (accounts.APIToken, accounts.Plaintext, error)
	RevokeAPIToken(ctx context.Context, p capability.Principal, id string) error
}

// The five route patterns, named so accountsOffered and the tests compare
// against them rather than restating a path (mirrors cancelJobPattern).
//
// None of these is "POST /console/accounts", and that is a constraint rather
// than a style choice: Register mounts a SECOND, bare-path registration for
// every route that constrains reach, and GET /console/accounts already owns
// the bare "/console/accounts" — a second one panics at registration. See
// console.go's route rows for the two panic texts, reproduced from a real
// ServeMux.
const (
	createAccountPattern     = "POST /console/accounts/create"
	setAccountRolePattern    = "POST /console/accounts/{account_id}/role"
	setAccountEnabledPattern = "POST /console/accounts/{account_id}/enabled"
	mintAPITokenPattern      = "POST /console/accounts/{account_id}/tokens"
	revokeAPITokenPattern    = "POST /console/api-tokens/{token_id}/revoke"
)

// The form-action builders. Each escapes the id exactly as
// decideApprovalAction does, because an Account id and a token id are not
// constrained by this package.
func createAccountAction() string { return "/console/accounts/create" }

func setAccountRoleAction(accountID string) string {
	return "/console/accounts/" + url.PathEscape(accountID) + "/role"
}

func setAccountEnabledAction(accountID string) string {
	return "/console/accounts/" + url.PathEscape(accountID) + "/enabled"
}

func mintAPITokenAction(accountID string) string {
	return "/console/accounts/" + url.PathEscape(accountID) + "/tokens"
}

func revokeAPITokenAction(tokenID string) string {
	return "/console/api-tokens/" + url.PathEscape(tokenID) + "/revoke"
}

// Bounds for these routes' own input, declared beside the code that uses them
// (decide.go's idiom). Each surface bounds its own input independently; none
// of these duplicates a domain rule, and none is imported from the surface
// that happens to agree with it.
const (
	// maxAccountIDBytes and maxTokenIDBytes mirror maxJobIDBytes (job.go).
	maxAccountIDBytes = 128
	maxTokenIDBytes   = 128

	// maxAccountNameBytes is the same 64 accounts.ValidateName enforces,
	// cross-referenced rather than imported. accounts.Repository.Create is
	// the single write path and validates for itself; this only bounds what
	// this surface will carry.
	maxAccountNameBytes = 64

	// maxTokenNameBytes is the number api.maxAPITokenNameLen enforces, for
	// the same reason it gives: a token name is echoed into an audit record,
	// so an unbounded one lets a caller size a row in the trail.
	maxTokenNameBytes = 128
)

// The two refusals spec 15 *States* asks be explicit rather than generic.
//
// These are OUR wording. Spec 15 asks for explicitness, not for particular
// sentences; nothing here is a quotation from it. They are consts so the tests
// compare against the const rather than a copy of the prose — the idiom
// policyCeilingNote already uses.
const (
	selfTargetRefusal = "An Account cannot change its own role or disable itself. Another admin " +
		"must do it: a control plane whose last admin can switch itself off has no way back in."

	lastAdminRefusal = "This is the last enabled admin, so it cannot be demoted or disabled. " +
		"Another admin must exist first: a control plane with zero enabled admins has no way back in."

	roleChangedRefusal = "The Account changed while you were editing. Review its current role and retry."

	// lowerRoleHint is the hint drawn inside the Lower role form and also the
	// server's refusal when a role form arrives with no role (design spec 15,
	// D32), so the two are one sentence.
	lowerRoleHint = "choose a lower role"
)

// accountsOffered reports whether the write half is wired at all. Three seams,
// all required:
//
//   - AccountAdmin is the write seam itself;
//   - Auth is PAIRED with it for the reason decideOffered states — a granting
//     act that cannot be step-up-verified must not be offered at all;
//   - Accounts is required because handleSetAccountRole reads the target's
//     current role through it. A Deps with AccountAdmin wired and Accounts nil
//     is constructible, and without this the role route is a nil dereference
//     rather than an honest absence. The read seam belongs in this write-half
//     predicate for that reason; it is not a tidy-up waiting to happen.
//
// Deliberately NOT through routesFor, unlike cancelOffered and decideOffered:
// routesFor takes a ROLE, and reading the caller's role inside this screen is
// exactly what this file must never do. It does not need to — all five write
// routes carry the SAME MinRole as the read route that renders the form, so
// any session rendering this screen can reach all five, and the mount gate is
// the whole control.
func accountsOffered(d Deps) bool {
	return d.AccountAdmin != nil && d.Auth != nil && d.Accounts != nil
}

// accountsStepUp is the step-up ask for the four privilege-granting Account
// acts. undone names, in the operator's terms, what did NOT happen ("Nothing
// was created.", "The role was not changed.") so each refusal says so plainly.
func accountsStepUp(undone string) stepUpAsk {
	return stepUpAsk{
		mode:     stepUpWindowed,
		required: "Step-up re-authentication is required for this act.",
		undone:   undone,
		act:      "an account administration act",
		render:   renderWriteResult,
	}
}

// writeRefusalRender draws one refusal; it has the shape of stepUpAsk.render.
type writeRefusalRender func(w http.ResponseWriter, pg Page, status int, heading, href, label string)

// renderWriteResult draws a refusal on the plain result page.
func renderWriteResult(w http.ResponseWriter, pg Page, status int, heading, href, label string) {
	w.WriteHeader(status)
	renderScreen(w, pg, accountsWriteResultTmpl, accountsWriteResultView{
		Heading: heading, Href: href, Label: label,
	})
}

// createRefusal draws a refused create as the "New account" form, open, with
// the refusal above it (design spec 15, D32). form is captured by value, so
// the caller sets StepUpFresh before building the closure.
//
// The form reopens for a refusal the caller can answer by editing or retrying
// it, and only when the refusal carries no link. It does not reopen for:
//   - authz.ErrUnauthorized (403): the capability layer refused the caller and
//     no edit to the form changes that, so the plain page renders it
//     (invariant 10);
//   - a refusal with a link: a session that ended, and "could not confirm",
//     where the Account may exist and reopening would invite a duplicate;
//   - 404 and the accounts.IsInvalidToken 409, which have no link and so would
//     reopen, but create cannot return either.
//
// The CSRF token comes from the pg passed in, never from anything captured
// earlier: after a successful step-up pg holds the rotated session's token.
func createRefusal(form accountCreateForm) writeRefusalRender {
	return func(w http.ResponseWriter, pg Page, status int, heading, href, label string) {
		answerable := status == http.StatusBadRequest ||
			status == http.StatusUnauthorized ||
			status == http.StatusConflict ||
			status == http.StatusTooManyRequests ||
			status == http.StatusInternalServerError
		if href != "" || !answerable {
			renderWriteResult(w, pg, status, heading, href, label)
			return
		}
		w.WriteHeader(status)
		form.Open = true
		form.Refusal = heading
		form.CSRFToken = pg.CSRFToken
		renderScreen(w, pg, accountsCreateRefusedTmpl, form)
	}
}

// roleChangeCouldGrant reports whether changing a role FROM from TO to could
// increase what the target Account may do. It is the only place this package
// decides whether a role change is a raise, and it decides it about the TARGET
// Account's own old and new role — never about the caller's.
//
// accounts.go also calls it at RENDER time, to split the offered targets into
// Raise and Lower. That is presentation only: the handler re-decides from the
// stored role, so a tampered form cannot skip step-up.
//
// Written to FAIL CLOSED. accounts.Role.AtLeast returns false when EITHER side
// is invalid, so the natural spelling — `to.AtLeast(from) && to != from` —
// reads a corrupt or unknown stored role as "not a raise" and skips the
// password. This spelling does the opposite: an unknown role on either side is
// treated as a raise and costs a password.
func roleChangeCouldGrant(from, to accounts.Role) bool {
	if !from.Valid() || !to.Valid() {
		return true
	}
	return to != from && to.AtLeast(from)
}

// accountsWriteResultView is the shell rendered for a write that did not
// redirect — every case but success, plus mint, which never redirects.
// Deliberately small, modelled on cancelResultView: the interesting rendering
// is the Accounts screen itself, and this page exists only to say why the
// redirect did not happen.
type accountsWriteResultView struct {
	Heading string
	Href    string
	Label   string
}

var accountsWriteResultTmpl = newScreen("accounts-write-result", `
<div class="placeholder">
  <p>{{.Heading}}</p>
  {{with .Href}}<p><a href="{{.}}">{{$.Label}}</a></p>{{end}}
</div>
`)

// accountsScreenPath is the Accounts screen itself — where every successful
// write but mint redirects back to.
const accountsScreenPath = "/console/accounts"

// accountsHrefFor builds the Accounts screen's link with one Account
// selected, through url.Values rather than concatenation — an Account name is
// not constrained by this package.
func accountsHrefFor(name string) string {
	if name == "" {
		return accountsScreenPath
	}
	return accountsScreenPath + "?" + url.Values{"account": {name}}.Encode()
}

// writeFailedWith renders, through render, a refusal the capability layer (or the domain) made.
// One switch shared by the four non-mint routes, with its classification
// aligned to api.writeAccountError so the two surfaces agree on what each
// refusal MEANS.
//
// undone names what did not happen; subject names the object in the
// operator's terms ("the Account", "this token") for the not-found branch.
//
// ident is how the CALLING ROUTE addresses its object, which is not always an
// id: four routes pass the path id, and create passes the submitted NAME,
// because a name is the only handle it has before the Account exists. The
// not-found sentence and the log field are worded for both rather than
// assuming an id, so create can never render "no Account with the id
// <a name>".
func writeFailedWith(w http.ResponseWriter, pg Page, err error, route, ident, undone, subject string, render writeRefusalRender) {
	var (
		status int
		res    accountsWriteResultView
	)
	switch {
	case errors.Is(err, authz.ErrUnauthorized):
		// The capability layer decided this; this screen renders what it
		// decided and does not restate the rule (invariant 10).
		status, res = http.StatusForbidden, accountsWriteResultView{
			Heading: "The Relay refused this: " + err.Error() + ". " + undone,
		}
	case errors.Is(err, capability.ErrSelfTargeted):
		status, res = http.StatusConflict, accountsWriteResultView{
			Heading: selfTargetRefusal + " " + undone,
			Href:    accountsScreenPath,
			Label:   "Back to Accounts.",
		}
	case errors.Is(err, accounts.ErrLastAdmin):
		status, res = http.StatusConflict, accountsWriteResultView{
			Heading: lastAdminRefusal + " " + undone,
			Href:    accountsScreenPath,
			Label:   "Back to Accounts.",
		}
	case errors.Is(err, accounts.ErrRoleChanged):
		status, res = http.StatusConflict, accountsWriteResultView{
			Heading: roleChangedRefusal + " " + undone,
			Href:    accountsScreenPath,
			Label:   "Back to Accounts.",
		}
	case errors.Is(err, accounts.ErrNotFound), errors.Is(err, accounts.ErrTokenNotFound):
		status, res = http.StatusNotFound, accountsWriteResultView{
			Heading: "No " + subject + " matching " + ident + " appears in this Relay's records. " + undone,
		}
	case errors.Is(err, accounts.ErrNameTaken):
		status, res = http.StatusConflict, accountsWriteResultView{Heading: "That Account name is already in use. Names are unique so an audit " +
			"attribution is never ambiguous. " + undone,
		}
	case errors.Is(err, accounts.ErrReservedName):
		status, res = http.StatusBadRequest, accountsWriteResultView{Heading: "That name is reserved. The founding admin is created by seeding, never " +
			"from a screen. " + undone,
		}
	case errors.Is(err, accounts.ErrInvalidName), errors.Is(err, accounts.ErrInvalidKind),
		errors.Is(err, accounts.ErrInvalidRole), errors.Is(err, accounts.ErrInvalidTTL):
		status, res = http.StatusBadRequest, accountsWriteResultView{
			Heading: "The Relay refused this: " + err.Error() + ". " + undone,
		}
	case accounts.IsInvalidToken(err):
		// Minting for a disabled Account: TokenService refuses it with the
		// same opaque ErrTokenInvalid every failed verification returns.
		status, res = http.StatusConflict, accountsWriteResultView{Heading: "This Relay would not mint a credential for that Account. Enable the Account " +
			"before minting one for it. " + undone,
		}
	case errors.Is(err, capability.ErrAccountsUnavailable):
		unavailable(w, "Account administration")
		return
	default:
		// "Did not happen" would be a claim this branch cannot back:
		// capability/accountadmin.go returns an error on a SUCCESSFUL write
		// whose audit append failed (CreateAccount, SetAccountRole,
		// SetAccountEnabled and MintAPIToken all do). The honest sentence
		// that does not require distinguishing the wrapped audit error is
		// "could not confirm", never "nothing happened".
		pg.logger().Error("console account administration returned an error",
			"route", route, "subject", subject, "target", ident, "error", err)
		status, res = http.StatusInternalServerError, accountsWriteResultView{Heading: "The Relay could not confirm this change was fully recorded. Reload the " +
			"Accounts screen and read the current state before trying again.",
			Href:  accountsScreenPath,
			Label: "Back to Accounts.",
		}
	}
	render(w, pg, status, res.Heading, res.Href, res.Label)
}

// writeFailed is writeFailedWith drawing the plain result page.
func writeFailed(w http.ResponseWriter, pg Page, err error, route, ident, undone, subject string) {
	writeFailedWith(w, pg, err, route, ident, undone, subject, renderWriteResult)
}

// writePrelude is the opening every one of the five handlers shares:
// principal, nil-seam check, ParseForm, page. It returns ok=false having
// already written the response.
//
// ParseForm is REQUIRED, not merely idempotent — decide.go explains why:
// submittedCSRFToken (security.go) reads the X-CSRF-Token HEADER first and
// only falls back to the form field, so an HTMX submission never parses the
// body at all.
func writePrelude(d Deps, w http.ResponseWriter, r *http.Request, title string) (capability.Principal, Page, bool) {
	caller, ok := principal(w, r)
	if !ok {
		return capability.Principal{}, Page{}, false
	}
	if !accountsOffered(d) {
		unavailable(w, "Account administration")
		return capability.Principal{}, Page{}, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "could not read the submitted form", http.StatusBadRequest)
		return capability.Principal{}, Page{}, false
	}
	pg, ok := page(d, w, r, title)
	if !ok {
		return capability.Principal{}, Page{}, false
	}
	return caller, pg, true
}

// pathID reads a bounded path value, or answers 404. An absent or overlong id
// is a path this Relay does not serve, not a form error.
func pathID(w http.ResponseWriter, r *http.Request, name string, max int) (string, bool) {
	id := r.PathValue(name)
	if id == "" || len(id) > max {
		http.NotFound(w, r)
		return "", false
	}
	return id, true
}

// badRequest renders a refusal of THIS SURFACE'S OWN input bounds — never a
// domain rule, which belongs to the single write path.
func badRequest(w http.ResponseWriter, pg Page, heading string) {
	w.WriteHeader(http.StatusBadRequest)
	renderScreen(w, pg, accountsWriteResultTmpl, accountsWriteResultView{Heading: heading})
}

// handleCreateAccount implements POST /console/accounts/create.
//
// ALWAYS step-up. Creating an Account of ANY role and ANY kind brings a new
// principal into existence, and creating an `operator` machine Account is
// precisely ADR-0009's warning; "only an admin needs a password" would be the
// narrower rule, and uniform is harder to get wrong.
func handleCreateAccount(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, pg, ok := writePrelude(d, w, r, "Accounts")
		if !ok {
			return
		}

		// What the operator typed is echoed into a refused re-render, each
		// field only when it passes its own check, so a refusal of one never
		// resets another to the first option. The password is never echoed.
		name := r.PostFormValue("name")
		kind := accounts.Kind(r.PostFormValue("kind"))
		role := accounts.Role(r.PostFormValue("role"))
		form := accountCreateForm{
			CreateAction: createAccountAction(),
			Roles:        allRoleNames(),
			Kinds:        accountKinds(),
		}
		if name != "" && len(name) <= maxAccountNameBytes {
			form.Name = name
		}
		if kind.Valid() {
			form.Kind = string(kind)
		}
		if role.Valid() {
			form.Role = string(role)
		}
		// refuseInput draws a refusal of this surface's own bounds. The window
		// is read only here, because a form is being drawn.
		refuseInput := func(heading string) {
			form.StepUpFresh = stepUpFresh(d, r)
			createRefusal(form)(w, pg, http.StatusBadRequest, heading, "", "")
		}

		if name == "" || len(name) > maxAccountNameBytes {
			refuseInput("An Account needs a name of 1 to 64 bytes. Nothing was created.")
			return
		}

		// Accepted only as an exact member of the closed set — an ABSENT
		// field included. Never defaulted in either direction, which is
		// decide.go's rule for `answer`: a kind or a role must be ASKED for.
		// Kind.Valid and Role.Valid are the DOMAIN's own closed sets, asked
		// rather than restated here, so this surface and accounts.Repository
		// cannot come to disagree about what the sets are.
		if !kind.Valid() {
			refuseInput("This form did not carry a recognisable Account kind. Nothing was created.")
			return
		}
		if !role.Valid() {
			refuseInput("This form did not carry a recognisable role. Nothing was created.")
			return
		}

		// A step-up refusal draws the password as required, the safe direction.
		ask := accountsStepUp("Nothing was created.")
		ask.render = createRefusal(form)
		if !requireStepUp(d, w, r, &pg, ask) {
			return
		}
		// The caller has just proved the password or is inside the window.
		// Presentation only; the next act re-decides.
		form.StepUpFresh = true

		created, err := d.AccountAdmin.CreateAccount(r.Context(), caller, accounts.Account{
			Name: name, Kind: kind, Role: role, Enabled: true,
		})
		if err != nil {
			writeFailedWith(w, pg, err, createAccountPattern, name, "Nothing was created.", "Account", createRefusal(form))
			return
		}
		http.Redirect(w, r, accountsHrefFor(created.Name), http.StatusSeeOther)
	}
}

// handleSetAccountRole implements POST /console/accounts/{account_id}/role.
//
// Step-up ONLY when the change could raise the role. The target's current role
// comes from d.Accounts.Account, and the write is a compare-and-set against
// that same role (see this file's header); roleChangeCouldGrant says why
// an unknown role on either side is treated as a raise.
//
// A submission of the role the target already holds is refused here, writing
// nothing and auditing nothing. That is Console-only narrowing: the Control API
// still accepts, and audits, a no-op role change. A self-targeted request
// skips this check and falls through, so the capability layer refuses AND
// audits it (ErrSelfTargeted).
//
// An absent role is refused in the hint's own words (lowerRoleHint): the
// Lower role form's current-role option is disabled, so pressing it with that
// option selected posts no role. A hand-built empty POST meant as a raise gets
// the same "lower" wording, which is acceptable because the rendered Raise
// select is required and the page cannot send it.
func handleSetAccountRole(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, pg, ok := writePrelude(d, w, r, "Accounts")
		if !ok {
			return
		}
		id, ok := pathID(w, r, "account_id", maxAccountIDBytes)
		if !ok {
			return
		}

		if r.PostFormValue("role") == "" {
			badRequest(w, pg, "No role was chosen: "+lowerRoleHint+". The role was not changed.")
			return
		}
		// Role.Valid, not a hand-restated set: the domain owns what the
		// three roles are (accounts.Role).
		role := accounts.Role(r.PostFormValue("role"))
		if !role.Valid() {
			badRequest(w, pg, "This form did not carry a recognisable role. The role was not changed.")
			return
		}

		// A read failure demands step-up rather than skipping it — fail
		// closed in the FRICTION direction. It does not refuse the act at
		// this layer. That is not a promise that a demote is never blocked by
		// a failing read: the unconditional capability.SetAccountRole this
		// branch falls back to reads the stored role before its own
		// compare-and-set, so a persistent read failure fails there too.
		target, readErr := d.Accounts.Account(r.Context(), caller, id)
		couldGrant := true
		if readErr == nil {
			if !capability.SelfTargeted(caller, id) && role == target.Role {
				badRequest(w, pg, "That is already this Account's role. The role was not changed.")
				return
			}
			couldGrant = roleChangeCouldGrant(target.Role, role)
		}
		if couldGrant && !requireStepUp(d, w, r, &pg, accountsStepUp("The role was not changed.")) {
			return
		}

		var err error
		if readErr == nil {
			// The step-up decision above was made from target.Role. The write
			// is a compare-and-set on exactly that role, so a concurrent change
			// between the read and here is refused rather than turning an
			// unstepped lower into a raise.
			err = d.AccountAdmin.SetAccountRoleFrom(r.Context(), caller, id, target.Role, role)
		} else {
			// The read failed, so couldGrant was true and step-up was taken
			// above: every transition from here is a stepped one, and there is
			// no observed role to compare against. Unconditional is safe on
			// this branch and on no other.
			err = d.AccountAdmin.SetAccountRole(r.Context(), caller, id, role)
		}
		if err != nil {
			writeFailed(w, pg, err, setAccountRolePattern, id, "The role was not changed.", "Account")
			return
		}
		http.Redirect(w, r, accountsScreenPath, http.StatusSeeOther)
	}
}

// handleSetAccountEnabled implements POST /console/accounts/{account_id}/enabled.
//
// Step-up iff the act is an ENABLE. Decided from the request alone — no read,
// so this route has no TOCTOU at all, unlike the role route above.
func handleSetAccountEnabled(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, pg, ok := writePrelude(d, w, r, "Accounts")
		if !ok {
			return
		}
		id, ok := pathID(w, r, "account_id", maxAccountIDBytes)
		if !ok {
			return
		}

		// Exactly "true" or "false". An absent or unrecognised value is a
		// refusal, never a default: the boolean must not be inferred from
		// silence in EITHER direction.
		submitted := r.PostFormValue("enabled")
		if submitted != "true" && submitted != "false" {
			badRequest(w, pg, "This form did not say whether to enable or disable the Account. Nothing was changed.")
			return
		}
		enabled := submitted == "true"

		undone := "The Account was not changed."
		if enabled && !requireStepUp(d, w, r, &pg, accountsStepUp(undone)) {
			return
		}

		if err := d.AccountAdmin.SetAccountEnabled(r.Context(), caller, id, enabled); err != nil {
			writeFailed(w, pg, err, setAccountEnabledPattern, id, undone, "Account")
			return
		}
		http.Redirect(w, r, accountsScreenPath, http.StatusSeeOther)
	}
}

// ttlChoices is the mint form's CLOSED vocabulary, with no default.
//
// A closed select rather than a free-form number, for the reason
// api/accounts.go gives for making ttl_seconds a POINTER: a forgotten field
// must never silently mint an immortal credential. Zero means "does not
// expire", which is legitimate — it is what a long-lived CI credential wants
// — but it has to be ASKED for.
var ttlChoices = []struct {
	Value string
	Label string
	TTL   time.Duration
}{
	{"30d", "30 days", 30 * 24 * time.Hour},
	{"90d", "90 days", 90 * 24 * time.Hour},
	{"365d", "365 days", 365 * 24 * time.Hour},
	{"never", "does not expire", 0},
}

// ttlFor resolves a submitted ttl value. ok is false for an absent or
// unrecognised one.
func ttlFor(value string) (time.Duration, bool) {
	for _, c := range ttlChoices {
		if c.Value == value {
			return c.TTL, true
		}
	}
	return 0, false
}

// mintedView is the ONE view type in this package with a field a secret can
// occupy, and Token is that field. It exists for exactly one render.
//
// LogValue redacts Token. accounts.Plaintext redacts under String, GoString,
// LogValue and MarshalJSON — but Token is a PLAIN STRING, because Reveal() has
// already been called by the time it lands here, so every one of those
// protections is gone. This method is what puts one of them back on the only
// shape that still carries the secret, matching accounts.APIToken.LogValue's
// precedent. It is not decoration: it is the structural half of "the plaintext
// never reaches a log", and it survives a future handler edit in a way a
// buffer assertion in one test does not.
type mintedView struct {
	AccountName string
	TokenID     string
	TokenName   string
	Expires     time.Time
	Token       string // the plaintext, revealed once (accounts.Plaintext.Reveal)
	BackHref    string
}

// LogValue implements slog.LogValuer, omitting Token entirely.
func (v mintedView) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("account_name", v.AccountName),
		slog.String("token_id", v.TokenID),
		slog.String("token_name", v.TokenName),
	)
}

// handleMintAPIToken implements POST /console/accounts/{account_id}/tokens.
//
// ALWAYS step-up: minting brings a new credential into existence.
//
// THIS IS THE ONE WRITE ROUTE THAT DOES NOT POST-REDIRECT-GET, because the
// plaintext must never enter a URL, a Location header, a query string or a
// browser history entry. It renders 200 with the secret in the body, once,
// with Cache-Control: no-store set explicitly.
func handleMintAPIToken(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, pg, ok := writePrelude(d, w, r, "Accounts")
		if !ok {
			return
		}
		id, ok := pathID(w, r, "account_id", maxAccountIDBytes)
		if !ok {
			return
		}

		name := r.PostFormValue("name")
		if name == "" || len(name) > maxTokenNameBytes {
			badRequest(w, pg, "A token needs a name of 1 to 128 bytes, so it can be audited and "+
				"pruned later. Nothing was minted.")
			return
		}
		ttl, ok := ttlFor(r.PostFormValue("ttl"))
		if !ok {
			badRequest(w, pg, "This form did not carry a recognisable lifetime. A token that never "+
				"expires is a legitimate choice and has to be made deliberately. Nothing was minted.")
			return
		}

		if !requireStepUp(d, w, r, &pg, accountsStepUp("Nothing was minted.")) {
			return
		}

		// pg was passed to requireStepUp by pointer, so this render carries the
		// ROTATED session's CSRF token, with no redirect in between.
		tok, plaintext, err := d.AccountAdmin.MintAPIToken(r.Context(), caller, id, name, ttl)
		if err != nil {
			// MINT CAN FAIL WITH A LIVE CREDENTIAL ALREADY IN THE STORE.
			// capability.MintAPIToken returns a live tok AND a live plaintext
			// together with a non-nil error when the mint succeeded and the
			// audit append failed. So this branch is reachable with a token
			// that exists and whose secret this process is about to discard
			// unrendered — which is the right thing to do with it, and is why
			// the id is logged and the page says to go and look.
			//
			// tok.ID is documented "safe to log" (accounts/tokens.go) and it
			// is the operator's only handle on such a token. plaintext is
			// never passed to slog in any form.
			w.Header().Set("Cache-Control", "no-store")
			if isMintRefusal(err) {
				writeFailed(w, pg, err, mintAPITokenPattern, id, "Nothing was minted.", "Account")
				return
			}
			d.logger().ErrorContext(r.Context(), "console api token mint returned an error",
				"account_id", id, "token_id", tok.ID, "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			renderScreen(w, pg, accountsWriteResultTmpl, accountsWriteResultView{
				Heading: "The Relay could not confirm this token was fully recorded. A token may have been " +
					"created; check this Account's token list and revoke anything unintended. Its id is " + tok.ID + ".",
				Href:  accountsScreenPath,
				Label: "Back to Accounts.",
			})
			return
		}

		// Set BEFORE any write. Render (layout.go) sets only Content-Type, so
		// nothing overwrites this. Rendered Console pages do not set it today;
		// this response is the one that must not sit in a shared cache or come
		// back on a back button.
		// The Account's NAME, for the heading and the back link, comes from a
		// read rather than from a hidden form field: the name is what selects
		// an Account on the read screen, and echoing a caller-supplied one
		// back would let the page name an Account that is not the one the
		// credential belongs to. Best-effort — a failed read costs the
		// selection on the back link, never the render of the secret, which
		// is the one thing this response exists to do.
		//
		// It is not free, and the cost is named rather than discovered: this
		// is a SECOND ControlAccountRead authorization on the mint path, and a
		// refusal of it writes its own refuseControl row in the trail. Both
		// are acceptable — the alternative is echoing a caller-supplied name
		// back onto the page that reveals a credential.
		accountName := ""
		if target, readErr := d.Accounts.Account(r.Context(), caller, id); readErr == nil {
			accountName = target.Name
		}

		w.Header().Set("Cache-Control", "no-store")
		renderScreen(w, pg, accountsMintedTmpl, mintedView{
			AccountName: accountName,
			TokenID:     tok.ID,
			TokenName:   tok.Name,
			Expires:     tok.ExpiresAt,
			// The single Reveal() call in this package, and the third in the
			// whole Relay — enumerated on Plaintext.Reveal's own doc comment
			// and checked by TestPlaintext_RevealCallSitesAreEnumerated.
			Token:    plaintext.Reveal(),
			BackHref: accountsHrefFor(accountName),
		})
	}
}

// isMintRefusal reports whether err is a refusal the shared mapping renders
// specifically, rather than the "could not confirm" default. Split out so the
// mint handler can take the default branch itself — it is the only one whose
// default sentence must name a token id.
func isMintRefusal(err error) bool {
	switch {
	case errors.Is(err, authz.ErrUnauthorized),
		errors.Is(err, accounts.ErrNotFound),
		errors.Is(err, accounts.ErrInvalidTTL),
		errors.Is(err, capability.ErrAccountsUnavailable),
		accounts.IsInvalidToken(err):
		return true
	default:
		return false
	}
}

// handleRevokeAPIToken implements POST /console/api-tokens/{token_id}/revoke.
//
// NO step-up, and no password field is rendered or read. Revocation grants
// nothing — it is the incident instrument, and an emergency brake that costs a
// password is one people route around at exactly the wrong moment (owner
// decision, 2026-09-19).
func handleRevokeAPIToken(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, pg, ok := writePrelude(d, w, r, "Accounts")
		if !ok {
			return
		}
		id, ok := pathID(w, r, "token_id", maxTokenIDBytes)
		if !ok {
			return
		}

		if err := d.AccountAdmin.RevokeAPIToken(r.Context(), caller, id); err != nil {
			writeFailed(w, pg, err, revokeAPITokenPattern, id, "The token was not revoked.", "API Token")
			return
		}
		http.Redirect(w, r, accountsScreenPath, http.StatusSeeOther)
	}
}

// accountsMintedTmpl is the reveal-once response: the plaintext, escaped by
// html/template, rendered exactly once, beside the sentence that says this is
// the only time it will ever appear.
var accountsMintedTmpl = newScreen("accounts-minted", `
<section class="panel minted">
  <h3>API Token minted &mdash; <span class="ident">{{.TokenName}}</span>{{with .AccountName}} for <span class="ident">{{.}}</span>{{end}}</h3>
  <p><b>Copy this now.</b> This is the only time this Relay will show it. It is stored as a hash and
  cannot be recovered &mdash; if it is lost, revoke this token and mint another.</p>
  <p><code>{{.Token}}</code></p>
  <p class="note">Token id <code>{{.TokenID}}</code>{{if .Expires.IsZero}}, which does not expire{{else}}, expiring {{stamp .Expires}}{{end}}; record the id, never the value above.</p>
  <p><a href="{{.BackHref}}">Back to Accounts</a></p>
</section>
`)
