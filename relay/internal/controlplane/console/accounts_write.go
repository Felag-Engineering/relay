package console

// accounts_write.go is the Accounts screen's write half (spec 15): the
// Console's second write seam, after Cancel (cancel.go). It lives in its own
// file, as that one does, so
// seams.go's "every seam here is read-only" claim stays true unqualified.
//
// A successful act returns to the screen it was made from, with a fixed
// one-line result chosen by a closed done= key. The destination is built here
// from an Account ID read through the registry, never from anything the request
// names. Two writes do not redirect: the mint and a temporary password (a human
// Account's create, and a re-issue), which reveal a secret once (ADR-0045).
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
// runs, every redaction that type provides is GONE — Token is a plain string,
// and so is each block of the harnessView mintedView carries, which embeds it
// too. mintedView, harnessView and temporaryPasswordView (temporarypassword.go)
// are the only view types a secret can occupy. That is why mintedView carries
// its own LogValue, why a reveal never post-redirect-gets, and why both the
// success and the audit-failure branch set Cache-Control: no-store explicitly.
// See mintedView and handleMintAPIToken.
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
// JobCanceller already takes.
type AccountAdministrator interface {
	CreateAccount(ctx context.Context, p capability.Principal, a accounts.Account) (accounts.Account, error)
	SetAccountRole(ctx context.Context, p capability.Principal, id string, role accounts.Role) error
	SetAccountRoleFrom(ctx context.Context, p capability.Principal, id string, from, to accounts.Role) error
	SetAccountEnabled(ctx context.Context, p capability.Principal, id string, enabled bool) error
	MintAPIToken(ctx context.Context, p capability.Principal, accountID, name string, lifetime capability.APITokenLifetime) (accounts.APIToken, accounts.Plaintext, error)
	RevokeAPIToken(ctx context.Context, p capability.Principal, id string) error
}

// The five route patterns, named so accountsOffered and the tests compare
// against them rather than restating a path (mirrors cancelJobPattern).
//
// None of these is "POST /console/accounts", and that is a constraint rather
// than a style choice: Register mounts a SECOND, bare-path registration for
// every route that constrains reach, and GET /console/accounts already owns
// the bare "/console/accounts" — a second one panics at registration. Create
// lives outside /console/accounts/ because the Account page owns the
// two-segment shape there (console.go).
const (
	createAccountPattern     = "POST /console/new-account/create"
	setAccountRolePattern    = "POST /console/accounts/{account_id}/role"
	setAccountEnabledPattern = "POST /console/accounts/{account_id}/enabled"
	mintAPITokenPattern      = "POST /console/accounts/{account_id}/tokens"
	revokeAPITokenPattern    = "POST /console/api-tokens/{token_id}/revoke"
)

// The form-action builders. Each escapes its id, because an
// Account id and a token id are not constrained by this package.
func createAccountAction() string { return "/console/new-account/create" }

// newAccountPath is the New account page.
const newAccountPath = "/console/new-account"

// accountPagePath is an Account's page. The name only locates the page; every
// form on it posts by Account ID.
func accountPagePath(name string) string {
	return "/console/accounts/" + url.PathEscape(name)
}

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

// Bounds for these routes' own input, declared beside the code that uses
// them. Each surface bounds its own input independently; none of these
// duplicates a domain rule, and none is imported from the surface
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
// selfPanelNote uses.
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

	// noRoleRefusal is the refusal for a role form that arrives with no role,
	// rendered by the role route and by the Lower role confirmation page alike.
	noRoleRefusal = "No role was chosen: " + lowerRoleHint + ". The role was not changed."
)

// accountsOffered reports whether the write half is wired at all. Three seams,
// all required:
//
//   - AccountAdmin is the write seam itself;
//   - Auth is PAIRED with it: a granting act that cannot be step-up-verified
//     must not be offered at all;
//   - Accounts is required because handleSetAccountRole reads the target's
//     current role through it. A Deps with AccountAdmin wired and Accounts nil
//     is constructible, and without this the role route is a nil dereference
//     rather than an honest absence. The read seam belongs in this write-half
//     predicate for that reason; it is not a tidy-up waiting to happen.
//
// Deliberately NOT through routesFor, unlike cancelOffered:
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

// createRefusal draws a refused create as the New account page, with the
// refusal above the submit button (spec 15). form is captured by value, so the
// caller sets StepUpFresh before building the closure.
//
// The form re-renders for a refusal the caller can answer by editing or
// retrying it, and only when the refusal carries no link. It does not for:
//   - authz.ErrUnauthorized (403): the capability layer refused the caller and
//     no edit to the form changes that, so the plain page renders it
//     (invariant 10);
//   - a refusal with a link: a session that ended, and "could not confirm",
//     where the Account may exist and a re-render would invite a duplicate;
//   - 404 and the accounts.IsInvalidToken 409, which have no link and so would
//     re-render, but create cannot return either.
//
// The CSRF token comes from the pg passed in, never from anything captured
// earlier: after a successful step-up pg holds the rotated session's token.
func createRefusal(form accountCreateForm) writeRefusalRender {
	return func(w http.ResponseWriter, pg Page, status int, heading, href, label string) {
		if href != "" || !refusalAnswerable(status) {
			renderWriteResult(w, pg, status, heading, href, label)
			return
		}
		w.WriteHeader(status)
		form.Refusal = heading
		form.CSRFToken = pg.CSRFToken
		renderScreen(w, pg, newAccountTmpl, form)
	}
}

// refusalAnswerable reports whether a refusal of this status is one the form
// can answer by editing or retrying (createRefusal, editRefusal).
func refusalAnswerable(status int) bool {
	switch status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusConflict,
		http.StatusTooManyRequests, http.StatusInternalServerError:
		return true
	}
	return false
}

// editSection names the section of the Account page a refused act was made
// from, which is where editRefusal draws the refusal.
type editSection int

const (
	editRole editSection = iota
	editState
	editMint
)

// editRefusal draws a refused role change, Enable or mint as the Account's edit
// view, with the refusal in the section it came from, above that section's
// button. mintName and mintTTL are the refused mint's inputs, echoed when they
// are ones the form could have sent; the step-up password is never echoed.
//
// The edit view re-renders for a refusal the caller can answer by editing or
// retrying it, and only when the refusal carries no link, or the 409 whose link
// is Back to Accounts (a self-targeted act, the last administrator, a role that
// changed): the re-render shows the Account's current state, which those ask
// the operator to read, and the page carries its own Back to Accounts. The
// plain result page renders everything else:
//   - authz.ErrUnauthorized (403): the capability layer refused the caller and
//     no edit changes that (invariant 10);
//   - a session that ended, which links to sign-in;
//   - "could not confirm" (500 with a link): the outcome is unknown, and a
//     re-render would invite a duplicate grant;
//   - 404, where the Account is gone.
//
// The re-render is the Account page, so it makes that page's recorded
// query_audit read (auditAccountPageRead) and falls back to the result page,
// carrying the refusal, when that read fails or cannot be recorded, when the
// Account or its tokens cannot be read, or when the page has no write controls.
// Its Account, password-status and API Token reads are the capability layer's
// ControlAccountRead and ControlAPITokenRead, which record only on refusal, so
// a re-render whose read the layer refuses may add a refuseControl row to the
// trail beside the act's own refusal (for example after a refused step-up).
//
// The CSRF token comes from the pg passed in, never from anything captured
// earlier: after a successful step-up pg holds the rotated session's token.
func editRefusal(d Deps, r *http.Request, caller capability.Principal, accountID string, section editSection, fresh bool, mintName, mintTTL string) writeRefusalRender {
	return func(w http.ResponseWriter, pg Page, status int, heading, href, label string) {
		linkIsBackToAccounts := status == http.StatusConflict && href == accountsScreenPath
		if !refusalAnswerable(status) || (href != "" && !linkIsBackToAccounts) {
			renderWriteResult(w, pg, status, heading, href, label)
			return
		}
		if d.Queries == nil || d.Accounts == nil {
			renderWriteResult(w, pg, status, heading, href, label)
			return
		}
		// The trail read comes before any Account read: the page's content is
		// never served without its query_audit row.
		d, lane, err := auditAccountPageRead(r.Context(), d, caller)
		if err != nil {
			renderWriteResult(w, pg, status, heading, href, label)
			return
		}
		a, err := d.Accounts.Account(r.Context(), caller, accountID)
		if err != nil {
			renderWriteResult(w, pg, status, heading, href, label)
			return
		}
		v, err := accountPageFor(r.Context(), d, caller, pg, a, fresh)
		if err != nil || v.Write == nil {
			renderWriteResult(w, pg, status, heading, href, label)
			return
		}
		// Nothing above reads through d.Queries after the audited read; the
		// check keeps a later lane read from being served unrecorded.
		if lane.unaudited {
			renderWriteResult(w, pg, status, heading, href, label)
			return
		}

		switch section {
		case editRole:
			v.RoleRefusal = heading
		case editState:
			v.StateRefusal = heading
		case editMint:
			v.MintRefusal = heading
			if len(mintName) >= 1 && len(mintName) <= maxTokenNameBytes {
				v.MintName = mintName
			}
			// An unrecognised lifetime leaves ttlOptions' own preselection: the
			// default for a human Account, none for a machine Account, so a
			// forgotten lifetime is never defaulted in.
			if _, ok := ttlFor(mintTTL); ok {
				for i := range v.Write.TTLs {
					v.Write.TTLs[i].Selected = v.Write.TTLs[i].Value == mintTTL
				}
			}
		}

		pg.Title = a.Name
		pg.Banner = banner(d, r)
		w.WriteHeader(status)
		renderScreen(w, pg, accountPageTmpl, v)
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

// accountsScreenPath is the Accounts list.
const accountsScreenPath = "/console/accounts"

// doneKey names the one-line result a successful act shows on the screen it
// returns to. The set is closed: a page renders only accountsDone's sentence,
// never the query value.
type doneKey string

const (
	doneCreated  doneKey = "created"
	doneRole     doneKey = "role"
	doneEnabled  doneKey = "enabled"
	doneDisabled doneKey = "disabled"
	doneRevoked  doneKey = "revoked"
)

var accountsDone = map[doneKey]string{
	doneCreated:  "Account created.",
	doneRole:     "Role changed.",
	doneEnabled:  "Account enabled.",
	doneDisabled: "Account disabled.",
	doneRevoked:  "API Token revoked.",
}

// doneSentence maps a raw done= query value to its fixed sentence. A pure map
// lookup: an unknown or hostile value yields "" and is never rendered.
func doneSentence(raw string) string { return accountsDone[doneKey(raw)] }

// doneHref is base with the done key. base is only ever accountsScreenPath or
// accountPagePath, both built here under the fixed /console/accounts prefix, so
// a Location can never become protocol-relative or leave the Console.
func doneHref(base string, key doneKey) string {
	return base + "?" + url.Values{"done": {string(key)}}.Encode()
}

// accountReturnHref chooses where the browser lands after a write that already
// happened, and decides nothing: it reads the Account's current name and links
// to its page, or to the list when that read fails. A failed read costs the
// destination, never the act.
func accountReturnHref(ctx context.Context, d Deps, caller capability.Principal, accountID string, key doneKey) string {
	a, err := d.Accounts.Account(ctx, caller, accountID)
	if err != nil || a.Name == "" {
		return doneHref(accountsScreenPath, key)
	}
	return doneHref(accountPagePath(a.Name), key)
}

// The origin of a Disable made from the list's row: a closed token carried
// through the confirmation page into the POST body, never a URL.
const (
	fromField = "from"
	fromList  = "list"
)

// cameFromList reports whether v is the one recognised origin. Anything else
// means the Account page.
func cameFromList(v string) bool { return v == fromList }

// backLink is a link back to the screen an act was made from.
type backLink struct {
	Href  string
	Label string
}

// accountBack links to the list, or, when toList is false and name is known, to
// that Account's page. A link to an Account page is labelled with the
// Account's name; only a link to the list says "Back to Accounts".
func accountBack(name string, toList bool) backLink {
	if toList || name == "" {
		return backLink{Href: accountsScreenPath, Label: "Back to Accounts"}
	}
	return backLink{Href: accountPagePath(name), Label: "Back to " + name}
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
	case errors.Is(err, accounts.ErrInvalidName), errors.Is(err, accounts.ErrInvalidKind),
		errors.Is(err, accounts.ErrInvalidRole), errors.Is(err, accounts.ErrInvalidTTL),
		errors.Is(err, capability.ErrAPITokenTTLRequired):
		status, res = http.StatusBadRequest, accountsWriteResultView{
			Heading: "The Relay refused this: " + err.Error() + ". " + undone,
		}
	case accounts.IsInvalidToken(err):
		// Minting for a disabled Account: TokenService refuses it with the
		// same opaque ErrTokenInvalid every failed verification returns.
		status, res = http.StatusConflict, accountsWriteResultView{Heading: "This Relay would not mint a credential for that Account. Enable the Account " +
			"before minting one for it. " + undone,
		}
	case errors.Is(err, accounts.ErrPasswordOwned):
		status, res = http.StatusConflict, accountsWriteResultView{
			Heading: "This Account's human has set their own password, and no control sets it again. " + undone,
			Href:    accountsScreenPath,
			Label:   "Back to Accounts.",
		}
	case errors.Is(err, accounts.ErrMachinePassword):
		status, res = http.StatusBadRequest, accountsWriteResultView{
			Heading: "A machine Account never holds a password. " + undone,
		}
	case errors.Is(err, capability.ErrAccountsUnavailable), errors.Is(err, capability.ErrTemporaryPasswordsUnavailable):
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

// writePrelude is the opening every one of the Account write handlers shares:
// principal, nil-seam check, ParseForm, page. It returns ok=false having
// already written the response.
//
// Secure has already parsed, and refused any unreadable form of, an authenticated
// unsafe request, so behind it this ParseForm is a no-op. It stays for a handler
// mounted without Secure, as the tests mount it, so that one never reads a form it
// has not parsed.
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

// handleCreateAccount implements POST /console/new-account/create.
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
		pg.Banner = banner(d, r)

		// What the operator typed is echoed into a refused re-render, each
		// field only when it passes its own check, so a refusal of one never
		// resets another to the first option. The password is never echoed.
		name := r.PostFormValue("name")
		kind := accounts.Kind(r.PostFormValue("kind"))
		role := accounts.Role(r.PostFormValue("role"))
		form := newAccountForm("", false)
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
		// field included. Never defaulted in either direction: a kind
		// or a role must be ASKED for.
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

		if kind == accounts.KindHuman {
			createHuman(d, w, r, pg, caller, form, accounts.Account{Name: name, Kind: kind, Role: role, Enabled: true})
			return
		}

		_, err := d.AccountAdmin.CreateAccount(r.Context(), caller, accounts.Account{
			Name: name, Kind: kind, Role: role, Enabled: true,
		})
		if err != nil {
			writeFailedWith(w, pg, err, createAccountPattern, name, "Nothing was created.", "Account", createRefusal(form))
			return
		}
		http.Redirect(w, r, doneHref(accountsScreenPath, doneCreated), http.StatusSeeOther)
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

		refuse := func(fresh bool) writeRefusalRender {
			return editRefusal(d, r, caller, id, editRole, fresh, "", "")
		}
		if r.PostFormValue("role") == "" {
			refuse(stepUpFresh(d, r))(w, pg, http.StatusBadRequest, noRoleRefusal, "", "")
			return
		}
		// Role.Valid, not a hand-restated set: the domain owns what the
		// three roles are (accounts.Role).
		role := accounts.Role(r.PostFormValue("role"))
		if !role.Valid() {
			refuse(stepUpFresh(d, r))(w, pg, http.StatusBadRequest,
				"This form did not carry a recognisable role. The role was not changed.", "", "")
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
				refuse(stepUpFresh(d, r))(w, pg, http.StatusBadRequest,
					"That is already this Account's role. The role was not changed.", "", "")
				return
			}
			couldGrant = roleChangeCouldGrant(target.Role, role)
		}
		ask := accountsStepUp("The role was not changed.")
		ask.render = refuse(false)
		if couldGrant && !requireStepUp(d, w, r, &pg, ask) {
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
			// After a successful step-up the window is fresh; an unstepped
			// lower reads the window.
			writeFailedWith(w, pg, err, setAccountRolePattern, id, "The role was not changed.", "Account",
				refuse(couldGrant || stepUpFresh(d, r)))
			return
		}
		if readErr == nil {
			// The read above already named the Account; no second read.
			http.Redirect(w, r, doneHref(accountPagePath(target.Name), doneRole), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, accountReturnHref(r.Context(), d, caller, id, doneRole), http.StatusSeeOther)
	}
}

// handleSetAccountEnabled implements POST /console/accounts/{account_id}/enabled.
//
// Step-up iff the act is an ENABLE. Decided from the request alone, before any
// read, so this route has no TOCTOU, unlike the role route above. Its one read
// comes after a successful write and only picks the destination.
//
// A Disable made from the list's row posts from=list (the confirmation page
// carries it) and returns to the list; anything else returns to the Account
// page. PostFormValue reads the body only, so a query-string from is ignored.
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
			editRefusal(d, r, caller, id, editState, stepUpFresh(d, r), "", "")(w, pg, http.StatusBadRequest,
				"This form did not say whether to enable or disable the Account. Nothing was changed.", "", "")
			return
		}
		enabled := submitted == "true"

		undone := "The Account was not changed."
		ask := accountsStepUp(undone)
		ask.render = editRefusal(d, r, caller, id, editState, false, "", "")
		if enabled && !requireStepUp(d, w, r, &pg, ask) {
			return
		}

		if err := d.AccountAdmin.SetAccountEnabled(r.Context(), caller, id, enabled); err != nil {
			// A Disable made from the list's row was not made from the edit view.
			if !enabled && cameFromList(r.PostFormValue(fromField)) {
				writeFailed(w, pg, err, setAccountEnabledPattern, id, undone, "Account")
				return
			}
			writeFailedWith(w, pg, err, setAccountEnabledPattern, id, undone, "Account",
				editRefusal(d, r, caller, id, editState, enabled || stepUpFresh(d, r), "", ""))
			return
		}
		key := doneDisabled
		if enabled {
			key = doneEnabled
		}
		if !enabled && cameFromList(r.PostFormValue(fromField)) {
			http.Redirect(w, r, doneHref(accountsScreenPath, key), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, accountReturnHref(r.Context(), d, caller, id, key), http.StatusSeeOther)
	}
}

// ttlChoices is the mint form's CLOSED vocabulary. A human Account's form
// preselects the capability layer's default lifetime; a machine Account's form
// has no default (ttlOptions leaves it out).
//
// A closed select rather than a free-form number, for the reason
// api/accounts.go gives for making ttl_seconds a POINTER: a forgotten field
// must never silently mint an immortal credential. The default arrives as the
// explicit value "default", never as a missing field. Zero means "does not
// expire", which is legitimate — it is what a long-lived CI credential wants
// — but it has to be ASKED for.
var ttlChoices = []struct {
	Value   string
	Label   string
	TTL     time.Duration
	Default bool
}{
	{"default", "7 days (default)", capability.HumanAPITokenDefaultTTL, true},
	{"30d", "30 days", 30 * 24 * time.Hour, false},
	{"90d", "90 days", 90 * 24 * time.Hour, false},
	{"365d", "365 days", 365 * 24 * time.Hour, false},
	{"never", "does not expire", 0, false},
}

// ttlFor resolves a submitted ttl value. ok is false for an absent or
// unrecognised one.
func ttlFor(value string) (capability.APITokenLifetime, bool) {
	for _, c := range ttlChoices {
		if c.Value != value {
			continue
		}
		if c.Default {
			return capability.DefaultAPITokenLifetime(), true
		}
		return capability.ExplicitAPITokenLifetime(c.TTL), true
	}
	return capability.APITokenLifetime{}, false
}

// mintedView is the view type in this package with a field a secret can
// occupy, and Token is that field; the harnessView it carries is the other view
// type a secret can occupy. It exists for exactly one render.
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
	Harness     *harnessView
	Back        backLink
}

// harnessView is the rendered Harness setup. Every field but CACertificate embeds
// the plaintext, so like Token these are plain strings with no redaction of their
// own; LogValue puts one back. Gleipnir is empty for a human Account's token.
type harnessView struct {
	CACertificate     string
	ClaudeCode        string
	ClaudeCodeMCPJSON string
	Gleipnir          string
	Check             string
}

// LogValue implements slog.LogValuer, omitting every block.
func (harnessView) LogValue() slog.Value { return slog.GroupValue() }

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
		ttl := r.PostFormValue("ttl")
		refuse := func(fresh bool) writeRefusalRender {
			return editRefusal(d, r, caller, id, editMint, fresh, name, ttl)
		}
		if name == "" || len(name) > maxTokenNameBytes {
			refuse(stepUpFresh(d, r))(w, pg, http.StatusBadRequest,
				"A token needs a name of 1 to 128 bytes, so it can be audited and "+
					"pruned later. Nothing was minted.", "", "")
			return
		}
		lifetime, ok := ttlFor(ttl)
		if !ok {
			refuse(stepUpFresh(d, r))(w, pg, http.StatusBadRequest,
				"This form did not carry a recognisable lifetime. A token that never "+
					"expires is a legitimate choice and has to be made deliberately. Nothing was minted.", "", "")
			return
		}

		ask := accountsStepUp("Nothing was minted.")
		ask.render = refuse(false)
		if !requireStepUp(d, w, r, &pg, ask) {
			return
		}

		// pg was passed to requireStepUp by pointer, so this render carries the
		// ROTATED session's CSRF token, with no redirect in between.
		tok, plaintext, err := d.AccountAdmin.MintAPIToken(r.Context(), caller, id, name, lifetime)
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
				writeFailedWith(w, pg, err, mintAPITokenPattern, id, "Nothing was minted.", "Account", refuse(true))
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
		// read rather than from a hidden form field: echoing a caller-supplied
		// one back would let the page name an Account that is not the one the
		// credential belongs to. Best-effort — a failed read costs the link
		// to the Account page (it falls back to the list), never the render of
		// the secret, which is the one thing this response exists to do.
		//
		// It is not free, and the cost is named rather than discovered: this
		// is a SECOND ControlAccountRead authorization on the mint path, and a
		// refusal of it writes its own refuseControl row in the trail. Both
		// are acceptable — the alternative is echoing a caller-supplied name
		// back onto the page that reveals a credential.
		//
		// The same read gives the Account's kind, which decides whether the
		// Gleipnir block is rendered; a failed read leaves it empty and drops
		// only that block.
		accountName := ""
		var kind accounts.Kind
		if target, readErr := d.Accounts.Account(r.Context(), caller, id); readErr == nil {
			accountName = target.Name
			kind = target.Kind
		}

		// One of the Reveal() calls in this package (the other is the temporary
		// password's, in temporarypassword.go) — the sites are enumerated on
		// Plaintext.Reveal's own doc comment and checked by
		// TestPlaintext_RevealCallSitesAreEnumerated.
		credential := plaintext.Reveal()

		w.Header().Set("Cache-Control", "no-store")
		renderScreen(w, pg, accountsMintedTmpl, mintedView{
			AccountName: accountName,
			TokenID:     tok.ID,
			TokenName:   tok.Name,
			Expires:     tok.ExpiresAt,
			Token:       credential,
			Harness:     harnessFor(d, credential, kind),
			Back:        accountBack(accountName, false),
		})
	}
}

// harnessFor renders the Harness setup for a freshly minted credential, or nil
// when there is none to render (no target is wired, or the credential is not
// shaped like an API Token). A render error never fails the mint: the token is
// already minted and is shown either way.
func harnessFor(d Deps, credential string, kind accounts.Kind) *harnessView {
	rendering, err := d.HarnessSetup.Render(credential, kind)
	if err != nil {
		return nil
	}
	return &harnessView{
		CACertificate:     rendering.CACertificate(),
		ClaudeCode:        rendering.ClaudeCode(),
		ClaudeCodeMCPJSON: rendering.ClaudeCodeMCPJSON(),
		Gleipnir:          rendering.Gleipnir(),
		Check:             rendering.Check(),
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
		errors.Is(err, capability.ErrAPITokenTTLRequired),
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
//
// The route carries only a token ID, so the confirmation page posts the owning
// Account's ID as a hidden hint that says only where to land. It is accepted
// only if the registry lists this token on that Account; an empty, overlong or
// mismatched hint, or a failed read, falls back to the list. A hand-built form
// therefore cannot make the result line name an Account the token is not on.
// The write itself never reads the hint.
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
		http.Redirect(w, r, revokeReturnHref(r.Context(), d, caller, r.PostFormValue("account"), id), http.StatusSeeOther)
	}
}

// revokeReturnHref is the landing for a revoked token: the owner's page when
// the registry lists tokenID on the Account the hint names, the list otherwise.
// A hint naming an Account the token is not on, an overlong one, and a failed
// read all land on the list (tested).
func revokeReturnHref(ctx context.Context, d Deps, caller capability.Principal, owner, tokenID string) string {
	list := doneHref(accountsScreenPath, doneRevoked)
	if owner == "" || len(owner) > maxAccountIDBytes {
		return list
	}
	toks, err := d.Accounts.APITokens(ctx, caller, owner)
	if err != nil {
		return list
	}
	for _, t := range toks {
		if t.ID == tokenID {
			return accountReturnHref(ctx, d, caller, owner, doneRevoked)
		}
	}
	return list
}

// accountsMintedTmpl is the reveal-once response: the plaintext, escaped by
// html/template, rendered as the token and again inside each harness block that
// embeds it, all in this one response, beside the sentence that says this is
// the only time it will ever appear.
var accountsMintedTmpl = newScreen("accounts-minted", `
<section class="panel minted">
  <h3>API Token minted &mdash; <span class="ident">{{.TokenName}}</span>{{with .AccountName}} for <span class="ident">{{.}}</span>{{end}}</h3>
  <p><code>{{.Token}}</code></p>
  <p class="note">Shown once.</p>
  <p class="note">Token id <code>{{.TokenID}}</code>{{if .Expires.IsZero}}, which does not expire{{else}}, expiring {{stamp .Expires}}{{end}}.</p>
  {{with .Harness}}
  <h4>relay-ca.pem</h4>
  <pre><code>{{.CACertificate}}</code></pre>
  <h4>Claude Code</h4>
  <pre><code>{{.ClaudeCode}}</code></pre>
  <h4>.mcp.json</h4>
  <pre><code>{{.ClaudeCodeMCPJSON}}</code></pre>
  {{with .Gleipnir}}<h4>Gleipnir</h4>
  <pre><code>{{.}}</code></pre>
  {{end}}<h4>Check</h4>
  <pre><code>{{.Check}}</code></pre>
  {{end}}
  <p><a href="{{.Back.Href}}">{{.Back.Label}}</a></p>
</section>
`)
