package console

// password.go is the "your account" surface: a signed-in human changes only
// their own password (ADR-0045 decisions 5 to 9). The same form is the forced
// change of a session opened with a temporary password.
//
// # What this file decides: nothing
//
// The proof of the current password, its throttle, its audit rows, the length
// bounds, the confirmation and "must differ" rules and the ending of the
// Account's other sessions are consoleauth's (Authenticator.ChangePassword),
// which takes the session's own identifier and no target Account. This file
// renders its answers (invariant 10). Which paths a restricted session reaches
// is declared here by PasswordChangeOnly and enforced once, at the
// authentication boundary.
//
// No response here echoes a password: every refusal re-renders the form with
// the three password fields empty.

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
)

const (
	// yourAccountPath is the "your account" page, reached from the signed-in
	// block. It is not /console/accounts, the admin list.
	yourAccountPath = "/console/account"

	// changePasswordPath accepts the change form.
	changePasswordPath = "/console/account/password"
)

// PasswordChangeOnly reports whether r targets what a session opened with a
// temporary password may reach: the change-password form and sign-out, and
// nothing else (ADR-0045 decision 5). Its extent is asserted exactly in a test.
//
// It fails closed and decides on exactly what the router dispatches. The
// router matches the escaped path and unescapes each segment after splitting
// it, so a decoded or cleaned path can name an allowed route while the router
// runs another (an encoded slash plus dot-segments). A request is therefore
// allowed only when its path carries no percent-encoding the standard library
// would not itself emit (RawPath empty) and is, byte for byte, one of the
// three paths or a cleaned path under the static assets the change page loads.
// Anything else, including an uncleaned path the router would
// only redirect, is answered by the required-change handler.
func PasswordChangeOnly(r *http.Request) bool {
	if r.URL.RawPath != "" {
		return false
	}
	switch r.URL.Path {
	case yourAccountPath, changePasswordPath, LogoutPath:
		return true
	}
	return strings.HasPrefix(r.URL.Path, AssetsPrefix) && r.URL.Path == cleanPath(r.URL.Path)
}

// PasswordChangeRequiredHandler answers every other request of a restricted
// session: a GET or HEAD is redirected to the change form, remembering where it
// was headed; any other method is refused.
func PasswordChangeRequiredHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Set your own password before anything else.", http.StatusForbidden)
			return
		}
		target := yourAccountPath
		if next := safeReturnPath(r.URL.RequestURI()); next != "" && next != HomePath {
			target += "?next=" + url.QueryEscape(next)
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
	})
}

// closed sentences for the your-account page.
const (
	passwordChangedSentence = "Password changed."

	notChangedSentence = "Your password was not changed."
)

// yourAccountView is the your-account page.
type yourAccountView struct {
	CSRFToken string
	Action    string
	// Username is the signed-in Account's name, for a password manager to file
	// the change against; the server never reads it back.
	Username string
	// Next is where a restricted session lands after the change; empty on an
	// ordinary session, which has no such form field.
	Next string
	// Done is the fixed sentence for a change that just happened.
	Done string

	// Refusal is the banner above the button; Field names the one field it is
	// about ("current", "new", "confirm"), or is empty.
	Refusal string
	Field   string
}

var yourAccountTmpl = newScreen("your-account", `
{{with .Done}}<p class="done" role="status">{{.}}</p>{{end}}
<form class="ctlform ctlgrid" method="post" action="{{.Action}}">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  {{with .Next}}<input type="hidden" name="next" value="{{.}}">{{end}}
  <input class="vh" type="text" name="username" value="{{.Username}}" autocomplete="username" readonly tabindex="-1" aria-hidden="true">
  <div class="fld">
    <label class="fldlabel" for="pw-current">Current password</label>
    <input id="pw-current" name="current_password" type="password" autocomplete="current-password" required{{if eq .Field "current"}} aria-invalid="true" aria-describedby="pw-error"{{end}}>
  </div>
  <div class="fld">
    <label class="fldlabel" for="pw-new">New password</label>
    <input id="pw-new" name="new_password" type="password" autocomplete="new-password" required{{if eq .Field "new"}} aria-invalid="true" aria-describedby="pw-error"{{end}}>
  </div>
  <div class="fld">
    <label class="fldlabel" for="pw-confirm">Confirm new password</label>
    <input id="pw-confirm" name="confirm_password" type="password" autocomplete="new-password" required{{if eq .Field "confirm"}} aria-invalid="true" aria-describedby="pw-error"{{end}}>
  </div>
  {{with .Refusal}}<p class="fielderr" id="pw-error" role="alert">{{.}}</p>{{end}}
  <button class="btn grant" type="submit">Change password</button>
</form>
`)

// handleYourAccount implements GET /console/account.
func handleYourAccount(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pg, cs, ok := yourAccountPrelude(d, w, r, false)
		if !ok {
			return
		}
		v := yourAccountView{
			CSRFToken: pg.CSRFToken,
			Action:    changePasswordPath,
			Username:  pg.Account,
		}
		if r.URL.Query().Get("done") == "password" {
			v.Done = passwordChangedSentence
		}
		if cs.Restricted {
			v.Next = safeReturnPath(r.URL.Query().Get("next"))
		}
		w.Header().Set("Cache-Control", "no-store")
		renderScreen(w, pg, yourAccountTmpl, v)
	}
}

// yourAccountPrelude is the opening both handlers share. A request with no
// resolved browser session (a bearer caller) has no Console password to
// change: the page draws its form like any Console page, and the change is
// refused as the wiring alarm handleLogout raises, since the boundary cannot
// produce it on the cookie lane. needSession is true for the change.
func yourAccountPrelude(d Deps, w http.ResponseWriter, r *http.Request, needSession bool) (Page, controlplane.ConsoleSession, bool) {
	if _, ok := principal(w, r); !ok {
		return Page{}, controlplane.ConsoleSession{}, false
	}
	cs, haveSession := controlplane.ConsoleSessionFromContext(r.Context())
	if needSession && !haveSession {
		d.logger().ErrorContext(r.Context(), "console password change reached without a resolved browser session",
			"path", r.URL.Path)
		http.Error(w, "the Relay could not identify the session to change a password for", http.StatusInternalServerError)
		return Page{}, controlplane.ConsoleSession{}, false
	}
	if needSession && d.Auth == nil {
		unavailable(w, "Console sign-in")
		return Page{}, controlplane.ConsoleSession{}, false
	}
	pg, ok := page(d, w, r, "Your account")
	if !ok {
		return Page{}, controlplane.ConsoleSession{}, false
	}
	return pg, cs, true
}

// handleChangePassword implements POST /console/account/password.
func handleChangePassword(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "could not read the submitted form", http.StatusBadRequest)
			return
		}
		pg, cs, ok := yourAccountPrelude(d, w, r, true)
		if !ok {
			return
		}
		w.Header().Set("Cache-Control", "no-store")

		next := ""
		if cs.Restricted {
			next = safeReturnPath(r.PostFormValue("next"))
		}
		refuse := func(status int, field, message string) {
			w.WriteHeader(status)
			renderScreen(w, pg, yourAccountTmpl, yourAccountView{
				CSRFToken: pg.CSRFToken,
				Action:    changePasswordPath,
				Username:  pg.Account,
				Next:      next,
				Refusal:   message,
				Field:     field,
			})
		}
		ended := func(message string) {
			w.WriteHeader(http.StatusUnauthorized)
			renderScreen(w, pg, accountsWriteResultTmpl, accountsWriteResultView{
				Heading: message, Href: LoginPath, Label: "Sign in again.",
			})
		}

		newID, err := d.Auth.ChangePassword(r.Context(), cs.ID, consoleauth.PasswordChange{
			Current: accounts.NewPassword(r.PostFormValue("current_password")),
			New:     accounts.NewPassword(r.PostFormValue("new_password")),
			Confirm: accounts.NewPassword(r.PostFormValue("confirm_password")),
			Source:  controlplane.SourceAddress(r),
		})
		switch {
		case err == nil:
			setSessionCookie(w, newID)
			target := yourAccountPath + "?done=password"
			if cs.Restricted {
				target = next
				if target == "" {
					target = HomePath
				}
			}
			http.Redirect(w, r, target, http.StatusSeeOther)
		case isThrottled(err):
			wait, _ := consoleauth.Throttled(err)
			setRetryAfter(w, wait)
			refuse(http.StatusTooManyRequests, "", throttleMessage(wait)+" "+notChangedSentence)
		case errors.Is(err, consoleauth.ErrCurrentPasswordRequired):
			refuse(http.StatusBadRequest, "current", "Enter your current password. "+notChangedSentence)
		case errors.Is(err, consoleauth.ErrBadCredentials):
			refuse(http.StatusUnauthorized, "current", "That password did not match. "+notChangedSentence)
		case errors.Is(err, accounts.ErrPasswordTooShort), errors.Is(err, accounts.ErrPasswordTooLong):
			refuse(http.StatusBadRequest, "new", "A password is 12 to 4096 bytes. "+notChangedSentence)
		case errors.Is(err, consoleauth.ErrPasswordMismatch):
			refuse(http.StatusBadRequest, "confirm", "The new password and its confirmation differ. "+notChangedSentence)
		case errors.Is(err, consoleauth.ErrPasswordUnchanged):
			refuse(http.StatusBadRequest, "new", "The new password must differ from the current one. "+notChangedSentence)
		case errors.Is(err, consoleauth.ErrNoSession):
			ended("Your session has ended. " + notChangedSentence)
		case errors.Is(err, consoleauth.ErrChangedSessionEnded):
			clearSessionCookie(w)
			ended("Your password was changed, but this session ended. Sign in with your new password.")
		case errors.Is(err, accounts.ErrPasswordChanged):
			refuse(http.StatusConflict, "", "Your password changed while you were editing. Reload and try again. "+notChangedSentence)
		case errors.Is(err, consoleauth.ErrPasswordChangeUnavailable):
			unavailable(w, "Password changes")
		default:
			// Never the password, and never the error text to the page.
			d.logger().ErrorContext(r.Context(), "console password change returned an error",
				"route", changePasswordPath, "error", err)
			refuse(http.StatusInternalServerError, "", "The Relay could not complete this change. Reload and read the current state before trying again.")
		}
	}
}
