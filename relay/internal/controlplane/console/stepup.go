package console

// stepup.go is the one step-up idiom for every Console write that takes one.
// consoleauth owns the window, the throttle, the audit and the rotation; this
// file only maps their answers onto a page (invariant 10: decide nothing).
//
// # Two modes, and which acts use which
//
//   - stepUpWindowed: the four privilege-granting Account acts. An empty
//     password proceeds only while consoleauth says this session's step-up
//     stamp is fresh (owner decision 2026-10-05: one password per
//     window). the composer uses stepUpPerAct unless a human first
//     amends ADR-0026 decision 3 and threat-model R11.
//   - stepUpPerAct: approval decide (approval.md AP-16: "re-authenticates at
//     the moment of deciding") and the bulk decide (AP-59: "entered
//     immediately before it is submitted"). A password is always required and
//     verified in that request, and the window is never consulted. Decide and
//     bulk decide may NEVER accept the window: moving either to stepUpWindowed
//     is a spec change to approval.md, made by a human first, not a code edit.
//
// Known and deliberate: a successful step-up in EITHER mode stamps the
// session, so a decision's password also opens the window for the Account
// acts. The stamp is the proof of a recent credential, whoever asked for it.
//
// Every successful step-up, in either mode, rotates the session identifier (a
// step-up is a privilege change). The response carries the new cookie, and
// the page's CSRF token is re-derived from the new id.
//
// Known and accepted: two submits racing on one session (a double-click, or
// two tabs posting at once). Both resolve the old id at the boundary. The
// first step-up rotates it, and the second's StepUp sees ErrNoSession and
// renders "Your session has ended", although the session lives on under the
// new id. This fails closed: nothing is done on the second request, and the
// browser already holds the new cookie from the first response. A request
// that arrives AFTER the rotation carrying the old cookie never reaches this
// file; the boundary sends it to sign-in. A stale CSRF token from another
// open tab is refused at Secure with the existing reload copy.

import (
	"errors"
	"net/http"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
)

type stepUpMode int

const (
	stepUpWindowed stepUpMode = iota
	stepUpPerAct
)

// stepUpAsk is what one act tells requireStepUp: its mode, its copy, and how
// to draw a refusal on its own result page.
type stepUpAsk struct {
	mode stepUpMode
	// required is the no-password sentence, e.g. "Step-up re-authentication
	// is required to decide an approval."
	required string
	// undone says what did not happen, e.g. "Nothing was decided."
	undone string
	// act is a log label, e.g. "an approval decision".
	act string
	// render writes status and the act's result page.
	render func(w http.ResponseWriter, pg Page, status int, heading, href, label string)
}

// refuseMissing renders the 401 for a request that carried no password and
// had no fresh window to stand in for one. Shared with decide's early check
// so the copy is defined once.
func (a stepUpAsk) refuseMissing(w http.ResponseWriter, pg Page) {
	a.render(w, pg, http.StatusUnauthorized, a.required+" "+a.undone, "", "")
}

// refuseSessionEnded renders the 401 for a session the store no longer knows,
// with a link back to sign-in.
func (a stepUpAsk) refuseSessionEnded(w http.ResponseWriter, pg Page) {
	a.render(w, pg, http.StatusUnauthorized, "Your session has ended. "+a.undone, LoginPath, "Sign in again.")
}

// requireStepUp reports whether the CALLER MAY PROCEED. It has already
// written the response on every false return, so `if !requireStepUp(...) {
// return }` is the only correct use, and no capability call may come before
// it.
//
// pg is taken by pointer so a successful step-up can swap in the rotated
// session's CSRF token: any page rendered afterwards, a refusal included,
// must carry a token that still validates.
//
// A submitted password is ALWAYS verified, even inside the window: a
// credential is never discarded unchecked, and a wrong one still costs a
// throttle strike. Neither the password nor the new identifier is logged.
func requireStepUp(d Deps, w http.ResponseWriter, r *http.Request, pg *Page, ask stepUpAsk) bool {
	cs, ok := controlplane.ConsoleSessionFromContext(r.Context())
	if !ok {
		// FAIL CLOSED: an authenticated request reached a gated /console/
		// route with no resolved browser session, which the cookie lane
		// cannot produce. There is no session to step up.
		d.logger().ErrorContext(r.Context(), "console step-up reached without a resolved browser session",
			"act", ask.act, "path", r.URL.Path)
		http.Error(w, "the Relay could not identify the session to step up", http.StatusInternalServerError)
		return false
	}

	password := r.PostFormValue("password")
	if password == "" {
		return stepUpWithoutPassword(d, w, r, *pg, ask, cs.ID)
	}

	newID, err := d.Auth.StepUp(r.Context(), cs.ID, accounts.NewPassword(password), controlplane.SourceAddress(r))
	switch {
	case err == nil:
		setSessionCookie(w, newID)
		w.Header().Set("Cache-Control", "no-store")
		pg.CSRFToken = d.Auth.CSRFToken(newID).Reveal()
		return true
	case isThrottled(err):
		wait, _ := consoleauth.Throttled(err)
		setRetryAfter(w, wait)
		ask.render(w, *pg, http.StatusTooManyRequests, throttleMessage(wait)+" "+ask.undone, "", "")
	case errors.Is(err, consoleauth.ErrBadCredentials):
		ask.render(w, *pg, http.StatusUnauthorized, "That password did not match. "+ask.undone, "", "")
	case errors.Is(err, consoleauth.ErrNoSession):
		ask.refuseSessionEnded(w, *pg)
	default:
		// Never the password, and never the error text to the page.
		d.logger().ErrorContext(r.Context(), "console step-up returned an error",
			"act", ask.act, "path", r.URL.Path, "error", err)
		ask.render(w, *pg, http.StatusInternalServerError, "The Relay could not verify your password. "+ask.undone, "", "")
	}
	return false
}

// stepUpWithoutPassword is requireStepUp's empty-password branch.
func stepUpWithoutPassword(d Deps, w http.ResponseWriter, r *http.Request, pg Page, ask stepUpAsk, id consoleauth.SessionID) bool {
	if ask.mode == stepUpPerAct {
		// The window is not consulted: a decision always costs a password.
		ask.refuseMissing(w, pg)
		return false
	}
	// Proceeding inside the window neither rotates nor re-stamps: the window
	// is measured from the step-up and never extended by use.
	err := d.Auth.RequireStepUp(id)
	switch {
	case err == nil:
		return true
	case errors.Is(err, consoleauth.ErrStepUpRequired):
		ask.refuseMissing(w, pg)
	case errors.Is(err, consoleauth.ErrNoSession):
		ask.refuseSessionEnded(w, pg)
	default:
		d.logger().ErrorContext(r.Context(), "console step-up window check returned an error",
			"act", ask.act, "path", r.URL.Path, "error", err)
		ask.render(w, pg, http.StatusInternalServerError, "The Relay could not verify your password. "+ask.undone, "", "")
	}
	return false
}

// stepUpFresh reports whether to render a stepUpWindowed form's password field
// as optional. Presentation only: the handler re-decides through
// requireStepUp, so a tampered or stale page can never skip step-up. It must
// never be used for a stepUpPerAct form.
func stepUpFresh(d Deps, r *http.Request) bool {
	cs, ok := controlplane.ConsoleSessionFromContext(r.Context())
	return ok && d.Auth != nil && d.Auth.RequireStepUp(cs.ID) == nil
}
