package console

// password_test.go covers ADR-0045 in the Console: the your-account page and
// the password change, the restricted session a temporary password opens, the
// reveal-once temporary password at a human Account's create and by re-issue,
// and the Account page's Temporary password section.

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
)

func passwordForm(current, next, confirm string) url.Values {
	return url.Values{"current_password": {current}, "new_password": {next}, "confirm_password": {confirm}}
}

// --- the restricted boundary's declaration -------------------------------

func TestPasswordChangeOnly_ExtentIsExact(t *testing.T) {
	for path, want := range map[string]bool{
		yourAccountPath:               true,
		changePasswordPath:            true,
		LogoutPath:                    true,
		"/console/account/":           false,
		"/console/":                   false,
		"/console":                    false,
		"/console/accounts":           false,
		"/console/account/password/x": false,
		"/console/new-account":        false,
		"/console/events":             false,
		LoginPath:                     false,
		"/api/v1/accounts":            false,
		// An uncleaned path is never allowed: only the exact bytes are.
		"/console/nodes/../account":        false,
		"/console/account/../accounts":     false,
		"/console/account/../../api/v1/x":  false,
		"/console/./account/password":      false,
		"/console/accounts/../account/":    false,
		"/console/account/password/../../": false,
		// The stylesheet is reachable; a traversal out of its prefix is not.
		"/console/assets/console.css":    true,
		"/console/assets/../accounts":    false,
		"/console/assets/../../api/v1/x": false,
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.URL.Path = path
		if got := PasswordChangeOnly(req); got != want {
			t.Errorf("PasswordChangeOnly(%q) = %v, want %v", path, got, want)
		}
	}
}

// The router dispatches on the escaped path, so a path whose decoded form
// names an allowed route is refused whenever it carries an encoding.
func TestPasswordChangeOnly_RefusesAnyPercentEncodedPath(t *testing.T) {
	for _, target := range []string{
		"/console/accounts/x%2F..%2F..%2Faccount",
		"/console/accounts/x%2f..%2f..%2faccount",
		"/console/nodes/n1%2F..%2F..%2Faccount",
		"/console/jobs/j%2F..%2F..%2Faccount%2Fpassword",
		"/console/accounts/%2e%2e/account",
		"/console/%2e%2e/console/account",
		"/console/accoun%74",
		"/console/account%2Fpassword",
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		if PasswordChangeOnly(req) {
			t.Errorf("PasswordChangeOnly(%q) = true (Path %q, RawPath %q), want false", target, req.URL.Path, req.URL.RawPath)
		}
	}
}

func TestPasswordChangeRequired_RedirectsGetWithNextAndRefusesOtherMethods(t *testing.T) {
	h := PasswordChangeRequiredHandler()

	for _, tc := range []struct{ target, want string }{
		{"/console/accounts?x=1", yourAccountPath + "?next=" + url.QueryEscape("/console/accounts?x=1")},
		{"/console/nodes/n1", yourAccountPath + "?next=" + url.QueryEscape("/console/nodes/n1")},
		{"/console/", yourAccountPath},
		{"/api/v1/operations", yourAccountPath}, // not a Console path: nothing to return to
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(method, tc.target, nil))
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != tc.want {
				t.Errorf("%s %s = %d Location %q, want 303 %q", method, tc.target, rec.Code, rec.Header().Get("Location"), tc.want)
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("%s %s is cacheable", method, tc.target)
			}
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, "/console/new-account/create", nil))
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "Set your own password before anything else.") {
			t.Errorf("%s = %d %q, want a 403 saying to set a password", method, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Location") != "" {
			t.Errorf("%s was redirected", method)
		}
	}
}

// --- the your-account page -----------------------------------------------

func TestYourAccount_DrawsTheChangeFormForAnySignedInHuman(t *testing.T) {
	x := newWriteFix(t, nil)
	rec := x.get(t, yourAccountPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body %s", rec.Code, contentOf(rec.Body.String()))
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("the page is cacheable")
	}
	form := contentOf(rec.Body.String())
	for _, want := range []string{
		`action="` + changePasswordPath + `"`,
		`name="current_password" type="password" autocomplete="current-password"`,
		`name="new_password" type="password" autocomplete="new-password"`,
		`name="confirm_password" type="password" autocomplete="new-password"`,
		`name="csrf_token"`,
		`name="username" value="mike" autocomplete="username" readonly`,
		`>Change password</button>`,
	} {
		if !strings.Contains(form, want) {
			t.Errorf("the form lacks %q:\n%s", want, form)
		}
	}
	if strings.Contains(form, `name="next"`) {
		t.Error("an ordinary session's form carries a next field")
	}
	if strings.Contains(form, "Password changed.") {
		t.Error("the page claims a change nobody made")
	}
	// A crafted done= value renders only through the closed map.
	crafted := x.get(t, yourAccountPath+"?done=%3Cb%3Ehi").Body.String()
	if strings.Contains(crafted, "<b>hi") || strings.Contains(crafted, "Password changed.") {
		t.Error("an unknown done= value was rendered")
	}
	if !strings.Contains(x.get(t, yourAccountPath+"?done=password").Body.String(), "Password changed.") {
		t.Error("done=password does not draw the result sentence")
	}
}

func TestShell_TheSignedInBlockLinksYourAccount(t *testing.T) {
	x := newWriteFix(t, nil)
	body := x.get(t, accountsScreenPath).Body.String()
	if !strings.Contains(body, `<a href="/console/account">Your account</a>`) {
		t.Errorf("the signed-in block does not link Your account:\n%s", body)
	}
}

// --- the change -----------------------------------------------------------

func TestChangePassword_RefusalsNameTheField(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		status     int
		field      string // the input marked aria-invalid, "" for none
		sentence   string
		retryAfter string
	}{
		{"current required", consoleauth.ErrCurrentPasswordRequired, 400, "pw-current", "current password", ""},
		{"wrong current", consoleauth.ErrBadCredentials, 401, "pw-current", "That password did not match. Your password was not changed.", ""},
		{"too short", accounts.ErrPasswordTooShort, 400, "pw-new", "12 to 4096 bytes", ""},
		{"too long", accounts.ErrPasswordTooLong, 400, "pw-new", "12 to 4096 bytes", ""},
		{"mismatch", consoleauth.ErrPasswordMismatch, 400, "pw-confirm", "confirmation differ", ""},
		{"unchanged", consoleauth.ErrPasswordUnchanged, 400, "pw-new", "must differ", ""},
		{"throttled", &consoleauth.ThrottledError{RetryAfter: 30 * time.Second}, 429, "", "Too many recent attempts", "30"},
		{"concurrent change", accounts.ErrPasswordChanged, 409, "", "changed while you were editing", ""},
		{"unclassified", errors.New("store down"), 500, "", "could not complete this change", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newWriteFix(t, nil)
			x.auth.changeErr = tc.err

			rec := x.post(t, changePasswordPath, passwordForm("secret-current-password", "secret-new-password!", "secret-new-password!"))
			body := rec.Body.String()
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.status, contentOf(body))
			}
			if got := rec.Header().Get("Retry-After"); got != tc.retryAfter {
				t.Errorf("Retry-After = %q, want %q", got, tc.retryAfter)
			}
			if !strings.Contains(body, tc.sentence) {
				t.Errorf("the refusal does not say %q:\n%s", tc.sentence, contentOf(body))
			}
			alert := strings.Index(body, `<p class="fielderr" id="pw-error" role="alert">`)
			if alert < 0 || alert > strings.Index(body, `>Change password</button>`) {
				t.Errorf("the banner is missing or not above the button:\n%s", contentOf(body))
			}
			for _, id := range []string{"pw-current", "pw-new", "pw-confirm"} {
				marked := regexp.MustCompile(`id="` + id + `"[^>]*aria-invalid="true" aria-describedby="pw-error"`).MatchString(body)
				if marked != (id == tc.field) {
					t.Errorf("field %s marked invalid = %v, want %v", id, marked, id == tc.field)
				}
			}
			// Never echoes a password back.
			for _, secret := range []string{"secret-current-password", "secret-new-password!"} {
				if strings.Contains(body, secret) {
					t.Errorf("the refusal echoes %q", secret)
				}
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Error("a refusal is cacheable")
			}
		})
	}
}

func TestChangePassword_RefusalsOfASessionTheChangeCannotContinue(t *testing.T) {
	x := newWriteFix(t, nil)
	x.auth.changeErr = consoleauth.ErrNoSession
	rec := x.post(t, changePasswordPath, passwordForm("a", "b", "c"))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `<a href="`+LoginPath+`">Sign in again.</a>`) {
		t.Errorf("ErrNoSession = %d:\n%s", rec.Code, contentOf(rec.Body.String()))
	}

	x = newWriteFix(t, nil)
	x.auth.changeErr = consoleauth.ErrChangedSessionEnded
	rec = x.post(t, changePasswordPath, passwordForm("a", "b", "c"))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "Your password was changed, but this session ended. Sign in with your new password.") {
		t.Errorf("ErrChangedSessionEnded = %d:\n%s", rec.Code, contentOf(rec.Body.String()))
	}
	if cleared := cookieNamed(rec.Result().Cookies(), consoleauth.SessionCookieName); cleared == nil || cleared.MaxAge >= 0 {
		t.Errorf("the ended session's cookie was not cleared: %+v", cleared)
	}

	x = newWriteFix(t, nil)
	x.auth.changeErr = consoleauth.ErrPasswordChangeUnavailable
	if rec = x.post(t, changePasswordPath, passwordForm("a", "b", "c")); rec.Code != http.StatusInternalServerError {
		t.Errorf("an unwired change = %d, want the unavailable 500", rec.Code)
	}
}

func TestChangePassword_SuccessRotatesTheCookieAndReturnsWithAResult(t *testing.T) {
	x := newWriteFix(t, nil)
	x.auth.changeID = consoleauth.ParseSessionID("rotated-after-change")

	rec := x.post(t, changePasswordPath, passwordForm("current-password!", "brand-new-password", "brand-new-password"))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != yourAccountPath+"?done=password" {
		t.Fatalf("status = %d Location %q, want 303 to the page with done=password", rec.Code, rec.Header().Get("Location"))
	}
	set := cookieNamed(rec.Result().Cookies(), consoleauth.SessionCookieName)
	if set == nil || set.Value != "rotated-after-change" || !set.HttpOnly || !set.Secure {
		t.Errorf("session cookie = %+v, want the rotated, HttpOnly, Secure one", set)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("the response is cacheable")
	}

	// The three passwords reach consoleauth, wrapped, with the verified source.
	if len(x.auth.changeCalls) != 1 {
		t.Fatalf("ChangePassword called %d times", len(x.auth.changeCalls))
	}
	c := x.auth.changeCalls[0]
	if c.Current.Reveal() != "current-password!" || c.New.Reveal() != "brand-new-password" || c.Confirm.Reveal() != "brand-new-password" || c.Source == "" {
		t.Errorf("call = %+v", c)
	}
}

func TestChangePassword_DoesNotTakeATargetAccountFromTheRequest(t *testing.T) {
	x := newWriteFix(t, nil)
	form := passwordForm("a-current-password", "a-new-password!!", "a-new-password!!")
	form.Set("account_id", "acct-ana")
	form.Set("account", "ana")
	x.auth.changeID = consoleauth.ParseSessionID("rotated")
	if rec := x.post(t, changePasswordPath, form); rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", rec.Code)
	}
	// ChangePassword's signature carries the session's own id and no Account:
	// nothing in the request can retarget it. The call is the whole evidence.
	if len(x.auth.changeCalls) != 1 {
		t.Fatalf("ChangePassword called %d times", len(x.auth.changeCalls))
	}
}

// --- the restricted session, end to end through the real boundary --------

// restrictedFix creates a human Account through the real create route (so its
// temporary password is the one the reveal showed), signs it in with that
// password, and returns the new human's session.
type restrictedFix struct {
	*realWriteFix
	name      string
	temporary string
	session   *http.Cookie
	csrf      string
}

func newRestrictedFix(t *testing.T) *restrictedFix {
	t.Helper()
	// A Freeze is engaged so every ordinary page would draw its banner: a
	// restricted page drawing none is then the gate's doing, not an empty one.
	admin := newRealWriteFix(t, func(d *Deps) { d.Freeze = fakeFreeze{frozen: true} })
	rec := admin.post(t, createAccountAction(), createForm("newbie", realWritePassword))
	if rec.Code != http.StatusOK {
		t.Fatalf("create = %d; body %s", rec.Code, contentOf(rec.Body.String()))
	}
	temp := scrapeTemporaryPassword(t, rec.Body.String())

	id, sess, err := admin.svc.Login(t.Context(), consoleauth.Attempt{Name: "newbie", Password: accounts.NewPassword(temp), Source: "127.0.0.1"})
	if err != nil {
		t.Fatalf("sign in with the temporary password: %v", err)
	}
	if !sess.Restricted {
		t.Fatal("a sign-in with a temporary password is not restricted")
	}
	return &restrictedFix{
		realWriteFix: admin,
		name:         "newbie",
		temporary:    temp,
		session:      &http.Cookie{Name: consoleauth.SessionCookieName, Value: id.Reveal()},
		csrf:         admin.sessions.CSRFToken(id).Reveal(),
	}
}

func (r *restrictedFix) do(method, path string, form url.Values) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		f := url.Values{"csrf_token": {r.csrf}}
		for k, vs := range form {
			f[k] = vs
		}
		body = strings.NewReader(f.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.AddCookie(r.session)
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	return rec
}

var temporaryPasswordPattern = regexp.MustCompile(`<code>([^<]+)</code>`)

func scrapeTemporaryPassword(t *testing.T, body string) string {
	t.Helper()
	m := temporaryPasswordPattern.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("the response carries no temporary password:\n%s", contentOf(body))
	}
	return m[1]
}

func TestRestrictedSession_ReachesOnlyTheChangeFormAndSignOut(t *testing.T) {
	x := newRestrictedFix(t)

	// Every other GET is a redirect to the form, remembering where it was going.
	for _, path := range []string{"/console/", "/console/accounts", "/console/access", "/console/activity", "/console/events"} {
		rec := x.do(http.MethodGet, path, nil)
		want := yourAccountPath
		if path != "/console/" {
			want += "?next=" + url.QueryEscape(path)
		}
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != want {
			t.Errorf("GET %s = %d Location %q, want 303 %q", path, rec.Code, rec.Header().Get("Location"), want)
		}
	}
	// Every other method is refused: no granting act, and no sign-in-page loop.
	for _, path := range []string{createAccountAction(), setAccountRoleAction("acct-1"), mintAPITokenAction("acct-1"), issueTemporaryPasswordAction("acct-1")} {
		if rec := x.do(http.MethodPost, path, url.Values{"password": {x.temporary}}); rec.Code != http.StatusForbidden {
			t.Errorf("POST %s = %d, want 403", path, rec.Code)
		}
	}
	if n := countKind(x.realWriteFix, t, audit.KindAccountCreate); n != 1 {
		t.Errorf("%d account_create records: a restricted session created an Account", n)
	}

	// An encoded slash with dot-segments decodes to an allowed path while the
	// router dispatches another route; the gate must hold on both methods, and
	// no handler behind it may run.
	for _, path := range []string{
		"/console/accounts/x%2F..%2F..%2Faccount",
		"/console/accounts/x%2f..%2f..%2faccount",
		"/console/nodes/n1%2F..%2F..%2Faccount",
		"/console/accounts/%2e%2e/account",
		"/console/account%2Fpassword",
	} {
		get := x.do(http.MethodGet, path, nil)
		if get.Code != http.StatusSeeOther || !strings.HasPrefix(get.Header().Get("Location"), yourAccountPath) {
			t.Errorf("GET %s = %d Location %q, want the redirect to the form", path, get.Code, get.Header().Get("Location"))
		}
		if post := x.do(http.MethodPost, path, url.Values{"password": {x.temporary}}); post.Code != http.StatusForbidden {
			t.Errorf("POST %s = %d, want 403", path, post.Code)
		}
	}

	// The sign-in page is a public route, and a restricted session still
	// reaches only the form: it is sent there, and cannot post a sign-in.
	if rec := x.do(http.MethodGet, LoginPath, nil); rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), yourAccountPath) {
		t.Errorf("GET %s = %d Location %q, want the redirect to the form", LoginPath, rec.Code, rec.Header().Get("Location"))
	}
	if rec := x.do(http.MethodPost, LoginPath, url.Values{"username": {"newbie"}, "password": {x.temporary}}); rec.Code != http.StatusForbidden {
		t.Errorf("POST %s = %d, want 403", LoginPath, rec.Code)
	}
	// Encoded paths that decode to a public route while the router dispatches
	// another are not public, so they hit the gate too.
	for _, path := range []string{
		"/console/accounts/x%2F..%2F..%2Flogin",
		"/console/nodes/n1%2F..%2F..%2Fassets%2Fx",
		"/console/assets/%2e%2e/accounts",
	} {
		if rec := x.do(http.MethodGet, path, nil); rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), yourAccountPath) {
			t.Errorf("GET %s = %d Location %q, want the redirect to the form", path, rec.Code, rec.Header().Get("Location"))
		}
	}
	// The stylesheet the form draws with stays reachable.
	if rec := x.do(http.MethodGet, assetURL("console.css"), nil); rec.Code != http.StatusOK {
		t.Errorf("GET the stylesheet = %d, want 200", rec.Code)
	}

	// The form itself draws, with no nav, no banner and the signed-in block.
	rec := x.do(http.MethodGet, yourAccountPath, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d", yourAccountPath, rec.Code)
	}
	page := rec.Body.String()
	if strings.Contains(page, `class="navitem`) || strings.Contains(page, `class="navgroups"`) && strings.Contains(page, `navsec`) {
		t.Errorf("a restricted session draws nav:\n%s", page)
	}
	if strings.Contains(page, `class="banner"`) {
		t.Error("a restricted session draws a banner")
	}
	if !strings.Contains(page, "signed in as <b>newbie</b>") || !strings.Contains(page, "Sign out") {
		t.Error("the signed-in block and sign-out are not drawn")
	}
	if !strings.Contains(page, `name="current_password"`) {
		t.Error("the change form is not drawn")
	}
}

func TestRestrictedSession_StepUpIsRefusedAtTheBoundaryAndInConsoleauth(t *testing.T) {
	x := newRestrictedFix(t)
	before := len(x.kinds(t))

	// A would-be granting act is stopped by the boundary: nothing is compared.
	if rec := x.do(http.MethodPost, createAccountAction(), createForm("other", x.temporary)); rec.Code != http.StatusForbidden {
		t.Fatalf("create = %d, want 403", rec.Code)
	}
	if got := len(x.kinds(t)); got != before {
		t.Errorf("a refused restricted request wrote %d records", got-before)
	}
	// And consoleauth refuses it too, behind the boundary.
	id := consoleauth.ParseSessionID(x.session.Value)
	if _, err := x.svc.StepUp(t.Context(), id, accounts.NewPassword(x.temporary), "127.0.0.1"); !errors.Is(err, consoleauth.ErrPasswordChangeRequired) {
		t.Errorf("StepUp = %v, want ErrPasswordChangeRequired", err)
	}
}

func TestChangePassword_RestrictedSuccessReturnsToNextAndLeavesAnOrdinarySession(t *testing.T) {
	x := newRestrictedFix(t)
	const next = "/console/accounts?x=1"

	// The form carries the destination the redirect remembered, sanitised.
	page := x.do(http.MethodGet, yourAccountPath+"?next="+url.QueryEscape(next), nil).Body.String()
	if !strings.Contains(page, `name="next" value="/console/accounts?x=1"`) {
		t.Errorf("the form does not carry next:\n%s", contentOf(page))
	}
	evil := x.do(http.MethodGet, yourAccountPath+"?next="+url.QueryEscape("https://evil.example/"), nil).Body.String()
	if strings.Contains(evil, "evil.example") {
		t.Error("an off-Console next was carried onto the form")
	}

	form := passwordForm(x.temporary, "the humans own new password", "the humans own new password")
	form.Set("next", next)
	rec := x.do(http.MethodPost, changePasswordPath, form)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != next {
		t.Fatalf("change = %d Location %q, want 303 %q; body %s", rec.Code, rec.Header().Get("Location"), next, contentOf(rec.Body.String()))
	}
	set := cookieNamed(rec.Result().Cookies(), consoleauth.SessionCookieName)
	if set == nil || set.Value == "" || set.Value == x.session.Value {
		t.Fatalf("session cookie = %+v, want a rotated identifier", set)
	}
	x.session = &http.Cookie{Name: consoleauth.SessionCookieName, Value: set.Value}

	// The session is ordinary now: the Console is reachable, and the old
	// restricted identifier is dead.
	home := x.do(http.MethodGet, "/console/", nil)
	if home.Code != http.StatusOK {
		t.Errorf("GET /console/ after the change = %d, want 200", home.Code)
	}
	// The control: an ordinary session of this fixture does draw the banner
	// the restricted pages must not.
	if !strings.Contains(home.Body.String(), `class="banner"`) {
		t.Error("an ordinary session draws no banner in a frozen fixture; the restricted no-banner assertions prove nothing")
	}

	// The temporary password no longer signs in; the new one does, unrestricted.
	if _, _, err := x.svc.Login(t.Context(), consoleauth.Attempt{Name: x.name, Password: accounts.NewPassword(x.temporary), Source: "127.0.0.2"}); !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Errorf("the redeemed temporary password still signs in: %v", err)
	}
	x.clk.advance(time.Minute) // past the strike the refused temporary password earned
	_, sess, err := x.svc.Login(t.Context(), consoleauth.Attempt{Name: x.name, Password: accounts.NewPassword("the humans own new password"), Source: "127.0.0.3"})
	if err != nil || sess.Restricted {
		t.Errorf("sign-in with the new password = restricted %v, %v", sess.Restricted, err)
	}

	// Access names both acts, with the redemption.
	var sawForced bool
	for _, r := range x.records(t) {
		if r.Kind == audit.KindPasswordChange && strings.Contains(r.Reason, "forced=true") {
			sawForced = true
		}
	}
	if !sawForced {
		t.Errorf("the trail has no password_change forced=true: %v", x.kinds(t))
	}
}

func TestChangePassword_RestrictedSuccessWithNoNextLandsOnHome(t *testing.T) {
	x := newRestrictedFix(t)
	rec := x.do(http.MethodPost, changePasswordPath, passwordForm(x.temporary, "the humans own new password", "the humans own new password"))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != HomePath {
		t.Errorf("change = %d Location %q, want 303 %q", rec.Code, rec.Header().Get("Location"), HomePath)
	}
}

func TestChangePassword_WrongCurrentOnARestrictedSessionRendersTheFormWithItsNext(t *testing.T) {
	x := newRestrictedFix(t)
	form := passwordForm("not the temporary password", "the humans own new password", "the humans own new password")
	form.Set("next", "/console/accounts")
	rec := x.do(http.MethodPost, changePasswordPath, form)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, contentOf(rec.Body.String()))
	}
	body := rec.Body.String()
	if !strings.Contains(body, `name="next" value="/console/accounts"`) {
		t.Error("the re-rendered form dropped the destination")
	}
	if strings.Contains(body, `class="navitem`) || strings.Contains(body, `class="banner"`) {
		t.Error("a refusal in a restricted session draws nav or a banner")
	}
}

// --- the reveal-once temporary password ----------------------------------

func TestAccountsWrite_ACreateOfAHumanRevealsATemporaryPasswordOnceAndNeverRedirects(t *testing.T) {
	x := newWriteFix(t, nil)
	rec := x.post(t, createAccountAction(), createForm("newbie", "p"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, contentOf(rec.Body.String()))
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q: the temporary password must never be in a redirect", loc)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	body := rec.Body.String()
	if n := strings.Count(body, fakeTemporaryPassword); n != 1 {
		t.Errorf("the temporary password appears %d times, want exactly once", n)
	}
	for _, want := range []string{"Account created", `<code>` + fakeTemporaryPassword + `</code>`, "Shown once.", "expires in 72 hours", `title="`} {
		if !strings.Contains(body, want) {
			t.Errorf("the reveal lacks %q:\n%s", want, contentOf(body))
		}
	}
	// No later render carries it.
	if strings.Contains(x.get(t, accountsScreenPath).Body.String(), fakeTemporaryPassword) {
		t.Error("the Accounts list carries the temporary password")
	}
}

func mustReadSource(t *testing.T, name string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(".", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(src)
}

func TestAccountsWrite_TheNewAccountFormHasNoPasswordForTheNewAccount(t *testing.T) {
	x := newWriteFix(t, nil)
	form := createFormOf(t, x.get(t, newAccountPath).Body.String())
	if n := strings.Count(form, `type="password"`); n != 1 {
		t.Errorf("the create form has %d password inputs, want only the admin's step-up one", n)
	}
	for _, field := range []string{"temporary", "new_password", "confirm"} {
		if strings.Contains(form, `name="`+field) {
			t.Errorf("the create form has a %q field", field)
		}
	}
}

func TestAccountsWrite_AMachineCreateStillRedirects(t *testing.T) {
	x := newWriteFix(t, nil)
	rec := x.post(t, createAccountAction(), url.Values{"name": {"ci-bot"}, "kind": {"machine"}, "role": {"viewer"}, "password": {"p"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != doneHref(accountsScreenPath, doneCreated) {
		t.Errorf("a machine create = %d Location %q, want the usual 303", rec.Code, rec.Header().Get("Location"))
	}
	if strings.Contains(rec.Body.String(), fakeTemporaryPassword) {
		t.Error("a machine create revealed a password")
	}
}

func TestAccountsWrite_AHumanCreateWithNoTemporaryPasswordSeamIsRefusedNotMadePasswordless(t *testing.T) {
	x := newWriteFix(t, func(d *Deps) { d.TemporaryPasswords = nil })
	rec := x.post(t, createAccountAction(), createForm("newbie", "p"))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want the unavailable 500", rec.Code)
	}
	if len(x.admin.creates) != 0 {
		t.Error("a passwordless human Account was created")
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
}

func TestAccountsWrite_AFailedHumanCreateRevealsNothing(t *testing.T) {
	x := newWriteFix(t, nil)
	x.admin.createErr = accounts.ErrNameTaken
	rec := x.post(t, createAccountAction(), createForm("newbie", "p"))
	if rec.Code != http.StatusConflict || strings.Contains(rec.Body.String(), fakeTemporaryPassword) {
		t.Errorf("status = %d; a failed create must show no password:\n%s", rec.Code, contentOf(rec.Body.String()))
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store on every branch", cc)
	}
}

func TestIssueTemporaryPassword_RevealsOnceUnderTheWindowedStepUp(t *testing.T) {
	x := newWriteFix(t, nil)
	path := issueTemporaryPasswordAction(targetViewerID)

	// No password and no fresh window: refused, nothing issued.
	rec := x.post(t, path, url.Values{})
	if rec.Code != http.StatusUnauthorized || len(x.admin.issues) != 0 {
		t.Fatalf("no password = %d with %d issues, want 401 and none", rec.Code, len(x.admin.issues))
	}
	if !strings.Contains(rec.Body.String(), "Nothing was issued.") {
		t.Error("the refusal does not say nothing was issued")
	}

	// A password (the fake accepts it), or a fresh window, issues.
	rec = x.post(t, path, url.Values{"password": {"p"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body %s", rec.Code, contentOf(rec.Body.String()))
	}
	if rec.Header().Get("Location") != "" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Location %q, Cache-Control %q: want no redirect and no-store", rec.Header().Get("Location"), rec.Header().Get("Cache-Control"))
	}
	body := rec.Body.String()
	if strings.Count(body, fakeTemporaryPassword) != 1 || !strings.Contains(body, "Temporary password issued") ||
		!strings.Contains(body, "Shown once.") || !strings.Contains(body, "expires in 72 hours") {
		t.Errorf("the reveal is wrong:\n%s", contentOf(body))
	}
	if !strings.Contains(body, `<span class="ident">ana</span>`) || !strings.Contains(body, `href="`+accountPagePath("ana")+`"`) {
		t.Errorf("the reveal does not name the Account from the registry:\n%s", contentOf(body))
	}
	if len(x.admin.issues) != 1 || x.admin.issues[0] != targetViewerID {
		t.Errorf("issues = %v, want one for %s", x.admin.issues, targetViewerID)
	}

	// Inside the window (consoleauth says fresh) no password is needed.
	x2 := newWriteFix(t, nil)
	x2.auth.fresh = true
	if rec := x2.post(t, path, url.Values{}); rec.Code != http.StatusOK {
		t.Errorf("inside the window = %d, want 200", rec.Code)
	}
}

func TestIssueTemporaryPassword_RefusalsAreRenderedAndRevealNothing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		says   string
	}{
		{"the human set their own", accounts.ErrPasswordOwned, http.StatusConflict, "has set their own password"},
		{"a machine", accounts.ErrMachinePassword, http.StatusBadRequest, "machine Account never holds a password"},
		{"unknown", accounts.ErrNotFound, http.StatusNotFound, "No Account matching"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newWriteFix(t, nil)
			x.admin.issueErr = tc.err
			rec := x.post(t, issueTemporaryPasswordAction(targetViewerID), url.Values{"password": {"p"}})
			if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.says) {
				t.Errorf("status = %d; want %d saying %q:\n%s", rec.Code, tc.status, tc.says, contentOf(rec.Body.String()))
			}
			if strings.Contains(rec.Body.String(), fakeTemporaryPassword) {
				t.Error("a refused issue revealed a password")
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Error("a refusal is cacheable")
			}
		})
	}
}

func TestTemporaryPasswordView_NeverLogsThePassword(t *testing.T) {
	v := temporaryPasswordView{Heading: "Account created", AccountName: "newbie", Password: "super-secret-temporary-value", ExpiresAt: testNow}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("rendered", "view", v)
	if strings.Contains(buf.String(), "super-secret-temporary-value") {
		t.Errorf("the view logs its password: %s", buf.String())
	}
	if strings.Contains(fmt.Sprintf("%v", v.LogValue()), "super-secret-temporary-value") {
		t.Error("LogValue carries the password")
	}
}

// TestTemporaryPassword_RevealIsCalledExactlyOnce: the reveal in
// temporarypassword.go is the only place the package unwraps a temporary
// password, and no other non-test file in the package calls Reveal on one.
func TestTemporaryPassword_RevealIsCalledExactlyOnce(t *testing.T) {
	src := mustReadSource(t, "temporarypassword.go")
	if n := strings.Count(src, ".Reveal()"); n != 1 {
		t.Errorf("temporarypassword.go calls Reveal %d times, want exactly 1", n)
	}
	for _, file := range []string{"password.go", "accounts_write.go", "accounts_page.go"} {
		if strings.Contains(mustReadSource(t, file), "Password.Reveal()") {
			t.Errorf("%s unwraps a password", file)
		}
	}
}

// --- the Account page's Temporary password section -----------------------

func TestAccountPage_TemporaryPasswordSection(t *testing.T) {
	future := testNow.Add(20 * time.Hour)
	past := testNow.Add(-time.Hour)
	for _, tc := range []struct {
		name    string
		account string
		status  accounts.PasswordStatus
		err     error
		drawn   bool
		says    string
		control bool
	}{
		{"live", "ana", accounts.PasswordStatus{TemporaryUntil: future}, nil, true, "Live, expires " + utcStamp(future), true},
		{"expired", "ana", accounts.PasswordStatus{TemporaryUntil: past}, nil, true, "Expired " + utcStamp(past), true},
		{"none issued", "ana", accounts.PasswordStatus{}, nil, true, "None issued.", true},
		{"the human set their own", "ana", accounts.PasswordStatus{Own: true}, nil, false, "", false},
		{"unreadable", "ana", accounts.PasswordStatus{}, errors.New("store down"), true, "could not be read", false},
		{"a machine Account", "gleipnir-prod", accounts.PasswordStatus{}, nil, false, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newWriteFix(t, func(d *Deps) {
				d.TemporaryPasswords = &fakeTemporaryPasswords{admin: &fakeAccountAdmin{}, status: tc.status, statusErr: tc.err}
			})
			rec := x.get(t, accountPagePath(tc.account))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d; body %s", rec.Code, contentOf(rec.Body.String()))
			}
			body := contentOf(rec.Body.String())
			drawn := strings.Contains(body, `id="temporary-password"`)
			if drawn != tc.drawn {
				t.Fatalf("section drawn = %v, want %v:\n%s", drawn, tc.drawn, body)
			}
			if !tc.drawn {
				return
			}
			if !strings.Contains(body, tc.says) {
				t.Errorf("the section does not say %q:\n%s", tc.says, body)
			}
			control := strings.Contains(body, "Issue new temporary password</button>")
			if control != tc.control {
				t.Errorf("issue control drawn = %v, want %v", control, tc.control)
			}
			if tc.control {
				if !strings.Contains(body, `action="`+issueTemporaryPasswordAction(targetViewerID)+`"`) {
					t.Errorf("the control does not post to the re-issue route:\n%s", body)
				}
				if !strings.Contains(body, `class="btn grant" type="submit">Issue new temporary password`) {
					t.Error("the control is not a filled grant button")
				}
			}
		})
	}
}

func TestAccountPage_NoTemporarySectionWhenTheSeamIsNotWired(t *testing.T) {
	x := newWriteFix(t, func(d *Deps) { d.TemporaryPasswords = nil })
	body := x.get(t, accountPagePath("ana")).Body.String()
	if strings.Contains(body, `id="temporary-password"`) {
		t.Error("the section is drawn with no seam behind it")
	}
}

func TestAccountPage_TemporarySectionStepUpFieldFollowsTheWindow(t *testing.T) {
	x := newWriteFix(t, func(d *Deps) {
		d.TemporaryPasswords = &fakeTemporaryPasswords{admin: &fakeAccountAdmin{}}
	})
	body := x.get(t, accountPagePath("ana")).Body.String()
	if !regexp.MustCompile(`id="temp-password" name="password" type="password" autocomplete="current-password" required`).MatchString(body) {
		t.Errorf("outside the window the step-up password is not required:\n%s", contentOf(body))
	}
	x.auth.fresh = true
	body = x.get(t, accountPagePath("ana")).Body.String()
	if regexp.MustCompile(`id="temp-password"[^>]*required`).MatchString(body) {
		t.Error("inside the window the step-up password is still required")
	}
}

// --- Access ----------------------------------------------------------------

func TestAccess_PasswordRecordsHaveTheirOwnSentencesAndDrawTheSource(t *testing.T) {
	for _, tc := range []struct {
		name  string
		facts trailFacts
		want  string
	}{
		{"issue", trailFacts{Kind: audit.KindPasswordTemporarySet, Reason: "account_id=a1 name=n expires_at=x", Source: "10.0.0.9"},
			"issued a temporary password"},
		{"forced change", trailFacts{Kind: audit.KindPasswordChange, Reason: "account_id=a1 forced=true other_sessions_ended=0", Source: "10.0.0.9"},
			"set their own password, redeeming a temporary one"},
		{"ordinary change", trailFacts{Kind: audit.KindPasswordChange, Reason: "account_id=a1 forced=false other_sessions_ended=2", Source: "10.0.0.9"},
			"changed their own password"},
		// forced= is read only on a password_change: an issue's free-text name
		// cannot make it say anything else.
		{"a name that says forced=true on an issue", trailFacts{Kind: audit.KindPasswordTemporarySet, Reason: "account_id=a1 name=x forced=true", Source: "10.0.0.9"},
			"issued a temporary password"},
	} {
		if got := accessSummary(tc.facts); got != tc.want {
			t.Errorf("%s: summary = %q, want %q", tc.name, got, tc.want)
		}
		row := accessRowFrom(tc.facts)
		if row.Kind != accessAccount {
			t.Errorf("%s: family = %q, want account", tc.name, row.Kind)
		}
		if row.Source != "10.0.0.9" {
			t.Errorf("%s: Source = %q, want the address drawn", tc.name, row.Source)
		}
	}
}
