package console

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
)

// The acceptance tests for the shared step-up helper (#879). The Account
// write path runs through the REAL controlplane.Authenticator, Secure, a real
// consoleauth.Service and a controllable clock, so "inside the window" and
// "after the window" are the real lane's answers, not a stand-in's.

func createForm(name, password string) url.Values {
	form := url.Values{"name": {name}, "kind": {"human"}, "role": {"viewer"}}
	if password != "" {
		form.Set("password", password)
	}
	return form
}

func accountExists(t *testing.T, x *realWriteFix, name string) bool {
	t.Helper()
	_, err := x.trail.Accounts().GetByName(context.Background(), name)
	return err == nil
}

func countKind(x *realWriteFix, t *testing.T, kind string) int {
	t.Helper()
	n := 0
	for _, k := range x.kinds(t) {
		if k == kind {
			n++
		}
	}
	return n
}

// passwordInputRequired reports whether the Accounts screen's create form
// still marks its password input required.
func passwordInputRequired(t *testing.T, body string) bool {
	t.Helper()
	i := strings.Index(body, `id="create-password"`)
	if i < 0 {
		t.Fatalf("the Accounts screen carries no create-password input:\n%s", contentOf(body))
	}
	end := strings.Index(body[i:], ">")
	return strings.Contains(body[i:i+end], " required")
}

func TestStepUp_AnAccountActInsideTheWindowProceedsWithoutAPassword(t *testing.T) {
	x := newRealWriteFix(t)

	if rec := x.post(t, createAccountAction(), createForm("first", realWritePassword)); rec.Code != http.StatusSeeOther {
		t.Fatalf("first create = %d; body %s", rec.Code, contentOf(rec.Body.String()))
	}

	// The screen no longer demands the password, and carries the rotated
	// session's token.
	rec := x.get(t, "/console/accounts")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET accounts = %d", rec.Code)
	}
	if passwordInputRequired(t, rec.Body.String()) {
		t.Error("inside the window the create form still marks the password input required")
	}
	if got := renderedCSRFToken(rec.Body.String()); got != x.csrf {
		t.Errorf("the rendered csrf_token does not belong to the current session")
	}

	x.clk.advance(time.Minute)
	if rec := x.post(t, createAccountAction(), createForm("second", "")); rec.Code != http.StatusSeeOther {
		t.Fatalf("a password-less create inside the window = %d; body %s", rec.Code, contentOf(rec.Body.String()))
	}
	if !accountExists(t, x, "second") {
		t.Error("the second Account was not created")
	}
	if n := countKind(x, t, audit.KindStepUp); n != 1 {
		t.Errorf("the trail holds %d step_up records, want exactly 1: the window must not re-prompt or re-stamp", n)
	}
}

func TestStepUp_AnAccountActAfterTheWindowPrompts(t *testing.T) {
	x := newRealWriteFix(t)
	if rec := x.post(t, createAccountAction(), createForm("first", realWritePassword)); rec.Code != http.StatusSeeOther {
		t.Fatalf("first create = %d; body %s", rec.Code, contentOf(rec.Body.String()))
	}

	x.clk.advance(consoleauth.DefaultStepUpWindow + time.Second)
	rec := x.post(t, createAccountAction(), createForm("second", ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a password-less create after the window = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Step-up re-authentication is required for this act.") {
		t.Errorf("the refusal does not ask for step-up:\n%s", contentOf(rec.Body.String()))
	}
	if accountExists(t, x, "second") {
		t.Error("the Account was created after the window lapsed")
	}
	if !passwordInputRequired(t, x.get(t, "/console/accounts").Body.String()) {
		t.Error("after the window the create form no longer marks the password input required")
	}
}

func TestStepUp_AFreshSignInDoesNotSatisfyStepUp(t *testing.T) {
	x := newRealWriteFix(t)

	rec := x.post(t, createAccountAction(), createForm("first", ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a password-less create on a fresh sign-in = %d, want 401", rec.Code)
	}
	if accountExists(t, x, "first") {
		t.Error("the Account was created on sign-in alone")
	}
}

func TestStepUp_AStampFromOneSessionDoesNotSatisfyAnother(t *testing.T) {
	x := newRealWriteFix(t)
	otherID, _, err := x.svc.Login(context.Background(), consoleauth.Attempt{
		Name: "mike", Password: accounts.NewPassword(realWritePassword), Source: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("second sign-in: %v", err)
	}
	other := &realWriteFix{
		handler: x.handler, trail: x.trail, sessions: x.sessions, svc: x.svc, clk: x.clk,
		session: &http.Cookie{Name: consoleauth.SessionCookieName, Value: otherID.Reveal()},
		csrf:    x.sessions.CSRFToken(otherID).Reveal(),
	}

	if rec := x.post(t, createAccountAction(), createForm("first", realWritePassword)); rec.Code != http.StatusSeeOther {
		t.Fatalf("step-up on the first session = %d; body %s", rec.Code, contentOf(rec.Body.String()))
	}
	rec := other.post(t, createAccountAction(), createForm("second", ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a password-less create on ANOTHER session = %d, want 401", rec.Code)
	}
	if accountExists(t, x, "second") {
		t.Error("another session's step-up satisfied this one")
	}
}

func TestStepUp_TheSessionIDDiffersAfterStepUp(t *testing.T) {
	x := newRealWriteFix(t)
	oldSession, oldCSRF := x.session, x.csrf

	rec := x.post(t, createAccountAction(), createForm("first", realWritePassword))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create = %d; body %s", rec.Code, contentOf(rec.Body.String()))
	}
	var set *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == consoleauth.SessionCookieName {
			set = c
		}
	}
	if set == nil || set.Value == "" {
		t.Fatal("a successful step-up set no session cookie")
	}
	if set.Value == oldSession.Value {
		t.Error("the session identifier did not change on step-up")
	}
	if !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
		t.Errorf("Cache-Control = %q, want no-store on a response that sets the session", rec.Header().Get("Cache-Control"))
	}

	// The old cookie is dead: the boundary sends it to sign-in.
	req := httptest.NewRequest(http.MethodGet, "/console/", nil)
	req.AddCookie(oldSession)
	dead := httptest.NewRecorder()
	x.handler.ServeHTTP(dead, req)
	if dead.Code != http.StatusSeeOther || !strings.HasPrefix(dead.Header().Get("Location"), LoginPath) {
		t.Errorf("the old cookie got %d to %q, want a 303 to sign-in", dead.Code, dead.Header().Get("Location"))
	}

	// The new cookie with the OLD token is refused by CSRF.
	body := url.Values{"csrf_token": {oldCSRF}}
	for k, vs := range createForm("second", realWritePassword) {
		body[k] = vs
	}
	stale := httptest.NewRequest(http.MethodPost, createAccountAction(), strings.NewReader(body.Encode()))
	stale.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	stale.AddCookie(x.session)
	staleRec := httptest.NewRecorder()
	x.handler.ServeHTTP(staleRec, stale)
	if staleRec.Code != http.StatusForbidden {
		t.Errorf("the rotated session with the pre-rotation CSRF token = %d, want 403", staleRec.Code)
	}
}

// A refusal that comes AFTER a real step-up must render the rotated session's
// CSRF token, not the dead one's: the step-up rotated the session before the
// capability layer refused.
func TestStepUp_ARefusalAfterAStepUpRendersTheRotatedCSRFToken(t *testing.T) {
	x := newRealWriteFix(t)
	oldCookie := x.session.Value
	oldToken := x.sessions.CSRFToken(consoleauth.ParseSessionID(x.session.Value)).Reveal()

	// The password is right, so the step-up passes and rotates; the name is
	// taken, so CreateAccount then refuses.
	rec := x.post(t, createAccountAction(), createForm(x.target.Name, realWritePassword))
	if rec.Code != http.StatusConflict {
		t.Fatalf("create with a taken name = %d, want 409; body %s", rec.Code, contentOf(rec.Body.String()))
	}
	if x.session.Value == oldCookie {
		t.Fatal("the session did not rotate")
	}
	newToken := x.sessions.CSRFToken(consoleauth.ParseSessionID(x.session.Value)).Reveal()
	if newToken == oldToken {
		t.Fatal("the rotated session carries the old CSRF token")
	}
	if !strings.Contains(rec.Body.String(), newToken) {
		t.Error("the refusal page does not carry the rotated session's CSRF token")
	}
	if strings.Contains(rec.Body.String(), oldToken) {
		t.Error("the refusal page carries the dead session's CSRF token")
	}
	if n := countKind(x, t, audit.KindStepUp); n != 1 {
		t.Errorf("%d step_up records, want 1: the refusal must have come after a step-up", n)
	}
}

func TestStepUp_AWrongPasswordInsideTheWindowIsStillRefused(t *testing.T) {
	x := newRealWriteFix(t)
	if rec := x.post(t, createAccountAction(), createForm("first", realWritePassword)); rec.Code != http.StatusSeeOther {
		t.Fatalf("first create = %d; body %s", rec.Code, contentOf(rec.Body.String()))
	}

	rec := x.post(t, createAccountAction(), createForm("second", "not the password"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong password inside the window = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "That password did not match. Nothing was created.") {
		t.Errorf("unexpected refusal:\n%s", contentOf(rec.Body.String()))
	}
	if accountExists(t, x, "second") {
		t.Error("an Account was created with a wrong password")
	}
}

func TestStepUp_AReducingActWritesNoStepUpRecord(t *testing.T) {
	x := newRealWriteFix(t)

	rec := x.post(t, setAccountEnabledAction(x.target.ID), url.Values{"enabled": {"false"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("disable = %d; body %s", rec.Code, contentOf(rec.Body.String()))
	}
	if n := countKind(x, t, audit.KindStepUp); n != 0 {
		t.Errorf("a reducing act wrote %d step_up records, want 0", n)
	}
}

func TestStepUp_TheWindowIsReadFromConsoleauth(t *testing.T) {
	t.Run("account create trusts consoleauth's freshness", func(t *testing.T) {
		x := newWriteFix(t, nil)
		x.auth.fresh = true

		rec := x.post(t, createAccountAction(), createForm("first", ""))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303; body %s", rec.Code, contentOf(rec.Body.String()))
		}
		if len(x.auth.stepUpCalls) != 0 {
			t.Errorf("StepUp was called %d times with no password submitted", len(x.auth.stepUpCalls))
		}
		if x.auth.requireCalls != 1 {
			t.Errorf("RequireStepUp was called %d times, want 1", x.auth.requireCalls)
		}
	})

	t.Run("a session that ended says so", func(t *testing.T) {
		x := newWriteFix(t, nil)
		x.auth.requireErr = consoleauth.ErrNoSession

		rec := x.post(t, createAccountAction(), createForm("first", ""))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "Your session has ended") || !strings.Contains(body, LoginPath) {
			t.Errorf("the refusal does not say the session ended with a sign-in link:\n%s", contentOf(body))
		}
		if len(x.admin.creates) != 0 {
			t.Error("an Account was created on a dead session")
		}
	})
}

// requireStepUp's own per-act empty-password branch, called directly with a
// test-local ask: no production route uses stepUpPerAct yet, and the composer's
// mutate apply must. A fresh window must not stand in for a per-act password.
func TestStepUp_APerActAskRefusesAnEmptyPasswordInsideTheWindow(t *testing.T) {
	x := newWriteFix(t, nil)
	x.auth.fresh = true

	perActAsk := stepUpAsk{
		mode:     stepUpPerAct,
		required: "Step-up re-authentication is required to apply.",
		undone:   "Nothing was applied.",
		act:      "a per-act test ask",
		render: func(w http.ResponseWriter, pg Page, status int, heading, _, _ string) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(heading))
		},
	}

	var proceeded bool
	rec := httptest.NewRecorder()
	boundary := controlplane.NewAuthenticator(
		roleVerifier{role: accounts.RoleAdmin},
		controlplane.WithConsoleSessions(x.f.svc, controlplane.ConsoleSessionOptions{
			Public:       Unauthenticated,
			Scope:        SessionScope,
			Unauthorized: UnauthorizedHandler(),
		}),
	).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pg := Page{CSRFToken: x.csrf}
		proceeded = requireStepUp(Deps{Auth: x.auth}, w, r, &pg, perActAsk)
	}))

	req := httptest.NewRequest(http.MethodPost, "/console/", strings.NewReader("password="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(x.session)
	boundary.ServeHTTP(rec, req)

	if proceeded {
		t.Fatal("requireStepUp let a password-less per-act ask proceed")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, contentOf(rec.Body.String()))
	}
	if !strings.Contains(rec.Body.String(), "Step-up re-authentication is required to apply. Nothing was applied.") {
		t.Errorf("the refusal copy changed:\n%s", contentOf(rec.Body.String()))
	}
	if x.auth.requireCalls != 0 {
		t.Errorf("RequireStepUp was consulted %d times; a per-act ask never reads the window", x.auth.requireCalls)
	}
	if len(x.auth.stepUpCalls) != 0 {
		t.Errorf("StepUp was called %d times with no password", len(x.auth.stepUpCalls))
	}
}
