package console

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
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

// decideSessionFixture is a real-Service Decide fixture with two pending
// approvals, signed in as mike. It follows the session cookie like a browser.
type decideSessionFixture struct {
	f       *loginFixture
	decider *fakeDecider
	session *http.Cookie
}

func newDecideSessionFixture(t *testing.T, decider *fakeDecider) *decideSessionFixture {
	t.Helper()
	fa := &fakeApprovals{pending: []approval.Request{pendingApprovalRequest("ap-1"), pendingApprovalRequest("ap-2")}}
	f := newLoginFixtureWith(t, func(d *Deps) {
		d.Approvals = fa
		d.Decide = decider
	})
	rec, cookies := f.signIn(t, "mike", consolePassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("sign-in = %d", rec.Code)
	}
	return &decideSessionFixture{f: f, decider: decider, session: cookieNamed(cookies, consoleauth.SessionCookieName)}
}

func (s *decideSessionFixture) card(t *testing.T, id string) string {
	t.Helper()
	rec := s.f.do(t, httptest.NewRequest(http.MethodGet, "/console/approvals/"+id, nil), s.session)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET card %s = %d", id, rec.Code)
	}
	return rec.Body.String()
}

// decide submits a decision from the card's own form and follows a rotated
// cookie.
func (s *decideSessionFixture) decide(t *testing.T, id, password string) *httptest.ResponseRecorder {
	t.Helper()
	form := decideForm(s.card(t, id), "approve", "", password)
	req := httptest.NewRequest(http.MethodPost, decideApprovalAction(id), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := s.f.do(t, req, s.session)
	if c := cookieNamed(rec.Result().Cookies(), consoleauth.SessionCookieName); c != nil && c.Value != "" && c.MaxAge >= 0 {
		s.session = &http.Cookie{Name: c.Name, Value: c.Value}
	}
	return rec
}

func TestStepUp_TheSessionIDDiffersAfterAStepUpToDecide(t *testing.T) {
	s := newDecideSessionFixture(t, &fakeDecider{})
	old := s.session

	rec := s.decide(t, "ap-1", consolePassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("decide = %d; body %s", rec.Code, contentOf(rec.Body.String()))
	}
	if s.session.Value == old.Value {
		t.Fatal("the decision's step-up did not rotate the session identifier")
	}
	dead := s.f.do(t, httptest.NewRequest(http.MethodGet, "/console/", nil), old)
	if dead.Code != http.StatusSeeOther || !strings.HasPrefix(dead.Header().Get("Location"), LoginPath) {
		t.Errorf("the old cookie got %d to %q, want a 303 to sign-in", dead.Code, dead.Header().Get("Location"))
	}
}

// TestStepUp_ADecisionInsideTheWindowStillNeedsAPassword is the AP-16 guard:
// a decision re-authenticates at the moment of deciding, even though a
// decision's own step-up stamped the session a moment ago.
func TestStepUp_ADecisionInsideTheWindowStillNeedsAPassword(t *testing.T) {
	decider := &fakeDecider{}
	s := newDecideSessionFixture(t, decider)

	if rec := s.decide(t, "ap-1", consolePassword); rec.Code != http.StatusSeeOther {
		t.Fatalf("first decision = %d; body %s", rec.Code, contentOf(rec.Body.String()))
	}

	if !strings.Contains(s.card(t, "ap-2"), `id="decide-password" name="password" type="password" autocomplete="current-password" required`) {
		t.Error("inside the window the decision form no longer marks its password input required")
	}
	rec := s.decide(t, "ap-2", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a password-less decision inside the window = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Step-up re-authentication is required to decide an approval. Nothing was decided.") {
		t.Errorf("the refusal copy changed:\n%s", contentOf(rec.Body.String()))
	}
	if len(decider.calls) != 1 {
		t.Errorf("the decider has %d calls, want 1: the second decision must not have been taken", len(decider.calls))
	}
}

func TestStepUp_ARefusalAfterAStepUpRendersTheRotatedCSRFToken(t *testing.T) {
	decider := &fakeDecider{err: approval.ErrPlanChanged}
	s := newDecideSessionFixture(t, decider)
	oldToken := s.f.sessions.CSRFToken(consoleauth.ParseSessionID(s.session.Value)).Reveal()

	rec := s.decide(t, "ap-1", consolePassword)
	if rec.Code != http.StatusConflict {
		t.Fatalf("decide with a changed plan = %d, want 409; body %s", rec.Code, contentOf(rec.Body.String()))
	}
	newToken := s.f.sessions.CSRFToken(consoleauth.ParseSessionID(s.session.Value)).Reveal()
	if newToken == oldToken {
		t.Fatal("the session did not rotate")
	}
	if !strings.Contains(rec.Body.String(), newToken) {
		t.Error("the refusal page does not carry the rotated session's CSRF token")
	}
	if strings.Contains(rec.Body.String(), oldToken) {
		t.Error("the refusal page carries the dead session's CSRF token")
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

	t.Run("decide never consults the window", func(t *testing.T) {
		decider := &fakeDecider{}
		auth := &fakeAuth{fresh: true}
		f := newLoginFixtureWith(t, func(d *Deps) {
			d.Approvals = &fakeApprovals{pending: []approval.Request{pendingApprovalRequest("ap-1")}}
			d.Decide = decider
			d.Auth = auth
		})
		id, _, err := f.svc.Login(context.Background(), consoleauth.Attempt{
			Name: "mike", Password: accounts.NewPassword(consolePassword), Source: "127.0.0.1",
		})
		if err != nil {
			t.Fatalf("sign in: %v", err)
		}
		body := url.Values{
			"csrf_token": {f.sessions.CSRFToken(id).Reveal()},
			"plan_hash":  {"hash-ap-1"},
			"answer":     {"approve"},
		}
		req := httptest.NewRequest(http.MethodPost, decideApprovalAction("ap-1"), strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := f.do(t, req, &http.Cookie{Name: consoleauth.SessionCookieName, Value: id.Reveal()})

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401; body %s", rec.Code, contentOf(rec.Body.String()))
		}
		if auth.requireCalls != 0 {
			t.Errorf("decide consulted the window %d times", auth.requireCalls)
		}
		if len(decider.calls) != 0 {
			t.Error("a decision was taken with no password")
		}
	})
}

// requireStepUp's own per-act empty-password branch, called directly: the
// decide handler's early check refuses first, so no handler-level test can
// reach it. A fresh window must not stand in for a decision's password.
func TestStepUp_APerActAskRefusesAnEmptyPasswordInsideTheWindow(t *testing.T) {
	x := newWriteFix(t, nil)
	x.auth.fresh = true

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
		proceeded = requireStepUp(Deps{Auth: x.auth}, w, r, &pg, decideStepUp)
	}))

	req := httptest.NewRequest(http.MethodPost, "/console/approvals/ap-1/decision", strings.NewReader("password="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(x.session)
	boundary.ServeHTTP(rec, req)

	if proceeded {
		t.Fatal("requireStepUp let a password-less per-act decision proceed")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, contentOf(rec.Body.String()))
	}
	if !strings.Contains(rec.Body.String(), "Step-up re-authentication is required to decide an approval. Nothing was decided.") {
		t.Errorf("the refusal copy changed:\n%s", contentOf(rec.Body.String()))
	}
	if x.auth.requireCalls != 0 {
		t.Errorf("RequireStepUp was consulted %d times; a per-act ask never reads the window", x.auth.requireCalls)
	}
	if len(x.auth.stepUpCalls) != 0 {
		t.Errorf("StepUp was called %d times with no password", len(x.auth.stepUpCalls))
	}
}
