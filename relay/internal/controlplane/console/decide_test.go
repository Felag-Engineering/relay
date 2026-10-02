package console

// decide_test.go covers the Console's decide-approval control (#453):
// the route (decide.go), and who sees the control at all (decideOffered,
// buildApprovalView's Decide gate). Patterned on cancel_test.go, the
// reference for a write route on this package.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// pendingApprovalRequest builds a pending Request this file's fixtures decide
// against, deliberately small: only the fields buildApprovalView and
// handleDecideApproval actually consult.
func pendingApprovalRequest(id string) approval.Request {
	return approval.Request{
		ID:         id,
		PlanHash:   "hash-" + id,
		Summary:    "restart nginx on 3 Nodes",
		ActionKind: jobs.ActionOperation,
		RiskClass:  jobs.RiskClassMutate,
		Require:    approval.Requirement{Count: 1, RequesterAllowed: true},
		State:      approval.StatePending,
		CreatedAt:  testNow.Add(-time.Hour),
		ExpiresAt:  testNow.Add(time.Hour),
	}
}

// decideRenderDeps is renderableDeps with req pending and both decide seams
// wired to fakes, for the render-only (GET) assertions that do not need a
// real session.
//
// decider and auth are typed as the SEAM INTERFACES, not the concrete fake
// types: a caller passing a literal nil here must produce a genuinely nil
// interface, not a non-nil interface wrapping a nil *fakeDecider/*fakeAuth
// (Go's typed-nil trap — control_surfaces_test.go documents the identical
// hazard for the composition root). decideOffered's `d.Decide == nil` check
// would silently pass on the wrapped form and this fixture would prove
// nothing about the unwired case.
func decideRenderDeps(req approval.Request, decider ApprovalDecider, auth Authenticator) Deps {
	d := renderableDeps()
	d.Approvals = &fakeApprovals{pending: []approval.Request{req}}
	d.Decide = decider
	d.Auth = auth
	return d
}

// renderedPlanHash scrapes the hidden plan_hash field's value, exactly as
// renderedCSRFToken (login_test.go) scrapes csrf_token.
var renderedPlanHashPattern = regexp.MustCompile(`name="plan_hash" value="([^"]*)"`)

func renderedPlanHash(body string) string {
	m := renderedPlanHashPattern.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return m[1]
}

// --- Who sees the control ---------------------------------------------------

func TestDecide_TheObjectCarriesTheControlAndTheQueueNeverDoes(t *testing.T) {
	req := pendingApprovalRequest("ap-1")
	d := decideRenderDeps(req, &fakeDecider{}, &fakeAuth{})
	h := newTestHandler(d, accounts.RoleOperator)

	queue := contentOf(get(t, h, "/console/approvals").Body.String())
	for _, banned := range []string{"<form", "<button", "<input"} {
		if strings.Contains(queue, banned) {
			t.Errorf("the queue rendered %q — binding decision 5 says deciding never happens in the list", banned)
		}
	}

	card := get(t, h, "/console/approvals/ap-1").Body.String()
	if !strings.Contains(card, `action="`+decideApprovalAction("ap-1")+`"`) {
		t.Error("the decision form's action is not this Request's decision path")
	}
	if !strings.Contains(card, `name="answer" value="approve"`) || !strings.Contains(card, `name="answer" value="deny"`) {
		t.Error("the card does not carry both answer buttons")
	}
	if !strings.Contains(card, `type="password"`) {
		t.Error("the card does not ask for a step-up password")
	}
	if !strings.Contains(card, `name="plan_hash" value="`+req.PlanHash+`"`) {
		t.Error("the card does not carry the hidden plan hash")
	}
	if !strings.Contains(card, `name="csrf_token"`) {
		t.Error("the decision form carries no CSRF token")
	}
}

func TestDecide_TheFormNamesWhatTheStepUpAuthorises(t *testing.T) {
	req := pendingApprovalRequest("ap-1")
	d := decideRenderDeps(req, &fakeDecider{}, &fakeAuth{})
	content := contentOf(get(t, newTestHandler(d, accounts.RoleOperator), "/console/approvals/ap-1").Body.String())

	if !strings.Contains(content, req.Summary) {
		t.Errorf("the step-up label does not name the Relay-authored summary: %s", content)
	}
}

// TestDecide_ApproveAndDenyAreVisuallyIdentical asserts spec 08 item 5 the
// same way the retired Read-egress screen's stylesheet test asserted its deny
// grammar: from the STYLESHEET, because a class applied with no rule behind
// it — or a rule that quietly diverges per button — renders as ordinary
// text and nothing in Go can see it from the markup alone.
//
// This is one of the two statements the PR body must say are asserted from
// the stylesheet rather than a rendering engine (the plan's stated limit,
// shared with the existing 390px criterion): the assertion below is that
// ONE class exists and that no rule anywhere selects on
// value="approve"/value="deny" to diverge it, not that a browser paints the
// two pixel-for-pixel identical.
func TestDecide_ApproveAndDenyAreVisuallyIdentical(t *testing.T) {
	req := pendingApprovalRequest("ap-1")
	d := decideRenderDeps(req, &fakeDecider{}, &fakeAuth{})
	body := get(t, newTestHandler(d, accounts.RoleOperator), "/console/approvals/ap-1").Body.String()

	if !strings.Contains(body, `name="answer" value="approve" class="decideanswer"`) ||
		!strings.Contains(body, `name="answer" value="deny" class="decideanswer"`) {
		t.Errorf("Approve and Deny do not carry the identical class: %s", body)
	}
	if strings.Contains(body, "autofocus") {
		t.Error("a decision button carries autofocus — spec 08: nothing focused by default")
	}

	css := get(t, newTestHandler(d, accounts.RoleOperator), "/console/assets/console.css").Body.String()
	if !strings.Contains(css, ".decideanswer") {
		t.Error("the stylesheet has no .decideanswer rule — the class renders as ordinary text")
	}
	for _, selector := range []string{`[value="approve"]`, `[value="deny"]`, ".decideanswer.approve", ".decideanswer.deny"} {
		if strings.Contains(css, selector) {
			t.Errorf("the stylesheet selects on %q — Approve and Deny must never diverge in weight or colour", selector)
		}
	}
}

func TestDecide_UnwiredSeamsOfferNothing(t *testing.T) {
	req := pendingApprovalRequest("ap-1")
	for _, tc := range []struct {
		name string
		d    Deps
	}{
		{"Decide nil", decideRenderDeps(req, nil, &fakeAuth{})},
		{"Auth nil", decideRenderDeps(req, &fakeDecider{}, nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := contentOf(get(t, newTestHandler(tc.d, accounts.RoleOperator), "/console/approvals/ap-1").Body.String())
			if strings.Contains(content, "<form") {
				t.Error("a card rendered a decision control with one decide seam unwired")
			}
		})
	}
}

func TestDecide_AGrantRequestOffersNoControl(t *testing.T) {
	req := pendingApprovalRequest("ap-1")
	d := decideRenderDeps(req, &fakeDecider{}, &fakeAuth{})
	d.Approvals = &fakeApprovals{
		pending: []approval.Request{req},
		grants:  []approval.Grant{{RequestID: req.ID}},
	}
	content := contentOf(get(t, newTestHandler(d, accounts.RoleOperator), "/console/approvals/ap-1").Body.String())
	if strings.Contains(content, "<form") {
		t.Error("a card offered a decision control on a Grant request")
	}
}

// TestDecide_AlreadySignedRendersPartialStateNotAForm is criterion 4's
// rendering half for the SIGNER: a count:2 rule with the caller's own
// Account already among the Decisions must render the "you signed this"
// partial state instead of a form — deciding again is not a second, distinct
// approver.
func TestDecide_AlreadySignedRendersPartialStateNotAForm(t *testing.T) {
	req := pendingApprovalRequest("ap-1")
	req.Require.Count = 2
	req.Decisions = []approval.Decision{{
		Account:      testAccountName(accounts.RoleOperator),
		AccountID:    testAccountID(accounts.RoleOperator),
		Approve:      true,
		DeciderHuman: true,
		At:           testNow.Add(-2 * time.Hour),
	}}
	d := decideRenderDeps(req, &fakeDecider{}, &fakeAuth{})
	content := contentOf(get(t, newTestHandler(d, accounts.RoleOperator), "/console/approvals/ap-1").Body.String())

	if strings.Contains(content, "<form") {
		t.Error("a card rendered a decision form for a caller who already signed")
	}
	if !strings.Contains(content, "You already signed this") {
		t.Errorf("the card does not say the caller already signed: %s", content)
	}
}

// TestDecide_PartialQuorumNamesWhoSigned is criterion 4's rendering half for
// a SECOND, distinct operator: the same count:2 record, signed by someone
// else, must still offer the form — and must name who signed and when.
func TestDecide_PartialQuorumNamesWhoSigned(t *testing.T) {
	req := pendingApprovalRequest("ap-1")
	req.Require.Count = 2
	req.Decisions = []approval.Decision{{
		Account:      "mike",
		AccountID:    "acct-mike",
		Approve:      true,
		DeciderHuman: true,
		At:           testNow.Add(-2 * time.Hour),
	}}
	d := decideRenderDeps(req, &fakeDecider{}, &fakeAuth{})
	content := contentOf(get(t, newTestHandler(d, accounts.RoleOperator), "/console/approvals/ap-1").Body.String())

	if !strings.Contains(content, "mike signed 2h ago") {
		t.Errorf("the quorum line does not name who signed and when: %s", content)
	}
	if !strings.Contains(content, "<form") {
		t.Error("a second, distinct operator was not offered the decision form")
	}
}

// --- The route itself --------------------------------------------------------

// decideLoginFixture is newLoginFixtureWith with req pending and decider
// wired as Deps.Decide; Deps.Auth stays the fixture's REAL consoleauth.Service
// so the step-up branches (wrong password, throttle) exercise the genuine
// authentication path rather than a stand-in for it.
//
// It returns the *fakeApprovals too, as a POINTER a test may still mutate
// after the fixture is built: Register captures Deps BY VALUE when it builds
// each route's handler closure, so replacing d.Approvals with a NEW value
// after the fact would never be seen by the mounted mux — but mutating the
// FIELDS of the same *fakeApprovals the closure already holds is, because an
// interface value and the closure that captured it share the same pointer.
// TestDecide_TheExcludedRequesterSeesNoFormAndAPostIsStillRefused needs
// exactly this: the excluded requester's Account ID is only known once the
// fixture has created it.
func decideLoginFixture(t *testing.T, req approval.Request, decider *fakeDecider) (*loginFixture, *fakeApprovals) {
	t.Helper()
	fa := &fakeApprovals{pending: []approval.Request{req}}
	f := newLoginFixtureWith(t, func(d *Deps) {
		d.Approvals = fa
		d.Decide = decider
	})
	return f, fa
}

// decideForm builds the POST body a browser would submit from the rendered
// card: csrf_token and plan_hash scraped from getBody, plus the caller's
// answer/reason/password.
func decideForm(getBody, answer, reason, password string) url.Values {
	return url.Values{
		"csrf_token": {renderedCSRFToken(getBody)},
		"plan_hash":  {renderedPlanHash(getBody)},
		"answer":     {answer},
		"reason":     {reason},
		"password":   {password},
	}
}

func TestDecide_AViewerSessionFindsTheRouteAbsent(t *testing.T) {
	req := pendingApprovalRequest("ap-1")
	decider := &fakeDecider{}
	f, _ := decideLoginFixture(t, req, decider)
	f.createAccountWithPassword(t, "watcher", accounts.RoleViewer, "a viewer password")

	rec, cookies := f.signIn(t, "watcher", "a viewer password")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("viewer sign-in status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	if session == nil {
		t.Fatal("no session cookie was set")
	}

	// A GENUINE token for the viewer's own session — the approval object is
	// rendered in Focus mode (spec 08: "no nav, nothing competing, one
	// card"), which drops the sign-out form's csrf_token along with the rest
	// of the nav, and a viewer is offered no decide form either, so the card
	// itself carries no token to scrape. The fleet view does, exactly as
	// cancel_test.go's identical viewer test uses it.
	fleetRec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/", nil), session)
	token := renderedCSRFToken(fleetRec.Body.String())
	if token == "" {
		t.Fatal("the fleet view rendered no CSRF token for the viewer's session")
	}
	body := url.Values{
		"csrf_token": {token},
		"plan_hash":  {req.PlanHash},
		"answer":     {"approve"},
		"password":   {"a viewer password"},
	}

	postReq := httptest.NewRequest(http.MethodPost, decideApprovalAction("ap-1"), strings.NewReader(body.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if rec := f.do(t, postReq, session); rec.Code != http.StatusNotFound {
		t.Errorf("viewer POST to decide = %d, want 404 (absent, not forbidden)", rec.Code)
	}

	optRec := f.do(t, httptest.NewRequest(http.MethodOptions, decideApprovalAction("ap-1"), nil), session)
	if optRec.Code != http.StatusNotFound {
		t.Errorf("viewer OPTIONS on decide = %d, want 404 — the method oracle must not confirm the route exists", optRec.Code)
	}
	if len(decider.calls) != 0 {
		t.Errorf("decider calls = %d, want 0", len(decider.calls))
	}
}

func TestDecide_ABearerLanePostIsRefusedAndNeverDecides(t *testing.T) {
	req := pendingApprovalRequest("ap-1")
	decider := &fakeDecider{}
	d := decideRenderDeps(req, decider, &fakeAuth{})
	h := newTestHandler(d, accounts.RoleOperator)

	rec := request(t, h, http.MethodPost, decideApprovalAction("ap-1"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if len(decider.calls) != 0 {
		t.Errorf("decider calls = %d, want 0", len(decider.calls))
	}
}

// TestDecide_MissingConsoleSessionFailsClosed pins decide.go's own defensive
// branch — cs, ok := controlplane.ConsoleSessionFromContext(...); if !ok —
// directly.
//
// In a PRODUCTION-shaped mux this branch is unreachable: Secure's
// sessionCSRFValid already refuses a bearer-lane POST (no ConsoleSession at
// all) before the handler ever runs, which
// TestDecide_ABearerLanePostIsRefusedAndNeverDecides proves immediately
// above. That is the correct design, and it means nothing exercises this
// handler-level check through the ordinary test handler. This test therefore
// has to go AROUND Secure — via newTestHandlerSkippingCSRF, which never
// wires console sessions into its Authenticator at all, so a bearer-lane
// request reaches the handler with a Principal but no ConsoleSession — to
// prove the branch still does the right thing on its own. If Secure's lane
// selection ever changes and this stops being redundant with the 403 above,
// this is the test that must not go stale silently; it must not be "fixed"
// by routing the request through the ordinary, CSRF-checked handler instead,
// which would make it stop testing this branch at all.
func TestDecide_MissingConsoleSessionFailsClosed(t *testing.T) {
	req := pendingApprovalRequest("ap-1")
	decider := &fakeDecider{}
	h := newTestHandlerSkippingCSRF(decideRenderDeps(req, decider, &fakeAuth{}), accounts.RoleOperator)

	rec := postSkippingCSRF(t, h, decideApprovalAction("ap-1"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	if len(decider.calls) != 0 {
		t.Errorf("decider calls = %d, want 0", len(decider.calls))
	}
}

func TestDecide_ARealSessionPostWithNoCSRFTokenIsRefused(t *testing.T) {
	req := pendingApprovalRequest("ap-1")
	decider := &fakeDecider{}
	f, _ := decideLoginFixture(t, req, decider)

	rec, cookies := f.signIn(t, "mike", consolePassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("sign-in status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	session := cookieNamed(cookies, consoleauth.SessionCookieName)

	postReq := httptest.NewRequest(http.MethodPost, decideApprovalAction("ap-1"), strings.NewReader("plan_hash="+req.PlanHash+"&answer=approve&password=x"))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRec := f.do(t, postReq, session)

	if postRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", postRec.Code, postRec.Body.String())
	}
	if len(decider.calls) != 0 {
		t.Errorf("decider calls = %d, want 0", len(decider.calls))
	}
}

func TestDecide_ARealSessionPostWithTheWrongCSRFTokenIsRefused(t *testing.T) {
	req := pendingApprovalRequest("ap-1")
	decider := &fakeDecider{}
	f, _ := decideLoginFixture(t, req, decider)

	rec, cookies := f.signIn(t, "mike", consolePassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("sign-in status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	session := cookieNamed(cookies, consoleauth.SessionCookieName)

	cardRec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/approvals/ap-1", nil), session)
	token := renderedCSRFToken(cardRec.Body.String())
	if token == "" {
		t.Fatal("the approval card rendered no CSRF token")
	}

	postReq := httptest.NewRequest(http.MethodPost, decideApprovalAction("ap-1"),
		strings.NewReader("csrf_token="+token+"-wrong&plan_hash="+req.PlanHash+"&answer=approve&password=x"))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRec := f.do(t, postReq, session)

	if postRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", postRec.Code, postRec.Body.String())
	}
	if len(decider.calls) != 0 {
		t.Errorf("decider calls = %d, want 0", len(decider.calls))
	}
}

func TestDecide_GETNeverDecides(t *testing.T) {
	decider := &fakeDecider{}
	h := newTestHandlerSkippingCSRF(decideRenderDeps(pendingApprovalRequest("ap-1"), decider, &fakeAuth{}), accounts.RoleOperator)

	rec := request(t, h, http.MethodGet, decideApprovalAction("ap-1"))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET on the decide route = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); !strings.Contains(allow, "POST") {
		t.Errorf("Allow header = %q, want it to name POST", allow)
	}
	if len(decider.calls) != 0 {
		t.Errorf("decider calls = %d, want 0", len(decider.calls))
	}
}

// --- Step-up, proven at the handler seam ------------------------------------

func TestDecide_NoPasswordNothingDecided(t *testing.T) {
	req := pendingApprovalRequest("ap-1")
	decider := &fakeDecider{}
	f, _ := decideLoginFixture(t, req, decider)

	_, cookies := f.signIn(t, "mike", consolePassword)
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	cardRec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/approvals/ap-1", nil), session)

	body := decideForm(cardRec.Body.String(), "approve", "", "")
	postReq := httptest.NewRequest(http.MethodPost, decideApprovalAction("ap-1"), strings.NewReader(body.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := f.do(t, postReq, session)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "step-up") && !strings.Contains(rec.Body.String(), "Step-up") {
		t.Errorf("the refusal does not say step-up is required: %s", rec.Body.String())
	}
	if len(decider.calls) != 0 {
		t.Errorf("decider calls = %d, want 0", len(decider.calls))
	}
}

func TestDecide_AWrongPasswordNeverReachesTheCapabilityLayer(t *testing.T) {
	req := pendingApprovalRequest("ap-1")
	decider := &fakeDecider{}
	f, _ := decideLoginFixture(t, req, decider)

	_, cookies := f.signIn(t, "mike", consolePassword)
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	cardRec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/approvals/ap-1", nil), session)

	body := decideForm(cardRec.Body.String(), "approve", "", "not mike's password")
	postReq := httptest.NewRequest(http.MethodPost, decideApprovalAction("ap-1"), strings.NewReader(body.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := f.do(t, postReq, session)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "did not match") {
		t.Errorf("the refusal does not say the password did not match: %s", rec.Body.String())
	}
	if len(decider.calls) != 0 {
		t.Errorf("decider calls = %d, want 0 — a bad password must never reach DecideApproval", len(decider.calls))
	}
}

func TestDecide_AThrottledStepUpSaysSoAndDecidesNothing(t *testing.T) {
	req := pendingApprovalRequest("ap-1")
	decider := &fakeDecider{}
	f, _ := decideLoginFixture(t, req, decider)

	_, cookies := f.signIn(t, "mike", consolePassword)
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	cardRec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/approvals/ap-1", nil), session)
	getBody := cardRec.Body.String()

	post := func(password string) *httptest.ResponseRecorder {
		body := decideForm(getBody, "approve", "", password)
		postReq := httptest.NewRequest(http.MethodPost, decideApprovalAction("ap-1"), strings.NewReader(body.Encode()))
		postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return f.do(t, postReq, session)
	}

	if rec := post("wrong once"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("first wrong password status = %d, want 401", rec.Code)
	}
	// consoleauth.Service.StepUp shares the sign-in throttle keyed by
	// (source, Account): one failure is enough to throttle the very next
	// attempt, matching TestConsole_ThrottleSaysSoAndSaysWhen.
	rec := post(consolePassword)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After header on a throttled decision")
	}
	if !strings.Contains(rec.Body.String(), "Too many recent attempts") {
		t.Errorf("the throttle does not say what happened: %s", rec.Body.String())
	}
	if len(decider.calls) != 0 {
		t.Errorf("decider calls = %d, want 0", len(decider.calls))
	}
}

func TestDecide_StepUpHappensBeforeTheDecision(t *testing.T) {
	var order []string
	req := pendingApprovalRequest("ap-1")
	decider := &fakeDecider{order: &order}
	auth := &fakeAuth{order: &order}
	f := newLoginFixtureWith(t, func(d *Deps) {
		d.Approvals = &fakeApprovals{pending: []approval.Request{req}}
		d.Decide = decider
		d.Auth = auth
	})

	id, _, err := f.svc.Login(context.Background(), consoleauth.Attempt{
		Name: "mike", Password: accounts.NewPassword(consolePassword), Source: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("mint session: %v", err)
	}
	sessionCookie := &http.Cookie{Name: consoleauth.SessionCookieName, Value: id.Reveal()}
	csrf := f.sessions.CSRFToken(id).Reveal()

	body := url.Values{
		"csrf_token": {csrf},
		"plan_hash":  {req.PlanHash},
		"answer":     {"approve"},
		"password":   {"whatever the fake accepts"},
	}
	postReq := httptest.NewRequest(http.MethodPost, decideApprovalAction("ap-1"), strings.NewReader(body.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := f.do(t, postReq, sessionCookie)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body %s", rec.Code, rec.Body.String())
	}
	if len(order) != 2 || order[0] != "StepUp" || order[1] != "DecideApproval" {
		t.Fatalf("call order = %v, want [StepUp DecideApproval]", order)
	}
}

// --- What reaches the capability layer, and how ------------------------------

func TestDecide_ApproveCitesThePlanHashAndTheOutOfBandChannel(t *testing.T) {
	req := pendingApprovalRequest("ap-1")
	decider := &fakeDecider{}
	f, _ := decideLoginFixture(t, req, decider)

	_, cookies := f.signIn(t, "mike", consolePassword)
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	cardRec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/approvals/ap-1", nil), session)

	body := decideForm(cardRec.Body.String(), "approve", "looks fine", consolePassword)
	postReq := httptest.NewRequest(http.MethodPost, decideApprovalAction("ap-1"), strings.NewReader(body.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := f.do(t, postReq, session)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != decideApprovalPageHref("ap-1") {
		t.Errorf("redirect Location = %q, want the approval object's own path", got)
	}
	if len(decider.calls) != 1 {
		t.Fatalf("decider calls = %d, want exactly 1", len(decider.calls))
	}
	call := decider.calls[0]
	if call.Decision.RequestID != "ap-1" {
		t.Errorf("RequestID = %q, want ap-1", call.Decision.RequestID)
	}
	if call.Decision.PlanHash != req.PlanHash {
		t.Errorf("PlanHash = %q, want %q (from the hidden field, not the record)", call.Decision.PlanHash, req.PlanHash)
	}
	if !call.Decision.Approve {
		t.Error("Approve = false, want true for answer=approve")
	}
	if call.Decision.Reason != "looks fine" {
		t.Errorf("Reason = %q, want the submitted reason", call.Decision.Reason)
	}
	if call.Decision.Channel != approval.ChannelOutOfBand {
		t.Errorf("Channel = %v, want ChannelOutOfBand — set by the surface, never the body", call.Decision.Channel)
	}
	if call.Principal.Account != "mike" {
		t.Errorf("Principal.Account = %q, want mike", call.Principal.Account)
	}
}

func TestDecide_DenyIsNeverADefault(t *testing.T) {
	req := pendingApprovalRequest("ap-1")

	t.Run("deny is explicit", func(t *testing.T) {
		decider := &fakeDecider{}
		f, _ := decideLoginFixture(t, req, decider)
		_, cookies := f.signIn(t, "mike", consolePassword)
		session := cookieNamed(cookies, consoleauth.SessionCookieName)
		cardRec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/approvals/ap-1", nil), session)

		body := decideForm(cardRec.Body.String(), "deny", "", consolePassword)
		postReq := httptest.NewRequest(http.MethodPost, decideApprovalAction("ap-1"), strings.NewReader(body.Encode()))
		postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := f.do(t, postReq, session)

		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303; body %s", rec.Code, rec.Body.String())
		}
		if len(decider.calls) != 1 || decider.calls[0].Decision.Approve {
			t.Fatalf("calls = %+v, want exactly one call with Approve=false", decider.calls)
		}
	})

	for _, answer := range []string{"", "yes", "true", "1", "APPROVE"} {
		t.Run("garbage answer "+answer, func(t *testing.T) {
			decider := &fakeDecider{}
			f, _ := decideLoginFixture(t, req, decider)
			_, cookies := f.signIn(t, "mike", consolePassword)
			session := cookieNamed(cookies, consoleauth.SessionCookieName)
			cardRec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/approvals/ap-1", nil), session)

			body := decideForm(cardRec.Body.String(), answer, "", consolePassword)
			postReq := httptest.NewRequest(http.MethodPost, decideApprovalAction("ap-1"), strings.NewReader(body.Encode()))
			postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := f.do(t, postReq, session)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("answer=%q status = %d, want 400; body %s", answer, rec.Code, rec.Body.String())
			}
			if len(decider.calls) != 0 {
				t.Errorf("answer=%q decider calls = %d, want 0", answer, len(decider.calls))
			}
		})
	}
}

// TestDecide_AStalePlanHashSaysTheViewMoved proves that the Console FORWARDS
// and RENDERS approval.ErrPlanChanged correctly (409, the "moved since this
// page was rendered" copy) when fakeDecider is told to return it. It does
// NOT prove that the domain actually returns ErrPlanChanged for a stale
// hash — that is the domain's own test (internal/approval), deliberately not
// re-proven here per invariant 10.
func TestDecide_AStalePlanHashSaysTheViewMoved(t *testing.T) {
	req := pendingApprovalRequest("ap-1")
	decider := &fakeDecider{err: approval.ErrPlanChanged}
	f, _ := decideLoginFixture(t, req, decider)

	_, cookies := f.signIn(t, "mike", consolePassword)
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	cardRec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/approvals/ap-1", nil), session)

	body := decideForm(cardRec.Body.String(), "approve", "", consolePassword)
	postReq := httptest.NewRequest(http.MethodPost, decideApprovalAction("ap-1"), strings.NewReader(body.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := f.do(t, postReq, session)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "moved since this page was rendered") {
		t.Errorf("body does not say the Plan moved: %s", rec.Body.String())
	}
}

// decideRefusalPost signs in, GETs the card to scrape a fresh CSRF token, and
// POSTs the decide form, returning the recorded response — the shared shape
// TestDecide_AStalePlanHashSaysTheViewMoved and its neighbours each inline.
func decideRefusalPost(t *testing.T, f *loginFixture, id string) *httptest.ResponseRecorder {
	t.Helper()
	_, cookies := f.signIn(t, "mike", consolePassword)
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	cardRec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/approvals/"+id, nil), session)

	body := decideForm(cardRec.Body.String(), "approve", "", consolePassword)
	postReq := httptest.NewRequest(http.MethodPost, decideApprovalAction(id), strings.NewReader(body.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return f.do(t, postReq, session)
}

// TestDecide_ARefusalRendersTheSameWhateverRequestComesBack (#724): the
// capability layer now returns the current Request alongside ErrNotPending
// and ErrDuplicateDecider, instead of the zero value. This handler discards
// the value on every error (`_, err := d.Decide.DecideApproval(...)`), so the
// rendered refusal must be identical either way, and must never leak a field
// only the non-zero Request carries. One fixture per variant: a fakeDecider
// is built once with its final onErr already set, not mutated between POSTs,
// because a fresh fixture per POST avoids sharing session and step-up
// throttle state across variants.
func TestDecide_ARefusalRendersTheSameWhateverRequestComesBack(t *testing.T) {
	sentinel := approval.Request{
		ID: "ap-1", State: approval.StateApproved, JobID: "job-sentinel-9",
		Decisions: []approval.Decision{{AccountID: "acct-ana", Account: "ana", Approve: true}},
	}

	for _, tc := range []struct {
		name string
		err  error
	}{
		{"already terminal", approval.ErrNotPending},
		{"duplicate decider", approval.ErrDuplicateDecider},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zero, _ := decideLoginFixture(t, pendingApprovalRequest("ap-1"), &fakeDecider{err: tc.err})
			nonZero, _ := decideLoginFixture(t, pendingApprovalRequest("ap-1"), &fakeDecider{err: tc.err, onErr: sentinel})

			zeroRec := decideRefusalPost(t, zero, "ap-1")
			nonZeroRec := decideRefusalPost(t, nonZero, "ap-1")

			if zeroRec.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409; body %s", zeroRec.Code, zeroRec.Body.String())
			}
			if nonZeroRec.Code != zeroRec.Code {
				t.Fatalf("status = %d with a zero Request back, %d with a non-zero one; want equal", zeroRec.Code, nonZeroRec.Code)
			}

			wantHeading := "The Relay refused this decision: " + tc.err.Error() + "."
			if !strings.Contains(zeroRec.Body.String(), wantHeading) {
				t.Errorf("zero-Request body does not render %q: %s", wantHeading, zeroRec.Body.String())
			}
			if !strings.Contains(nonZeroRec.Body.String(), wantHeading) {
				t.Errorf("non-zero-Request body does not render %q: %s", wantHeading, nonZeroRec.Body.String())
			}
			if strings.Contains(nonZeroRec.Body.String(), "job-sentinel-9") {
				t.Error("the refusal body leaked a field from the discarded Request")
			}
		})
	}
}

// TestDecide_TheDefaultErrorNeverClaimsNothingWasRecorded pins the wording a
// security review (cycle 2) flagged: DecideApproval's default/unrecognised
// error branch must NOT say "was not recorded", because that branch is also
// what fires when the decision WAS durably recorded and only the audit write
// failed (capability's approval_decide.go returns the real, persisted result
// joined to that error, deliberately). Saying "not recorded" there is the
// opposite of true — an operator could deny a request, be told nothing
// happened, and walk away believing it is still parked while the denial is
// terminal. The copy here says only that the Relay could not CONFIRM the
// decision, and tells the operator to reload rather than trust either
// reading.
func TestDecide_TheDefaultErrorNeverClaimsNothingWasRecorded(t *testing.T) {
	req := pendingApprovalRequest("ap-1")
	decider := &fakeDecider{err: errors.New("boom: the store fell over")}
	f, _ := decideLoginFixture(t, req, decider)

	_, cookies := f.signIn(t, "mike", consolePassword)
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	cardRec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/approvals/ap-1", nil), session)

	body := decideForm(cardRec.Body.String(), "approve", "", consolePassword)
	postReq := httptest.NewRequest(http.MethodPost, decideApprovalAction("ap-1"), strings.NewReader(body.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := f.do(t, postReq, session)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	body2 := rec.Body.String()
	if strings.Contains(body2, "was not recorded") {
		t.Errorf("the default error branch claims the decision was not recorded, which is false whenever "+
			"DecideApproval durably recorded it and only the audit write failed: %s", body2)
	}
	if !strings.Contains(body2, "could not confirm this decision was fully recorded") {
		t.Errorf("the default error branch does not say the Relay could not CONFIRM the decision: %s", body2)
	}
	if strings.Contains(body2, "boom") {
		t.Error("the raw error leaked to the screen; it must only be logged")
	}
}

// TestDecide_TheExcludedRequesterSeesNoFormAndAPostIsStillRefused proves that
// the Console renders no form for the excluded requester AND still forwards
// a POST to the capability layer, rendering whatever it says (409, here
// approval.ErrRequesterExcluded) — a fake decider stands in for the domain,
// so this is a proof about the SURFACE's behavior, not about the domain's
// self-approval rule. The domain's own rule is proven once
// (internal/approval's TestRequesterCannotApproveOwnRequest) and is
// deliberately not re-proven here (invariant 10). Because of that, this test
// and this file give criterion 3's SELF-APPROVAL half no END-TO-END Console
// proof — TestApprovalCallout_ConsoleSelfApprovalIsRefused
// (approval_console_e2e_test.go) closes that gap against the real domain;
// only the MACHINE half of criterion 3 had an end-to-end leg before that.
func TestDecide_TheExcludedRequesterSeesNoFormAndAPostIsStillRefused(t *testing.T) {
	req := pendingApprovalRequest("ap-1")
	decider := &fakeDecider{err: approval.ErrRequesterExcluded}
	f, fa := decideLoginFixture(t, req, decider)
	// mike's Account ID is only known once the fixture has created it, so the
	// requester is set AFTER construction — mutating the *fakeApprovals the
	// mounted mux already holds a pointer to (see decideLoginFixture's doc).
	fa.pending[0].RequestedByID = f.mike.ID
	fa.pending[0].RequestedBy = "mike"
	fa.pending[0].Require.RequesterAllowed = false

	_, cookies := f.signIn(t, "mike", consolePassword)
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	cardRec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/approvals/ap-1", nil), session)
	if strings.Contains(contentOf(cardRec.Body.String()), "<form") {
		t.Error("the excluded requester's own card still offered a decision form")
	}

	// The card carries no Decide form here, and the approval object renders
	// in Focus mode (no nav, no sign-out form either), so there is no
	// csrf_token anywhere on THIS page to scrape — the fleet view still
	// carries the same session token.
	fleetRec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/", nil), session)
	token := renderedCSRFToken(fleetRec.Body.String())
	if token == "" {
		t.Fatal("the fleet view rendered no CSRF token")
	}
	body := url.Values{
		"csrf_token": {token},
		"plan_hash":  {req.PlanHash},
		"answer":     {"approve"},
		"password":   {consolePassword},
	}
	postReq := httptest.NewRequest(http.MethodPost, decideApprovalAction("ap-1"), strings.NewReader(body.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := f.do(t, postReq, session)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	if len(decider.calls) != 1 {
		t.Errorf("decider calls = %d, want 1 — the POST still reaches the layer and is refused there", len(decider.calls))
	}
}

func TestDecide_AGrantRequestOffersNoControlAndThePostIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*fakeApprovals)
		heading string
	}{
		{
			name: "a Grant",
			mutate: func(a *fakeApprovals) {
				a.grants = []approval.Grant{{RequestID: "ap-1"}}
			},
			heading: "authorizes a Scope",
		},
		{
			name: "the Grant store is unreadable",
			mutate: func(a *fakeApprovals) {
				a.grantsErr = errQueryFailed
			},
			heading: "Approval grant store could not be read",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := pendingApprovalRequest("ap-1")
			decider := &fakeDecider{}
			f, fa := decideLoginFixture(t, req, decider)
			tc.mutate(fa)

			_, cookies := f.signIn(t, "mike", consolePassword)
			session := cookieNamed(cookies, consoleauth.SessionCookieName)
			cardRec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/approvals/ap-1", nil), session)
			if strings.Contains(contentOf(cardRec.Body.String()), "<form") {
				t.Error("a Grant-shaped card still offered a decision form")
			}

			// Neither the plan_hash nor a csrf_token is on THIS card (the
			// Grant card renders no plan action block, and the object is
			// rendered in Focus mode with no sign-out form either), so the
			// token comes from the fleet view and the plan hash is the
			// Request's own, exactly as a caller reading only the queue's
			// stored hash would submit.
			fleetRec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/", nil), session)
			token := renderedCSRFToken(fleetRec.Body.String())
			if token == "" {
				t.Fatal("the fleet view rendered no CSRF token")
			}
			body := url.Values{
				"csrf_token": {token},
				"plan_hash":  {req.PlanHash},
				"answer":     {"approve"},
				"password":   {consolePassword},
			}
			postReq := httptest.NewRequest(http.MethodPost, decideApprovalAction("ap-1"), strings.NewReader(body.Encode()))
			postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := f.do(t, postReq, session)

			if rec.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.heading) {
				t.Errorf("body does not carry the expected refusal: %s", rec.Body.String())
			}
			if len(decider.calls) != 0 {
				t.Errorf("decider calls = %d, want 0 — a Grant is refused before the capability layer is asked", len(decider.calls))
			}
		})
	}
}

func TestDecide_TheReasonIsBounded(t *testing.T) {
	req := pendingApprovalRequest("ap-1")
	decider := &fakeDecider{}
	f, _ := decideLoginFixture(t, req, decider)

	_, cookies := f.signIn(t, "mike", consolePassword)
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	cardRec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/approvals/ap-1", nil), session)

	body := decideForm(cardRec.Body.String(), "approve", strings.Repeat("a", maxDecideReasonBytes+1), consolePassword)
	postReq := httptest.NewRequest(http.MethodPost, decideApprovalAction("ap-1"), strings.NewReader(body.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := f.do(t, postReq, session)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if len(decider.calls) != 0 {
		t.Errorf("decider calls = %d, want 0", len(decider.calls))
	}
}

// TestDecide_ThePlanHashIsBounded is maxDecideReasonBytes' sibling for
// plan_hash: empty (a decision binds to a Plan it was shown, so nothing
// usable to bind to is refused exactly like an absent one) and oversized
// both refuse before the capability layer is ever asked.
func TestDecide_ThePlanHashIsBounded(t *testing.T) {
	for _, tc := range []struct {
		name     string
		planHash string
	}{
		{"empty", ""},
		{"oversized", strings.Repeat("a", maxPlanHashBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := pendingApprovalRequest("ap-1")
			decider := &fakeDecider{}
			f, _ := decideLoginFixture(t, req, decider)

			_, cookies := f.signIn(t, "mike", consolePassword)
			session := cookieNamed(cookies, consoleauth.SessionCookieName)
			cardRec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/approvals/ap-1", nil), session)

			body := url.Values{
				"csrf_token": {renderedCSRFToken(cardRec.Body.String())},
				"plan_hash":  {tc.planHash},
				"answer":     {"approve"},
				"password":   {consolePassword},
			}
			postReq := httptest.NewRequest(http.MethodPost, decideApprovalAction("ap-1"), strings.NewReader(body.Encode()))
			postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := f.do(t, postReq, session)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("plan_hash=%s status = %d, want 400; body %s", tc.name, rec.Code, rec.Body.String())
			}
			if len(decider.calls) != 0 {
				t.Errorf("plan_hash=%s decider calls = %d, want 0", tc.name, len(decider.calls))
			}
		})
	}
}

// TestDecide_OverlongApprovalIDNeverReachesTheSeam mirrors
// TestCancel_OverlongJobIDNeverReachesTheSeam (cancel_test.go): an id over
// maxApprovalIDBytes 404s before the seam is ever asked — before even the
// ConsoleSession check, since the id is validated first.
func TestDecide_OverlongApprovalIDNeverReachesTheSeam(t *testing.T) {
	decider := &fakeDecider{}
	h := newTestHandlerSkippingCSRF(decideRenderDeps(pendingApprovalRequest("ap-1"), decider, &fakeAuth{}), accounts.RoleOperator)

	long := strings.Repeat("a", maxApprovalIDBytes+1)
	rec := postSkippingCSRF(t, h, decideApprovalAction(long))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if len(decider.calls) != 0 {
		t.Errorf("decider calls = %d, want 0 — an overlong id must never reach the seam", len(decider.calls))
	}
}

// --- The seam itself ---------------------------------------------------------

func TestDecide_SeamCarriesOnlyDecideApproval(t *testing.T) {
	typ := reflect.TypeOf((*ApprovalDecider)(nil)).Elem()
	if typ.NumMethod() != 1 {
		t.Fatalf("ApprovalDecider has %d methods, want exactly 1", typ.NumMethod())
	}
	if typ.Method(0).Name != "DecideApproval" {
		t.Errorf("ApprovalDecider's one method is %q, want DecideApproval", typ.Method(0).Name)
	}
}
