package console

// cancel_test.go covers the Console's Cancel control (#595): the route
// (cancel.go), and who sees the control at all (cancelOffered). Job detail's
// own rendering of the result — the honest "which is which" block — is
// covered in job_test.go, beside the rest of that screen's acceptance.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// runningJobSummary is a Job with one Task still unresolved — the state that
// makes cancelOffered's InFlight-above-zero half true.
func runningJobSummary(tasks []capability.TaskRow) capability.JobSummary {
	sum := oneJob(tasks, jobs.RiskClassMutate)
	sum.Total = len(tasks) + 1
	sum.Unresolved = 1
	sum.State = jobs.JobStateRunning
	return sum
}

// runningJob is a running Job with one Task resolved of three — a fixture
// whose Total/Unresolved a test does not have to keep consistent by hand.
func runningJob(id, requester, accountID string) capability.JobSummary {
	return capability.JobSummary{
		JobID:              id,
		CreatedAt:          testNow,
		State:              jobs.JobStateRunning,
		ActionKind:         jobs.ActionOperation,
		OperationName:      "service.restart",
		RiskClass:          jobs.RiskClassMutate,
		Requester:          requester,
		RequesterAccountID: accountID,
		Total:              3,
		Unresolved:         2,
	}
}

// cancelDeps is jobDeps with the Cancel seam wired.
func cancelDeps(q *fakeQueries, c JobCanceller) Deps {
	d := jobDeps(q)
	d.Cancel = c
	return d
}

// jobBodyAs is jobBody with an explicit role, since jobBody hardcodes admin.
func jobBodyAs(t *testing.T, d Deps, role accounts.Role, path string) string {
	t.Helper()
	rec := get(t, newTestHandler(d, role), path)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", path, rec.Code)
	}
	return rec.Body.String()
}

// newTestHandlerSkippingCSRF mounts the Console without Secure's CSRF check.
// The real-session tests below already prove CSRF is enforced on the cancel
// route; this is for a test whose subject is something else entirely (an
// unknown Job, an overlong id, a GET on a POST-only route), where carrying a
// real signed-in session would only obscure what is actually under test.
func newTestHandlerSkippingCSRF(d Deps, role accounts.Role) http.Handler {
	authn := controlplane.NewAuthenticator(roleVerifier{role: role})
	mux := http.NewServeMux()
	Register(mux, d)
	return authn.Middleware(mux)
}

func postSkippingCSRF(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Authorization", "Bearer "+testCredential)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// --- Who sees the control ---------------------------------------------------

func TestCancel_ViewerSeesNoControlOnARunningJob(t *testing.T) {
	tasks := []capability.TaskRow{mutateTask("node-a", jobs.OutcomeSuccess, "ok")}
	q := &fakeQueries{jobs: []capability.JobSummary{runningJobSummary(tasks)}, tasks: tasks}
	content := contentOf(jobBodyAs(t, cancelDeps(q, &fakeCanceller{}), accounts.RoleViewer, jobPath("")))

	for _, banned := range []string{"<form", "<button", cancelJobAction(testJobID), "Cancel asks this Job"} {
		if strings.Contains(content, banned) {
			t.Errorf("a viewer's Job page renders %q — a viewer must see no control", banned)
		}
	}
}

func TestCancel_OperatorSeesTheControlWhileTasksAreInFlight(t *testing.T) {
	for _, role := range []accounts.Role{accounts.RoleOperator, accounts.RoleAdmin} {
		t.Run(string(role), func(t *testing.T) {
			tasks := []capability.TaskRow{mutateTask("node-a", jobs.OutcomeSuccess, "ok")}
			q := &fakeQueries{jobs: []capability.JobSummary{runningJobSummary(tasks)}, tasks: tasks}
			body := jobBodyAs(t, cancelDeps(q, &fakeCanceller{}), role, jobPath(""))

			if !strings.Contains(body, `action="`+cancelJobAction(testJobID)+`"`) {
				t.Error("the form action is not this Job's cancel path")
			}
			if !strings.Contains(body, `name="csrf_token"`) {
				t.Error("the cancel form carries no CSRF token")
			}
			if !strings.Contains(body, "Cancel asks this Job") {
				t.Error("the one-line explanation beside Cancel is missing")
			}
		})
	}
}

func TestCancel_NoControlOnceEveryTaskHasResolved(t *testing.T) {
	tasks := []capability.TaskRow{mutateTask("node-a", jobs.OutcomeSuccess, "ok")}
	sum := oneJob(tasks, jobs.RiskClassMutate) // Unresolved is zero
	q := &fakeQueries{jobs: []capability.JobSummary{sum}, tasks: tasks}
	content := contentOf(jobBodyAs(t, cancelDeps(q, &fakeCanceller{}), accounts.RoleOperator, jobPath("")))

	if strings.Contains(content, "<form") {
		t.Error("a Job with nothing in flight still renders a control")
	}
}

func TestCancel_NoControlWhenTheSeamIsUnwired(t *testing.T) {
	tasks := []capability.TaskRow{mutateTask("node-a", jobs.OutcomeSuccess, "ok")}
	q := &fakeQueries{jobs: []capability.JobSummary{runningJobSummary(tasks)}, tasks: tasks}
	d := jobDeps(q) // d.Cancel is nil
	content := contentOf(jobBodyAs(t, d, accounts.RoleOperator, jobPath("")))

	if strings.Contains(content, "<form") {
		t.Error("a Job page rendered a control with no Cancel seam wired")
	}
}

// --- The route itself --------------------------------------------------------

func TestCancel_ARealSessionPostReachesTheCapabilityLayerAndRedirects(t *testing.T) {
	tasks := []capability.TaskRow{mutateTask("node-a", jobs.OutcomeSuccess, "ok")}
	q := &fakeQueries{jobs: []capability.JobSummary{runningJobSummary(tasks)}, tasks: tasks}
	canceller := &fakeCanceller{}
	f := newLoginFixtureWith(t, func(d *Deps) {
		d.Queries = q
		d.Cancel = canceller
	})

	rec, cookies := f.signIn(t, "mike", consolePassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("sign-in status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	if session == nil {
		t.Fatal("no session cookie was set")
	}

	getRec := f.do(t, httptest.NewRequest(http.MethodGet, jobPath(""), nil), session)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET Job page = %d, want 200; body %s", getRec.Code, getRec.Body.String())
	}
	token := renderedCSRFToken(getRec.Body.String())
	if token == "" {
		t.Fatal("the Job page rendered no CSRF token")
	}

	postReq := httptest.NewRequest(http.MethodPost, cancelJobAction(testJobID),
		strings.NewReader("csrf_token="+token))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRec := f.do(t, postReq, session)

	if postRec.Code != http.StatusSeeOther {
		t.Fatalf("POST cancel = %d, want 303; body %s", postRec.Code, postRec.Body.String())
	}
	if got := postRec.Header().Get("Location"); got != "/console/jobs/"+testJobID {
		t.Errorf("redirect Location = %q, want the Job detail path", got)
	}
	if len(canceller.calls) != 1 {
		t.Fatalf("canceller calls = %d, want exactly 1", len(canceller.calls))
	}
	if got := canceller.calls[0]; got.JobID != testJobID || got.Principal.Account != "mike" {
		t.Errorf("canceller call = %+v, want JobID=%q and mike's Principal", got, testJobID)
	}
}

// TestCancel_ABearerLaneCancelPostIsRefusedAndNeverCancels covers the BEARER
// lane: sessionCSRFValid fails closed with no ConsoleSession on the context
// at all (security.go), which is what an Authorization: Bearer request aimed
// at this POST route always is. The signed-in session lane — the one a
// browser actually uses — is covered by the two tests below.
func TestCancel_ABearerLaneCancelPostIsRefusedAndNeverCancels(t *testing.T) {
	tasks := []capability.TaskRow{mutateTask("node-a", jobs.OutcomeSuccess, "ok")}
	q := &fakeQueries{jobs: []capability.JobSummary{runningJobSummary(tasks)}, tasks: tasks}
	canceller := &fakeCanceller{}
	h := newTestHandler(cancelDeps(q, canceller), accounts.RoleOperator)

	rec := request(t, h, http.MethodPost, cancelJobAction(testJobID))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if len(canceller.calls) != 0 {
		t.Errorf("canceller calls = %d, want 0", len(canceller.calls))
	}
}

// TestCancel_ARealSessionPostWithNoCSRFTokenIsRefused is the session lane's
// half of the CSRF proof: a genuine signed-in cookie, but the form carries no
// csrf_token field at all. submittedCSRFToken then compares the session's
// real token against the empty string, which consoleauth.CSRFTokensEqual
// must never call a match.
func TestCancel_ARealSessionPostWithNoCSRFTokenIsRefused(t *testing.T) {
	tasks := []capability.TaskRow{mutateTask("node-a", jobs.OutcomeSuccess, "ok")}
	q := &fakeQueries{jobs: []capability.JobSummary{runningJobSummary(tasks)}, tasks: tasks}
	canceller := &fakeCanceller{}
	f := newLoginFixtureWith(t, func(d *Deps) {
		d.Queries = q
		d.Cancel = canceller
	})

	rec, cookies := f.signIn(t, "mike", consolePassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("sign-in status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	if session == nil {
		t.Fatal("no session cookie was set")
	}

	postReq := httptest.NewRequest(http.MethodPost, cancelJobAction(testJobID), strings.NewReader(""))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRec := f.do(t, postReq, session)

	if postRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", postRec.Code, postRec.Body.String())
	}
	if len(canceller.calls) != 0 {
		t.Errorf("canceller calls = %d, want 0", len(canceller.calls))
	}
}

// TestCancel_ARealSessionPostWithTheWrongCSRFTokenIsRefused is the same
// session lane with a token that is well-formed but not the session's own —
// the shape an attacker's forged form would actually submit, as opposed to
// leaving the field off entirely.
func TestCancel_ARealSessionPostWithTheWrongCSRFTokenIsRefused(t *testing.T) {
	tasks := []capability.TaskRow{mutateTask("node-a", jobs.OutcomeSuccess, "ok")}
	q := &fakeQueries{jobs: []capability.JobSummary{runningJobSummary(tasks)}, tasks: tasks}
	canceller := &fakeCanceller{}
	f := newLoginFixtureWith(t, func(d *Deps) {
		d.Queries = q
		d.Cancel = canceller
	})

	rec, cookies := f.signIn(t, "mike", consolePassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("sign-in status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	if session == nil {
		t.Fatal("no session cookie was set")
	}

	getRec := f.do(t, httptest.NewRequest(http.MethodGet, jobPath(""), nil), session)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET Job page = %d, want 200; body %s", getRec.Code, getRec.Body.String())
	}
	token := renderedCSRFToken(getRec.Body.String())
	if token == "" {
		t.Fatal("the Job page rendered no CSRF token")
	}

	postReq := httptest.NewRequest(http.MethodPost, cancelJobAction(testJobID),
		strings.NewReader("csrf_token="+token+"-wrong"))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRec := f.do(t, postReq, session)

	if postRec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", postRec.Code, postRec.Body.String())
	}
	if len(canceller.calls) != 0 {
		t.Errorf("canceller calls = %d, want 0", len(canceller.calls))
	}
}

func TestCancel_AViewerSessionFindsTheRouteAbsent(t *testing.T) {
	canceller := &fakeCanceller{}
	f := newLoginFixtureWith(t, func(d *Deps) { d.Cancel = canceller })
	f.createAccountWithPassword(t, "watcher", accounts.RoleViewer, "a viewer password")

	rec, cookies := f.signIn(t, "watcher", "a viewer password")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("viewer sign-in status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	if session == nil {
		t.Fatal("no session cookie was set")
	}

	// A GENUINE token for the viewer's own session — otherwise Secure's CSRF
	// check (which runs BEFORE the route table, outside the mux) would
	// answer 403 for the wrong reason, and the test would not be asking
	// what it claims to. A viewer can reach the fleet view, which is where
	// this token comes from.
	fleetRec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/", nil), session)
	token := renderedCSRFToken(fleetRec.Body.String())
	if token == "" {
		t.Fatal("the fleet view rendered no CSRF token for the viewer's session")
	}

	postReq := httptest.NewRequest(http.MethodPost, cancelJobAction(testJobID),
		strings.NewReader("csrf_token="+token))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if rec := f.do(t, postReq, session); rec.Code != http.StatusNotFound {
		t.Errorf("viewer POST to cancel = %d, want 404 (absent, not forbidden)", rec.Code)
	}

	optRec := f.do(t, httptest.NewRequest(http.MethodOptions, cancelJobAction(testJobID), nil), session)
	if optRec.Code != http.StatusNotFound {
		t.Errorf("viewer OPTIONS on cancel = %d, want 404 — the method oracle must not confirm the route exists", optRec.Code)
	}
	if len(canceller.calls) != 0 {
		t.Errorf("canceller calls = %d, want 0", len(canceller.calls))
	}
}

func TestCancel_GETNeverCancels(t *testing.T) {
	canceller := &fakeCanceller{}
	h := newTestHandlerSkippingCSRF(cancelDeps(&fakeQueries{}, canceller), accounts.RoleOperator)

	rec := request(t, h, http.MethodGet, cancelJobAction(testJobID))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET on the cancel route = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); !strings.Contains(allow, "POST") {
		t.Errorf("Allow header = %q, want it to name POST", allow)
	}
	if len(canceller.calls) != 0 {
		t.Errorf("canceller calls = %d, want 0", len(canceller.calls))
	}
}

func TestCancel_RefusalRendersTheCapabilityLayersAnswer(t *testing.T) {
	refusal := errors.New("cancelling a Job requires operator")
	canceller := &fakeCanceller{err: errors.Join(refusal, authz.ErrUnauthorized)}
	h := newTestHandlerSkippingCSRF(cancelDeps(&fakeQueries{}, canceller), accounts.RoleOperator)

	rec := postSkippingCSRF(t, h, cancelJobAction(testJobID))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, refusal.Error()) {
		t.Errorf("body does not carry the refusal reason: %s", body)
	}
	if !strings.Contains(body, "The Job continues") {
		t.Error("a refused cancel does not say the Job continues")
	}
}

// TestCancel_MachineScopingRefusalRendersA403 covers #614's second refusal
// sentinel: a machine Account cannot hold a Console session in practice, but
// the adapter must render EVERY capability-layer refusal as a refusal
// (invariant 10) rather than let an unrecognized one fall to the 500
// default, which would misreport a refused cancel as one that "may have"
// stopped Tasks it never touched.
func TestCancel_MachineScopingRefusalRendersA403(t *testing.T) {
	canceller := &fakeCanceller{err: capability.ErrJobNotRequestedByCaller}
	h := newTestHandlerSkippingCSRF(cancelDeps(&fakeQueries{}, canceller), accounts.RoleOperator)

	rec := postSkippingCSRF(t, h, cancelJobAction(testJobID))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "The Relay refused this cancel") {
		t.Errorf("body does not carry the refusal heading: %s", body)
	}
	if !strings.Contains(body, "The Job continues") {
		t.Error("a refused cancel does not say the Job continues")
	}
}

func TestCancel_UnknownJobIs404(t *testing.T) {
	canceller := &fakeCanceller{err: jobs.ErrJobNotFound}
	h := newTestHandlerSkippingCSRF(cancelDeps(&fakeQueries{}, canceller), accounts.RoleOperator)

	rec := postSkippingCSRF(t, h, cancelJobAction("job-does-not-exist"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
}

func TestCancel_OverlongJobIDNeverReachesTheSeam(t *testing.T) {
	canceller := &fakeCanceller{}
	h := newTestHandlerSkippingCSRF(cancelDeps(&fakeQueries{}, canceller), accounts.RoleOperator)

	long := strings.Repeat("a", maxJobIDBytes+1)
	rec := postSkippingCSRF(t, h, cancelJobAction(long))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if len(canceller.calls) != 0 {
		t.Errorf("canceller calls = %d, want 0 — an overlong id must never reach the seam", len(canceller.calls))
	}
}

func TestCancel_SeamCarriesOnlyCancelJob(t *testing.T) {
	typ := reflect.TypeOf((*JobCanceller)(nil)).Elem()
	if typ.NumMethod() != 1 {
		t.Fatalf("JobCanceller has %d methods, want exactly 1", typ.NumMethod())
	}
	if typ.Method(0).Name != "CancelJob" {
		t.Errorf("JobCanceller's one method is %q, want CancelJob", typ.Method(0).Name)
	}
}
