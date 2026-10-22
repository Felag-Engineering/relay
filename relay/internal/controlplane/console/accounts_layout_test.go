package console

// The Account page's layout and the New account page's refusal path (design
// spec 15): Role, State, then API Tokens; a refused create re-renders the New
// account page; Lower role never dimmed.

import (
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
)

func TestAccounts_TheAccountPageOrdersRoleStateTokens(t *testing.T) {
	body := accountsWriteBody(t, accountPagePath("gleipnir-prod"))
	last := -1
	for _, marker := range []string{
		"Back to Accounts",
		"<h2>Role</h2>",
		"<h2>State</h2>",
		"<h2>API Tokens</h2>",
	} {
		at := strings.Index(body, marker)
		if at < 0 || at < last {
			t.Fatalf("%q is at %d, after the previous section at %d (or missing)", marker, at, last)
		}
		last = at
	}
}

func TestAccountsWrite_ARefusedCreateRendersTheNewAccountPage(t *testing.T) {
	valid := url.Values{"name": {"newbie"}, "kind": {"human"}, "role": {"viewer"}, "password": {"p"}}
	with := func(k, v string) url.Values {
		f := url.Values{}
		for key, vs := range valid {
			f[key] = vs
		}
		f.Set(k, v)
		return f
	}
	for _, tc := range []struct {
		name       string
		form       url.Values
		setup      func(*writeFix)
		status     int
		sentence   string
		retryAfter string
		noStepUp   bool
	}{
		{name: "no name", form: with("name", ""), status: 400, sentence: "An Account needs a name", noStepUp: true},
		{name: "unknown kind", form: with("kind", "robot"), status: 400, sentence: "recognisable Account kind", noStepUp: true},
		{name: "unknown role", form: with("role", "root"), status: 400, sentence: "recognisable role", noStepUp: true},
		{name: "no password outside the window", form: with("password", ""), status: 401, sentence: "Step-up re-authentication is required", noStepUp: true},
		{name: "wrong password", form: valid, status: 401, sentence: "did not match",
			setup: func(x *writeFix) { x.auth.stepUpErr = consoleauth.ErrBadCredentials }},
		{name: "throttled", form: valid, status: 429, sentence: "Too many recent attempts", retryAfter: "30",
			setup: func(x *writeFix) {
				x.auth.stepUpErr = &consoleauth.ThrottledError{RetryAfter: 30 * time.Second}
			}},
		{name: "unclassified step-up error", form: valid, status: 500, sentence: "could not verify your password",
			setup: func(x *writeFix) { x.auth.stepUpErr = errors.New("store down") }},
		{name: "name taken", form: valid, status: 409, sentence: "already in use",
			setup: func(x *writeFix) { x.admin.createErr = accounts.ErrNameTaken }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newWriteFix(t, nil)
			if tc.setup != nil {
				tc.setup(x)
			}
			rec := x.post(t, createAccountAction(), tc.form)
			body := rec.Body.String()
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.status, contentOf(body))
			}
			alert := strings.Index(body, `<p class="fielderr" role="alert">`)
			if alert < 0 || !strings.Contains(body, tc.sentence) {
				t.Errorf("the refusal does not say %q in its alert:\n%s", tc.sentence, contentOf(body))
			}
			if submit := strings.Index(body, `type="submit">Create account</button>`); submit < alert {
				t.Errorf("the alert (at %d) is not above the submit button (at %d)", alert, submit)
			}
			if !strings.Contains(body, `action="`+createAccountAction()+`"`) {
				t.Error("the re-rendered form does not post to the create action")
			}
			if !strings.Contains(body, `<a href="/console/accounts">Back to Accounts</a>`) {
				t.Error("the refusal page has no Back to Accounts")
			}
			if got := rec.Header().Get("Retry-After"); got != tc.retryAfter {
				t.Errorf("Retry-After = %q, want %q", got, tc.retryAfter)
			}
			if tc.status != 409 && len(x.admin.creates) != 0 {
				t.Errorf("CreateAccount was called %d times for a refusal that precedes it", len(x.admin.creates))
			}
			if tc.noStepUp && len(x.auth.stepUpCalls) != 0 {
				t.Errorf("step-up was attempted %d times", len(x.auth.stepUpCalls))
			}
		})
	}
}

// createFormOf returns the New account form's markup alone: the layout's
// Sign-out form carries a csrf_token too, and comes first on the page.
func createFormOf(t *testing.T, body string) string {
	t.Helper()
	form := regexp.MustCompile(`(?s)<form[^>]*action="` + regexp.QuoteMeta(createAccountAction()) + `".*?</form>`).FindString(body)
	if form == "" {
		t.Fatalf("no create form on the page:\n%s", contentOf(body))
	}
	return form
}

func TestAccountsWrite_ARefusedCreateAfterStepUpCarriesTheRotatedCSRFToken(t *testing.T) {
	x := newWriteFix(t, nil)
	x.auth.stepUpID = consoleauth.ParseSessionID("rotated-id")
	x.admin.createErr = accounts.ErrNameTaken

	rec := x.post(t, createAccountAction(), url.Values{
		"name": {"newbie"}, "kind": {"human"}, "role": {"viewer"}, "password": {"p"},
	})
	body := rec.Body.String()
	if rec.Code != http.StatusConflict || !strings.Contains(body, `action="`+createAccountAction()+`"`) {
		t.Fatalf("status = %d, want a 409 with the form re-rendered:\n%s", rec.Code, contentOf(body))
	}
	want := "fake-csrf-" + x.auth.stepUpID.Reveal()
	if got := renderedCSRFToken(createFormOf(t, body)); got != want || got == x.csrf {
		t.Errorf("the re-rendered form carries %q, want the rotated session's %q (not the pre-rotation %q)", got, want, x.csrf)
	}
	if !strings.Contains(body, "optional, you confirmed it recently") {
		t.Errorf("after a successful step-up the password is not drawn as optional:\n%s", contentOf(body))
	}

	wrong := newWriteFix(t, nil)
	wrong.auth.stepUpErr = consoleauth.ErrBadCredentials
	body = wrong.post(t, createAccountAction(), url.Values{
		"name": {"newbie"}, "kind": {"human"}, "role": {"viewer"}, "password": {"p"},
	}).Body.String()
	if !strings.Contains(body, "Your password &mdash; required to create an Account") {
		t.Errorf("after a step-up refusal the password is not drawn as required:\n%s", contentOf(body))
	}
}

func TestAccountsWrite_ARefusedCreateEchoesNameKindAndRoleButNeverThePassword(t *testing.T) {
	const password = "hunter2-do-not-echo"
	x := newWriteFix(t, nil)
	x.admin.createErr = accounts.ErrNameTaken
	body := x.post(t, createAccountAction(), url.Values{
		"name": {"ci-agent"}, "kind": {"machine"}, "role": {"operator"}, "password": {password},
	}).Body.String()
	for _, want := range []string{
		`value="ci-agent"`,
		`value="machine" required checked>`,
		`value="operator" required checked>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the refused form does not echo %q:\n%s", want, contentOf(body))
		}
	}
	if strings.Contains(body, password) {
		t.Error("the refused form echoes the password")
	}

	// A refused name does not clear kind and role.
	body = newWriteFix(t, nil).post(t, createAccountAction(), url.Values{
		"name": {""}, "kind": {"machine"}, "role": {"operator"},
	}).Body.String()
	if !strings.Contains(body, `value="machine" required checked>`) || !strings.Contains(body, `value="operator" required checked>`) {
		t.Errorf("a refused name reset kind or role:\n%s", contentOf(body))
	}

	long := strings.Repeat("n", maxAccountNameBytes+1)
	body = newWriteFix(t, nil).post(t, createAccountAction(), url.Values{
		"name": {long}, "kind": {"human"}, "role": {"viewer"},
	}).Body.String()
	if strings.Contains(body, long) {
		t.Error("an overlong name is echoed")
	}
}

func TestAccountsWrite_ACreateRefusalTheFormCannotAnswerDoesNotRerenderIt(t *testing.T) {
	valid := url.Values{"name": {"newbie"}, "kind": {"human"}, "role": {"viewer"}, "password": {"p"}}
	for _, tc := range []struct {
		name     string
		setup    func(*writeFix)
		status   int
		sentence string
	}{
		{"session ended", func(x *writeFix) { x.auth.stepUpErr = consoleauth.ErrNoSession }, 401, "Sign in again."},
		{"the capability layer refused", func(x *writeFix) { x.admin.createErr = authz.ErrUnauthorized }, 403, "The Relay refused this"},
		{"could not confirm", func(x *writeFix) { x.admin.createErr = errors.New("audit append") }, 500, "could not confirm"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newWriteFix(t, nil)
			tc.setup(x)
			rec := x.post(t, createAccountAction(), valid)
			body := rec.Body.String()
			if rec.Code != tc.status || !strings.Contains(body, tc.sentence) {
				t.Fatalf("status = %d, want %d with %q:\n%s", rec.Code, tc.status, tc.sentence, contentOf(body))
			}
			if strings.Contains(body, createAccountAction()) {
				t.Errorf("the refusal re-rendered a form it cannot help with:\n%s", contentOf(body))
			}
		})
	}
}

func TestAccountsWrite_LowerRoleIsNeverDimmedAndCarriesTheHint(t *testing.T) {
	forms := regexp.MustCompile(`(?s)<form class="ctlform ctlrow rolechange".*?</form>`)
	for _, q := range []string{accountPagePath("mike"), accountPagePath("gleipnir-prod")} {
		body := accountsWriteBody(t, q)
		var lower string
		for _, f := range forms.FindAllString(body, -1) {
			if !strings.Contains(f, `type="password"`) {
				lower = f
			}
		}
		if lower == "" {
			t.Fatalf("%s: no Lower role form", q)
		}
		if !strings.Contains(lower, `<span class="note" id="lower-role-hint">`+lowerRoleHint+`</span>`) {
			t.Errorf("%s: the Lower role form does not carry the hint:\n%s", q, lower)
		}
		if regexp.MustCompile(`<button[^>]*disabled`).MatchString(lower) {
			t.Errorf("%s: the Lower role button is disabled:\n%s", q, lower)
		}
		if strings.Contains(lower, "required") {
			t.Errorf("%s: the Lower role form can be invalid, so a stylesheet could dim it:\n%s", q, lower)
		}
		open := lower[:strings.Index(lower, ">")]
		for _, want := range []string{`method="get"`, `autocomplete="off"`} {
			if !strings.Contains(open, want) {
				t.Errorf("%s: the Lower role form lacks %s: %s", q, want, open)
			}
		}
	}
}

func TestAccountsWrite_AutocompleteIsOffOnTheCreateAndMintNames(t *testing.T) {
	for id, path := range map[string]string{
		"create-name": newAccountPath,
		"mint-name":   accountPagePath("gleipnir-prod"),
	} {
		body := accountsWriteBody(t, path)
		tag := regexp.MustCompile(`<input id="` + id + `"[^>]*>`).FindString(body)
		if tag == "" {
			t.Fatalf("no input %s", id)
		}
		if !strings.Contains(tag, `autocomplete="off"`) {
			t.Errorf("%s does not turn autocomplete off: %s", id, tag)
		}
	}
}

func TestAccountsWrite_AnEmptyLowerSubmitIsRefusedInTheHintsWords(t *testing.T) {
	for name, form := range map[string]url.Values{
		"role field absent": {},
		"role field empty":  {"role": {""}},
	} {
		t.Run(name, func(t *testing.T) {
			x := newRealWriteFix(t)
			before := len(x.records(t))
			rec := x.post(t, setAccountRoleAction(x.target.ID), form)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", rec.Code, contentOf(rec.Body.String()))
			}
			if !strings.Contains(rec.Body.String(), template.HTMLEscapeString("No role was chosen: "+lowerRoleHint+".")) {
				t.Errorf("the refusal is not in the hint's words:\n%s", contentOf(rec.Body.String()))
			}
			if after := len(x.records(t)); after != before {
				t.Errorf("the trail grew from %d to %d rows for a refused submit", before, after)
			}
			got, err := x.trail.Accounts().Get(t.Context(), x.target.ID)
			if err != nil || got.Role != accounts.RoleOperator {
				t.Fatalf("the target is %v (err %v), want it unchanged as operator", got.Role, err)
			}

			// The reducing act itself is untouched.
			rec = x.post(t, setAccountRoleAction(x.target.ID), url.Values{"role": {"viewer"}})
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("a real lower role = %d, want 303; body %s", rec.Code, contentOf(rec.Body.String()))
			}
			got, _ = x.trail.Accounts().Get(t.Context(), x.target.ID)
			if got.Role != accounts.RoleViewer {
				t.Errorf("the role is %s after a lower, want viewer", got.Role)
			}
		})
	}
}

func TestAccountsWrite_ARealRefusedCreateCarriesATokenThatStillValidates(t *testing.T) {
	x := newRealWriteFix(t)
	before := x.csrf

	rec := x.post(t, createAccountAction(), url.Values{
		"name": {"second-admin"}, "kind": {"human"}, "role": {"viewer"}, "password": {realWritePassword},
	})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `action="`+createAccountAction()+`"`) {
		t.Fatalf("status = %d, want a 409 with the form re-rendered:\n%s", rec.Code, contentOf(rec.Body.String()))
	}
	rendered := renderedCSRFToken(createFormOf(t, rec.Body.String()))
	if rendered != x.csrf || rendered == before {
		t.Fatalf("the re-rendered form carries %q, want the rotated session's %q (not %q)", rendered, x.csrf, before)
	}

	rec = x.post(t, createAccountAction(), url.Values{
		"csrf_token": {rendered},
		"name":       {"third-admin"}, "kind": {"machine"}, "role": {"viewer"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("resubmitting the re-rendered form = %d, want 303; body %s", rec.Code, contentOf(rec.Body.String()))
	}
	if _, err := x.trail.Accounts().GetByName(t.Context(), "third-admin"); err != nil {
		t.Errorf("the resubmitted Account was not created: %v", err)
	}
}
