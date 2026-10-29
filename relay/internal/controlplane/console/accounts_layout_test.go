package console

// The Account page's layout and the New account page's refusal path (design
// spec 15): Role, State, then API Tokens; a refused create re-renders the New
// account page; Lower role never dimmed.

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
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

// editSectionOf returns the region of the Account page an edit refusal is drawn
// in: Role up to State, State up to the next section, or the mint form.
func editSectionOf(t *testing.T, body, section string) string {
	t.Helper()
	switch section {
	case "role":
		return between(t, body, "<h2>Role</h2>", "<h2>State</h2>")
	case "state":
		start := strings.Index(body, "<h2>State</h2>")
		if start < 0 {
			t.Fatalf("no State section:\n%s", contentOf(body))
		}
		rest := body[start+len("<h2>State</h2>"):]
		end := strings.Index(rest, "<h2>")
		if end < 0 {
			t.Fatalf("no section after State:\n%s", contentOf(body))
		}
		return rest[:end]
	default:
		return formWithAction(t, body, mintAPITokenAction(targetOperatorID))
	}
}

func between(t *testing.T, body, from, to string) string {
	t.Helper()
	start := strings.Index(body, from)
	end := strings.Index(body, to)
	if start < 0 || end < start {
		t.Fatalf("%q ... %q not found in order:\n%s", from, to, contentOf(body))
	}
	return body[start:end]
}

func TestAccountsWrite_ARefusedEditActRendersTheAccountPage(t *testing.T) {
	const alert = `<p class="fielderr" role="alert">`
	for _, tc := range []struct {
		name       string
		path       string
		form       url.Values
		setup      func(*writeFix)
		status     int
		sentence   string
		section    string // role, state or mint
		action     string // the form the page must still carry; empty for the Self note
		retryAfter string
		noWrite    bool // the refusal precedes the capability call
	}{
		{name: "role raise: no password outside the window", path: setAccountRoleAction(targetViewerID),
			form: url.Values{"role": {"operator"}}, status: 401, sentence: "Step-up re-authentication is required",
			section: "role", action: setAccountRoleAction(targetViewerID), noWrite: true},
		{name: "role raise: wrong password", path: setAccountRoleAction(targetViewerID),
			form: url.Values{"role": {"operator"}, "password": {"p"}}, status: 401, sentence: "did not match",
			setup:   func(x *writeFix) { x.auth.stepUpErr = consoleauth.ErrBadCredentials },
			section: "role", action: setAccountRoleAction(targetViewerID), noWrite: true},
		{name: "role raise: throttled", path: setAccountRoleAction(targetViewerID),
			form: url.Values{"role": {"operator"}, "password": {"p"}}, status: 429, sentence: "Too many recent attempts",
			setup: func(x *writeFix) {
				x.auth.stepUpErr = &consoleauth.ThrottledError{RetryAfter: 30 * time.Second}
			},
			section: "role", action: setAccountRoleAction(targetViewerID), retryAfter: "30", noWrite: true},
		{name: "role: already held", path: setAccountRoleAction(targetViewerID),
			form: url.Values{"role": {"viewer"}, "password": {"p"}}, status: 400, sentence: "That is already this Account's role",
			section: "role", action: setAccountRoleAction(targetViewerID), noWrite: true},
		{name: "role: none", path: setAccountRoleAction(targetOperatorID),
			form: url.Values{}, status: 400, sentence: noRoleRefusal,
			section: "role", action: setAccountRoleAction(targetOperatorID), noWrite: true},
		{name: "role: last admin", path: setAccountRoleAction(targetOperatorID),
			form: url.Values{"role": {"viewer"}}, status: 409, sentence: lastAdminRefusal,
			setup:   func(x *writeFix) { x.admin.roleErr = accounts.ErrLastAdmin },
			section: "role", action: setAccountRoleAction(targetOperatorID)},
		{name: "role: role changed", path: setAccountRoleAction(targetOperatorID),
			form: url.Values{"role": {"viewer"}}, status: 409, sentence: roleChangedRefusal,
			setup:   func(x *writeFix) { x.admin.roleErr = accounts.ErrRoleChanged },
			section: "role", action: setAccountRoleAction(targetOperatorID)},
		{name: "enable: no password", path: setAccountEnabledAction(targetDisabledID),
			form: url.Values{"enabled": {"true"}}, status: 401, sentence: "Step-up re-authentication is required",
			section: "state", action: setAccountEnabledAction(targetDisabledID), noWrite: true},
		{name: "enable: self-targeted", path: setAccountEnabledAction(targetDisabledID),
			form: url.Values{"enabled": {"true"}, "password": {"p"}}, status: 409, sentence: selfTargetRefusal,
			setup:   func(x *writeFix) { x.admin.enableErr = capability.ErrSelfTargeted },
			section: "state", action: setAccountEnabledAction(targetDisabledID)},
		{name: "enabled: unrecognised value", path: setAccountEnabledAction(targetDisabledID),
			form: url.Values{"enabled": {"maybe"}}, status: 400, sentence: "did not say whether to enable or disable",
			section: "state", action: setAccountEnabledAction(targetDisabledID), noWrite: true},
		{name: "mint: no name", path: mintAPITokenAction(targetOperatorID),
			form: url.Values{"ttl": {"30d"}, "password": {"p"}}, status: 400, sentence: "A token needs a name",
			section: "mint", action: mintAPITokenAction(targetOperatorID), noWrite: true},
		{name: "mint: unrecognised lifetime", path: mintAPITokenAction(targetOperatorID),
			form: url.Values{"name": {"ci"}, "ttl": {"bogus"}, "password": {"p"}}, status: 400,
			sentence: "did not carry a recognisable lifetime",
			section:  "mint", action: mintAPITokenAction(targetOperatorID), noWrite: true},
		{name: "mint: no password", path: mintAPITokenAction(targetOperatorID),
			form: url.Values{"name": {"ci"}, "ttl": {"30d"}}, status: 401, sentence: "Step-up re-authentication is required",
			section: "mint", action: mintAPITokenAction(targetOperatorID), noWrite: true},
		{name: "mint: disabled Account", path: mintAPITokenAction(targetOperatorID),
			form: url.Values{"name": {"ci"}, "ttl": {"30d"}, "password": {"p"}}, status: 409,
			sentence: "would not mint a credential for that Account",
			setup:    func(x *writeFix) { x.admin.mintErr = accounts.ErrTokenInvalid },
			section:  "mint", action: mintAPITokenAction(targetOperatorID)},
		{name: "mint: invalid lifetime", path: mintAPITokenAction(targetOperatorID),
			form: url.Values{"name": {"ci"}, "ttl": {"30d"}, "password": {"p"}}, status: 400,
			sentence: accounts.ErrInvalidTTL.Error(),
			setup:    func(x *writeFix) { x.admin.mintErr = accounts.ErrInvalidTTL },
			section:  "mint", action: mintAPITokenAction(targetOperatorID)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newWriteFix(t, nil)
			if tc.setup != nil {
				tc.setup(x)
			}
			rec := x.post(t, tc.path, tc.form)
			body := rec.Body.String()
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.status, contentOf(body))
			}
			if !strings.Contains(body, template.HTMLEscapeString(tc.sentence)) {
				t.Errorf("the refusal does not say %q:\n%s", tc.sentence, contentOf(body))
			}
			if n := strings.Count(body, `class="fielderr"`); n != 1 {
				t.Errorf("the page carries %d refusal banners, want 1:\n%s", n, contentOf(body))
			}
			region := editSectionOf(t, body, tc.section)
			at := strings.Index(region, alert)
			if at < 0 {
				t.Fatalf("the %s section has no alert:\n%s", tc.section, contentOf(body))
			}
			switch tc.section {
			case "mint":
				if submit := strings.Index(region, `type="submit">Mint API Token</button>`); submit < at {
					t.Errorf("the alert (at %d) is not above the Mint button (at %d)", at, submit)
				}
			default:
				if button := strings.Index(region, `<button`); button >= 0 && button < at {
					t.Errorf("the alert (at %d) is below a button (at %d)", at, button)
				}
			}
			if !strings.Contains(body, `<a href="/console/accounts">Back to Accounts</a>`) {
				t.Error("the page has no Back to Accounts")
			}
			if !strings.Contains(body, `action="`+tc.action+`"`) {
				t.Errorf("the page lacks the form for %s", tc.action)
			}
			if got := rec.Header().Get("Retry-After"); got != tc.retryAfter {
				t.Errorf("Retry-After = %q, want %q", got, tc.retryAfter)
			}
			if tc.noWrite && len(x.admin.roles)+len(x.admin.enables)+len(x.admin.mints) != 0 {
				t.Errorf("the capability layer was called for a refusal that precedes it: %+v %+v %+v",
					x.admin.roles, x.admin.enables, x.admin.mints)
			}
		})
	}
}

// editRefusalRoutes are the three routes whose refusals re-render, each posting
// something refused before any capability call.
func editRefusalRoutes() []struct {
	name, path string
	form       url.Values
} {
	return []struct {
		name, path string
		form       url.Values
	}{
		{"role", setAccountRoleAction(targetOperatorID), url.Values{"role": {""}}},
		{"enabled", setAccountEnabledAction(targetDisabledID), url.Values{"enabled": {"maybe"}}},
		{"mint", mintAPITokenAction(targetOperatorID), url.Values{"name": {""}, "ttl": {"30d"}}},
	}
}

func TestAccountsWrite_ARefusedEditRecordsTheAccountPagesTrailRead(t *testing.T) {
	for _, route := range editRefusalRoutes() {
		t.Run(route.name, func(t *testing.T) {
			q := &fakeQueries{}
			x := newWriteFix(t, func(d *Deps) { d.Queries = q })
			rec := x.post(t, route.path, route.form)
			body := rec.Body.String()
			if rec.Code != http.StatusBadRequest || !strings.Contains(body, "<h2>Role</h2>") ||
				!strings.Contains(body, `class="fielderr"`) {
				t.Fatalf("status %d, want the 400 edit view:\n%s", rec.Code, contentOf(body))
			}
			if q.auditCalls != 1 {
				t.Fatalf("the re-render made %d trail reads, want 1", q.auditCalls)
			}
			if !reflect.DeepEqual(q.auditFilters[0].Kinds, agentCallKinds) || q.auditLimits[0] != 1 {
				t.Errorf("the trail read is %+v limit %d, want the Account page's own", q.auditFilters[0], q.auditLimits[0])
			}
		})
	}
}

func TestAccountsWrite_AnEditRefusalWhoseTrailReadFailsKeepsTheResultPage(t *testing.T) {
	for _, route := range editRefusalRoutes() {
		for _, tc := range []struct {
			name   string
			mutate func(*Deps)
		}{
			{"unaudited", func(d *Deps) { d.Queries = &fakeQueries{auditErr: capability.ErrReadUnaudited} }},
			{"store down", func(d *Deps) { d.Queries = &fakeQueries{auditErr: errors.New("trail store down")} }},
			{"no read lane", func(d *Deps) { d.Queries = nil }},
		} {
			t.Run(route.name+"/"+tc.name, func(t *testing.T) {
				x := newWriteFix(t, tc.mutate)
				rec := x.post(t, route.path, route.form)
				body := rec.Body.String()
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want the refusal's own 400:\n%s", rec.Code, contentOf(body))
				}
				for _, absent := range []string{`class="fielderr"`, "<h2>Role</h2>", "rolestate", "<h2>API Tokens</h2>"} {
					if strings.Contains(body, absent) {
						t.Errorf("the result page carries %q, so the Account page was served without its trail read:\n%s",
							absent, contentOf(body))
					}
				}
				if !strings.Contains(body, `class="placeholder"`) {
					t.Errorf("the refusal is not on the plain result page:\n%s", contentOf(body))
				}
			})
		}
	}
}

// failingAccountReader passes the first okReads Account calls through and
// fails every later one, so a test can fail the re-render's read without
// failing the handler's own.
type failingAccountReader struct {
	AccountReader
	okReads, calls int
}

func (f *failingAccountReader) Account(ctx context.Context, p capability.Principal, id string) (accounts.Account, error) {
	f.calls++
	if f.calls > f.okReads {
		return accounts.Account{}, errors.New("account store down")
	}
	return f.AccountReader.Account(ctx, p, id)
}

func TestAccountsWrite_AnEditRefusalTheFormCannotAnswerKeepsTheResultPage(t *testing.T) {
	for _, tc := range []struct {
		name     string
		path     string
		form     url.Values
		setup    func(*writeFix)
		mutate   func(*Deps)
		status   int
		sentence string
	}{
		{name: "session ended", path: setAccountRoleAction(targetViewerID),
			form: url.Values{"role": {"operator"}, "password": {"p"}}, status: 401, sentence: "Your session has ended",
			setup: func(x *writeFix) { x.auth.stepUpErr = consoleauth.ErrNoSession }},
		{name: "capability layer refusal", path: setAccountRoleAction(targetOperatorID),
			form: url.Values{"role": {"viewer"}}, status: 403, sentence: authz.ErrUnauthorized.Error(),
			setup: func(x *writeFix) { x.admin.roleErr = authz.ErrUnauthorized }},
		{name: "could not confirm", path: setAccountRoleAction(targetOperatorID),
			form: url.Values{"role": {"viewer"}}, status: 500, sentence: "could not confirm",
			setup: func(x *writeFix) { x.admin.roleErr = errors.New("audit append") }},
		{name: "could not confirm an enable", path: setAccountEnabledAction(targetDisabledID),
			form: url.Values{"enabled": {"true"}, "password": {"p"}}, status: 500, sentence: "could not confirm",
			setup: func(x *writeFix) { x.admin.enableErr = errors.New("audit append") }},
		{name: "no such Account", path: setAccountRoleAction(targetOperatorID),
			form: url.Values{"role": {"viewer"}}, status: 404, sentence: "appears in this Relay",
			setup: func(x *writeFix) { x.admin.roleErr = accounts.ErrNotFound }},
		{name: "disable made from the list", path: setAccountEnabledAction(targetOperatorID),
			form: url.Values{"enabled": {"false"}, fromField: {fromList}}, status: 409, sentence: lastAdminRefusal,
			setup: func(x *writeFix) { x.admin.enableErr = accounts.ErrLastAdmin }},
		{name: "role: the re-render cannot read the Account", path: setAccountRoleAction(targetOperatorID),
			form: url.Values{"role": {"viewer"}}, status: 409, sentence: roleChangedRefusal,
			setup:  func(x *writeFix) { x.admin.roleErr = accounts.ErrRoleChanged },
			mutate: func(d *Deps) { d.Accounts = &failingAccountReader{AccountReader: d.Accounts, okReads: 1} }},
		{name: "enable: the re-render cannot read the Account", path: setAccountEnabledAction(targetDisabledID),
			form: url.Values{"enabled": {"true"}}, status: 401, sentence: "Step-up re-authentication is required",
			mutate: func(d *Deps) { d.Accounts = &failingAccountReader{AccountReader: d.Accounts} }},
		{name: "mint: the re-render cannot read the Account", path: mintAPITokenAction(targetOperatorID),
			form: url.Values{"ttl": {"30d"}}, status: 400, sentence: "A token needs a name",
			mutate: func(d *Deps) { d.Accounts = &failingAccountReader{AccountReader: d.Accounts} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newWriteFix(t, tc.mutate)
			if tc.setup != nil {
				tc.setup(x)
			}
			rec := x.post(t, tc.path, tc.form)
			body := rec.Body.String()
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.status, contentOf(body))
			}
			if !strings.Contains(body, template.HTMLEscapeString(tc.sentence)) {
				t.Errorf("the refusal does not say %q:\n%s", tc.sentence, contentOf(body))
			}
			if strings.Contains(body, `class="fielderr"`) || strings.Contains(body, "<h2>Role</h2>") {
				t.Errorf("the refusal re-rendered the Account page:\n%s", contentOf(body))
			}
		})
	}
}

func TestAccountsWrite_ARefusedEditAfterStepUpCarriesTheRotatedCSRFToken(t *testing.T) {
	for _, tc := range []struct {
		name     string
		path     string
		form     url.Values
		setup    func(*writeFix)
		required string
	}{
		{"role", setAccountRoleAction(targetViewerID), url.Values{"role": {"operator"}, "password": {"p"}},
			func(x *writeFix) { x.admin.roleErr = accounts.ErrRoleChanged }, "required to raise a role"},
		{"mint", mintAPITokenAction(targetOperatorID), url.Values{"name": {"ci"}, "ttl": {"30d"}, "password": {"p"}},
			func(x *writeFix) { x.admin.mintErr = accounts.ErrInvalidTTL }, "required to mint a token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newWriteFix(t, nil)
			x.auth.stepUpID = consoleauth.ParseSessionID("rotated-id")
			tc.setup(x)
			rec := x.post(t, tc.path, tc.form)
			body := rec.Body.String()
			if !strings.Contains(body, `class="fielderr"`) {
				t.Fatalf("status = %d, want the edit view:\n%s", rec.Code, contentOf(body))
			}
			form := formWithAction(t, body, tc.path)
			want := "fake-csrf-" + x.auth.stepUpID.Reveal()
			if got := renderedCSRFToken(form); got != want || got == x.csrf {
				t.Errorf("the re-rendered form carries %q, want the rotated session's %q (not %q)", got, want, x.csrf)
			}
			if !strings.Contains(form, "optional, you confirmed it recently") {
				t.Errorf("after a successful step-up the password is not drawn as optional:\n%s", form)
			}

			wrong := newWriteFix(t, nil)
			wrong.auth.stepUpErr = consoleauth.ErrBadCredentials
			body = wrong.post(t, tc.path, tc.form).Body.String()
			if form := formWithAction(t, body, tc.path); !strings.Contains(form, tc.required) {
				t.Errorf("after a step-up refusal the password is not drawn as required:\n%s", form)
			}
		})
	}
}

func TestAccountsWrite_ARefusedMintEchoesNameAndLifetimeButNeverThePassword(t *testing.T) {
	const password = "hunter2-do-not-echo"
	mint := func(t *testing.T, id string, form url.Values) string {
		t.Helper()
		x := newWriteFix(t, nil)
		x.admin.mintErr = accounts.ErrInvalidTTL
		form.Set("password", password)
		return formWithAction(t, x.post(t, mintAPITokenAction(id), form).Body.String(), mintAPITokenAction(id))
	}

	form := mint(t, targetOperatorID, url.Values{"name": {"ci-deploy-2"}, "ttl": {"90d"}})
	if !strings.Contains(form, `value="ci-deploy-2"`) {
		t.Errorf("the refused mint does not echo the name:\n%s", form)
	}
	if !strings.Contains(form, `<option value="90d" selected>`) {
		t.Errorf("the refused mint does not reselect the lifetime:\n%s", form)
	}
	if strings.Contains(form, password) {
		t.Error("the refused mint echoes the password")
	}

	long := strings.Repeat("n", maxTokenNameBytes+1)
	if got := mint(t, targetOperatorID, url.Values{"name": {long}, "ttl": {"30d"}}); strings.Contains(got, long) {
		t.Error("an overlong name was echoed")
	}

	// A machine Account's form has no default, so nothing is selected for a
	// lifetime that was not one of its options, and a forgotten lifetime is
	// never defaulted in. "default" is only sendable by a forged or stale form.
	for _, ttl := range []string{"bogus", "default"} {
		got := mint(t, targetOperatorID, url.Values{"name": {"ci"}, "ttl": {ttl}})
		if strings.Contains(got, " selected>") {
			t.Errorf("ttl %q on a machine Account selected a lifetime:\n%s", ttl, got)
		}
	}
}
