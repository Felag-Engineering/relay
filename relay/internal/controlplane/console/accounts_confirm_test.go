package console

// accounts_confirm_test.go covers the confirmation pages for the three acts
// that reduce authority (accounts_confirm.go; issue #1046, design spec 15 D24):
// each danger button GETs a named page that performs nothing and holds the one
// POST form, and a direct POST to the write route is decided exactly as before.

import (
	"go/ast"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
)

// confirmDeps is the Accounts screen's fixture with the write half wired, for
// the bearer-lane handler.
func confirmDeps() Deps {
	d := sweepFixture()
	d.AccountAdmin = &fakeAccountAdmin{}
	d.Auth = &fakeAuth{}
	return d
}

// accountsConfirmGet fetches path as an admin on the bearer lane.
func accountsConfirmGet(t *testing.T, d Deps, path string) *httptest.ResponseRecorder {
	t.Helper()
	return get(t, newTestHandler(d, accounts.RoleAdmin), path)
}

// accountsConfirmBody is the body of a confirmation page that must answer 200.
func accountsConfirmBody(t *testing.T, path string) string {
	t.Helper()
	rec := accountsConfirmGet(t, confirmDeps(), path)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200; body %s", path, rec.Code, contentOf(rec.Body.String()))
	}
	return rec.Body.String()
}

// onlyPostForm returns the single POST form in the page's content. The
// layout's sign-out form is outside <main>, so contentOf excludes it.
func onlyPostForm(t *testing.T, body string) string {
	t.Helper()
	forms := postForms(contentOf(body))
	if len(forms) != 1 {
		t.Fatalf("found %d POST forms in the content, want exactly 1:\n%s", len(forms), contentOf(body))
	}
	return forms[0]
}

var hiddenInput = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

// formFields are the hidden fields a rendered form would submit.
func formFields(form string) url.Values {
	out := url.Values{}
	for _, m := range hiddenInput.FindAllStringSubmatch(form, -1) {
		out.Set(m[1], m[2])
	}
	return out
}

func TestAccountsConfirm_EachDestructiveButtonIsDangerAndOpensItsConfirmationByGet(t *testing.T) {
	body := accountsWriteBody(t, accountPagePath("gleipnir-prod"))
	for _, tc := range []struct{ button, action string }{
		{"Lower role", confirmLowerRoleAction(targetOperatorID)},
		{"Disable", confirmDisableAction(targetOperatorID)},
		{"Revoke", confirmRevokeAction(targetOperatorID, targetLiveToken)},
	} {
		form := formWithAction(t, body, tc.action)
		if !strings.Contains(form, `method="get"`) {
			t.Errorf("%s: the form does not GET its confirmation page:\n%s", tc.button, form)
		}
		if !strings.Contains(form, `<button class="btn danger" type="submit">`+tc.button+`</button>`) {
			t.Errorf("%s: the button is not a danger button:\n%s", tc.button, form)
		}
		for _, banned := range []string{`csrf_token`, `type="password"`} {
			if strings.Contains(form, banned) {
				t.Errorf("%s: a form that performs nothing carries %s:\n%s", tc.button, banned, form)
			}
		}
	}
}

func TestAccountsConfirm_RevokePageNamesTheTokenAndTheConsequence(t *testing.T) {
	body := accountsConfirmBody(t, confirmRevokeAction(targetOperatorID, targetLiveToken))
	content := contentOf(body)
	want := `Revoke token <code>ci-deploy</code>? Anything using it fails immediately; this cannot be undone.`
	if !strings.Contains(content, want) {
		t.Errorf("the page does not say %q:\n%s", want, content)
	}
	form := onlyPostForm(t, body)
	if !strings.Contains(form, `action="`+revokeAPITokenAction(targetLiveToken)+`"`) {
		t.Errorf("the form does not post to the revoke route:\n%s", form)
	}
	if !strings.Contains(form, `name="csrf_token"`) || !strings.Contains(form, `class="btn danger"`) {
		t.Errorf("the form lacks its CSRF token or the danger button:\n%s", form)
	}
	if strings.Contains(form, `type="password"`) {
		t.Errorf("revocation takes no password:\n%s", form)
	}
	if !strings.Contains(content, `<a href="`+accountPagePath("gleipnir-prod")+`">Back to gleipnir-prod</a>`) {
		t.Errorf("no plain link back:\n%s", content)
	}
}

func TestAccountsConfirm_DisablePageNamesTheAccountAndTheConsequence(t *testing.T) {
	body := accountsConfirmBody(t, confirmDisableAction(targetViewerID))
	content := contentOf(body)
	want := `Disable <code>ana</code>? It can no longer sign in or call the Relay; re-enabling takes a password.`
	if !strings.Contains(content, want) {
		t.Errorf("the page does not say %q:\n%s", want, content)
	}
	form := onlyPostForm(t, body)
	if !strings.Contains(form, `action="`+setAccountEnabledAction(targetViewerID)+`"`) {
		t.Errorf("the form does not post to the enabled route:\n%s", form)
	}
	if f := formFields(form); f.Get("enabled") != "false" || !strings.Contains(form, `name="csrf_token"`) {
		t.Errorf("the form does not submit enabled=false with a token: %v", f)
	}
	if strings.Contains(form, `type="password"`) {
		t.Errorf("disabling takes no password:\n%s", form)
	}
	if !strings.Contains(content, `<a href="`+accountPagePath("ana")+`">Back to ana</a>`) {
		t.Errorf("no plain link back:\n%s", content)
	}
}

func TestAccountsConfirm_LowerPageNamesFromToAndTheConsequence(t *testing.T) {
	body := accountsConfirmBody(t, confirmLowerRoleAction(targetAdminID)+"?role=operator")
	content := contentOf(body)
	want := `Lower <code>mike</code> from <code>admin</code> to <code>operator</code>? ` +
		`Its API Tokens carry the lower role from their next request.`
	if !strings.Contains(content, want) {
		t.Errorf("the page does not say %q:\n%s", want, content)
	}
	form := onlyPostForm(t, body)
	if !strings.Contains(form, `action="`+setAccountRoleAction(targetAdminID)+`"`) {
		t.Errorf("the form does not post to the role route:\n%s", form)
	}
	if f := formFields(form); f.Get("role") != "operator" || !strings.Contains(form, `name="csrf_token"`) {
		t.Errorf("the form does not submit role=operator with a token: %v", f)
	}
	if strings.Contains(form, `type="password"`) {
		t.Errorf("lowering takes no password:\n%s", form)
	}
	if !strings.Contains(content, `<a href="`+accountPagePath("mike")+`">Back to mike</a>`) {
		t.Errorf("no plain link back:\n%s", content)
	}
}

func TestAccountsConfirm_PressingTheButtonPerformsNothing(t *testing.T) {
	x := newWriteFix(t, nil)
	for _, path := range []string{
		confirmDisableAction(targetViewerID),
		confirmDisableAction(targetDisabledID),
		confirmLowerRoleAction(targetOperatorID) + "?role=viewer",
		confirmLowerRoleAction(targetOperatorID),
		confirmLowerRoleAction(targetOperatorID) + "?role=admin",
		confirmRevokeAction(targetOperatorID, targetLiveToken),
		confirmRevokeAction(targetOperatorID, "tok-revoked"),
		confirmRevokeAction(targetOperatorID, "tok-nope"),
	} {
		x.get(t, path)
	}
	a := x.admin
	if n := len(a.creates) + len(a.roles) + len(a.enables) + len(a.mints) + len(a.revokes); n != 0 {
		t.Errorf("the confirmation pages called the capability seam %d times", n)
	}
	if got := len(x.auth.stepUpCalls); got != 0 {
		t.Errorf("StepUp was called %d times by a confirmation page", got)
	}
	if x.auth.requireCalls != 0 {
		t.Errorf("the step-up window was consulted %d times by a confirmation page", x.auth.requireCalls)
	}
}

func TestAccountsConfirm_LowerWithNoRoleIsRefusedInTheHintsWords(t *testing.T) {
	d := confirmDeps()
	for _, tc := range []struct {
		name, path, sentence string
		notEchoed            string
		status               int
	}{
		{"no role", confirmLowerRoleAction(targetAdminID), noRoleRefusal, "", http.StatusBadRequest},
		{"unchanged", confirmLowerRoleAction(targetAdminID) + "?role=admin",
			"That is already this Account's role.", "", http.StatusBadRequest},
		{"a raise", confirmLowerRoleAction(targetOperatorID) + "?role=admin",
			"admin is not below this Account's role", "", http.StatusBadRequest},
		{"not a role", confirmLowerRoleAction(targetAdminID) + "?role=bogus",
			"This form did not carry a recognisable role.", "bogus", http.StatusBadRequest},
	} {
		rec := accountsConfirmGet(t, d, tc.path)
		body := rec.Body.String()
		if rec.Code != tc.status {
			t.Errorf("%s: status = %d, want %d", tc.name, rec.Code, tc.status)
		}
		if !strings.Contains(body, template.HTMLEscapeString(tc.sentence)) {
			t.Errorf("%s: the page does not say %q:\n%s", tc.name, tc.sentence, contentOf(body))
		}
		if tc.notEchoed != "" && strings.Contains(body, tc.notEchoed) {
			t.Errorf("%s: the page echoes the unrecognised value %q", tc.name, tc.notEchoed)
		}
		if forms := postForms(contentOf(body)); len(forms) != 0 {
			t.Errorf("%s: a refusal offers a POST form:\n%s", tc.name, contentOf(body))
		}
	}
	if !strings.Contains(noRoleRefusal, lowerRoleHint) {
		t.Errorf("the no-role refusal %q does not carry the hint %q", noRoleRefusal, lowerRoleHint)
	}
}

func TestAccountsConfirm_PagesOfferNoFormWhereTheScreenDrawsNoButton(t *testing.T) {
	d := confirmDeps()
	fa := sweepAccounts()
	self := testAccountID(accounts.RoleAdmin)
	fa.accounts = append(fa.accounts, accounts.Account{
		ID: self, Name: testAccountName(accounts.RoleAdmin),
		Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true,
	})
	d.Accounts = fa

	for _, tc := range []struct {
		name, path, sentence string
		back                 string // the link's label: the Account page's name, or the list
		status               int
	}{
		{"self disable", confirmDisableAction(self), selfTargetRefusal, "Back to " + testAccountName(accounts.RoleAdmin), http.StatusConflict},
		{"self lower", confirmLowerRoleAction(self) + "?role=operator", selfTargetRefusal, "Back to " + testAccountName(accounts.RoleAdmin), http.StatusConflict},
		{"already disabled", confirmDisableAction(targetDisabledID), "is already disabled", "Back to retired-ci", http.StatusConflict},
		{"already revoked", confirmRevokeAction(targetOperatorID, "tok-revoked"), "is already revoked", "Back to gleipnir-prod", http.StatusConflict},
		{"token on another Account", confirmRevokeAction(targetAdminID, targetLiveToken),
			"No API Token matching", "Back to mike", http.StatusNotFound},
		{"unknown Account", confirmDisableAction("acct-nope"), "No Account matching", "Back to Accounts", http.StatusNotFound},
	} {
		rec := accountsConfirmGet(t, d, tc.path)
		content := contentOf(rec.Body.String())
		if rec.Code != tc.status {
			t.Errorf("%s: status = %d, want %d", tc.name, rec.Code, tc.status)
		}
		if !strings.Contains(content, template.HTMLEscapeString(tc.sentence)) {
			t.Errorf("%s: the page does not say %q:\n%s", tc.name, tc.sentence, content)
		}
		if strings.Contains(content, "<form") {
			t.Errorf("%s: a refusal offers a form:\n%s", tc.name, content)
		}
		if !strings.Contains(content, tc.back+".") {
			t.Errorf("%s: no link back:\n%s", tc.name, content)
		}
	}
}

// confirmedAct is one of the three acts, driven both ways.
type confirmedAct struct {
	name     string
	page     string
	post     string
	form     url.Values
	count    func(*fakeAccountAdmin) int
	failWith func(*fakeAccountAdmin, error)
}

func confirmedActs() []confirmedAct {
	return []confirmedAct{
		{
			name: "disable", page: confirmDisableAction(targetViewerID), post: setAccountEnabledAction(targetViewerID),
			form:     url.Values{"enabled": {"false"}},
			count:    func(a *fakeAccountAdmin) int { return len(a.enables) },
			failWith: func(a *fakeAccountAdmin, err error) { a.enableErr = err },
		},
		{
			name: "lower", page: confirmLowerRoleAction(targetOperatorID) + "?role=viewer", post: setAccountRoleAction(targetOperatorID),
			form:     url.Values{"role": {"viewer"}},
			count:    func(a *fakeAccountAdmin) int { return len(a.roles) },
			failWith: func(a *fakeAccountAdmin, err error) { a.roleErr = err },
		},
		{
			name: "revoke", page: confirmRevokeAction(targetOperatorID, targetLiveToken), post: revokeAPITokenAction(targetLiveToken),
			form:     url.Values{},
			count:    func(a *fakeAccountAdmin) int { return len(a.revokes) },
			failWith: func(a *fakeAccountAdmin, err error) { a.revokeErr = err },
		},
	}
}

func TestAccountsConfirm_ThePageFormPostsWithTheSessionTokenAndTheWriteProceeds(t *testing.T) {
	for _, act := range confirmedActs() {
		t.Run(act.name, func(t *testing.T) {
			x := newWriteFix(t, nil)
			rec := x.get(t, act.page)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s = %d; body %s", act.page, rec.Code, contentOf(rec.Body.String()))
			}
			form := onlyPostForm(t, rec.Body.String())
			m := renderedCSRFTokenPattern.FindStringSubmatch(form)
			if m == nil || m[1] != x.csrf {
				t.Fatalf("the form's CSRF token is %v, want the session's", m)
			}
			// x.post adds the session token itself, so what is submitted is
			// the form's own fields plus the token it carries.
			fields := formFields(form)
			fields.Del("csrf_token")
			if post := x.post(t, act.post, fields); post.Code != http.StatusSeeOther {
				t.Fatalf("POST %s = %d, want 303; body %s", act.post, post.Code, contentOf(post.Body.String()))
			}
			if got := act.count(x.admin); got != 1 {
				t.Errorf("the capability seam was called %d times, want 1", got)
			}
			if len(x.auth.stepUpCalls) != 0 || x.auth.requireCalls != 0 {
				t.Errorf("step-up was consulted: %d calls, %d requires", len(x.auth.stepUpCalls), x.auth.requireCalls)
			}
		})
	}
}

func TestAccountsConfirm_ADirectPostWithoutThePageStillWorksAndStillNeedsCSRF(t *testing.T) {
	for _, act := range confirmedActs() {
		t.Run(act.name, func(t *testing.T) {
			x := newWriteFix(t, nil)
			if rec := x.post(t, act.post, act.form); rec.Code != http.StatusSeeOther {
				t.Fatalf("POST with a valid token = %d, want 303", rec.Code)
			}
			if got := act.count(x.admin); got != 1 {
				t.Fatalf("the capability seam was called %d times, want 1", got)
			}

			for name, token := range map[string]string{"no token": "", "wrong token": "not-this-session-s-token"} {
				body := url.Values{}
				for k, vs := range act.form {
					body[k] = vs
				}
				if token != "" {
					body.Set("csrf_token", token)
				}
				req := httptest.NewRequest(http.MethodPost, act.post, strings.NewReader(body.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if rec := x.f.do(t, req, x.session); rec.Code != http.StatusForbidden {
					t.Errorf("%s: POST = %d, want 403", name, rec.Code)
				}
			}
			if got := act.count(x.admin); got != 1 {
				t.Errorf("a refused POST reached the capability seam: %d calls", got)
			}
		})
	}
}

func TestAccountsConfirm_ACapabilityRefusalIsRenderedTheSameWithOrWithoutThePage(t *testing.T) {
	refusals := map[string]error{
		"disable": accounts.ErrLastAdmin,
		"lower":   accounts.ErrLastAdmin,
		"revoke":  authz.ErrUnauthorized,
	}
	for _, act := range confirmedActs() {
		t.Run(act.name, func(t *testing.T) {
			x := newWriteFix(t, nil)
			act.failWith(x.admin, refusals[act.name])

			direct := x.post(t, act.post, act.form)
			fields := formFields(onlyPostForm(t, x.get(t, act.page).Body.String()))
			fields.Del("csrf_token")
			viaPage := x.post(t, act.post, fields)

			if direct.Code == http.StatusSeeOther {
				t.Fatalf("the fake's refusal did not take effect: %d", direct.Code)
			}
			if viaPage.Code != direct.Code || contentOf(viaPage.Body.String()) != contentOf(direct.Body.String()) {
				t.Errorf("the page changed the refusal: direct %d, via page %d\n%s\n---\n%s",
					direct.Code, viaPage.Code, contentOf(direct.Body.String()), contentOf(viaPage.Body.String()))
			}
		})
	}
}

func TestAccountsConfirm_ConfirmationRoutesAreAbsentBelowAdmin(t *testing.T) {
	d := confirmDeps()
	for _, role := range []accounts.Role{accounts.RoleViewer, accounts.RoleOperator} {
		h := newTestHandler(d, role)
		miss := get(t, h, "/console/no-such-route")
		missOptions := request(t, h, http.MethodOptions, "/console/no-such-route")
		for _, path := range []string{
			confirmDisableAction(targetViewerID),
			confirmLowerRoleAction(targetAdminID) + "?role=operator",
			confirmRevokeAction(targetOperatorID, targetLiveToken),
		} {
			rec := get(t, h, path)
			if rec.Code != http.StatusNotFound || rec.Body.String() != miss.Body.String() {
				t.Errorf("role %s: GET %s = %d, want the byte-identical 404 of an unmounted path", role, path, rec.Code)
			}
			opt := request(t, h, http.MethodOptions, path)
			if opt.Code != http.StatusNotFound || opt.Body.String() != missOptions.Body.String() {
				t.Errorf("role %s: OPTIONS %s = %d, want the byte-identical 404 of an unmounted path", role, path, opt.Code)
			}
		}
	}
}

func TestAccountsConfirm_NoScriptNoConfirmNoInlineStyle(t *testing.T) {
	for _, path := range []string{
		confirmDisableAction(targetViewerID),
		confirmLowerRoleAction(targetAdminID) + "?role=operator",
		confirmRevokeAction(targetOperatorID, targetLiveToken),
	} {
		body := accountsConfirmBody(t, path)
		assertNoInlineScript(t, path, body)
		assertCSPClean(t, path, body)
		if strings.Contains(body, "confirm(") {
			t.Errorf("%s calls confirm(); the confirmation is a page", path)
		}
		if strings.Contains(strings.ToLower(contentOf(body)), " style=") {
			t.Errorf("%s carries an inline style attribute", path)
		}
	}
}

// TestAccountsConfirm_NoCallerRoleComparisonLivesInTheConfirmationPages holds
// accounts_confirm.go to the rules the write half is held to: it interprets no
// caller role (invariant 10), and it never reads an Account's kind, which the
// registryKindFiles allowlist would otherwise admit.
func TestAccountsConfirm_NoCallerRoleComparisonLivesInTheConfirmationPages(t *testing.T) {
	code := guardedFileCode(t, accountsConfirmFile)
	for _, banned := range callerRoleSpellings {
		if strings.Contains(code, banned) {
			t.Errorf("%s reads or re-derives the CALLER's authority (%s) — a confirmation page "+
				"interprets no caller role (invariant 10)", accountsConfirmFile, banned)
		}
	}
	if got := strings.Count(code, ".AtLeast("); got != 0 {
		t.Errorf("%s calls AtLeast %d times, want 0; roleTargets carries the one comparison", accountsConfirmFile, got)
	}

	_, file := parseGuardedFile(t, accountsConfirmFile)
	if !callerAuthorityProducers["confirmPrelude"] {
		t.Error("confirmPrelude is not a registered caller-authority producer, so a handler could " +
			"rename its results and read the caller's role unseen")
	}
	// The handlers take (d Deps) and reach the caller only through
	// confirmPrelude, so the name appearing in their scope is the producer
	// being recognised.
	handlers := map[string]bool{
		"handleConfirmDisable": false, "handleConfirmLowerRole": false, "handleConfirmRevokeAPIToken": false,
	}
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if _, isHandler := handlers[fd.Name.Name]; !isHandler {
			continue
		}
		handlers[fd.Name.Name] = true
		idents := callerAuthorityIdents(fd)
		for _, want := range []string{"caller", "pg"} {
			if !idents[want] {
				t.Errorf("%s: %q is not a known caller-authority identifier in scope", fd.Name.Name, want)
			}
		}
	}
	for name, seen := range handlers {
		if !seen {
			t.Errorf("%s is not declared in %s — the guard is inspecting nothing", name, accountsConfirmFile)
		}
	}
	for _, ident := range callerAuthorityReads(file) {
		t.Errorf("%s reads %s.Role, the caller's authority", accountsConfirmFile, ident)
	}
	if got := len(atLeastCallSites(file)); got != 0 {
		t.Errorf("%s has %d AtLeast call sites, want 0", accountsConfirmFile, got)
	}

	ast.Inspect(file, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Kind" {
			t.Errorf("%s reads a .Kind; the confirmation pages never read an Account's registry kind", accountsConfirmFile)
		}
		return true
	})
}
