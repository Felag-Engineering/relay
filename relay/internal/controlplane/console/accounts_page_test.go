package console

// accounts_page_test.go covers the Account page, the New account page, the
// list's row actions and where a successful act returns to.

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

// absentBelowAdmin fails unless method path answers, for role, byte-for-byte
// what an unmounted path answers. CSRF is skipped so the comparison is against
// the mux's own 404 and not Secure's CSRF refusal.
func absentBelowAdmin(t *testing.T, role accounts.Role, method, path string) {
	t.Helper()
	d := sweepFixture()
	d.AccountAdmin = &fakeAccountAdmin{}
	d.Auth = &fakeAuth{}
	h := newTestHandlerSkippingCSRF(d, role)

	do := func(p string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, p, strings.NewReader(createForm("newbie", "p").Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+testCredential)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	got, unmounted := do(path), do("/console/no-such-route")
	if got.Code != http.StatusNotFound {
		t.Errorf("role %s: %s %s = %d, want 404", role, method, path, got.Code)
		return
	}
	if got.Body.String() != unmounted.Body.String() {
		t.Errorf("role %s: %s %s differs from an unmounted path — the difference is the oracle", role, method, path)
	}
}

func TestAccounts_TheNewPathsAreAdminOnlyAndAbsentBelow(t *testing.T) {
	for _, role := range []accounts.Role{accounts.RoleViewer, accounts.RoleOperator} {
		for _, c := range []struct{ method, path string }{
			{http.MethodGet, accountPagePath("gleipnir-prod")},
			{http.MethodOptions, accountPagePath("gleipnir-prod")},
			{http.MethodGet, newAccountPath},
			{http.MethodOptions, newAccountPath},
			{http.MethodPost, createAccountAction()},
			{http.MethodOptions, createAccountAction()},
		} {
			absentBelowAdmin(t, role, c.method, c.path)
		}
	}

	h := newTestHandler(accountsFixture(), accounts.RoleAdmin)
	for _, path := range []string{accountPagePath("gleipnir-prod"), newAccountPath} {
		if got := get(t, h, path).Code; got != http.StatusOK {
			t.Errorf("GET %s as an admin = %d, want 200", path, got)
		}
	}
}

// The old create path is the Account page's method-less twin. The exact Allow
// string is net/http's own formatting for a GET route.
func TestAccounts_TheOldCreatePathIsTheAccountPagesTwin(t *testing.T) {
	const oldCreate = "/console/accounts/create"

	x := newWriteFix(t, nil)
	rec := x.post(t, oldCreate, createForm("newbie", "p"))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("an admin's POST %s = %d, want 405; body %s", oldCreate, rec.Code, contentOf(rec.Body.String()))
	}
	if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
		t.Errorf("Allow = %q, want %q", got, "GET, HEAD")
	}
	if n := len(x.admin.creates); n != 0 {
		t.Errorf("the old create path reached CreateAccount %d times", n)
	}

	for _, role := range []accounts.Role{accounts.RoleViewer, accounts.RoleOperator} {
		absentBelowAdmin(t, role, http.MethodPost, oldCreate)
	}
}

func TestAccounts_AnAccountNamedNewOrCreateHasItsPage(t *testing.T) {
	d := accountsFixture()
	fa := sweepAccounts()
	for _, name := range []string{"new", "create"} {
		fa.accounts = append(fa.accounts, accounts.Account{
			ID: "acct-" + name, Name: name, Kind: accounts.KindHuman, Role: accounts.RoleViewer, Enabled: true,
		})
	}
	d.Accounts = fa
	Register(http.NewServeMux(), d) // panics on a route conflict

	h := newTestHandler(d, accounts.RoleAdmin)
	for _, name := range []string{"new", "create"} {
		rec := get(t, h, accountPagePath(name))
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", accountPagePath(name), rec.Code)
			continue
		}
		if got := topbarHeading(rec.Body.String()); got != name {
			t.Errorf("the page for %q is headed %q", name, got)
		}
	}
}

// Lookup is exact: a different case is a different (absent) Account.
func TestAccounts_TheAccountLookupIsCaseExact(t *testing.T) {
	h := newTestHandler(accountsFixture(), accounts.RoleAdmin)
	if got := get(t, h, accountPagePath("Gleipnir-Prod")).Code; got != http.StatusNotFound {
		t.Errorf("a differently cased name = %d, want 404", got)
	}
}

func TestAccounts_AMissingOrOverlongNameIsOne404(t *testing.T) {
	h := newTestHandler(accountsFixture(), accounts.RoleAdmin)

	missing := get(t, h, accountPagePath("nobody"))
	long := strings.Repeat("n", maxAccountNameBytes+1)
	overlong := get(t, h, accountPagePath(long))
	for name, rec := range map[string]*httptest.ResponseRecorder{"missing": missing, "overlong": overlong} {
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", name, rec.Code)
		}
		if !strings.Contains(contentOf(rec.Body.String()), `<a href="/console/accounts">Back to Accounts</a>`) {
			t.Errorf("%s: not the account-missing page:\n%s", name, contentOf(rec.Body.String()))
		}
	}
	if !strings.Contains(missing.Body.String(), "<code>nobody</code>") {
		t.Error("the missing page does not name the Account asked for")
	}
	if strings.Contains(overlong.Body.String(), long) {
		t.Error("an overlong name is echoed")
	}
}

var (
	topbarH1 = regexp.MustCompile(`(?s)<header class="topbar"><h1>(.*?)</h1>`)
	h2Tag    = regexp.MustCompile(`(?s)<h2>(.*?)</h2>`)
)

func topbarHeading(body string) string {
	m := topbarH1.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return html.UnescapeString(m[1])
}

func TestAccounts_TheAccountNameIsTheOnlyHeadingCarryingIt(t *testing.T) {
	body := get(t, newTestHandler(accountsFixture(), accounts.RoleAdmin), accountPagePath("gleipnir-prod")).Body.String()
	if got := topbarHeading(body); got != "gleipnir-prod" {
		t.Errorf("the topbar heading is %q, want the Account's name", got)
	}
	var h2s []string
	for _, m := range h2Tag.FindAllStringSubmatch(contentOf(body), -1) {
		h2s = append(h2s, m[1])
	}
	if want := []string{"Role", "State", "API Tokens"}; !reflect.DeepEqual(h2s, want) {
		t.Errorf("the page's h2 headings are %v, want %v", h2s, want)
	}
}

var formActionPattern = regexp.MustCompile(`<form\b[^>]*\baction="([^"]+)"`)

func TestAccounts_EveryFormOnTheAccountPagePostsByID(t *testing.T) {
	const name, id = "gleipnir-prod", targetOperatorID
	body := accountsWriteBody(t, accountPagePath(name))
	content := contentOf(body)

	allowed := map[string]bool{
		setAccountRoleAction(id):                 true,
		confirmLowerRoleAction(id):               true,
		setAccountEnabledAction(id):              true,
		confirmDisableAction(id):                 true,
		mintAPITokenAction(id):                   true,
		confirmRevokeAction(id, targetLiveToken): true,
	}
	seen := 0
	for _, m := range formActionPattern.FindAllStringSubmatch(content, -1) {
		seen++
		action := html.UnescapeString(m[1])
		if !allowed[action] {
			t.Errorf("the Account page has a form posting to %s, which is not an ID-addressed Account route", action)
		}
		if strings.Contains(action, name) {
			t.Errorf("the form action %s carries the Account's name", action)
		}
	}
	if seen < 4 {
		t.Fatalf("found %d forms, want the role, state and token forms", seen)
	}
	for _, form := range formsWithMethod(content, "post") {
		if !strings.Contains(form, `name="csrf_token"`) {
			t.Errorf("a POST form carries no CSRF field:\n%s", form)
		}
	}
}

func TestAccounts_TheRowActionsFollowStateAndSelf(t *testing.T) {
	d := accountsFixture()
	d.AccountAdmin = &fakeAccountAdmin{}
	d.Auth = &fakeAuth{}
	fa := sweepAccounts()
	self := testAccountID(accounts.RoleAdmin)
	fa.accounts = append(fa.accounts, accounts.Account{
		ID: self, Name: testAccountName(accounts.RoleAdmin),
		Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true,
	})
	d.Accounts = fa
	body := get(t, newTestHandler(d, accounts.RoleAdmin), accountsPath).Body.String()

	edit := func(name string) string { return `href="` + accountPagePath(name) + `"` }

	enabled := rowFor(t, body, "ana")
	if !strings.Contains(enabled, edit("ana")) {
		t.Errorf("an enabled row has no Edit:\n%s", enabled)
	}
	form := formWithAction(t, enabled, confirmDisableAction(targetViewerID))
	if !strings.Contains(form, `method="get"`) || !strings.Contains(form, `name="from" value="list"`) ||
		strings.Contains(form, `type="password"`) {
		t.Errorf("an enabled row's Disable is not a passwordless GET carrying from=list:\n%s", form)
	}

	disabled := rowFor(t, body, "retired-ci")
	if !strings.Contains(disabled, edit("retired-ci")) {
		t.Errorf("a disabled row has no Edit:\n%s", disabled)
	}
	if !strings.Contains(disabled, `href="`+accountPagePath("retired-ci")+`#state"`) {
		t.Errorf("a disabled row's Enable does not link to the Account page's state section:\n%s", disabled)
	}
	if strings.Contains(disabled, "<form") || strings.Contains(disabled, "Disable") {
		t.Errorf("a disabled row carries a form or a Disable:\n%s", disabled)
	}

	own := rowFor(t, contentOf(body), testAccountName(accounts.RoleAdmin))
	if !strings.Contains(own, edit(testAccountName(accounts.RoleAdmin))) {
		t.Errorf("the signed-in Account's row has no Edit:\n%s", own)
	}
	if strings.Contains(own, "Disable") || strings.Contains(own, "<form") {
		t.Errorf("the signed-in Account's row offers Disable:\n%s", own)
	}

	if posts := formsWithMethod(contentOf(body), "post"); len(posts) != 0 {
		t.Errorf("the list carries %d POST forms", len(posts))
	}
}

func TestAccounts_ASelfAccountPageStatesWhyInPlaceOfControls(t *testing.T) {
	d := accountsFixture()
	d.AccountAdmin = &fakeAccountAdmin{}
	d.Auth = &fakeAuth{}
	fa := sweepAccounts()
	self := testAccountID(accounts.RoleAdmin)
	fa.accounts = append(fa.accounts, accounts.Account{
		ID: self, Name: testAccountName(accounts.RoleAdmin),
		Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true,
	})
	d.Accounts = fa
	body := get(t, newTestHandler(d, accounts.RoleAdmin), accountPagePath(testAccountName(accounts.RoleAdmin))).Body.String()
	content := contentOf(body)

	for _, want := range []string{"Role <b>admin</b>.", "enabled.", html.EscapeString(selfPanelNote)} {
		if !strings.Contains(content, want) {
			t.Errorf("the self page lacks %q:\n%s", want, content)
		}
	}
	if n := strings.Count(content, html.EscapeString(selfPanelNote)); n != 1 {
		t.Errorf("the self note renders %d times, want once", n)
	}
	for _, action := range []string{
		setAccountRoleAction(self), confirmLowerRoleAction(self),
		setAccountEnabledAction(self), confirmDisableAction(self),
	} {
		if strings.Contains(content, `action="`+action+`"`) {
			t.Errorf("the self page offers a form to %s", action)
		}
	}
	if !strings.Contains(content, `action="`+mintAPITokenAction(self)+`"`) {
		t.Error("the self page lost its mint form")
	}
}

func TestAccounts_TheRolePanelDrawsEveryRolesDescription(t *testing.T) {
	body := accountsWriteBody(t, newAccountPath)
	content := contentOf(body)

	for _, r := range allRoleNames() {
		want := "<dt>" + r + "</dt><dd>" + html.EscapeString(accounts.Role(r).Description()) + "</dd>"
		if !strings.Contains(content, want) {
			t.Errorf("the role panel lacks %q:\n%s", want, content)
		}
	}
	if !strings.Contains(content, `<fieldset class="fld" aria-describedby="role-descriptions">`) ||
		!strings.Contains(content, `id="role-descriptions"`) {
		t.Error("the role fieldset is not described by the role panel")
	}
	if regexp.MustCompile(`name="role"[^>]*\bchecked`).MatchString(content) {
		t.Error("a plain GET checks a role radio; a role must be chosen, never defaulted")
	}
	if regexp.MustCompile(`name="kind"[^>]*\bchecked`).MatchString(content) {
		t.Error("a plain GET checks a kind radio")
	}
}

// A role description is drawn from a plain string field, so no template can
// call Description on a typed role where the module-wide guard in
// internal/accounts cannot see it.
func TestAccounts_NoViewModelCarriesATypedRole(t *testing.T) {
	roleType := reflect.TypeOf(accounts.Role(""))
	seen := map[reflect.Type]bool{}
	var walk func(path string, typ reflect.Type)
	walk = func(path string, typ reflect.Type) {
		if typ == roleType {
			t.Errorf("%s is an accounts.Role; view models carry roles as strings", path)
			return
		}
		switch typ.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(path, typ.Elem())
		case reflect.Struct:
			if seen[typ] {
				return
			}
			seen[typ] = true
			for i := 0; i < typ.NumField(); i++ {
				walk(path+"."+typ.Field(i).Name, typ.Field(i).Type)
			}
		}
	}
	for _, v := range []any{
		accountsView{}, accountRow{}, accountPageView{}, accountCreateForm{},
		accountChange{}, roleLine{}, tokenRow{}, accountConfirmView{},
	} {
		walk(reflect.TypeOf(v).Name(), reflect.TypeOf(v))
	}
}

// ---------------------------------------------------------------------------
// Where a successful act returns to.
// ---------------------------------------------------------------------------

func TestAccountsWrite_ASuccessfulActReturnsWhereItWasMade(t *testing.T) {
	list := func(key doneKey) string { return "/console/accounts?done=" + string(key) }
	page := func(name string, key doneKey) string { return accountPagePath(name) + "?done=" + string(key) }

	for _, tc := range []struct {
		name string
		path string
		form url.Values
		want string
	}{
		// A machine Account's create redirects as before; a human's reveals a
		// temporary password and is covered by TestAccountsWrite_ACreateOfAHuman....
		{"create a machine Account", createAccountAction(), url.Values{"name": {"ci-bot"}, "kind": {"machine"}, "role": {"viewer"}, "password": {"p"}}, list(doneCreated)},
		{"raise", setAccountRoleAction(targetViewerID), url.Values{"role": {"operator"}, "password": {"p"}}, page("ana", doneRole)},
		{"lower", setAccountRoleAction(targetOperatorID), url.Values{"role": {"viewer"}}, page("gleipnir-prod", doneRole)},
		{"enable", setAccountEnabledAction(targetDisabledID), url.Values{"enabled": {"true"}, "password": {"p"}}, page("retired-ci", doneEnabled)},
		{"disable", setAccountEnabledAction(targetViewerID), url.Values{"enabled": {"false"}}, page("ana", doneDisabled)},
		{"disable from the list", setAccountEnabledAction(targetViewerID), url.Values{"enabled": {"false"}, "from": {"list"}}, list(doneDisabled)},
		{"disable from another value", setAccountEnabledAction(targetViewerID), url.Values{"enabled": {"false"}, "from": {"page"}}, page("ana", doneDisabled)},
		{"disable from a URL", setAccountEnabledAction(targetViewerID), url.Values{"enabled": {"false"}, "from": {"https://evil.example/"}}, page("ana", doneDisabled)},
		{"disable from a protocol-relative URL", setAccountEnabledAction(targetViewerID), url.Values{"enabled": {"false"}, "from": {"//evil.example"}}, page("ana", doneDisabled)},
		// from in the query string is not the body, and is ignored.
		{"disable with from only in the query", setAccountEnabledAction(targetViewerID) + "?from=list", url.Values{"enabled": {"false"}}, page("ana", doneDisabled)},
		{"revoke", revokeAPITokenAction(targetLiveToken), url.Values{"account": {targetOperatorID}}, page("gleipnir-prod", doneRevoked)},
		{"revoke with no account", revokeAPITokenAction(targetLiveToken), url.Values{}, list(doneRevoked)},
		{"revoke naming an Account the token is not on", revokeAPITokenAction(targetLiveToken), url.Values{"account": {targetAdminID}}, list(doneRevoked)},
		{"revoke naming an overlong Account", revokeAPITokenAction(targetLiveToken), url.Values{"account": {strings.Repeat("a", maxAccountIDBytes+1)}}, list(doneRevoked)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newWriteFix(t, nil)
			rec := x.post(t, tc.path, tc.form)
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303; body %s", rec.Code, contentOf(rec.Body.String()))
			}
			loc := rec.Header().Get("Location")
			if loc != tc.want {
				t.Errorf("Location = %q, want %q", loc, tc.want)
			}
			if !strings.HasPrefix(loc, "/console/accounts") || strings.HasPrefix(loc, "//") {
				t.Errorf("Location %q leaves the Accounts screens", loc)
			}
		})
	}
}

// A failed read after the write costs the destination and never the act.
func TestAccountsWrite_AFailedReadAfterTheWriteFallsBackToTheList(t *testing.T) {
	list := func(key doneKey) string { return "/console/accounts?done=" + string(key) }
	for _, tc := range []struct {
		name  string
		path  string
		form  url.Values
		want  string
		wrote func(*fakeAccountAdmin) int
	}{
		{"enable", setAccountEnabledAction(targetDisabledID), url.Values{"enabled": {"true"}, "password": {"p"}},
			list(doneEnabled), func(a *fakeAccountAdmin) int { return len(a.enables) }},
		{"disable", setAccountEnabledAction(targetViewerID), url.Values{"enabled": {"false"}},
			list(doneDisabled), func(a *fakeAccountAdmin) int { return len(a.enables) }},
		{"revoke", revokeAPITokenAction(targetLiveToken), url.Values{"account": {targetOperatorID}},
			list(doneRevoked), func(a *fakeAccountAdmin) int { return len(a.revokes) }},
		{"lower", setAccountRoleAction(targetOperatorID), url.Values{"role": {"viewer"}, "password": {"p"}},
			list(doneRole), func(a *fakeAccountAdmin) int { return len(a.roles) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newWriteFix(t, func(d *Deps) {
				fa := sweepAccounts()
				fa.accountErr = errQueryFailed
				d.Accounts = fa
			})
			rec := x.post(t, tc.path, tc.form)
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303; body %s", rec.Code, contentOf(rec.Body.String()))
			}
			if loc := rec.Header().Get("Location"); loc != tc.want {
				t.Errorf("Location = %q, want %q", loc, tc.want)
			}
			if n := tc.wrote(x.admin); n != 1 {
				t.Errorf("the write happened %d times, want exactly once", n)
			}
		})
	}
}

func TestAccounts_TheConfirmationCarriesItsOriginForward(t *testing.T) {
	x := newWriteFix(t, nil)

	fromList := x.get(t, confirmDisableAction(targetViewerID)+"?from=list").Body.String()
	if f := formFields(onlyPostForm(t, fromList)); f.Get("from") != "list" {
		t.Errorf("the confirmation reached from the list does not carry from=list: %v", f)
	}
	if !strings.Contains(contentOf(fromList), `<a href="/console/accounts">Back to Accounts</a>`) {
		t.Errorf("the list-origin confirmation does not link back to the list:\n%s", contentOf(fromList))
	}

	for _, q := range []string{"", "?from=page", "?from=https://evil.example/"} {
		body := x.get(t, confirmDisableAction(targetViewerID)+q).Body.String()
		if f := formFields(onlyPostForm(t, body)); f.Has("from") {
			t.Errorf("%q: the confirmation carries a from field: %v", q, f)
		}
		if !strings.Contains(contentOf(body), `<a href="`+accountPagePath("ana")+`">Back to ana</a>`) {
			t.Errorf("%q: the confirmation does not link back to the Account page:\n%s", q, contentOf(body))
		}
	}

	revoke := x.get(t, confirmRevokeAction(targetOperatorID, targetLiveToken)).Body.String()
	if f := formFields(onlyPostForm(t, revoke)); f.Get("account") != targetOperatorID {
		t.Errorf("the revoke confirmation does not carry the owning Account's ID: %v", f)
	}
}

func TestAccounts_TheResultLineIsFromAClosedSet(t *testing.T) {
	h := newTestHandler(accountsFixture(), accounts.RoleAdmin)
	status := regexp.MustCompile(`<p class="done" role="status">([^<]*)</p>`)

	for _, base := range []string{accountsPath, accountPagePath("gleipnir-prod")} {
		for key, sentence := range accountsDone {
			// gleipnir-prod is enabled, so its page cannot show "disabled";
			// TestAccounts_TheAccountPageShowsOnlyAStateLineItsStateAgreesWith
			// pins that.
			if base != accountsPath && key == doneDisabled {
				continue
			}
			body := get(t, h, base+"?done="+string(key)).Body.String()
			m := status.FindStringSubmatch(body)
			if m == nil || m[1] != sentence {
				t.Errorf("%s?done=%s renders %v, want %q", base, key, m, sentence)
			}
		}
		for _, raw := range []string{"unknown", "<script>alert(1)</script>", "Account created.", "CREATED", ""} {
			body := get(t, h, base+"?done="+url.QueryEscape(raw)).Body.String()
			if status.MatchString(body) {
				t.Errorf("%s?done=%q renders a result line", base, raw)
			}
			if raw != "" && strings.Contains(body, raw) && raw != "Account created." {
				t.Errorf("%s?done=%q echoes the raw value", base, raw)
			}
		}
	}
}

// A crafted link must not make the Account page claim a state change that did
// not happen: enabled and disabled show only when the Account is in that state.
func TestAccounts_TheAccountPageShowsOnlyAStateLineItsStateAgreesWith(t *testing.T) {
	h := newTestHandler(accountsFixture(), accounts.RoleAdmin)
	for _, c := range []struct {
		name, done string
		shown      bool
	}{
		{"gleipnir-prod", "enabled", true},
		{"gleipnir-prod", "disabled", false},
		{"retired-ci", "disabled", true},
		{"retired-ci", "enabled", false},
	} {
		body := get(t, h, accountPagePath(c.name)+"?done="+c.done).Body.String()
		if got := strings.Contains(body, `class="done"`); got != c.shown {
			t.Errorf("%s?done=%s: result line shown = %v, want %v", c.name, c.done, got, c.shown)
		}
	}
}

func TestAccountsWrite_TheMintResponseSaysOnlyShownOnce(t *testing.T) {
	x := newWriteFix(t, nil)
	rec := x.post(t, mintAPITokenAction(targetOperatorID), url.Values{
		"name": {"ci-deploy"}, "ttl": {"90d"}, "password": {"p"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body %s", rec.Code, contentOf(rec.Body.String()))
	}
	content := contentOf(rec.Body.String())
	if !strings.Contains(content, "Shown once.") || strings.Contains(content, "Copy this now") {
		t.Errorf("the minted page does not say only %q:\n%s", "Shown once.", content)
	}
	if want := fmt.Sprintf(`<a href="%s">Back to gleipnir-prod</a>`, accountPagePath("gleipnir-prod")); !strings.Contains(content, want) {
		t.Errorf("the minted page lacks %s:\n%s", want, content)
	}
	if rec.Header().Get("Location") != "" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("the mint response redirects or is cacheable")
	}
	// The value is absent from every later render, the Account page included.
	later := x.get(t, accountPagePath("gleipnir-prod")).Body.String()
	if strings.Contains(later, sweepMintedPlaintext) {
		t.Error("the Account page renders the minted plaintext")
	}
}
