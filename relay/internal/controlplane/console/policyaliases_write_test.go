package console

// policyaliases_write_test.go holds the Policy alias write route to the same
// guards as every other Console write: a genuine CSRF token, a bounded body,
// a seam as narrow as the route, and links that carry the hash and never the
// alias.

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

// aliasLoginFixture is a real sign-in lane over a fleet whose Node reports a
// well-formed fingerprint, with w wired as the alias writer.
func aliasLoginFixture(t *testing.T, w *fakeAliasWriter) *loginFixture {
	t.Helper()
	d, _, _ := aliasDeps(map[string]string{fpA: "web-hardened"}, aliasNode("node-1", fpA, true))
	return newLoginFixtureWith(t, func(login *Deps) {
		login.Queries = d.Queries
		login.AliasWriter = w
	})
}

// A signed-in session's alias POST is refused with no token, a wrong token,
// another session's token or a planted __Host- cookie, and the capability layer
// is never reached.
func TestPolicyAliases_ARealSessionPostWithNoOrWrongCSRFTokenIsRefused(t *testing.T) {
	w := &fakeAliasWriter{}
	f := aliasLoginFixture(t, w)
	session := signedInSession(t, f, "mike", consolePassword)
	other := signedInSession(t, f, "mike", consolePassword)

	page := func(s *http.Cookie) string {
		return renderedCSRFToken(f.do(t, httptest.NewRequest(http.MethodGet, aliasNodePath, nil), s).Body.String())
	}
	own, theirs := page(session), page(other)
	if own == "" || theirs == "" || own == theirs {
		t.Fatalf("want two distinct session tokens, got %q and %q", own, theirs)
	}

	const planted = "AttackerChosenValue-well_formed-by-shape-00"
	for name, c := range map[string]struct {
		token   string
		cookies []*http.Cookie
	}{
		"no token":                 {"", nil},
		"a wrong token":            {own + "-wrong", nil},
		"another session's token":  {theirs, nil},
		"a planted __Host- cookie": {planted, []*http.Cookie{{Name: signInCSRFCookieName, Value: planted}}},
	} {
		body := url.Values{"fingerprint": {fpA}, "op": {"set"}, "alias": {"x"}}
		if c.token != "" {
			body.Set("csrf_token", c.token)
		}
		req := httptest.NewRequest(http.MethodPost, policyAliasesAction, strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := f.do(t, req, append([]*http.Cookie{session}, c.cookies...)...)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s = %d, want 403", name, rec.Code)
		}
	}
	if sets, clears := w.calls(); len(sets)+len(clears) != 0 {
		t.Errorf("the writer was called by a refused request: %v %v", sets, clears)
	}

	// The genuine token is accepted, so the refusals above were the CSRF check's.
	body := url.Values{"csrf_token": {own}, "fingerprint": {fpA}, "op": {"set"}, "alias": {"x"}}
	req := httptest.NewRequest(http.MethodPost, policyAliasesAction, strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if rec := f.do(t, req, session); rec.Code != http.StatusSeeOther {
		t.Errorf("a genuine token = %d, want 303", rec.Code)
	}
}

// A body over the form limit is refused whole, before the capability layer is
// called, so there is no alias change and no record of one.
func TestPolicyAliases_AnOverSizeBodyIsRefusedWholeAndWritesNothing(t *testing.T) {
	t.Run("through the session lane", func(t *testing.T) {
		w := &fakeAliasWriter{}
		f := aliasLoginFixture(t, w)
		session := signedInSession(t, f, "mike", consolePassword)
		token := renderedCSRFToken(f.do(t, httptest.NewRequest(http.MethodGet, aliasNodePath, nil), session).Body.String())
		fixed := "csrf_token=" + token + "&fingerprint=" + fpA + "&op=set&alias=x&pad="
		post := func(total int) *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodPost, policyAliasesAction, strings.NewReader(fixed+strings.Repeat("a", total-len(fixed))))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return f.do(t, req, session)
		}

		rec := post(maxFormBodyBytes + 1)
		if rec.Code != http.StatusRequestEntityTooLarge || !strings.HasSuffix(strings.TrimSpace(rec.Body.String()), tagNotChanged) {
			t.Errorf("a body one byte over the limit = %d %q, want 413 ending %q", rec.Code, rec.Body.String(), tagNotChanged)
		}
		if sets, clears := w.calls(); len(sets)+len(clears) != 0 {
			t.Errorf("the writer was called for an over-size body: %v %v", sets, clears)
		}
		if rec := post(maxFormBodyBytes); rec.Code == http.StatusRequestEntityTooLarge || rec.Code == http.StatusForbidden {
			t.Errorf("a body exactly at the limit = %d, want it read", rec.Code)
		}
	})

	t.Run("in the handler", func(t *testing.T) {
		d, _, w := aliasDeps(nil, aliasNode("node-1", fpA, true))
		rec := aliasPost(t, d, accounts.RoleAdmin, url.Values{
			"fingerprint": {fpA}, "op": {"set"}, "alias": {"x"},
			"pad": {strings.Repeat("a", maxFormBodyBytes+1)},
		})
		content := contentOf(rec.Body.String())
		if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(content, bodyTooLargeHeading) {
			t.Errorf("status %d, want 413 with %q; %s", rec.Code, bodyTooLargeHeading, content)
		}
		if sets, clears := w.calls(); len(sets)+len(clears) != 0 {
			t.Errorf("the writer was called for an over-size body: %v %v", sets, clears)
		}
	})
}

// The write seam is exactly Set and Clear: a wider one is a wider write surface.
func TestPolicyAliases_WriteSeamCarriesOnlySetAndClear(t *testing.T) {
	typ := reflect.TypeOf((*PolicyAliasWriter)(nil)).Elem()
	var got []string
	for i := 0; i < typ.NumMethod(); i++ {
		got = append(got, typ.Method(i).Name)
	}
	if want := []string{"ClearPolicyAlias", "SetPolicyAlias"}; !slices.Equal(got, want) {
		t.Fatalf("PolicyAliasWriter carries %v, want exactly %v", got, want)
	}
}

// Proves QRY-33.
//
// Every link that follows a fingerprint carries its hash and never its alias,
// so a rename cannot change what a link selects.
func TestPolicyAliases_FiltersAndLinksCarryTheHashNeverTheAlias(t *testing.T) {
	d, _ := aliasScreenFixture()
	h := newTestHandler(d, accounts.RoleAdmin)
	hrefRe := regexp.MustCompile(`href="([^"]*)"`)

	for _, path := range []string{aliasFleetPath, aliasNodePath} {
		body := get(t, h, path).Body.String()
		carrying := 0
		for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
			href, err := url.QueryUnescape(html.UnescapeString(m[1]))
			if err != nil {
				t.Fatalf("%s: unreadable link %q: %v", path, m[1], err)
			}
			if strings.Contains(href, "web-hardened") || strings.Contains(href, "db-baseline") {
				t.Errorf("%s: a link carries an alias: %s", path, href)
			}
			if strings.Contains(href, "state:policy-fingerprint="+fpA) {
				carrying++
			}
		}
		if carrying == 0 {
			t.Errorf("%s: no link carries state:policy-fingerprint=%s", path, fpA)
		}
	}
}
