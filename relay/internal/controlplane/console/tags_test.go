package console

// tags_test.go proves the Console's tag controls (tags.go): who sees them, that
// every write reaches the capability layer's TagWriter and nothing else, that a
// bulk write sends the Node IDs the confirmation page listed and never the
// filter, and that the new forms and pages hold the CSRF, CSP and
// no-inline-script guards. The fake TagWriter records and decides nothing, so a
// refusal here is the capability layer's answer rendered, not the Console's.

import (
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

const (
	// filteredFleet is the Fleet view of the three web Nodes, grouped by
	// nothing: the view that offers the bulk form.
	filteredFleet = "/console/?filter=node%3Arole%3Dweb&group=-"

	// confirmWebLink asks to add tag:owner=team-a to the three web Nodes.
	confirmWebLink = confirmTagsPath + "?filter=node%3Arole%3Dweb&op=add&label=tag%3Aowner%3Dteam-a"
)

var formActionRe = regexp.MustCompile(`<form\b[^>]*\saction="([^"]*)"`)

// hiddenValues is every value of the inputs named name in html, in order.
func hiddenValues(html, name string) []string {
	re := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]*)"`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(html, -1) {
		out = append(out, m[1])
	}
	return out
}

// tagDeps is the sweep fixture with a fresh, fully observable TagWriter.
func tagDeps(tw *fakeTagWriter) Deps {
	d := sweepFixture()
	d.Tags = tw
	return d
}

func formsOf(body string) []string {
	return append(formsWithMethod(body, "get"), formsWithMethod(body, "post")...)
}

func hasCSRFToken(form string) bool { return strings.Contains(form, `name="csrf_token"`) }

func formsTargeting(forms []string, action string) []string {
	var out []string
	for _, f := range forms {
		if strings.Contains(f, `action="`+action+`"`) {
			out = append(out, f)
		}
	}
	return out
}

// TestTags_NewFormsAndPagesHoldTheCSRFAndCSPGuards renders every page the tag
// controls add, including the ones no generic sweep reaches (the filtered Fleet
// view, a POST's result page and every refusal), and checks the guards on each.
func TestTags_NewFormsAndPagesHoldTheCSRFAndCSPGuards(t *testing.T) {
	rendered := 0

	t.Run("filtered fleet", func(t *testing.T) {
		for _, role := range []accounts.Role{accounts.RoleOperator, accounts.RoleAdmin} {
			rec := get(t, newTestHandler(sweepFixture(), role), filteredFleet)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: GET %s = %d, want 200", role, filteredFleet, rec.Code)
			}
			rendered++
			body := rec.Body.String()
			assertCSPClean(t, filteredFleet, body)
			content := contentOf(body)
			for _, f := range formsWithMethod(content, "get") {
				if hasCSRFToken(f) {
					t.Errorf("%s: a GET form carries a CSRF token: %s", role, f)
				}
			}
			for _, f := range postForms(content) {
				if !hasCSRFToken(f) {
					t.Errorf("%s: a POST form carries no CSRF token: %s", role, f)
				}
			}
			tagForms := formsTargeting(formsWithMethod(content, "get"), confirmTagsPath)
			if len(tagForms) != 1 {
				t.Fatalf("%s: %d GET forms to the confirmation page, want exactly 1", role, len(tagForms))
			}
			for _, field := range []string{`name="filter"`, `name="group"`, `name="op"`, `name="label"`} {
				if !strings.Contains(tagForms[0], field) {
					t.Errorf("%s: the tag form lacks %s", role, field)
				}
			}
		}
	})

	t.Run("confirmation page", func(t *testing.T) {
		rec := get(t, newTestHandler(sweepFixture(), accounts.RoleOperator), confirmWebLink)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", confirmWebLink, rec.Code)
		}
		rendered++
		assertCSPClean(t, confirmWebLink, rec.Body.String())
		content := contentOf(rec.Body.String())
		posts := postForms(content)
		for _, f := range posts {
			if !hasCSRFToken(f) {
				t.Errorf("a POST form on the confirmation page carries no CSRF token: %s", f)
			}
		}
		if n := len(formsTargeting(posts, bulkTagsAction)); n != 1 {
			t.Errorf("%d POST forms to %s, want exactly 1", n, bulkTagsAction)
		}
		for _, f := range formsWithMethod(content, "get") {
			if hasCSRFToken(f) {
				t.Errorf("a GET form carries a CSRF token: %s", f)
			}
		}
	})

	t.Run("confirmation refusals", func(t *testing.T) {
		good := "&op=add&label=tag%3Aowner%3Dteam-a"
		for name, c := range map[string]struct {
			query  string
			status int
		}{
			"empty filter":    {"?filter=" + good, http.StatusBadRequest},
			"refused filter":  {"?filter=foo" + good, http.StatusBadRequest},
			"wrong namespace": {"?filter=node%3Arole%3Dweb&op=add&label=node%3Arole%3Dweb", http.StatusBadRequest},
			"unknown op":      {"?filter=node%3Arole%3Dweb&op=nonesuch&label=tag%3Aowner%3Dteam-a", http.StatusBadRequest},
			"no match":        {"?filter=node%3Arole%3Dnonesuch" + good, http.StatusNotFound},
		} {
			path := confirmTagsPath + c.query
			rec := get(t, newTestHandler(sweepFixture(), accounts.RoleOperator), path)
			if rec.Code != c.status {
				t.Errorf("%s: GET %s = %d, want %d", name, path, rec.Code, c.status)
				continue
			}
			rendered++
			assertCSPClean(t, name, rec.Body.String())
			if strings.Contains(contentOf(rec.Body.String()), "<form") {
				t.Errorf("%s: a refusal page holds a form", name)
			}
		}
	})

	t.Run("bulk result", func(t *testing.T) {
		h := newTestHandlerSkippingCSRF(tagDeps(&fakeTagWriter{}), accounts.RoleOperator)
		rec := postFormSkippingCSRF(t, h, bulkTagsAction, url.Values{
			"node_id": {"node-web-1", "node-web-2"}, "op": {"add"}, "label": {"tag:owner=team-a"},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("POST %s = %d, want 200; %s", bulkTagsAction, rec.Code, rec.Body.String())
		}
		rendered++
		assertCSPClean(t, "bulk result", rec.Body.String())
		if strings.Contains(contentOf(rec.Body.String()), "<form") {
			t.Error("the bulk result page holds a form")
		}
	})

	t.Run("per-Node success", func(t *testing.T) {
		// A 303 to the Node's own page: there is no body to check, and the page
		// it lands on is rendered by the node-detail sweeps.
		h := newTestHandlerSkippingCSRF(tagDeps(&fakeTagWriter{}), accounts.RoleOperator)
		rec := postFormSkippingCSRF(t, h, nodeTagsAction("node-web-1"), url.Values{
			"op": {"add"}, "label": {"tag:owner=team-a"},
		})
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/console/nodes/node-web-1" {
			t.Errorf("status %d, Location %q; want 303 to the Node page", rec.Code, rec.Header().Get("Location"))
		}
		rendered++
	})

	t.Run("write failures", func(t *testing.T) {
		for name, c := range map[string]struct {
			err     error
			status  int
			changed bool // the page says "Nothing was changed."
		}{
			"refusal": {errors.Join(fmt.Errorf("%w: tagging needs an operator", authz.ErrUnauthorized), errors.New("audit down")), http.StatusForbidden, true},
			"missing": {errors.Join(&capability.TagNodesNotFoundError{NodeIDs: []string{"x"}}, errors.New("audit down")), http.StatusNotFound, true},
			"changed": {capability.ErrTagChanged, http.StatusConflict, true},
			"bad":     {capability.ErrTagMalformed, http.StatusBadRequest, true},
			"unknown": {errors.New("boom"), http.StatusInternalServerError, false},
			"unwired": {capability.ErrTagsUnavailable, http.StatusInternalServerError, false},
		} {
			for _, path := range []string{nodeTagsAction("node-web-1"), bulkTagsAction} {
				h := newTestHandlerSkippingCSRF(tagDeps(&fakeTagWriter{err: c.err}), accounts.RoleOperator)
				rec := postFormSkippingCSRF(t, h, path, url.Values{
					"node_id": {"node-web-1"}, "op": {"add"}, "label": {"tag:owner=team-a"},
				})
				if rec.Code != c.status {
					t.Errorf("%s %s: status %d, want %d; %s", name, path, rec.Code, c.status, rec.Body.String())
					continue
				}
				rendered++
				assertCSPClean(t, name+" "+path, rec.Body.String())
				content := contentOf(rec.Body.String())
				if strings.Contains(content, "<form") {
					t.Errorf("%s %s: a failure page holds a form", name, path)
				}
				if c.changed && !strings.Contains(content, tagNotChanged) {
					t.Errorf("%s %s: the page does not say %q", name, path, tagNotChanged)
				}
			}
		}
	})

	if rendered < 15 {
		t.Fatalf("only %d pages rendered — the guard checked almost nothing", rendered)
	}
}

func TestTags_AViewerSeesNoTagControlAnywhere(t *testing.T) {
	for _, role := range sessionRoles {
		t.Run(string(role), func(t *testing.T) {
			h := newTestHandler(sweepFixture(), role)
			node := get(t, h, "/console/nodes/node-web-1")
			fleet := get(t, h, filteredFleet)
			if node.Code != http.StatusOK || fleet.Code != http.StatusOK {
				t.Fatalf("node %d, fleet %d, want 200 both", node.Code, fleet.Code)
			}
			nodeContent := contentOf(node.Body.String())
			fleetContent := contentOf(fleet.Body.String())
			if !strings.Contains(nodeContent, `data-ns="tag"`) {
				t.Fatal("the Node page draws no tag chip — the fixture proves nothing")
			}

			offered := role != accounts.RoleViewer
			for name, present := range map[string]bool{
				"a tag add form":      strings.Contains(nodeContent, "Add tag"),
				"a tag remove button": strings.Contains(nodeContent, ">Remove</button>"),
				"a tags action":       strings.Contains(nodeContent, nodeTagsAction("node-web-1")),
				"a POST form":         len(postForms(nodeContent)) > 0,
				"the bulk tag form":   strings.Contains(fleetContent, confirmTagsPath),
				"the bulk tag button": strings.Contains(fleetContent, "Tag these"),
			} {
				if present != offered {
					t.Errorf("%s: %s present = %v, want %v", role, name, present, offered)
				}
			}
		})
	}
}

func TestTags_NoControlWhenTheSeamIsUnwired(t *testing.T) {
	d := sweepFixture()
	d.Tags = nil
	h := newTestHandler(d, accounts.RoleAdmin)

	if c := contentOf(get(t, h, "/console/nodes/node-web-1").Body.String()); strings.Contains(c, "<form") {
		t.Error("Node detail draws a form with no tag seam wired")
	}
	fleet := contentOf(get(t, h, filteredFleet).Body.String())
	if strings.Contains(fleet, confirmTagsPath) || strings.Contains(fleet, "Tag these") {
		t.Error("the filtered Fleet view draws the bulk tag form with no tag seam wired")
	}

	if rec := get(t, h, confirmWebLink); rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "was not wired") {
		t.Errorf("confirmation page: %d %q, want 500 naming the unwired seam", rec.Code, rec.Body.String())
	}
	skip := newTestHandlerSkippingCSRF(d, accounts.RoleAdmin)
	form := url.Values{"node_id": {"node-web-1"}, "op": {"add"}, "label": {"tag:owner=team-a"}}
	for _, path := range []string{nodeTagsAction("node-web-1"), bulkTagsAction} {
		rec := postFormSkippingCSRF(t, skip, path, form)
		if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "was not wired") {
			t.Errorf("POST %s: %d %q, want 500 naming the unwired seam", path, rec.Code, rec.Body.String())
		}
	}
}

// signedInSession signs the fixture's admin in and returns the session cookie.
func signedInSession(t *testing.T, f *loginFixture, user, password string) *http.Cookie {
	t.Helper()
	rec, cookies := f.signIn(t, user, password)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("sign-in status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	if session == nil {
		t.Fatal("no session cookie was set")
	}
	return session
}

func tagLoginFixture(t *testing.T, tw *fakeTagWriter) *loginFixture {
	return newLoginFixtureWith(t, func(d *Deps) {
		d.Queries = fleetFixture().Queries
		d.Tags = tw
	})
}

func TestTags_AViewerSessionFindsTheTagRoutesAbsent(t *testing.T) {
	tw := &fakeTagWriter{}
	f := tagLoginFixture(t, tw)
	f.createAccountWithPassword(t, "watcher", accounts.RoleViewer, "a viewer password")
	session := signedInSession(t, f, "watcher", "a viewer password")

	// A genuine token for the viewer's own session, so Secure's CSRF check does
	// not answer 403 for the wrong reason.
	token := renderedCSRFToken(f.do(t, httptest.NewRequest(http.MethodGet, "/console/", nil), session).Body.String())
	if token == "" {
		t.Fatal("the fleet view rendered no CSRF token for the viewer")
	}
	post := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("csrf_token="+token+"&op=add&label=tag%3Aa%3Db&node_id=node-web-1"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return f.do(t, req, session)
	}

	unmounted := post("/console/nodes/node-web-1/nonesuch").Body.String()
	for _, path := range []string{nodeTagsAction("node-web-1"), bulkTagsAction} {
		rec := post(path)
		if rec.Code != http.StatusNotFound || rec.Body.String() != unmounted {
			t.Errorf("viewer POST %s = %d; want the unmounted-path 404, byte for byte", path, rec.Code)
		}
	}
	unmountedGet := f.do(t, httptest.NewRequest(http.MethodGet, "/console/nonesuch", nil), session)
	rec := f.do(t, httptest.NewRequest(http.MethodGet, confirmWebLink, nil), session)
	if rec.Code != http.StatusNotFound || rec.Body.String() != unmountedGet.Body.String() {
		t.Errorf("viewer GET %s = %d; want the unmounted-path 404, byte for byte", confirmTagsPath, rec.Code)
	}
	if n := len(tw.calls()); n != 0 {
		t.Errorf("the TagWriter was called %d times for a viewer", n)
	}
}

func TestTags_ARealSessionTagPostWithNoOrWrongCSRFTokenIsRefused(t *testing.T) {
	tw := &fakeTagWriter{}
	f := tagLoginFixture(t, tw)
	session := signedInSession(t, f, "mike", consolePassword)
	other := signedInSession(t, f, "mike", consolePassword)

	page := func(s *http.Cookie) string {
		return renderedCSRFToken(f.do(t, httptest.NewRequest(http.MethodGet, "/console/nodes/node-web-1", nil), s).Body.String())
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
		for _, path := range []string{nodeTagsAction("node-web-1"), bulkTagsAction} {
			body := url.Values{"op": {"add"}, "label": {"tag:a=b"}, "node_id": {"node-web-1"}}
			if c.token != "" {
				body.Set("csrf_token", c.token)
			}
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := f.do(t, req, append([]*http.Cookie{session}, c.cookies...)...)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s to %s = %d, want 403", name, path, rec.Code)
			}
		}
	}
	if n := len(tw.calls()); n != 0 {
		t.Errorf("the TagWriter was called %d times by a refused request", n)
	}
}

func TestTags_ABearerLaneTagPostIsRefused(t *testing.T) {
	tw := &fakeTagWriter{}
	h := newTestHandler(tagDeps(tw), accounts.RoleOperator)
	for _, path := range []string{nodeTagsAction("node-web-1"), bulkTagsAction} {
		if rec := request(t, h, http.MethodPost, path); rec.Code != http.StatusForbidden {
			t.Errorf("bearer POST %s = %d, want 403", path, rec.Code)
		}
	}
	if n := len(tw.calls()); n != 0 {
		t.Errorf("the TagWriter was called %d times by a bearer-lane request", n)
	}
}

func TestTags_NodeDetailAddReachesTheCapabilityLayerUnparsed(t *testing.T) {
	tw := &fakeTagWriter{}
	f := tagLoginFixture(t, tw)
	session := signedInSession(t, f, "mike", consolePassword)

	pageRec := f.do(t, httptest.NewRequest(http.MethodGet, "/console/nodes/node-web-1", nil), session)
	token := renderedCSRFToken(pageRec.Body.String())
	if pageRec.Code != http.StatusOK || token == "" {
		t.Fatalf("Node page %d, token %q", pageRec.Code, token)
	}
	body := url.Values{"csrf_token": {token}, "op": {"add"}, "label": {"tag:owner=team-a"}}
	req := httptest.NewRequest(http.MethodPost, nodeTagsAction("node-web-1"), strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := f.do(t, req, session)

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/console/nodes/node-web-1" {
		t.Fatalf("status %d, Location %q; want 303 to the Node page", rec.Code, rec.Header().Get("Location"))
	}
	calls := tw.calls()
	if len(calls) != 1 {
		t.Fatalf("%d WriteTag calls, want exactly 1", len(calls))
	}
	want := capability.TagWrite{NodeIDs: []string{"node-web-1"}, Op: capability.TagAdd, Label: "tag:owner=team-a"}
	if !reflect.DeepEqual(calls[0].Write, want) || calls[0].Principal.Account != "mike" {
		t.Errorf("WriteTag got %+v from %q, want %+v from mike", calls[0].Write, calls[0].Principal.Account, want)
	}
}

func TestTags_POSTFieldsComeFromTheBodyOnly(t *testing.T) {
	tw := &fakeTagWriter{}
	h := newTestHandlerSkippingCSRF(tagDeps(tw), accounts.RoleOperator)

	postFormSkippingCSRF(t, h, nodeTagsAction("node-web-1")+"?op=remove&label=tag:pci",
		url.Values{"op": {"add"}, "label": {"tag:owner=team-a"}})
	postFormSkippingCSRF(t, h, bulkTagsAction+"?node_id=node-db-1&op=remove&label=tag:pci",
		url.Values{"node_id": {"node-web-1"}, "op": {"add"}, "label": {"tag:owner=team-a"}})
	// A body that omits op and label records empty ones, never the query's.
	postFormSkippingCSRF(t, h, nodeTagsAction("node-web-1")+"?op=remove&label=tag:pci", url.Values{})
	postFormSkippingCSRF(t, h, bulkTagsAction+"?node_id=node-db-1&op=remove&label=tag:pci", url.Values{})

	want := []capability.TagWrite{
		{NodeIDs: []string{"node-web-1"}, Op: capability.TagAdd, Label: "tag:owner=team-a"},
		{NodeIDs: []string{"node-web-1"}, Op: capability.TagAdd, Label: "tag:owner=team-a"},
		{NodeIDs: []string{"node-web-1"}},
		{},
	}
	calls := tw.calls()
	if len(calls) != len(want) {
		t.Fatalf("%d WriteTag calls, want %d", len(calls), len(want))
	}
	for i, c := range calls {
		if !reflect.DeepEqual(c.Write, want[i]) {
			t.Errorf("call %d: %+v, want %+v", i, c.Write, want[i])
		}
	}
}

func TestTags_NodeDetailRemoveFormsNameOnlyTags(t *testing.T) {
	h := newTestHandler(sweepFixture(), accounts.RoleOperator)

	content := contentOf(get(t, h, "/console/nodes/node-web-1").Body.String())
	removes := formsTargeting(postForms(content), nodeTagsAction("node-web-1"))
	var remove []string
	for _, f := range removes {
		if strings.Contains(f, `name="op" value="remove"`) {
			remove = append(remove, f)
		}
	}
	tags := strings.Count(content, `data-ns="tag"`)
	if tags == 0 || len(remove) != tags {
		t.Fatalf("%d remove forms for %d tag chips, want one each and at least one", len(remove), tags)
	}
	for _, f := range remove {
		if !strings.Contains(f, `name="label" value="tag:pci"`) || !strings.Contains(f, `aria-label="Remove tag:pci"`) {
			t.Errorf("a remove form does not name tag:pci: %s", f)
		}
	}

	// node-db-1 carries node: and relay: labels and no tag: a remove form after
	// one of those would be a control for a namespace this screen never writes.
	dbContent := contentOf(get(t, h, "/console/nodes/node-db-1").Body.String())
	if !strings.Contains(dbContent, `data-ns="relay"`) || !strings.Contains(dbContent, `data-ns="node"`) {
		t.Fatal("node-db-1 draws no node: and relay: chips — the fixture proves nothing")
	}
	for _, f := range postForms(dbContent) {
		if strings.Contains(f, `name="op" value="remove"`) {
			t.Errorf("a remove form on a Node with no tag: %s", f)
		}
	}
}

func TestTags_RefusalsRenderTheCapabilityLayersAnswer(t *testing.T) {
	const auditDetail = "audit store detail must stay off the page"
	for name, c := range map[string]struct {
		err    error
		status int
		must   []string
	}{
		"role refusal": {errors.Join(fmt.Errorf("%w: needs operator", authz.ErrUnauthorized), errors.New(auditDetail)),
			http.StatusForbidden, []string{"The Relay refused this tag change", "needs operator", tagNotChanged}},
		"unknown Node": {errors.Join(&capability.TagNodesNotFoundError{NodeIDs: []string{"ghost-1"}}, errors.New(auditDetail)),
			http.StatusNotFound, []string{"ghost-1", tagNotChanged}},
		"vanished Node": {&capability.TagNodesNotFoundError{},
			http.StatusNotFound, []string{tagNodeGoneHeading}},
		"changed": {capability.ErrTagChanged,
			http.StatusConflict, []string{tagChangedHeading}},
		"too many": {errors.Join(capability.ErrTooManyTags, errors.New(auditDetail)),
			http.StatusConflict, []string{strconv.Itoa(registry.MaxTagsPerNode), tagNotChanged}},
		"namespace": {capability.ErrTagNamespaceRequired,
			http.StatusBadRequest, []string{"Only a tag: label is written here", tagNotChanged}},
		"malformed": {errors.Join(capability.ErrTagMalformed, errors.New(auditDetail)),
			http.StatusBadRequest, []string{"may hold only ASCII letters", tagNotChanged}},
		"too long": {capability.ErrTagTooLong,
			http.StatusBadRequest, []string{strconv.Itoa(registry.MaxTagKeyLen), strconv.Itoa(registry.MaxTagValueLen), tagNotChanged}},
		"unknown": {errors.New("disk on fire"),
			http.StatusInternalServerError, []string{tagUnconfirmedHeading}},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHandlerSkippingCSRF(tagDeps(&fakeTagWriter{err: c.err}), accounts.RoleOperator)
			for _, path := range []string{nodeTagsAction("node-web-1"), bulkTagsAction} {
				rec := postFormSkippingCSRF(t, h, path, url.Values{"node_id": {"node-web-1"}, "op": {"add"}, "label": {"tag:a=b"}})
				if rec.Code != c.status {
					t.Fatalf("%s: status %d, want %d; %s", path, rec.Code, c.status, rec.Body.String())
				}
				body := rec.Body.String()
				for _, s := range c.must {
					if !strings.Contains(body, s) {
						t.Errorf("%s: the page does not contain %q", path, s)
					}
				}
				for _, banned := range []string{"invariant", "ADR-", auditDetail, "disk on fire"} {
					if strings.Contains(body, banned) {
						t.Errorf("%s: the page contains %q", path, banned)
					}
				}
			}
		})
	}
}

func TestTags_FleetOffersTheBulkFormOnlyOnAFilteredMatchingView(t *testing.T) {
	h := newTestHandler(sweepFixture(), accounts.RoleOperator)
	form := func(path string) []string {
		return formsTargeting(formsWithMethod(contentOf(get(t, h, path).Body.String()), "get"), confirmTagsPath)
	}

	forms := form(filteredFleet)
	if len(forms) != 1 {
		t.Fatalf("filtered fleet: %d tag forms, want 1", len(forms))
	}
	if got := hiddenValues(forms[0], "filter"); !reflect.DeepEqual(got, []string{"node:role=web"}) {
		t.Errorf("hidden filter = %v", got)
	}
	if got := hiddenValues(forms[0], "group"); !reflect.DeepEqual(got, []string{"-"}) {
		t.Errorf("hidden group = %v", got)
	}
	if hasCSRFToken(forms[0]) {
		t.Error("the GET tag form carries a CSRF token")
	}
	if !strings.Contains(forms[0], "Tag these 3") {
		t.Errorf("the button does not name the count: %s", forms[0])
	}

	pinned := form("/console/?filter=node%3Arole%3Dweb&group=-&pin=node-web-1")
	if len(pinned) != 1 || !reflect.DeepEqual(hiddenValues(pinned[0], "pin"), []string{"node-web-1"}) {
		t.Errorf("a pinned view's tag form does not carry the pin: %v", pinned)
	}

	for name, path := range map[string]string{
		"unfiltered":     "/console/",
		"refused filter": "/console/?filter=foo",
		"no match":       "/console/?filter=node%3Arole%3Dnonesuch",
	} {
		if n := len(form(path)); n != 0 {
			t.Errorf("%s: %d tag forms, want none", name, n)
		}
	}
}

func TestTags_ConfirmListsTheMatchedNodesAndWritesNothing(t *testing.T) {
	tw := &fakeTagWriter{}
	h := newTestHandler(tagDeps(tw), accounts.RoleOperator)
	rec := get(t, h, confirmWebLink)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	content := contentOf(rec.Body.String())

	q := regexp.MustCompile(`(?s)<p class="confirmq">(.*?)</p>`).FindStringSubmatch(content)
	if q == nil || !strings.Contains(q[1], "Add") || !strings.Contains(q[1], "tag:owner=team-a") || !strings.Contains(q[1], "3 Nodes") {
		t.Fatalf("the question does not name the operation, the tag and the count: %v", q)
	}
	for _, id := range []string{"web-1", "web-2", "web-3"} {
		if !strings.Contains(content, `<code class="nodeid">node-`+id+`</code>`) {
			t.Errorf("node-%s is not listed", id)
		}
	}
	if strings.Contains(content, "node-db-1") {
		t.Error("an unmatched Node is listed")
	}

	posts := postForms(content)
	if len(posts) != 1 {
		t.Fatalf("%d POST forms, want 1", len(posts))
	}
	form := posts[0]
	if got := hiddenValues(form, "node_id"); !slices.Equal(got, []string{"node-web-1", "node-web-2", "node-web-3"}) {
		t.Errorf("node_id inputs = %v", got)
	}
	if !reflect.DeepEqual(hiddenValues(form, "op"), []string{"add"}) || !reflect.DeepEqual(hiddenValues(form, "label"), []string{"tag:owner=team-a"}) {
		t.Errorf("op or label wrong: %s", form)
	}
	if !hasCSRFToken(form) {
		t.Error("the POST form carries no CSRF token")
	}
	for _, name := range []string{"filter", "group", "pin"} {
		if strings.Contains(form, `name="`+name+`"`) {
			t.Errorf("the POST form carries a %q field — the IDs are the only thing that names Nodes", name)
		}
	}
	if n := len(tw.calls()); n != 0 {
		t.Errorf("the confirmation page called WriteTag %d times", n)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("the confirmation page is cacheable")
	}
}

func TestTags_ConfirmResolvesTheFilterAsTheFleetViewDoes(t *testing.T) {
	d := sweepFixture()
	h := newTestHandler(d, accounts.RoleOperator)
	nodes := fleetNodes(d)

	for _, filter := range []string{"node:role=web", "tag:pci=yes", "state:offline", "node:env=prod,node:role=db"} {
		v := buildFleetView(d, nodes, 0, filter, "-")
		var want []string
		for _, g := range v.Wall {
			for _, n := range g.Nodes {
				want = append(want, n.ID)
			}
		}
		if len(want) == 0 {
			t.Fatalf("%q matches no Node in the fixture — the case proves nothing", filter)
		}

		path := confirmTagsPath + "?" + url.Values{"filter": {filter}, "op": {"add"}, "label": {"tag:owner=team-a"}}.Encode()
		rec := get(t, h, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("%q: status %d, want 200", filter, rec.Code)
		}
		got := hiddenValues(contentOf(rec.Body.String()), "node_id")
		slices.Sort(want)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("%q: the confirmation page lists %v, the Fleet view matched %v", filter, got, want)
		}
	}
}

func TestTags_ConfirmRefusesWithNoFormWhenThereIsNothingToConfirm(t *testing.T) {
	tw := &fakeTagWriter{}
	d := tagDeps(tw)
	// Any registry read fails, so a case that reaches ListNodes would answer
	// 500 instead of its refusal: the label is checked before any read.
	failing := fakeQueriesCopy(d)
	failing.nodesErr = errors.New("registry down")
	dFailing := d
	dFailing.Queries = failing

	const good = "filter=node%3Arole%3Dweb&op=add&label=tag%3Aowner%3Dteam-a"
	for name, c := range map[string]struct {
		d      Deps
		query  string
		status int
	}{
		"empty filter":    {dFailing, "op=add&label=tag%3Aowner%3Dteam-a", http.StatusBadRequest},
		"blank filter":    {dFailing, "filter=%20&op=add&label=tag%3Aowner%3Dteam-a", http.StatusBadRequest},
		"refused filter":  {d, "filter=foo&op=add&label=tag%3Aowner%3Dteam-a", http.StatusBadRequest},
		"wrong namespace": {dFailing, "filter=node%3Arole%3Dweb&op=add&label=node%3Arole%3Dweb", http.StatusBadRequest},
		"remove a value":  {dFailing, "filter=node%3Arole%3Dweb&op=remove&label=tag%3Aowner%3Dteam-a", http.StatusBadRequest},
		"unknown op":      {dFailing, "filter=node%3Arole%3Dweb&op=nonesuch&label=tag%3Aowner%3Dteam-a", http.StatusBadRequest},
		"no match":        {d, "filter=node%3Arole%3Dnonesuch&op=add&label=tag%3Aowner%3Dteam-a", http.StatusNotFound},
		"the lane fails":  {dFailing, good, http.StatusInternalServerError},
	} {
		rec := get(t, newTestHandler(c.d, accounts.RoleOperator), confirmTagsPath+"?"+c.query)
		if rec.Code != c.status {
			t.Errorf("%s: status %d, want %d; %s", name, rec.Code, c.status, rec.Body.String())
		}
		if strings.Contains(contentOf(rec.Body.String()), "<form") {
			t.Errorf("%s: the page holds a form", name)
		}
	}
	if failing.listNodeCalls != 1 {
		t.Errorf("%d registry reads on the failing lane, want 1 (only the case that reaches the read; no pre-check refusal reads the registry)", failing.listNodeCalls)
	}
	if n := len(tw.calls()); n != 0 {
		t.Errorf("a confirmation page called WriteTag %d times", n)
	}
}

func TestTags_BulkPostSendsTheConfirmedIDsNeverTheFilter(t *testing.T) {
	tw := &fakeTagWriter{}
	h := newTestHandlerSkippingCSRF(tagDeps(tw), accounts.RoleOperator)
	rec := postFormSkippingCSRF(t, h, bulkTagsAction, url.Values{
		"node_id": {"node-web-1", "node-web-2"}, "op": {"add"}, "label": {"tag:owner=team-a"},
		"filter": {"node:role=db"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	calls := tw.calls()
	if len(calls) != 1 {
		t.Fatalf("%d WriteTag calls, want exactly 1 — a bulk write is one act, never a loop", len(calls))
	}
	want := capability.TagWrite{NodeIDs: []string{"node-web-1", "node-web-2"}, Op: capability.TagAdd, Label: "tag:owner=team-a"}
	if !reflect.DeepEqual(calls[0].Write, want) {
		t.Errorf("WriteTag got %+v, want %+v", calls[0].Write, want)
	}
}

func TestTags_BulkResultListsTheNodesChanged(t *testing.T) {
	tw := &fakeTagWriter{result: capability.TagWriteResult{
		Changed: []registry.TagChange{{
			NodeID: "node-web-1", Key: "pci",
			After: registry.TagValue{Set: true, Value: "yes"},
		}},
		Unchanged: []string{"node-web-2"},
	}}
	h := newTestHandlerSkippingCSRF(tagDeps(tw), accounts.RoleOperator)
	rec := postFormSkippingCSRF(t, h, bulkTagsAction, url.Values{
		"node_id": {"node-web-1", "node-web-2"}, "op": {"add"}, "label": {"tag:pci=yes"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	content := contentOf(rec.Body.String())
	for _, want := range []string{
		`<code class="nodeid">node-web-1</code>`, `<span class="dim">not set</span>`, `<code>yes</code>`,
		"1 Node changed, 1 unchanged", `<code class="nodeid">node-web-2</code>`,
	} {
		if !strings.Contains(content, want) {
			t.Errorf("the result page does not contain %q:\n%s", want, content)
		}
	}
}

func TestTags_SeamCarriesOnlyWriteTag(t *testing.T) {
	typ := reflect.TypeOf((*TagWriter)(nil)).Elem()
	if typ.NumMethod() != 1 || typ.Method(0).Name != "WriteTag" {
		t.Fatalf("TagWriter must carry exactly WriteTag, has %d methods", typ.NumMethod())
	}
}

// allRenderedFormPages renders every page a sweep can reach as role: every
// walkable screen, the filtered Fleet view (the walked one is unfiltered, so it
// never draws the bulk form) and Node detail for every fixture Node.
func allRenderedFormPages(t *testing.T, role accounts.Role) map[string]string {
	t.Helper()
	d := sweepFixture()
	h := newTestHandler(d, role)
	paths := walkableScreens(routesFor(d, role), fixtureIDs)
	paths = append(paths, filteredFleet)
	for _, n := range fleetNodes(d) {
		paths = append(paths, "/console/nodes/"+n.NodeID)
	}
	pages := map[string]string{}
	for _, path := range paths {
		rec := get(t, h, path)
		if rec.Code != http.StatusOK {
			t.Errorf("%s as %s = %d, want 200", path, role, rec.Code)
			continue
		}
		pages[path] = contentOf(rec.Body.String())
	}

	// The sweep fixture's fingerprints are malformed, so it draws no alias
	// editor; the alias fixture's pages are added under their own keys.
	ah := newTestHandler(aliasSweepFixture(true), role)
	for _, path := range aliasSweepPaths {
		rec := get(t, ah, path)
		if rec.Code != http.StatusOK {
			t.Errorf("%s as %s = %d, want 200", path, role, rec.Code)
			continue
		}
		pages["alias/"+path] = contentOf(rec.Body.String())
	}
	return pages
}

var (
	labelFieldRe  = regexp.MustCompile(`<input\b[^>]*\bname="label"[^>]*>`)
	valueAttrRe   = regexp.MustCompile(`\bvalue="([^"]*)"`)
	removeButton  = regexp.MustCompile(`<button\b([^>]*)>Remove</button>`)
	ariaLabelAttr = regexp.MustCompile(`\baria-label="([^"]*)"`)

	// pinnedPostActions are the only POST targets any screen draws: sign in
	// and out, Cancel, the Account writes, the password change, the two tag writes, the mint
	// form (which takes tag: initial tags, ADR-0050) and the Policy
	// alias write. A future route that writes a label fails here until it is
	// named.
	pinnedPostActions = regexp.MustCompile(`^(` + strings.Join([]string{
		regexp.QuoteMeta(LoginPath), regexp.QuoteMeta(LogoutPath),
		`/console/jobs/[^/]+/cancel`,
		`/console/new-account/create`,
		`/console/accounts/[^/]+/(role|enabled|tokens|temporary-password)`,
		`/console/account/password`,
		`/console/api-tokens/[^/]+/revoke`,
		`/console/nodes/[^/]+/tags`,
		`/console/tags`,
		`/console/policy-aliases`,
		`/console/add-nodes/tokens`,
	}, "|") + `)$`)
)

// TestConsole_NoScreenOffersAnEditForANodeRelayOrStateLabel is the render test
// over every screen: the only label a form ever writes is a tag: label, and the
// only routes that take one are the tag routes and the mint form's initial tags
// (invariant 7, ADR-0050).
func TestConsole_NoScreenOffersAnEditForANodeRelayOrStateLabel(t *testing.T) {
	targets := map[string]bool{}
	for _, role := range sessionRoles {
		for path, content := range allRenderedFormPages(t, role) {
			for _, form := range formsOf(content) {
				action := ""
				if m := formActionRe.FindStringSubmatch(form); m != nil {
					action = m[1]
				}
				for _, input := range labelFieldRe.FindAllString(form, -1) {
					if m := valueAttrRe.FindStringSubmatch(input); m != nil && !strings.HasPrefix(m[1], "tag:") {
						t.Errorf("%s as %s: a label field holds %q, which is not a tag: label", path, role, m[1])
					}
					switch {
					case regexp.MustCompile(`^/console/nodes/[^/]+/tags$`).MatchString(action):
						targets["node"] = true
					case action == bulkTagsAction:
						targets["bulk"] = true
					case action == confirmTagsPath:
						targets["confirm"] = true
					default:
						t.Errorf("%s as %s: a form with a label field targets %q, not a tag route", path, role, action)
					}
				}
			}
			for _, form := range postForms(content) {
				m := formActionRe.FindStringSubmatch(form)
				if m == nil || !pinnedPostActions.MatchString(m[1]) {
					t.Errorf("%s as %s: a POST form targets %v, which is not a known write route", path, role, m)
				}
			}
			for _, m := range removeButton.FindAllStringSubmatch(content, -1) {
				aria := ariaLabelAttr.FindStringSubmatch(m[1])
				if aria == nil || !strings.HasPrefix(aria[1], "Remove tag:") {
					t.Errorf("%s as %s: a Remove button does not name a tag: term (%q)", path, role, m[1])
				}
			}
		}
		if role == accounts.RoleOperator && len(targets) != 3 {
			t.Errorf("as operator, label forms were seen for %v, want the node, bulk and confirm targets", targets)
		}
	}

	// The route table's writes are exactly the pinned set.
	var writes []string
	for _, r := range Routes(sweepFixture()) {
		if r.Method != http.MethodGet {
			writes = append(writes, r.Pattern())
		}
	}
	slices.Sort(writes)
	want := []string{
		"POST " + LoginPath, "POST " + LogoutPath,
		"POST /console/jobs/{job_id}/cancel",
		"POST /console/new-account/create",
		"POST /console/accounts/{account_id}/role",
		"POST /console/accounts/{account_id}/enabled",
		"POST /console/accounts/{account_id}/tokens",
		"POST /console/accounts/{account_id}/temporary-password",
		"POST " + changePasswordPath,
		"POST /console/api-tokens/{token_id}/revoke",
		nodeTagsPattern, bulkTagsPattern, policyAliasesPattern,
		mintEnrollmentTokenPattern,
	}
	slices.Sort(want)
	if !slices.Equal(writes, want) {
		t.Errorf("the Console's non-GET routes are %v, want %v", writes, want)
	}
}

// sessionTagPost posts body to path as the signed-in session, with a genuine
// CSRF token for that session as the first field, so a refusal cannot be the
// CSRF check's.
func sessionTagPost(t *testing.T, f *loginFixture, session *http.Cookie, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	token := renderedCSRFToken(f.do(t, httptest.NewRequest(http.MethodGet, "/console/nodes/node-web-1", nil), session).Body.String())
	if token == "" {
		t.Fatal("the Node page rendered no CSRF token")
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("csrf_token="+token+"&"+body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return f.do(t, req, session)
}

func TestTags_AnOverSizeBodyIsRefusedWholeAndWritesNothing(t *testing.T) {
	// The CSRF check is the first read of the body, so the bound has to hold
	// through the real session lane and, with no Secure in front, in the handler.
	for name, c := range map[string]struct {
		path  string
		limit int
	}{
		"bulk":     {bulkTagsAction, int(maxBulkTagBodyBytes)},
		"per-Node": {nodeTagsAction("node-web-1"), maxFormBodyBytes},
	} {
		t.Run(name+" through the session lane", func(t *testing.T) {
			tw := &fakeTagWriter{}
			f := tagLoginFixture(t, tw)
			session := signedInSession(t, f, "mike", consolePassword)
			token := renderedCSRFToken(f.do(t, httptest.NewRequest(http.MethodGet, "/console/nodes/node-web-1", nil), session).Body.String())
			fixed := "csrf_token=" + token + "&op=add&label=tag%3Aa%3Db&node_id=node-web-1&pad="
			post := func(total int) *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodPost, c.path, strings.NewReader(fixed+strings.Repeat("a", total-len(fixed))))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return f.do(t, req, session)
			}

			rec := post(c.limit + 1)
			if rec.Code != http.StatusRequestEntityTooLarge || !strings.HasSuffix(strings.TrimSpace(rec.Body.String()), tagNotChanged) {
				t.Errorf("a body one byte over the limit = %d %q, want 413 ending %q", rec.Code, rec.Body.String(), tagNotChanged)
			}
			if n := len(tw.calls()); n != 0 {
				t.Errorf("WriteTag was called %d times for an over-size body", n)
			}
			if rec := post(c.limit); rec.Code == http.StatusRequestEntityTooLarge || rec.Code == http.StatusForbidden {
				t.Errorf("a body exactly at the limit = %d, want it read", rec.Code)
			}
		})
		t.Run(name+" in the handler", func(t *testing.T) {
			tw := &fakeTagWriter{}
			h := newTestHandlerSkippingCSRF(tagDeps(tw), accounts.RoleOperator)
			rec := postFormSkippingCSRF(t, h, c.path, url.Values{
				"node_id": {"node-web-1"}, "op": {"add"}, "label": {"tag:a=b"},
				"pad": {strings.Repeat("a", c.limit+1)},
			})
			content := contentOf(rec.Body.String())
			if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(content, bodyTooLargeHeading) {
				t.Errorf("status %d, want 413 with %q; %s", rec.Code, bodyTooLargeHeading, content)
			}
			if n := len(tw.calls()); n != 0 {
				t.Errorf("WriteTag was called %d times for an over-size body", n)
			}
		})
	}
	if !strings.HasSuffix(bodyTooLargeHeading, tagNotChanged) {
		t.Errorf("%q does not end %q", bodyTooLargeHeading, tagNotChanged)
	}
}

// netURLFieldCeiling is the most fields net/url parses from one body.
const netURLFieldCeiling = 10_000

// The Node cap is the capability layer's. The Console hands it the list as
// posted, in one call, and renders its refusal.
func TestTags_ABulkListOverTheNodeCapIsTheCapabilityLayersRefusal(t *testing.T) {
	ids := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = "n" + strconv.Itoa(i)
		}
		return out
	}
	if maxBulkTagNodes != 256 {
		t.Fatalf("maxBulkTagNodes = %d, want the capability layer's 256", maxBulkTagNodes)
	}

	tw := &fakeTagWriter{}
	h := newTestHandlerSkippingCSRF(tagDeps(tw), accounts.RoleOperator)
	rec := postFormSkippingCSRF(t, h, bulkTagsAction, url.Values{
		"node_id": ids(maxBulkTagNodes), "op": {"add"}, "label": {"tag:a=b"},
	})
	if calls := tw.calls(); rec.Code != http.StatusOK || len(calls) != 1 || len(calls[0].Write.NodeIDs) != maxBulkTagNodes {
		t.Errorf("256 Nodes: status %d, %d calls; want 200 and one call over %d IDs", rec.Code, len(calls), maxBulkTagNodes)
	}

	refused := &fakeTagWriter{err: capability.ErrTagTooManyNodes}
	h = newTestHandlerSkippingCSRF(tagDeps(refused), accounts.RoleOperator)
	rec = postFormSkippingCSRF(t, h, bulkTagsAction, url.Values{
		"node_id": ids(maxBulkTagNodes + 1), "op": {"add"}, "label": {"tag:a=b"},
	})
	content := contentOf(rec.Body.String())
	if rec.Code != http.StatusBadRequest || !strings.Contains(content, tagTooManyNodesText) {
		t.Fatalf("257 Nodes: status %d, want 400 with %q; %s", rec.Code, tagTooManyNodesText, content)
	}
	if calls := refused.calls(); len(calls) != 1 || len(calls[0].Write.NodeIDs) != maxBulkTagNodes+1 {
		t.Errorf("257 Nodes: %d calls; want the whole list passed to WriteTag once", len(calls))
	}

	// More fields than net/url parses is unreadable, and refused before WriteTag.
	tw = &fakeTagWriter{}
	h = newTestHandlerSkippingCSRF(tagDeps(tw), accounts.RoleOperator)
	rec = postFormSkippingCSRF(t, h, bulkTagsAction, url.Values{
		"node_id": ids(netURLFieldCeiling + 1), "op": {"add"}, "label": {"tag:a=b"},
	})
	if rec.Code < 400 || len(tw.calls()) != 0 {
		t.Fatalf("a list past the parser's ceiling: status %d, %d calls; want a refusal and no call", rec.Code, len(tw.calls()))
	}
}

// maxLengthFleet is n Nodes matching node:role=web, each with an ID of exactly
// maxTagNodeIDBytes bytes: the largest confirmation form the bound must admit.
func maxLengthFleet(n int) []registry.Node {
	nodes := make([]registry.Node, 0, n)
	for i := range n {
		num := strconv.Itoa(i)
		nodes = append(nodes, registry.Node{
			NodeID:     strings.Repeat("n", maxTagNodeIDBytes-len(num)) + num,
			NodeLabels: map[string]string{"role": "web"},
			LastSeen:   testNow.Add(-4 * time.Second),
			Connected:  true,
		})
	}
	return nodes
}

func TestTags_TheConfirmPageAndItsPostAgreeAtTheCountBound(t *testing.T) {
	tw := &fakeTagWriter{}
	f := newLoginFixtureWith(t, func(d *Deps) {
		*d = withFleet(*d, maxLengthFleet(maxBulkTagNodes)...)
		d.Tags = tw
	})
	session := signedInSession(t, f, "mike", consolePassword)

	// At the bound: the page offers a form, and the form's own POST is accepted.
	rec := f.do(t, httptest.NewRequest(http.MethodGet, confirmWebLink, nil), session)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm at the bound = %d, want 200", rec.Code)
	}
	content := contentOf(rec.Body.String())
	form := url.Values{
		"node_id": hiddenValues(content, "node_id"), "op": hiddenValues(content, "op"), "label": hiddenValues(content, "label"),
	}
	if len(form["node_id"]) != maxBulkTagNodes {
		t.Fatalf("the confirm page lists %d Nodes, want %d", len(form["node_id"]), maxBulkTagNodes)
	}
	body := form.Encode()
	if int64(len(body)) >= maxBulkTagBodyBytes {
		t.Fatalf("the form's own body is %d bytes, not under the bound %d — the bound refuses what the page offers", len(body), maxBulkTagBodyBytes)
	}
	post := sessionTagPost(t, f, session, bulkTagsAction, body)
	if post.Code != http.StatusOK {
		t.Fatalf("the confirm form's POST = %d, want 200; %.200s", post.Code, post.Body.String())
	}
	if calls := tw.calls(); len(calls) != 1 || len(calls[0].Write.NodeIDs) != maxBulkTagNodes {
		t.Errorf("%d WriteTag calls, want one over %d IDs", len(calls), maxBulkTagNodes)
	}

	// One over: the page refuses with no form, and tells the operator to narrow.
	over := withFleet(sweepFixture(), maxLengthFleet(maxBulkTagNodes+1)...)
	over.Tags = tw
	rec = get(t, newTestHandler(over, accounts.RoleOperator), confirmWebLink)
	refusal := contentOf(rec.Body.String())
	if rec.Code != http.StatusBadRequest || strings.Contains(refusal, "<form") || !strings.Contains(refusal, tagTooManyNodesText) {
		t.Errorf("confirm over the bound = %d, form present %v; want a 400 sentence and no form", rec.Code, strings.Contains(refusal, "<form"))
	}
	if n := len(tw.calls()); n != 1 {
		t.Errorf("%d WriteTag calls after the refused page, want still 1", n)
	}
}

func TestTags_AMissingNodeRefusalNamesFewIDsAndCountsTheRest(t *testing.T) {
	var ids []string
	for i := range 40 {
		ids = append(ids, "ghost-"+strconv.Itoa(i))
	}
	h := newTestHandlerSkippingCSRF(tagDeps(&fakeTagWriter{err: &capability.TagNodesNotFoundError{NodeIDs: ids}}), accounts.RoleOperator)
	rec := postFormSkippingCSRF(t, h, bulkTagsAction, url.Values{"node_id": {"node-web-1"}, "op": {"add"}, "label": {"tag:a=b"}})
	content := contentOf(rec.Body.String())
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
	for _, id := range ids[:maxNamedMissingNodes] {
		if !strings.Contains(content, id) {
			t.Errorf("%s is not named", id)
		}
	}
	if strings.Contains(content, ids[maxNamedMissingNodes]+",") || strings.Contains(content, ids[maxNamedMissingNodes]+" ") {
		t.Errorf("%s is named; only the first %d are", ids[maxNamedMissingNodes], maxNamedMissingNodes)
	}
	if !strings.Contains(content, "and "+strconv.Itoa(len(ids)-maxNamedMissingNodes)+" more") {
		t.Errorf("the page does not count the rest: %s", content)
	}
	if got := tagMissingNodesHeading(ids[:maxNamedMissingNodes]); strings.Contains(got, "more") {
		t.Errorf("exactly %d IDs say %q, want no count", maxNamedMissingNodes, got)
	}
}

func TestTags_ConfirmRefusalsAreNotCachedAndTheirBackLinkIsWellFormed(t *testing.T) {
	h := newTestHandler(sweepFixture(), accounts.RoleOperator)
	backLink := regexp.MustCompile(`<a href="([^"]*)">Back to the fleet</a>`)
	for name, c := range map[string]struct {
		query    string
		wantBack string
	}{
		"empty filter":  {"op=add&label=tag%3Aa%3Db", fleetPath},
		"no match":      {"filter=node%3Arole%3Dnonesuch&op=add&label=tag%3Aa%3Db", fleetPath + "?filter=node%3Arole%3Dnonesuch"},
		"wrong label":   {"filter=node%3Arole%3Dweb&op=add&label=node%3Aa%3Db", fleetPath + "?filter=node%3Arole%3Dweb"},
		"refused query": {"filter=foo&group=env&op=add&label=tag%3Aa%3Db", fleetPath + "?filter=foo&group=env"},
	} {
		rec := get(t, h, confirmTagsPath+"?"+c.query)
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control = %q, want no-store", name, rec.Header().Get("Cache-Control"))
		}
		if got := backLink.FindStringSubmatch(rec.Body.String()); got == nil || html.UnescapeString(got[1]) != c.wantBack {
			t.Errorf("%s: back link = %v, want %q", name, got, c.wantBack)
		}
	}

	failing := tagDeps(&fakeTagWriter{err: capability.ErrTagChanged})
	rec := postFormSkippingCSRF(t, newTestHandlerSkippingCSRF(failing, accounts.RoleOperator), bulkTagsAction,
		url.Values{"node_id": {"node-web-1"}, "op": {"add"}, "label": {"tag:a=b"}})
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("a write refusal page Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}
}

// sessionTagPostWithHeaderToken posts raw body to path as the signed-in session
// with a genuine CSRF token for that session in the header, so the form carries
// no token of its own and a refusal cannot be the CSRF check's.
func sessionTagPostWithHeaderToken(t *testing.T, f *loginFixture, session *http.Cookie, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	token := renderedCSRFToken(f.do(t, httptest.NewRequest(http.MethodGet, "/console/nodes/node-web-1", nil), session).Body.String())
	if token == "" {
		t.Fatal("the Node page rendered no CSRF token")
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(csrfHeaderName, token)
	return f.do(t, req, session)
}

func TestTags_AnUnreadableFormIsRefusedWholeAndWritesNothing(t *testing.T) {
	// net/url salvages the readable pairs of a malformed body and returns an
	// error; Secure must refuse the body rather than let the CSRF check and the
	// handler act on what survived.
	manyFields := strings.Repeat("node_id=a&", netURLFieldCeiling+1)
	for name, c := range map[string]struct {
		path string
		body string
	}{
		"bulk, bad percent-escape":     {bulkTagsAction, "op=add&label=tag%3Aa%3Db&node_id=node-web-1&node_id=%zz"},
		"bulk, semicolon separator":    {bulkTagsAction, "op=add&label=tag%3Aa%3Db&node_id=node-web-1&node_id=x;y"},
		"bulk, past the field ceiling": {bulkTagsAction, "op=add&label=tag%3Aa%3Db&" + manyFields},
		"per-Node, bad percent-escape": {nodeTagsAction("node-web-1"), "op=add&label=tag%3Aa%3Db&pad=%zz"},
	} {
		for lane, post := range map[string]func(*testing.T, *loginFixture, *http.Cookie, string, string) *httptest.ResponseRecorder{
			"token in the form":   sessionTagPost,
			"token in the header": sessionTagPostWithHeaderToken,
		} {
			t.Run(name+", "+lane, func(t *testing.T) {
				tw := &fakeTagWriter{}
				f := tagLoginFixture(t, tw)
				session := signedInSession(t, f, "mike", consolePassword)
				rec := post(t, f, session, c.path, c.body)
				if rec.Code != http.StatusBadRequest {
					t.Errorf("status = %d, want 400; %.200s", rec.Code, rec.Body.String())
				}
				if n := len(tw.calls()); n != 0 {
					t.Errorf("WriteTag was called %d times for an unreadable form", n)
				}
			})
		}
	}
}

func TestTags_OnlyTheExactBulkSpellingGetsTheBulkBodyLimit(t *testing.T) {
	// ServeMux routes on the escaped path, so /console/nodes/..%2F/tags reaches
	// the per-Node handler even though its decoded, cleaned path is the bulk
	// route's. It, and an encoded spelling of the bulk route, get the small limit.
	pad := "op=add&label=tag%3Aa%3Db&pad=" + strings.Repeat("a", 2*maxFormBodyBytes)
	for _, path := range []string{"/console/nodes/..%2F/tags", "/console/nodes/x%2F..%2F..%2F/tags", "/console/%74ags"} {
		t.Run(path, func(t *testing.T) {
			tw := &fakeTagWriter{}
			f := tagLoginFixture(t, tw)
			session := signedInSession(t, f, "mike", consolePassword)
			rec := sessionTagPost(t, f, session, path, pad)
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Errorf("a %d-byte body to %s = %d, want 413", len(pad), path, rec.Code)
			}
			if n := len(tw.calls()); n != 0 {
				t.Errorf("WriteTag was called %d times", n)
			}
		})
	}
}
