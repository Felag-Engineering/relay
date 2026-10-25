package console

// no_inline_script_test.go is the Console's script policy, in three guards.
//
// The property being defended is "NO INLINE SCRIPT", not "no script". Those
// were the same thing until day one (#427) needed a live watch, and the
// specification is explicit about which one is the rule: "Behaviour that needs
// JavaScript lives in an external file served from the Console's own origin"
// (spec 11), because the content security policy admits `script-src 'self'`
// and nothing inline. A page that grows an inline handler still renders and
// quietly does not work — the failure a reviewer does not see.
//
// So the rendered-body guard below no longer bans the substring "<script". It
// asserts the SHAPE instead: every occurrence must carry a src under
// /console/assets/, and the element body must be empty.
//
// That is a NARROWER guard than a substring ban, so it comes with a second,
// stricter one that a substring ban never gave us: a SOURCE-level scan of the
// whole package. The rendered-body guard only ever sees the paths a test walks
// and the template branches those renders happen to take, so a <script> behind
// an unexercised {{if}} is invisible to it. The source scan sees every file
// regardless, and permits the byte sequence in exactly one of them.
//
// The third guard proves the first one is not applied selectively:
// TestConsole_EveryGetRouteIsSweptForCSP asserts that every GET route
// Routes() mounts is either rendered and swept for the whole ban list
// (assertCSPClean, below) or is one of a short, named list of routes that are
// not rendered screens at all.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

// assetPath is the only src a Console page may load: one plain file directly
// under /console/assets/HASH/, HASH being the current content hash. No
// traversal, no directory, no origin.
var assetPath = regexp.MustCompile(`^` + regexp.QuoteMeta(AssetsPrefix+assetHash+"/") + `[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)

// inlineHandler matches an on*= event-handler attribute in any of three
// shapes: immediately preceded by whitespace or a quote (`<button
// onclick="…">`, `<button class="x" onclick="…">`), immediately preceded by
// a solidus (`<img/onclick="go()">` — the solidus is a real attribute
// separator to the HTML tokenizer, not decoration: `/` between two unquoted
// attributes is exactly as much a boundary as a space is), or at the very
// START of the scanned text, with nothing before it at all (a fragment
// whose body BEGINS with `onclick=` — an HTMX fragment need not open with a
// tag). A class that only covered the first two shapes is not a superset of
// the components ban list (components_test.go's
// TestComponents_ContainNoInlineScript bans "onclick=" and "onload=" with no
// leading character requirement at all), so assertCSPClean's widened ban
// list (below) would have let the third shape newly pass.
//
// A match here is "a handler attribute OR rendered content that looks like
// one": the pattern also matches prose such as a space followed by "one=" or
// "only=". Fixtures that generate Node ids, label values and Task output
// must keep those strings alphanumeric with hyphens and nothing else.
var inlineHandler = regexp.MustCompile(`(^|["'/\s])on[a-z]+\s*=`)

// TestInlineHandler_MatchesEveryDroppedShape pins inlineHandler's coverage by
// test rather than by comment: each of the three shapes the doc comment above
// names failed to match under an earlier, narrower version of this regexp,
// and a future edit that narrows it again should fail here first.
func TestInlineHandler_MatchesEveryDroppedShape(t *testing.T) {
	matches := map[string]string{
		"quote-preceded":   `<main id="x"onclick="go()">`,
		"solidus-preceded": `<img/onclick="go()">`,
		"start-of-text":    `onclick="go()"`,
	}
	for name, s := range matches {
		if !inlineHandler.MatchString(s) {
			t.Errorf("%s: inlineHandler did not match %q — this shape must be caught", name, s)
		}
	}

	tolerated := []string{
		"Node abc123 is online and quarantined.",
		"The configuration is on the node, not the relay.",
		// A hyphen is not an attribute-name boundary either: "onclick=" here
		// is part of a longer identifier, not a handler attribute.
		`data-onclick="x"`,
		// "=" alone must not trip the check; only "on" immediately followed
		// by letters and then "=" does.
		"The setting is on. x=y is unrelated.",
	}
	for _, s := range tolerated {
		if inlineHandler.MatchString(strings.ToLower(s)) {
			t.Errorf("inlineHandler matched ordinary prose %q — it must tolerate this", s)
		}
	}
}

// attrValue reads a double-quoted attribute out of an already-lowercased open
// tag.
func attrValue(openTag, name string) (string, bool) {
	i := strings.Index(openTag, " "+name+`="`)
	if i < 0 {
		return "", false
	}
	rest := openTag[i+len(name)+3:]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return "", false
	}
	return rest[:j], true
}

// scriptHookFile is the ONE file in this package permitted to contain a script
// tag: the layout's external-file hook (Page.Scripts). Every screen renders
// through the layout, so one hook is all the package needs, and keeping it to
// one file means a reviewer looking for "how does script reach a Console page"
// has exactly one answer.
const scriptHookFile = "layout.go"

func TestConsole_NoScriptTagOutsideTheLayout(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	checked := 0
	literals := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		checked++
		src, readErr := os.ReadFile(filepath.Join(".", name))
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}
		if strings.Contains(strings.ToLower(string(src)), "<script") && name != scriptHookFile {
			t.Errorf("%s contains a script tag. The layout's Page.Scripts hook (%s) is the only "+
				"place one may appear: it emits an external file from this origin with an empty "+
				"body, which is the only shape the content security policy admits.", name, scriptHookFile)
		}

		// The SOURCE-level half of the guard (11-console-shell.md box 2): every
		// STRING LITERAL in the file, refused for hx-on:, javascript: and the
		// handler-attribute shape. This has to walk go/ast's *ast.BasicLit
		// values rather than the file's bytes — a raw byte scan FAILS here,
		// because hx-on: and javascript: both appear in Go comments
		// (layout.go, security.go) explaining why they are banned, and a
		// substring check over the whole file would flag its own
		// documentation. go/ast is already used in this package
		// (accounts_write_test.go), so this is an established pattern, not a
		// new one.
		//
		// This is a DRIFT guard, not an adversarial one: it catches a literal
		// handler attribute typed into a template, which is how one has
		// actually shipped here before. It is not proof against a string
		// built to evade it — `"hx-" + "on:"`, or a handler assembled from
		// variables at runtime, walks straight past a literal scan, and the
		// strconv.Unquote failure path below skips a literal it cannot read
		// rather than failing the build over it.
		//
		// It can also false-positive the same way the rendered-body check
		// does (assertCSPClean's doc comment, below): a future error message
		// or help text containing a space followed by "only=" or "one=" would
		// fail this scan too, because inlineHandler cannot tell a handler
		// attribute from prose that looks like one. And because inlineHandler
		// also matches at the very start of the scanned text (the `^` in its
		// prefix group), a Go string literal that itself BEGINS with
		// `on<letters>=` — e.g. `"only=true"` — trips this scan too, with no
		// leading character needed at all.
		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, filepath.Join(".", name), src, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			literals++
			val, unquoteErr := strconv.Unquote(lit.Value)
			if unquoteErr != nil {
				// A literal go/parser handed back but strconv could not
				// unquote is not a hazard this guard can read the content
				// of; skip it rather than fail the build over it.
				return true
			}
			lower := strings.ToLower(val)
			if strings.Contains(lower, "hx-on:") {
				t.Errorf("%s: string literal %q contains hx-on:, which IS script", name, val)
			}
			if strings.Contains(lower, "javascript:") {
				t.Errorf("%s: string literal %q contains javascript:, which IS script", name, val)
			}
			if m := inlineHandler.FindString(lower); m != "" {
				t.Errorf("%s: string literal %q contains the handler-attribute shape %q", name, val, strings.Trim(m, " \t\r\n\"'/"))
			}
			return true
		})
	}

	// A guard that silently checks nothing is worse than no guard: it reports
	// success forever. Assert it actually walked the package, and that the
	// literal scan actually inspected something.
	if checked == 0 {
		t.Fatal("script guard inspected zero files — the guard is not running")
	}
	if literals == 0 {
		t.Fatal("the string-literal CSP guard inspected zero literals — it is not running")
	}
}

// assertNoInlineScript asserts that every <script> in body is external, served
// from this origin, and empty.
//
// It covers the <script> SHAPE rule and only that. Everything else the
// content security policy bans (hx-on:, javascript:, every inline
// event-handler attribute, an inline style attribute) lives in assertCSPClean
// below, which calls this helper first and then applies the rest of the list.
func assertNoInlineScript(t *testing.T, path, body string) {
	t.Helper()

	// Lowercase before scanning: <SCRIPT> and <Script> are the same element to
	// a browser, so "every occurrence" has to mean every occurrence.
	lower := strings.ToLower(body)

	for i := 0; ; {
		rel := strings.Index(lower[i:], "<script")
		if rel < 0 {
			return
		}
		start := i + rel

		gt := strings.Index(lower[start:], ">")
		if gt < 0 {
			t.Errorf("%s: a <script tag is never closed — this cannot be reasoned about, so it fails", path)
			return
		}
		openTag := lower[start : start+gt+1]

		// A missing closing tag is a FAILURE, not something to skip past. A
		// self-closed or unterminated <script> is exactly the shape a
		// fail-open scanner walks straight through.
		closeRel := strings.Index(lower[start:], "</script>")
		if closeRel < 0 || closeRel < gt {
			t.Errorf("%s: a <script> element has no </script> — the content security policy admits "+
				"only an external, empty script element", path)
			return
		}

		if inner := strings.TrimSpace(body[start+gt+1 : start+closeRel]); inner != "" {
			t.Errorf("%s: a <script> element carries a body (%q) — the content security policy "+
				"admits no inline script", path, inner)
		}

		// The src is matched as a WHOLE VALUE, not as a prefix. A prefix
		// check passes `src="/console/assets/../../evil.js"`, which a
		// browser normalises to /evil.js before it fetches anything, and
		// `src="/console/assets/" onerror="…"`, where everything dangerous
		// is in the attribute the prefix check never looked at.
		src, ok := attrValue(openTag, "src")
		if !ok {
			t.Errorf("%s: a <script> element has no src (%q) — script-src 'self' admits only an "+
				"external file from this origin", path, openTag)
		} else if !assetPath.MatchString(src) {
			t.Errorf("%s: a <script> element loads %q — the only permitted shape is one plain file "+
				"under /console/assets/HASH/", path, src)
		}

		// An event-handler attribute on the tag IS inline script, and it
		// survives every check above because the element body is empty.
		if m := inlineHandler.FindString(openTag); m != "" {
			t.Errorf("%s: a <script> element carries the handler attribute %q, which is inline "+
				"script the content security policy blocks", path, strings.Trim(m, " \t\r\n\"'/"))
		}

		i = start + closeRel + len("</script>")
	}
}

// assertCSPClean is the one place the content security policy's whole
// ban list lives: assertNoInlineScript's SHAPE rule for <script>, plus
// hx-on:, javascript:, every inline event-handler attribute, and an inline
// style attribute in either quote form. It replaces five call sites' own
// copies of the same list, one of which (components_test.go) had no leading
// space on its onclick=/onload= entries and so was not a strict subset of
// the widened inlineHandler above — this helper is now the only place that
// distinction can drift back in.
//
// "Strict subset" holds in HTML-tokenizer semantics, not raw-substring
// terms: an attribute name starts only after whitespace, a `/`, a closing
// quote, or at the start of a fragment, and inlineHandler's `(^|["'/\s])`
// prefix requires one of exactly those boundaries. Non-attribute text such
// as `xonclick=` or `data-onclick=` no longer matches, deliberately — those
// are not attribute-name boundaries to a browser either.
//
// where names the call site for the failure message. It is not a URL: the
// components call site passes a template name, not a path, so "where" rather
// than "path".
//
// This holds over RENDERED HTML. It says nothing about a template branch no
// test's render walks — that half is TestConsole_NoScriptTagOutsideTheLayout's
// source-literal scan, above. And a match on the handler-attribute check
// below is "a handler attribute OR rendered content that looks like one":
// the pattern also matches prose such as a space followed by "one=" or
// "only=", so a fixture that generates Node ids, label values or Task output
// must keep those strings alphanumeric with hyphens and nothing else.
func assertCSPClean(t *testing.T, where, body string) {
	t.Helper()

	assertNoInlineScript(t, where, body)

	// Lowercase once, before every remaining check, so HX-ON: and OnClick=
	// cannot slip past a case-sensitive scan of the raw body — strictly
	// stronger than the copies this helper replaces, which scanned raw bytes.
	lower := strings.ToLower(body)

	for _, banned := range []string{"hx-on:", "javascript:"} {
		if strings.Contains(lower, banned) {
			t.Errorf("%s rendered %q — the content security policy admits no inline script", where, banned)
		}
	}

	if m := inlineHandler.FindString(lower); m != "" {
		t.Errorf("%s rendered the handler-attribute shape %q — an event-handler attribute is inline script",
			where, strings.Trim(m, " \t\r\n\"'/"))
	}

	// An inline STYLE is blocked by `style-src 'self'` exactly as an inline
	// script is blocked by `script-src 'self'` — and it fails far more
	// quietly, because the element still renders, just unstyled.
	//
	// This assertion exists because the outcome bar shipped with
	// style="width:N%" and every segment painted at zero width: the bar the
	// specification calls "the entire reason anyone is looking" had never
	// once been visible. The Go tests all passed, because they asserted the
	// segment was in the HTML and it was.
	if strings.Contains(lower, `style="`) || strings.Contains(lower, "style='") {
		t.Errorf("%s rendered an inline style attribute — the content security policy discards it, "+
			"so the element renders unstyled and nothing says so. Use a class or a data attribute.", where)
	}
}

// TestConsole_EveryGetRouteIsSweptForCSP is the "every GET route Routes()
// exposes" half of the issue, made mechanical rather than eyeballed.
//
// It does not render anything itself — TestScreens_NoInlineScriptSurvivesAnywhere
// and the five assertCSPClean call sites do that. This test proves the SET
// walkableScreens returns is complete: every GET route Routes() mounts is
// either in that set or is one of the three named, reasoned exemptions, and
// none of those three has quietly stopped existing.
//
// THE TRAP THIS AVOIDS: re-applying walkableScreens' own skip conditions here
// would make this test assert the skip list against itself. The three
// exemptions are spelled out as literals below instead, so this asserts the
// skip list against the ROUTE TABLE.
func TestConsole_EveryGetRouteIsSweptForCSP(t *testing.T) {
	d := sweepFixture()
	d.Events = newFakeEvents()
	d.Trust = fakeTrust{ca: testCAFingerprint, server: testServerFingerprint}

	routes := Routes(d)

	swept := map[string]bool{}
	for _, link := range walkableScreens(routes, fixtureIDs) {
		swept[link] = true
	}

	// Each exemption names why it is not a rendered screen:
	//   /console/assets/{path...} - serves bytes; stylesheet_test.go, jsassets_test.go
	//   /console/events           - text/event-stream, never parsed as HTML
	//   LoginPath                 - redirects a signed-in request; covered by
	//                               its own unauthenticated render in login_test.go
	exempt := map[string]bool{
		"/console/assets/{path...}": false,
		"/console/events":           false,
		LoginPath:                   false,
	}

	getRoutes := 0
	for _, r := range routes {
		if r.Method != http.MethodGet {
			continue
		}
		getRoutes++

		if _, ok := exempt[r.Path]; ok {
			exempt[r.Path] = true
			continue
		}

		// walkableScreens returns SUBSTITUTED LINKS (r.Link(), then
		// ReplaceAll per fixtureIDs placeholder), not route patterns — Link()
		// differs from Path for the root route ("/console/{$}" links as
		// "/console/") — so comparing against r.Path would be red on day one.
		link, ok := fixturePath(r, fixtureIDs)
		if !ok {
			t.Errorf("GET %s has no substitution in fixtureIDs, so walkableScreens silently skips it "+
				"— add one, or this route's CSP is unswept", r.Path)
			continue
		}
		if !swept[link] {
			t.Errorf("GET %s (%s) is not in walkableScreens' output — the CSP sweep does not cover it", r.Path, link)
		}
	}

	for path, seen := range exempt {
		if !seen {
			t.Errorf("the exemption for %s names a route that is no longer in Routes() — remove the stale exemption", path)
		}
	}
	if want := getRoutes - len(exempt); len(swept) != want {
		t.Errorf("walkableScreens swept %d paths, want %d (%d GET routes minus %d exemptions)",
			len(swept), want, getRoutes, len(exempt))
	}
}

// TestConsole_EveryScriptAScreenLoadsIsActuallyServed closes the other half of
// the CSP problem.
//
// assertNoInlineScript proves every <script> is EXTERNAL and shaped correctly.
// It says nothing about whether the file is there. A typo in a screen's
// p.Scripts produces a page that is perfectly conforming, renders fine, 404s
// one request, and silently has no behaviour — with every Go test green. That
// is the same class of failure as the stylesheet that was never mounted (#439)
// and the inline style the CSP discarded (components.go): correct-looking
// markup pointing at nothing.
//
// Derived from the route table, so a screen added later is covered without
// anyone remembering to add it — and so is any script it loads.
func TestConsole_EveryScriptAScreenLoadsIsActuallyServed(t *testing.T) {
	d := fleetFixture()
	// Both live screens mount scripts only when the event seam is wired, so
	// an unwired sweep would walk right past the thing this test is for.
	d.Events = newFakeEvents()
	d.Trust = fakeTrust{ca: testCAFingerprint, server: testServerFingerprint}
	// nodes is carried forward from fleetFixture's fleet (#680): this literal
	// REPLACES d.Queries rather than extending it.
	d.Queries = &fakeQueries{
		nodes: fleetNodes(d),
	}
	h := newTestHandler(d, accounts.RoleAdmin)

	paths := walkableScreens(Routes(d), fixtureIDs)
	// Day one renders only on an empty registry, and it is one of the two
	// screens that loads a script.
	empty := dayOneDeps()
	empty.Queries = &fakeQueries{}

	checked := 0
	renders := map[string]http.Handler{}
	for _, p := range paths {
		renders[p] = h
	}
	renders["/console/"+dayOneMarker] = newTestHandler(empty, accounts.RoleAdmin)

	for path, handler := range renders {
		fetch := path
		if fetch == "/console/"+dayOneMarker {
			fetch = "/console/"
		}
		body := get(t, handler, fetch).Body.String()
		for _, src := range scriptSources(body) {
			checked++
			rec := get(t, handler, src)
			if rec.Code != http.StatusOK {
				t.Errorf("%s loads %s, which the asset route answers %d — the page conforms to the "+
					"content security policy and has no behaviour at all", fetch, src, rec.Code)
				continue
			}
			if rec.Body.Len() == 0 {
				t.Errorf("%s loads %s, which is served empty", fetch, src)
			}
		}
	}

	// The guard must be finding scripts, or it proves nothing. Day one and
	// Activity load two each.
	if checked < 4 {
		t.Fatalf("the sweep fetched %d scripts — it is not finding the screens that load them", checked)
	}
}

// dayOneMarker distinguishes the zero-Node render of "/console/" from the
// fleet render of the same path in the map above.
const dayOneMarker = "#dayone"

// scriptSources returns every <script src> in body.
func scriptSources(body string) []string {
	var out []string
	lower := strings.ToLower(body)
	for i := 0; ; {
		rel := strings.Index(lower[i:], "<script")
		if rel < 0 {
			return out
		}
		start := i + rel
		gt := strings.Index(lower[start:], ">")
		if gt < 0 {
			return out
		}
		if src, ok := attrValue(lower[start:start+gt+1], "src"); ok {
			out = append(out, src)
		}
		i = start + gt + 1
	}
}
