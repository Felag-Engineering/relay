package console

// no_inline_script_test.go is the Console's script policy, in two guards.
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

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
)

// assetPath is the only src a Console page may load: one plain file directly
// under /console/assets/. No traversal, no directory, no origin.
var assetPath = regexp.MustCompile(`^/console/assets/[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)

// inlineHandler matches an on*= event-handler attribute.
var inlineHandler = regexp.MustCompile(`\son[a-z]+\s*=`)

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
		if !strings.Contains(strings.ToLower(string(src)), "<script") {
			continue
		}
		if name != scriptHookFile {
			t.Errorf("%s contains a script tag. The layout's Page.Scripts hook (%s) is the only "+
				"place one may appear: it emits an external file from this origin with an empty "+
				"body, which is the only shape the content security policy admits.", name, scriptHookFile)
		}
	}

	// A guard that silently checks nothing is worse than no guard: it reports
	// success forever. Assert it actually walked the package.
	if checked == 0 {
		t.Fatal("script guard inspected zero files — the guard is not running")
	}
}

// assertNoInlineScript asserts that every <script> in body is external, served
// from this origin, and empty.
//
// Shared by the shell's guard and the every-screen sweep, which keep their own
// separate ban-lists for everything else (hx-on:, javascript:, onclick=,
// onload=, style=) — this helper covers the script rule and only that.
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
				"under /console/assets/", path, src)
		}

		// An event-handler attribute on the tag IS inline script, and it
		// survives every check above because the element body is empty.
		if m := inlineHandler.FindString(openTag); m != "" {
			t.Errorf("%s: a <script> element carries the handler attribute %q, which is inline "+
				"script the content security policy blocks", path, strings.TrimSpace(m))
		}

		i = start + closeRel + len("</script>")
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
	d := withExecution(fleetFixture(), true)
	// Both live screens mount scripts only when the event seam is wired, so
	// an unwired sweep would walk right past the thing this test is for.
	d.Events = newFakeEvents()
	d.Trust = fakeTrust{ca: testCAFingerprint, server: testServerFingerprint}
	d.Queries = &fakeQueries{}
	h := newTestHandler(d, accounts.RoleAdmin)

	paths := walkableScreens(d, fixtureIDs)
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
