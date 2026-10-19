package console

// freshness_test.go proves 00-foundations.md "How old a page is": Fleet states
// its age in words, an old page says so in weight and never in amber, the
// words are right with scripts off, and the script that advances them asks
// for nothing.

import (
	"bytes"
	"html"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

func TestRenderedAge_OldPageSaysSoInWordsAndWeight(t *testing.T) {
	render := func(age time.Duration) string {
		var b bytes.Buffer
		if err := componentsTmpl.ExecuteTemplate(&b, "rendered-age", newRenderedAge(testNow.Add(-age), testNow)); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}

	old := render(12 * time.Minute)
	for _, want := range []string{
		`datetime="2026-08-25 11:48:00Z"`, `title="2026-08-25 11:48:00Z"`,
		`data-age="720"`, `data-stale="yes"`, ">rendered 12 min ago, Refresh to re-read</time>",
	} {
		if !strings.Contains(old, want) {
			t.Errorf("an old page lacks %s:\n%s", want, old)
		}
	}

	fresh := render(40 * time.Second)
	if !strings.Contains(fresh, ">rendered 40s ago</time>") || strings.Contains(fresh, "data-stale") {
		t.Errorf("a fresh page is marked or worded as old:\n%s", fresh)
	}
}

// TestFreshness_OldIsWeightNotAmber: an old page is heavier, never amber —
// amber is for the fleet's own attention states.
func TestFreshness_OldIsWeightNotAmber(t *testing.T) {
	css := cssCommentPattern.ReplaceAllString(readAsset(t, "assets/console.css"), "")
	var staleRules int
	for _, m := range cssRulePattern.FindAllStringSubmatch(css, -1) {
		selector, decls := m[1], m[2]
		if !strings.Contains(selector, "data-stale") && !strings.Contains(selector, ".asat") {
			continue
		}
		if strings.Contains(selector, "data-stale") {
			staleRules++
			if _, ok := declValue(decls, "font-weight"); !ok {
				t.Errorf("%s does not draw an old page heavier", strings.TrimSpace(selector))
			}
		}
		for _, banned := range []string{"attention", "amber", "warning"} {
			if strings.Contains(strings.ToLower(decls), banned) {
				t.Errorf("%s uses %s; an old page is never amber", strings.TrimSpace(selector), banned)
			}
		}
	}
	if staleRules == 0 {
		t.Error("no rule styles data-stale")
	}
}

var scriptTag = regexp.MustCompile(`<script\b[^>]*>`)

func TestFleet_ReadsCorrectlyWithScriptsOff(t *testing.T) {
	rec := get(t, newTestHandler(fleetFixture(), accounts.RoleAdmin), "/console/")
	body := rec.Body.String()
	content := contentOf(body)

	if !strings.Contains(content, "rendered just now</time>") {
		t.Error("the server-rendered text does not state the page's age")
	}
	if tags := scriptTag.FindAllString(body, -1); len(tags) != 1 || tags[0] != `<script src="/console/assets/freshness.js" defer>` {
		t.Errorf("Fleet's scripts = %q, want only freshness.js", tags)
	}
	if !strings.Contains(content, `<a class="refreshbtn"`) {
		t.Error("Refresh is not a plain link")
	}
	if strings.Contains(strings.ToLower(body), `http-equiv="refresh"`) {
		t.Error("Fleet reloads itself on a timer")
	}
	if !strings.Contains(body, "<time ") {
		t.Error("the age is not in a <time>")
	}
}

// TestFleet_RefreshIsAnAuditedRead backs the sentence beside Fleet's Refresh
// with the read the page makes.
func TestFleet_RefreshIsAnAuditedRead(t *testing.T) {
	refreshHref := regexp.MustCompile(`class="refreshbtn" href="([^"]*)"`)
	for _, path := range []string{
		"/console/?group=env",
		"/console/?filter=tag:x",
		"/console/?filter=node:role=nonesuch",
	} {
		t.Run(path, func(t *testing.T) {
			d := fleetFixture()
			q := d.Queries.(*fakeQueries)
			h := newTestHandler(d, accounts.RoleAdmin)
			m := refreshHref.FindStringSubmatch(get(t, h, path).Body.String())
			if m == nil {
				t.Fatal("the page renders no Refresh link")
			}
			before := q.listNodeCalls
			get(t, h, html.UnescapeString(m[1]))
			if q.listNodeCalls != before+1 {
				t.Errorf("following Refresh made %d list reads, want 1", q.listNodeCalls-before)
			}
		})
	}
}

// The text-level bans run without node; the DOM test then proves behaviour.
func TestAssets_FreshnessScriptRequestsAndReloadsNothing(t *testing.T) {
	var code []string
	for _, line := range strings.Split(readAsset(t, "assets/freshness.js"), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "//") {
			code = append(code, line)
		}
	}
	src := strings.Join(code, "\n")

	for _, banned := range []string{
		"fetch", "XMLHttpRequest", "EventSource", "sendBeacon", "WebSocket", "postMessage",
		"location", "reload", "navigator", ".open(", ".src", ".href", "document.write",
		"innerHTML", "outerHTML", "insertAdjacentHTML", "cookie", "Storage",
		"eval", "Function(", "import(", "setInterval", "addEventListener", "aria-live", "role",
	} {
		if strings.Contains(src, banned) {
			t.Errorf("freshness.js contains %q", banned)
		}
	}
	for _, required := range []string{"textContent", "data-rendered-age", "data-age"} {
		if !strings.Contains(src, required) {
			t.Errorf("freshness.js lacks %q", required)
		}
	}
	for _, m := range regexp.MustCompile(`setAttribute\(([^,)]*)`).FindAllStringSubmatch(src, -1) {
		if m[1] != `"data-stale"` {
			t.Errorf("freshness.js sets attribute %s; only data-stale is allowed", m[1])
		}
	}
}
