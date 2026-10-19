package console

// phone_layout_test.go guards #832's phone layout at the seams Go can see:
// the markup that pairs each filter label with its control, the data-label
// that names every card cell, the menu fold that needs no script, and the
// order of rules in console.css that makes the fold work. Go has no layout
// engine, so these assert the structure that makes the rendering true; the
// rendering itself is checked in a browser.

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

var (
	vfieldPairPattern = regexp.MustCompile(
		`<div class="vfield[^"]*">\s*<label class="vlabel" for="([^"]+)">[^<]*</label>\s*<(?:input|select)[^>]*\bid="([^"]+)"`)
	dataLabelPattern = regexp.MustCompile(`<td\b[^>]*\bdata-label="([^"]*)"`)
	tdOpenPattern    = regexp.MustCompile(`<td\b[^>]*>`)
)

func TestConsole_EveryFilterLabelIsWrappedWithItsControl(t *testing.T) {
	pages := map[string]struct {
		d    Deps
		path string
	}{
		"fleet":    {fleetFixture(), "/console/"},
		"activity": {sweepFixture(), "/console/activity"},
		"access":   {accessDeps(&fakeQueries{}), "/console/access"},
	}
	for name, p := range pages {
		body := get(t, newTestHandler(p.d, accounts.RoleAdmin), p.path).Body.String()
		pairs := vfieldPairPattern.FindAllStringSubmatch(body, -1)
		if len(pairs) == 0 {
			t.Errorf("%s: no .vfield wraps a label and its control", name)
		}
		if labels := strings.Count(body, `class="vlabel"`); len(pairs) != labels {
			t.Errorf("%s: %d filter labels but %d are wrapped with their control", name, labels, len(pairs))
		}
		for _, m := range pairs {
			if m[1] != m[2] {
				t.Errorf("%s: label for=%q is wrapped with the control id=%q", name, m[1], m[2])
			}
		}
	}
}

// cardTable returns the markup of the first <table class="..."> with exactly
// the given class attribute, up to its closing tag.
func cardTable(t *testing.T, body, class string) string {
	t.Helper()
	i := strings.Index(body, `<table class="`+class+`"`)
	if i < 0 {
		t.Fatalf(`no <table class="%s"> rendered`, class)
	}
	j := strings.Index(body[i:], "</table>")
	if j < 0 {
		t.Fatalf("table %q has no closing tag", class)
	}
	return body[i : i+j]
}

func labelsOf(table string) map[string]bool {
	got := map[string]bool{}
	for _, m := range dataLabelPattern.FindAllStringSubmatch(table, -1) {
		got[m[1]] = true
	}
	return got
}

func TestFleet_PhoneCardsLabelEveryCell(t *testing.T) {
	body := get(t, newTestHandler(fleetFixture(), accounts.RoleAdmin), "/console/").Body.String()
	table := cardTable(t, body, "cards")
	rows := strings.Count(table, "<tr>") - 1 // minus the header row
	if rows < 1 {
		t.Fatal("the Fleet card table has no body rows — this guard is not running")
	}
	for _, td := range tdOpenPattern.FindAllString(table, -1) {
		if !strings.Contains(td, "data-label=") && !strings.Contains(td, "livecell") {
			t.Errorf("a Fleet cell is neither labelled nor the liveness cell: %s", td)
		}
	}
	got := labelsOf(table)
	for _, want := range []string{"Node · hostname self-reported", "State", "Last seen", "Pin to compare"} {
		if !got[want] {
			t.Errorf("no Fleet cell is labelled %q; labels: %v", want, got)
		}
	}
	if !strings.Contains(table, `class="pinbtn"`) {
		t.Error("the Fleet card table has no pin toggle for the guard to cover")
	}
}

func TestAccounts_PhoneCardsLabelEveryCell(t *testing.T) {
	body := accountsWriteBody(t, "?account=gleipnir-prod")
	table := cardTable(t, body, "rows cards")
	for _, td := range tdOpenPattern.FindAllString(table, -1) {
		if !strings.Contains(td, "data-label=") {
			t.Errorf("an Accounts cell is unlabelled: %s", td)
		}
	}
	if got := labelsOf(table); !got["Account"] || !got["State"] {
		t.Errorf("Accounts cells lack the Account and State labels; labels: %v", got)
	}
	// The API-token table is a different table and is not reflowed here.
	if strings.Count(body, `class="rows cards"`) != 1 {
		t.Errorf("want exactly one card table on Accounts, got %d", strings.Count(body, `class="rows cards"`))
	}
}

func TestCompare_EveryValueCellNamesItsColumn(t *testing.T) {
	body := get(t, newTestHandler(fleetFixture(), accounts.RoleAdmin), "/console/compare?nodes=node-web-1,node-web-2").Body.String()
	table := cardTable(t, body, "cmp")
	got := labelsOf(table)
	for _, id := range []string{"node-web-1", "node-web-2"} {
		if !got[id] {
			t.Errorf("no Compare value cell is labelled with the Node ID %q; labels: %v", id, got)
		}
	}
	for label := range got {
		if label != "node-web-1" && label != "node-web-2" {
			t.Errorf("Compare value cell labelled %q, which is not a rendered column ID", label)
		}
	}
	if !strings.Contains(table, "<code>") || !strings.Contains(table, "<pre>") {
		t.Error("labelled Compare cells lost their <code> or <pre> content wrapper")
	}
}

func TestLayout_PhoneNavCollapsesWithoutScript(t *testing.T) {
	body := get(t, newTestHandler(renderableDeps(), accounts.RoleAdmin), "/console/").Body.String()
	aside := strings.Index(body, `<aside class="nav">`)
	toggle := strings.Index(body, `id="navtoggle"`)
	navbody := strings.Index(body, `<div class="navbody">`)
	nav := strings.Index(body, `<nav class="navgroups"`)
	navEnd := strings.Index(body, "</nav>")
	foot := strings.Index(body, `<div class="navfoot">`)
	asideEnd := strings.Index(body, "</aside>")
	if !strings.Contains(body, `<label for="navtoggle" class="navbtn">Menu</label>`) {
		t.Error("the Menu label is not tied to the checkbox")
	}
	if aside < 0 || toggle < aside || navbody < toggle || nav < navbody || navEnd < nav || foot < navEnd || asideEnd < foot {
		t.Errorf("shell order wrong: aside=%d toggle=%d navbody=%d nav=%d /nav=%d foot=%d /aside=%d",
			aside, toggle, navbody, nav, navEnd, foot, asideEnd)
	}
}

// topLevelRuleStarts returns, for each top-level selector in the
// comment-stripped css, the byte offset where it starts.
func topLevelRuleStarts(t *testing.T, css string) map[string]int {
	t.Helper()
	starts := map[string]int{}
	depth, selectorStart := 0, 0
	for i, r := range css {
		switch r {
		case '{':
			if depth == 0 {
				starts[strings.TrimSpace(css[selectorStart:i])] = selectorStart
				if matchingBrace(css, i) < 0 {
					t.Fatalf("unmatched { at byte %d in console.css", i)
				}
			}
			depth++
		case '}':
			depth--
			if depth == 0 {
				selectorStart = i + 1
			}
		}
	}
	return starts
}

func TestConsole_PhoneLayoutRulesLiveInTheirBreakpoints(t *testing.T) {
	raw, err := assetsFS.ReadFile("assets/console.css")
	if err != nil {
		t.Fatalf("read console.css: %v", err)
	}
	css := cssCommentPattern.ReplaceAllString(string(raw), "")

	narrow := mediaBlock(css, "max-width: 800px")
	for _, want := range []string{".navbody { display: none; }", ".navtoggle:checked ~ .navbody"} {
		if !strings.Contains(narrow, want) {
			t.Errorf("the 800px block lacks %q", want)
		}
	}
	phone := mediaBlock(css, "max-width: 600px")
	for _, want := range []string{
		"table.cards td[data-label]::before", "content: attr(data-label)",
		".vfield, .vfield.wide { flex-basis: 100%; }",
		"table.cards caption, .cmp caption { display: block;",
		"table.cards td.pincell .pinbtn",
	} {
		if !strings.Contains(phone, want) {
			t.Errorf("the 600px block lacks %q", want)
		}
	}

	// The desktop defaults must come BEFORE the media block that overrides
	// them: at equal specificity the later rule wins.
	starts := topLevelRuleStarts(t, css)
	narrowAt := starts["@media (max-width: 800px)"]
	phoneAt := starts["@media (max-width: 600px)"]
	if narrowAt == 0 || phoneAt == 0 {
		t.Fatal("could not locate the 800px and 600px blocks at top level")
	}
	for list, at := range starts {
		// A selector list is judged part by part: ".foo, .navbody {}" is
		// still a navbody rule.
		for _, sel := range strings.Split(list, ",") {
			sel = strings.TrimSpace(sel)
			for _, c := range []string{".navtoggle", ".navtop", ".navbtn", ".navbody"} {
				if strings.HasPrefix(sel, c) && at > narrowAt {
					t.Errorf("top-level %q is declared after the 800px block and would override its phone rules", sel)
				}
			}
			if strings.HasPrefix(sel, ".vfield") && at > phoneAt {
				t.Errorf("top-level %q is declared after the 600px block and would override its phone rules", sel)
			}
		}
	}
}
