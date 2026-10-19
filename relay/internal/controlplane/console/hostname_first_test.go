package console

// hostname_first_test.go guards 00-foundations "Self-reported names": wherever
// a Node is shown to a human its self-reported hostname leads and the full
// verified ID follows, while every link, pin and form value carries the ID.

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

const (
	hfAlpha = "node-4e05a1c9aa01"
	hfBravo = "node-4e05a1c9bb02"
	hfPlain = "node-4e05a1c9cc03" // no hostname
	hfShape = "node-4e05a1c9dd04" // hostname shaped like a Node ID
	hfBidi  = "node-4e05a1c9ee05" // hostname with a bidi control
)

// hostnameFirstFleet gives every Node a distinct Policy fingerprint, so the
// Compare table renders whichever rows a view keeps.
func hostnameFirstFleet() Deps {
	node := func(id, host, fp string) registry.Node {
		return registry.Node{NodeID: id, Facts: registry.Facts{Hostname: host}, PolicyFingerprint: fp, Connected: true, LastSeen: testNow}
	}
	return withFleet(renderableDeps(),
		node(hfAlpha, "alpha", strings.Repeat("a", 64)),
		node(hfBravo, "bravo", strings.Repeat("b", 64)),
		node(hfPlain, "", strings.Repeat("c", 64)),
		node(hfShape, "node-0123abcd", strings.Repeat("d", 64)),
		node(hfBidi, "al\u202epha", strings.Repeat("e", 64)),
	)
}

func hostnameFirstBody(t *testing.T, path string) string {
	t.Helper()
	return get(t, newTestHandler(hostnameFirstFleet(), accounts.RoleAdmin), path).Body.String()
}

var cmpnodeHeading = regexp.MustCompile(`(?s)<th scope="col" class="cmpnode">.*?</th>`)

func compareHeadings(t *testing.T, body string) []string {
	t.Helper()
	got := cmpnodeHeading.FindAllString(body, -1)
	if len(got) == 0 {
		t.Fatal("no Compare column headings rendered")
	}
	return got
}

func TestCompare_HeadingLeadsWithHostnameOverTheFullID(t *testing.T) {
	body := hostnameFirstBody(t, "/console/compare?nodes="+hfAlpha+","+hfBravo)
	heading := compareHeadings(t, body)[0]

	steps := []string{
		`<a href="/console/nodes/` + hfAlpha + `?pin=` + hfAlpha + `%2C` + hfBravo + `" class="cmpname">`,
		`<span class="selfrep" title="` + selfReportedTitleEscaped() + `">alpha</span>`,
		`<span class="selfreptag">self-reported</span>`,
		`<code class="nodeid">` + hfAlpha + `</code>`,
	}
	rest := heading
	for _, step := range steps {
		i := strings.Index(rest, step)
		if i < 0 {
			t.Fatalf("heading lacks %q, in this order; heading:\n%s", step, heading)
		}
		rest = rest[i+len(step):]
	}
	if strings.Contains(body, `<div class="sub">alpha</div>`) {
		t.Error("the hostname is still drawn as a secondary line")
	}
}

func TestCompare_ValueCellLabelsLeadWithHostname(t *testing.T) {
	body := hostnameFirstBody(t, "/console/compare?nodes="+hfAlpha+","+hfBravo)
	got := labelsOf(cardTable(t, body, "cmp"))
	want := map[string]bool{
		"alpha (self-reported) · " + hfAlpha: true,
		"bravo (self-reported) · " + hfBravo: true,
	}
	if len(got) != len(want) {
		t.Fatalf("labels = %v, want %v", got, want)
	}
	for label := range want {
		if !got[label] {
			t.Errorf("labels = %v, want %v", got, want)
		}
	}
}

func TestCompare_UnusableHostnameFallsBackToTheID(t *testing.T) {
	body := hostnameFirstBody(t, "/console/compare?nodes="+hfPlain+","+hfShape+","+hfBidi)
	headings := compareHeadings(t, body)
	if len(headings) != 3 {
		t.Fatalf("want 3 headings, got %d", len(headings))
	}
	for i, id := range []string{hfPlain, hfShape, hfBidi} {
		h := headings[i]
		if !strings.Contains(h, `<code class="nodeid">`+id+`</code>`) {
			t.Errorf("heading %d lacks the full ID %q:\n%s", i, id, h)
		}
		if strings.Contains(h, "selfrep") {
			t.Errorf("heading %d for %q carries a self-reported marking with no usable hostname:\n%s", i, id, h)
		}
	}
	got := labelsOf(cardTable(t, body, "cmp"))
	for _, id := range []string{hfPlain, hfShape, hfBidi} {
		if !got[id] {
			t.Errorf("no value cell is labelled with the bare ID %q; labels: %v", id, got)
		}
	}
	for _, raw := range []string{"node-0123abcd", "al\u202epha"} {
		if strings.Contains(body, raw) {
			t.Errorf("the unusable self-report %q reached the page", raw)
		}
	}
}

// chipFor returns the pin chip whose markup names id, from its opening span to
// the end of its unpin link.
func chipFor(t *testing.T, body, id string) string {
	t.Helper()
	for _, part := range strings.Split(body, `<span class="pinchip">`)[1:] {
		end := strings.Index(part, `class="unpin"`)
		if end < 0 {
			continue
		}
		// Hrefs carry the whole pin set, so only the drawn ID says whose chip
		// this is.
		if strings.Contains(part[:end], `">`+id+`</code>`) {
			return part[:end+strings.Index(part[end:], "</a>")]
		}
	}
	t.Fatalf("no pin chip names %q", id)
	return ""
}

var hostnameFirstPinnedScreens = []struct {
	name, path, unpinBravo string
}{
	{"fleet", "/console/?pin=" + hfAlpha + "," + hfBravo, `href="/console/?pin=` + hfAlpha + `"`},
	{"node detail", "/console/nodes/" + hfPlain + "?pin=" + hfAlpha + "," + hfBravo, `href="/console/nodes/` + hfPlain + `?pin=` + hfAlpha + `"`},
	{"compare", "/console/compare?nodes=" + hfAlpha + "," + hfBravo, `href="/console/compare?nodes=` + hfAlpha + `"`},
}

func TestPinChips_LeadWithHostnameOverTheFullID(t *testing.T) {
	for _, tc := range hostnameFirstPinnedScreens {
		t.Run(tc.name, func(t *testing.T) {
			body := hostnameFirstBody(t, tc.path)
			pin := hfAlpha + `%2C` + hfBravo
			wantAlpha := `<a href="/console/nodes/` + hfAlpha + `?pin=` + pin + `"><span class="selfrep" title="` + selfReportedTitleEscaped() +
				`">alpha<span class="vh"> (self-reported)</span></span> <code class="nodeid">` + hfAlpha + `</code></a>`
			if chip := chipFor(t, body, hfAlpha); !strings.Contains(chip, wantAlpha) {
				t.Errorf("alpha chip lacks %q:\n%s", wantAlpha, chip)
			}
			if chip := chipFor(t, body, hfBravo); !strings.Contains(chip, `>bravo<`) || !strings.Contains(chip, tc.unpinBravo) {
				t.Errorf("bravo chip does not lead with its hostname or lacks the unpin link %s:\n%s", tc.unpinBravo, chip)
			}
		})
	}
}

func TestPinChips_CurrentAndFallbackAndUnknown(t *testing.T) {
	body := hostnameFirstBody(t, "/console/nodes/"+hfAlpha+"?pin="+hfAlpha+","+hfPlain+",node-typo")

	node := `<span class="selfrep" title="` + selfReportedTitleEscaped() + `">alpha<span class="vh"> (self-reported)</span></span> <code class="nodeid">` + hfAlpha + `</code>`
	current := chipFor(t, body, hfAlpha)
	if want := `<span class="pinname">` + node + `</span><span class="dim">this Node</span>`; !strings.Contains(current, want) {
		t.Errorf("current chip lacks %q:\n%s", want, current)
	}
	if strings.Contains(current[:strings.Index(current, `class="unpin"`)], "<a href") {
		t.Errorf("the current chip links to the page already open:\n%s", current)
	}

	plain := `<a href="/console/nodes/` + hfPlain + `?pin=` + hfAlpha + `%2C` + hfPlain + `%2Cnode-typo"><code class="nodeid">` + hfPlain + `</code></a>`
	if chip := chipFor(t, body, hfPlain); !strings.Contains(chip, plain) || strings.Contains(chip, "selfrep") {
		t.Errorf("a Node with no hostname should lead with its bare ID, want %q:\n%s", plain, chip)
	}

	typo := chipFor(t, body, "node-typo")
	if !strings.Contains(typo, `<code class="dim">node-typo</code>`) || !strings.Contains(typo, "not in this registry") || strings.Contains(typo, "selfrep") {
		t.Errorf("an unresolved id changed its dead chip:\n%s", typo)
	}
}

var (
	hrefOrActionPattern = regexp.MustCompile(`\b(?:href|action)="([^"]*)"`)
	inputValuePattern   = regexp.MustCompile(`<input\b[^>]*\bvalue="([^"]*)"`)
)

func TestHostnameFirst_LinksPinsAndSelectorsCarryOnlyIDs(t *testing.T) {
	for _, tc := range hostnameFirstPinnedScreens {
		t.Run(tc.name, func(t *testing.T) {
			body := hostnameFirstBody(t, tc.path)
			var carried []string
			for _, m := range hrefOrActionPattern.FindAllStringSubmatch(body, -1) {
				carried = append(carried, m[1])
			}
			for _, m := range inputValuePattern.FindAllStringSubmatch(body, -1) {
				carried = append(carried, m[1])
			}
			if len(carried) == 0 {
				t.Fatal("collected no links or form values; this guard is not running")
			}
			for _, v := range carried {
				if strings.Contains(v, "alpha") || strings.Contains(v, "bravo") {
					t.Errorf("a link or form value carries a hostname: %q", v)
				}
			}
		})
	}
}

func TestPinChips_OnwardCompareLinkCarriesOnlyIDs(t *testing.T) {
	want := `href="/console/compare?nodes=` + hfAlpha + `%2C` + hfBravo + `"`
	for _, tc := range hostnameFirstPinnedScreens {
		if tc.name == "compare" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			if body := hostnameFirstBody(t, tc.path); !strings.Contains(body, want) {
				t.Errorf("the onward Compare link is not %s", want)
			}
		})
	}
}

func TestBuildPinState_UnresolvedIDCarriesNoHostname(t *testing.T) {
	// A resolver that reports a name for an id it does not know must not
	// have that name shown.
	resolve := func(string) (string, bool) { return "x", false }
	p := buildPinState(resolve, []string{"node-typo"}, fleetPath, "pin")
	if len(p.Pins) != 1 {
		t.Fatalf("want one pin, got %d", len(p.Pins))
	}
	if pin := p.Pins[0]; pin.Known || pin.Hostname != "" || pin.Href != "" {
		t.Errorf("dead chip should carry no hostname or link, got %+v", pin)
	}
}

func TestFleet_WallTooltipLeadsWithHostname(t *testing.T) {
	body := hostnameFirstBody(t, "/console/")
	for _, want := range []string{
		`title="alpha (self-reported) · ` + hfAlpha + ` · `,
		`title="` + hfPlain + ` · `,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("wall tooltips lack %q", want)
		}
	}
}

// TestConsole_NodeIDIsNeverTruncated makes "smaller, mono, muted, in full" a
// test: no rule may clip a Node ID, and the secondary-ID rule exists.
func TestConsole_NodeIDIsNeverTruncated(t *testing.T) {
	raw, err := assetsFS.ReadFile("assets/console.css")
	if err != nil {
		t.Fatalf("read console.css: %v", err)
	}
	css := cssCommentPattern.ReplaceAllString(string(raw), "")

	var secondary, nodeid string
	for _, m := range cssRulePattern.FindAllStringSubmatch(css, -1) {
		sel, decls := strings.TrimSpace(m[1]), m[2]
		for _, prop := range []string{"text-overflow", "line-clamp", "-webkit-line-clamp"} {
			if _, ok := declValue(decls, prop); ok {
				t.Errorf("%s declares %s, which can hide part of a Node ID", sel, prop)
			}
		}
		if strings.Contains(sel, ".nodeid") || strings.Contains(sel, ".selfrep") || strings.Contains(sel, "data-label") {
			if v, ok := declValue(decls, "overflow"); ok && v == "hidden" {
				t.Errorf("%s declares overflow: hidden", sel)
			}
			if _, ok := declValue(decls, "max-width"); ok {
				t.Errorf("%s declares max-width", sel)
			}
		}
		switch sel {
		case ".selfrep ~ .nodeid":
			secondary = decls
		case ".nodeid":
			nodeid = decls
		}
	}
	if secondary == "" {
		t.Fatal("no `.selfrep ~ .nodeid` rule: the secondary ID has no styling")
	}
	if v, _ := declValue(secondary, "font-size"); v != "var(--text-xs)" {
		t.Errorf("secondary ID font-size = %q, want var(--text-xs)", v)
	}
	if v, _ := declValue(secondary, "color"); v != "var(--text-muted)" {
		t.Errorf("secondary ID color = %q, want var(--text-muted)", v)
	}
	if v, _ := declValue(nodeid, "font-family"); v != "var(--font-mono)" {
		t.Errorf(".nodeid font-family = %q, want var(--font-mono)", v)
	}
}
