package console

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// systemStateOf returns the System-state section of a rendered Fleet page.
func systemStateOf(t *testing.T, body string) string {
	t.Helper()
	content := contentOf(body)
	i := strings.Index(content, `class="systemstate"`)
	if i < 0 {
		t.Fatal("the page has no System-state section")
	}
	rest := content[i:]
	j := strings.Index(rest, "</section>")
	if j < 0 {
		t.Fatal("the System-state section is not closed")
	}
	return rest[:j]
}

func fleetBody(t *testing.T, d Deps, query string) string {
	t.Helper()
	rec := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/"+query)
	if rec.Code != 200 {
		t.Fatalf("GET /console/%s = %d, want 200", query, rec.Code)
	}
	return rec.Body.String()
}

func TestFleet_HeadlineLeadsWithReachableThenFingerprints(t *testing.T) {
	body := fleetBody(t, fleetFixture(), "")
	ss := systemStateOf(t, body)

	for _, want := range []string{"3</b> of 4 reachable", "3</b> Policy fingerprints"} {
		if !strings.Contains(ss, want) {
			t.Errorf("the headline lacks %q", want)
		}
	}
	order := []string{"reachable", "Policy fingerprint", `class="sskey"`, `class="wall"`}
	last := -1
	for _, marker := range order {
		i := strings.Index(ss, marker)
		if i < 0 || i <= last {
			t.Fatalf("%q is missing or out of order in the System-state section", marker)
		}
		last = i
	}

	content := contentOf(body)
	hl, group := strings.Index(content, `class="sshl"`), strings.Index(content, `<details class="group"`)
	if hl < 0 || group < 0 || hl > group {
		t.Errorf("the headline (at %d) does not come before the first group card (at %d)", hl, group)
	}
}

func hexFP(c string) string { return strings.Repeat(c, 64) }

func TestFleet_HeadlineDrawsEachFingerprintInFull(t *testing.T) {
	var nodes []registry.Node
	for i, fp := range []string{hexFP("a"), hexFP("a"), hexFP("b"), hexFP("c")} {
		nodes = append(nodes, registry.Node{NodeID: "node-" + strconv.Itoa(i), PolicyFingerprint: fp, Connected: true})
	}
	ss := systemStateOf(t, fleetBody(t, withFleet(renderableDeps(), nodes...), ""))
	i := strings.Index(ss, `class="ssfps"`)
	if i < 0 {
		t.Fatal("the headline lists no fingerprints")
	}
	list := ss[i:]
	list = list[:strings.Index(list, "</ul>")]

	last := -1
	for _, want := range []string{
		`<code class="fphash">` + hexFP("a") + `</code> <b>2</b>`,
		`<code class="fphash">` + hexFP("b") + `</code> <b>1</b>`,
		`<code class="fphash">` + hexFP("c") + `</code> <b>1</b>`,
	} {
		at := strings.Index(list, want)
		if at < 0 {
			t.Fatalf("the fingerprint list lacks %q", want)
		}
		if at < last {
			t.Errorf("%q is out of order: want count descending, then hash", want)
		}
		last = at
	}
}

func TestFleet_HeadlineCountsUnreportedFingerprintsApart(t *testing.T) {
	d := fleetFixture()
	if ss := systemStateOf(t, fleetBody(t, d, "")); strings.Contains(ss, "not reported") {
		t.Error("the headline says not reported although every Node reports a fingerprint")
	}

	d = withFleet(d, append(fleetNodes(d), registry.Node{NodeID: "node-new", Connected: true})...)
	v := buildFleetView(d, fleetNodes(d), 0, "", "-")
	if v.PolicyFingerprintCount != 3 {
		t.Errorf("PolicyFingerprintCount = %d, want 3: a Node with no fingerprint is not a fingerprint", v.PolicyFingerprintCount)
	}
	if v.PolicyFingerprintUnreported != 1 {
		t.Errorf("PolicyFingerprintUnreported = %d, want 1", v.PolicyFingerprintUnreported)
	}
	if ss := systemStateOf(t, fleetBody(t, d, "")); !strings.Contains(ss, "not reported <b>1</b>") {
		t.Error("the headline does not state the unreported count")
	}
}

func TestFleet_HeadlineCountsTheMatchedSetNotTheDrawnCards(t *testing.T) {
	const groups = groupCards + 5
	var nodes []registry.Node
	for i := 0; i < groups; i++ {
		nodes = append(nodes, registry.Node{
			NodeID:            "node-" + strconv.Itoa(i),
			NodeLabels:        map[string]string{"shard": "s" + strconv.Itoa(i)},
			PolicyFingerprint: fmt.Sprintf("%064x", 1000+i),
			Connected:         i%2 == 0,
		})
	}
	d := withFleet(renderableDeps(), nodes...)
	v := buildFleetView(d, fleetNodes(d), 0, "", "shard")

	if len(v.Groups) != groupCards {
		t.Fatalf("drew %d cards, want %d", len(v.Groups), groupCards)
	}
	if want := (groups + 1) / 2; v.Reachable != want {
		t.Errorf("Reachable = %d, want %d over every matched Node", v.Reachable, want)
	}
	if v.PolicyFingerprintCount != groups {
		t.Errorf("PolicyFingerprintCount = %d, want %d", v.PolicyFingerprintCount, groups)
	}
	if len(v.PolicyFingerprints) != headlineFingerprints {
		t.Errorf("listed %d fingerprints, want %d", len(v.PolicyFingerprints), headlineFingerprints)
	}
	if v.PolicyFingerprintsElided != groups-headlineFingerprints {
		t.Errorf("PolicyFingerprintsElided = %d, want %d", v.PolicyFingerprintsElided, groups-headlineFingerprints)
	}
	ss := systemStateOf(t, fleetBody(t, d, "?group=shard"))
	if !strings.Contains(ss, "more Policy fingerprints not listed") {
		t.Error("the headline does not say how many fingerprints it left out")
	}

	ss = systemStateOf(t, fleetBody(t, fleetFixture(), "?filter=node:role=web"))
	for _, want := range []string{"3</b> of 3 reachable", "2</b> Policy fingerprints"} {
		if !strings.Contains(ss, want) {
			t.Errorf("a filtered headline lacks %q", want)
		}
	}
}

// A refused filter leaves the whole fleet on screen, so the headline counts the
// whole fleet (spec 01, D26).
func TestFleet_HeadlineCountsTheWholeFleetUnderARefusedFilter(t *testing.T) {
	d := fleetFixture()
	v := buildFleetView(d, fleetNodes(d), 0, "tag:x", "-")
	if v.FilterOK {
		t.Fatal("tag:x was accepted; this test needs a refused filter")
	}
	if v.Reachable != 3 || v.Matched != 4 || v.PolicyFingerprintCount != 3 {
		t.Errorf("headline = %d of %d reachable, %d fingerprints; want 3 of 4, 3", v.Reachable, v.Matched, v.PolicyFingerprintCount)
	}
}

func TestFleet_HeadlineHasNoApprovalsOrJobCount(t *testing.T) {
	ss := strings.ToLower(systemStateOf(t, fleetBody(t, fleetFixture(), "")))
	for _, banned := range []string{"approval", "pending", "job"} {
		if strings.Contains(ss, banned) {
			t.Errorf("the System-state section mentions %q; the headline carries no such figure", banned)
		}
	}
}

// cssDecls returns the declarations of the rule whose selector is exactly sel.
func cssDecls(t *testing.T, css, sel string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(sel) + `\s*\{([^}]*)\}`)
	m := re.FindStringSubmatch(css)
	if m == nil {
		t.Fatalf("console.css has no rule for %s", sel)
	}
	return m[1]
}

// Pixel size needs a browser; this pins the size classes. The nav wordmark
// (.brand) ties the headline at --text-lg and sits outside the content area.
// .empty h2 and .dayone h2 are also --text-lg but never render beside the
// headline, so they are not listed.
func TestFleet_HeadlineIsTheLargestTypeAfterTheHeading(t *testing.T) {
	raw, err := assetsFS.ReadFile("assets/console.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(raw)

	if got, _ := declValue(cssDecls(t, css, ".ssfig"), "font-size"); got != "var(--text-lg)" {
		t.Errorf(".ssfig font-size = %q, want var(--text-lg)", got)
	}
	if got, _ := declValue(cssDecls(t, css, ".topbar h1"), "font-size"); got != "var(--text-xl)" {
		t.Errorf(".topbar h1 font-size = %q, want var(--text-xl)", got)
	}
	for _, sel := range []string{".ghead h2", ".gcount", ".gdev", ".ssline", ".sskeyitem", ".sshead h2", ".fphash", ".ssfps"} {
		got, _ := declValue(cssDecls(t, css, sel), "font-size")
		if got == "var(--text-lg)" || got == "var(--text-xl)" {
			t.Errorf("%s font-size = %q, which rivals the headline", sel, got)
		}
	}
}

func TestFleet_GroupsAreNativeDetails(t *testing.T) {
	d := fleetFixture()
	body := fleetBody(t, d, "?group=role")
	v := buildFleetView(d, fleetNodes(d), 0, "", "role")

	if got := strings.Count(body, `<details class="group"`); got != len(v.Groups) {
		t.Errorf("%d <details> cards, want %d", got, len(v.Groups))
	}
	if strings.Contains(body, `<section class="group`) {
		t.Error("a group card is still a <section>")
	}
	if got := strings.Count(body, `<details class="group" open>`); got != countOpen(v) {
		t.Errorf("%d cards render open, want %d", got, countOpen(v))
	}
	if got := strings.Count(body, `<details class="group"`+">\n  <summary class=\"ghead\">") +
		strings.Count(body, `<details class="group" open>`+"\n  <summary class=\"ghead\">"); got != len(v.Groups) {
		t.Errorf("%d cards start with their summary, want %d", got, len(v.Groups))
	}
	for _, banned := range []string{"onclick", "ontoggle"} {
		if strings.Contains(body, banned) {
			t.Errorf("the page carries a %s handler; cards must work with scripts off", banned)
		}
	}
}

func countOpen(v fleetView) int {
	n := 0
	for _, g := range v.Groups {
		if g.Open {
			n++
		}
	}
	return n
}

func TestFleet_ClosedHealthyGroupIsOneLineAndExpandsWithoutScript(t *testing.T) {
	var nodes []registry.Node
	for i := 0; i < legibleGroup+10; i++ {
		nodes = append(nodes, registry.Node{
			NodeID: "node-" + strconv.Itoa(i), NodeLabels: map[string]string{"role": "web"},
			DaemonVersion: "0.6.0", PolicyFingerprint: "same", Connected: true,
		})
	}
	body := contentOf(fleetBody(t, withFleet(renderableDeps(), nodes...), "?group=role"))

	i := strings.Index(body, `<details class="group"`)
	if i < 0 {
		t.Fatal("no group card")
	}
	card := body[i : i+strings.Index(body[i:], "</details>")]
	if strings.HasPrefix(card, `<details class="group" open`) {
		t.Fatal("a large, entirely healthy group renders open")
	}
	summary := card[:strings.Index(card, "</summary>")]
	if !strings.Contains(summary, "no deviations") {
		t.Error("the closed card's one line does not say there are no deviations")
	}
	if !strings.Contains(card, `class="gbody"`) || !strings.Contains(card, "every Node here is reachable") {
		t.Error("the closed card does not carry its body, so it cannot expand with scripts off")
	}
	if strings.Contains(card, "<table") {
		t.Error("a closed healthy card renders an empty table")
	}
}

func TestFleet_SmallFleetGroupOpensAndIsTheFleet(t *testing.T) {
	d := withFleet(renderableDeps(), []registry.Node{
		{NodeID: "node-a", NodeLabels: map[string]string{"role": "web"}, DaemonVersion: "0.6.0", PolicyFingerprint: "same", Connected: true},
		{NodeID: "node-b", NodeLabels: map[string]string{"role": "web"}, DaemonVersion: "0.6.0", PolicyFingerprint: "same", Connected: true},
	}...)
	body := contentOf(fleetBody(t, d, "?group=role"))

	i := strings.Index(body, `<details class="group" open>`)
	if i < 0 {
		t.Fatal("a small healthy group does not render open")
	}
	card := body[i : i+strings.Index(body[i:], "</details>")]
	for _, want := range []string{"node-a", "node-b", "Every Node in"} {
		if !strings.Contains(card, want) {
			t.Errorf("the open card lacks %q", want)
		}
	}
}

// A Node-reported fingerprint that is not SHA-256 hex is counted but never
// drawn, whatever its size or characters; a well-formed one is still drawn.
func TestFleet_HeadlineNeverDrawsAMalformedFingerprint(t *testing.T) {
	huge := strings.Repeat("Z", 1<<20)
	bidi := "abc\u202edef"
	good := hexFP("d")
	d := withFleet(renderableDeps(),
		registry.Node{NodeID: "node-huge", PolicyFingerprint: huge, Connected: true},
		registry.Node{NodeID: "node-bidi", PolicyFingerprint: bidi, Connected: true},
		registry.Node{NodeID: "node-good", PolicyFingerprint: good, Connected: true},
	)
	v := buildFleetView(d, fleetNodes(d), 0, "", "-")
	if v.PolicyFingerprintCount != 3 {
		t.Errorf("PolicyFingerprintCount = %d, want 3: malformed values still count", v.PolicyFingerprintCount)
	}
	if v.PolicyFingerprintMalformed != 2 || len(v.PolicyFingerprints) != 1 {
		t.Errorf("malformed = %d, listed = %d; want 2, 1", v.PolicyFingerprintMalformed, len(v.PolicyFingerprints))
	}

	ss := systemStateOf(t, fleetBody(t, d, ""))
	if strings.Contains(ss, "\u202e") || strings.Contains(ss, "ZZZZ") {
		t.Error("the headline drew a malformed fingerprint")
	}
	for _, want := range []string{"3</b> Policy fingerprints", "2 malformed, not listed", `<code class="fphash">` + good + `</code>`} {
		if !strings.Contains(ss, want) {
			t.Errorf("the headline lacks %q", want)
		}
	}
}
