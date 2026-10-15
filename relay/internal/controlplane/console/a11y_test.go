package console

// a11y_test.go guards #473's fix: every screen, not just Fleet, scopes its
// header cells, names or hides its liveness dots, and carries a machine-
// readable datetime — plus the two stylesheet properties (a visible focus
// ring, and a grow ladder that matches its own const) the issue asked for
// alongside them.

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

var (
	// thStartTag matches a <th ...> or <th> start tag but never <thead>: the
	// optional group requires whitespace before any attribute text, so
	// "thead"'s 'e' can satisfy neither the empty match nor the group, and the
	// tag's own '>' — never a later one — closes the match. A bare <th> with
	// no attributes therefore stops at its own '>' instead of reading through
	// to a following sibling or child tag's close (review finding #473 cycle
	// 1 item 2).
	thStartTag = regexp.MustCompile(`<th(?:\s[^>]*)?>`)
	// timeStartTag matches a <time ...> or <time> start tag, bounded the same
	// way as thStartTag.
	timeStartTag = regexp.MustCompile(`<time(?:\s[^>]*)?>`)
	// dotStartTag matches a liveness dot's <span class="dot" ...> start tag.
	// "dot" is matched as a whole token of the class attribute — bounded by
	// \b on both sides, so it is found regardless of what other classes share
	// the attribute (class="dot extra", class="extra dot") and never matches
	// a class merely containing "dot" as a substring (class="dotted") — and
	// regardless of where the class attribute falls among the tag's other
	// attributes.
	dotStartTag = regexp.MustCompile(`<span\b[^>]*\bclass="[^"]*\bdot\b[^"]*"[^>]*>`)
)

// checkA11yTags asserts #473's rule on every <th>, <time> and liveness dot
// start tag found in src: a th carries scope=, a time carries datetime=, and
// a dot is either named (role="img" and aria-label=) or explicitly
// decorative (aria-hidden="true"). where is the file or path src came from,
// reported alongside the offending tag so a failure names its source.
//
// No template action found anywhere in this package's templates contains
// ">" today (none builds a tag's own delimiter), so [^>]* is sound whether
// src is template source or rendered HTML.
func checkA11yTags(t *testing.T, where, src string) (ths, times, dots int) {
	t.Helper()

	for _, tag := range thStartTag.FindAllString(src, -1) {
		ths++
		if !strings.Contains(tag, `scope="`) {
			t.Errorf("%s: header cell %s carries no scope= — the association to its column is guesswork", where, tag)
		}
	}
	for _, tag := range timeStartTag.FindAllString(src, -1) {
		times++
		if !strings.Contains(tag, `datetime="`) {
			t.Errorf("%s: %s carries no datetime= — assistive technology and machine readers get only the rendered text", where, tag)
		}
	}
	for _, tag := range dotStartTag.FindAllString(src, -1) {
		dots++
		named := strings.Contains(tag, `role="img"`) && strings.Contains(tag, `aria-label="`)
		hidden := strings.Contains(tag, `aria-hidden="true"`)
		if !named && !hidden {
			t.Errorf("%s: liveness dot %s is colour-only — it must carry role=\"img\" and aria-label=, "+
				"or be marked aria-hidden=\"true\" if adjacent text already names the state", where, tag)
		}
	}
	return ths, times, dots
}

// TestA11yTagRegexes_AreTagBoundedAndMatchClassTokens is the regression pin
// for review finding 2 (#473 cycle 1): thStartTag, timeStartTag and
// dotStartTag must stop at their own tag's '>' rather than reading through to
// a following sibling or child tag's close, and dotStartTag must find "dot"
// as a class TOKEN rather than a literal "class=\"dot\"" string, so a dot
// sharing its class attribute with another class is still caught.
func TestA11yTagRegexes_AreTagBoundedAndMatchClassTokens(t *testing.T) {
	// A bare, attribute-less <th>/<time> immediately followed by content and
	// a sibling start tag: the regression under review was a pattern whose
	// "own tag's '>'" was optional rather than required, so it kept consuming
	// past it looking for the next '>' — which belonged to the CLOSING tag,
	// or worse, a following tag entirely.
	if got := thStartTag.FindString(`<th>Text</th><th scope="col">Next</th>`); got != "<th>" {
		t.Errorf("thStartTag matched %q, want just the bare start tag %q — it read into a sibling tag", got, "<th>")
	}
	if got := timeStartTag.FindString(`<time>2026-09-21</time><span>after</span>`); got != "<time>" {
		t.Errorf("timeStartTag matched %q, want just the bare start tag %q — it read into a child tag", got, "<time>")
	}

	for _, tag := range []string{
		`<span class="dot extra" data-live="on"></span>`,
		`<span class="extra dot" data-live="on"></span>`,
		`<span class="extra dot more" data-live="on"></span>`,
	} {
		if !dotStartTag.MatchString(tag) {
			t.Errorf("dotStartTag did not match multi-class dot span %q", tag)
		}
	}
	if dotStartTag.MatchString(`<span class="dotted"></span>`) {
		t.Error(`dotStartTag matched class="dotted" — "dot" must be a whole class token, not a substring`)
	}
}

// TestConsole_EveryTemplateScopesHeaderCellsNamesDotsAndDatesTimes is the
// source-scan half of #473: every screen's own template source, not just
// Fleet's. It reaches tables the rendered sweep below never populates (the
// Accounts screen's conditional Change/Revoke headers, for one) because it
// reads the template text directly rather than a rendered page.
//
// Same file-walk as TestConsole_NoTableCellIsTakenOutOfTableLayout
// (stylesheet_test.go): every non-test .go file in the package directory.
func TestConsole_EveryTemplateScopesHeaderCellsNamesDotsAndDatesTimes(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	var ths, times, dots int
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		n1, n2, n3 := checkA11yTags(t, name, string(src))
		ths += n1
		times += n2
		dots += n3
	}
	if ths == 0 {
		t.Fatal("found zero <th> tags across the package — this guard is not running")
	}
	if times == 0 {
		t.Fatal("found zero <time> tags across the package — this guard is not running")
	}
	if dots == 0 {
		t.Fatal("found zero liveness dots across the package — this guard is not running")
	}
}

// TestConsole_EveryRenderedScreenScopesHeaderCellsAndNamesLiveness is the
// rendered half: it walks every GET screen the route table mounts, the same
// way TestScreens_NoInlineScriptSurvivesAnywhere does, and checks the actual
// HTML a browser (and a screen reader) would see — including headers and
// dots a template only renders conditionally, which the source scan above
// cannot evaluate.
func TestConsole_EveryRenderedScreenScopesHeaderCellsAndNamesLiveness(t *testing.T) {
	d := sweepFixture()
	h := newTestHandler(d, accounts.RoleAdmin)

	var ths, times, dots int
	for _, path := range walkableScreens(Routes(d), fixtureIDs) {
		rec := get(t, h, path)
		if rec.Code != http.StatusOK {
			continue
		}
		n1, n2, n3 := checkA11yTags(t, path, rec.Body.String())
		ths += n1
		times += n2
		dots += n3
	}
	if ths == 0 {
		t.Fatal("swept zero <th> tags across every rendered screen — this guard is not running")
	}
	if times == 0 {
		t.Fatal("swept zero <time> tags across every rendered screen — this guard is not running")
	}
	if dots == 0 {
		t.Fatal("swept zero liveness dots across every rendered screen — this guard is not running")
	}
}

// TestNode_HeadLivenessDotIsNamed is a rendered, per-screen regression pin on
// the Node-detail head's dot specifically: the source scan and the sweep
// above both cover it, but neither names the ONE element a regression here
// would actually break for a screen-reader user landing on a Node's page.
//
// The wording is deliberately identical to the .seen text beside it
// ("connected") when the Node is connected — accepted, not a bug (#473): the
// dot's own name is what carries "not connected" when the Node is offline,
// since .seen says "last seen X ago" in that state instead, so the dot
// cannot be decorative in one state and named in the other.
func TestNode_HeadLivenessDotIsNamed(t *testing.T) {
	body := get(t, newTestHandler(fleetFixture(), accounts.RoleAdmin), "/console/nodes/node-web-1").Body.String()

	i := strings.Index(body, `class="nodehead"`)
	if i < 0 {
		t.Fatal(`no element with class="nodehead" rendered`)
	}
	rest := body[i:]
	j := strings.Index(rest, "</div>")
	if j < 0 {
		t.Fatal("nodehead has no closing </div>")
	}
	head := rest[:j]

	if !strings.Contains(head, `role="img"`) || !strings.Contains(head, `aria-label="connected"`) {
		t.Errorf("the node-head liveness dot for a connected Node carries no accessible name: %s", head)
	}
}

// TestConsole_HasOneGlobalFocusRingAndNoneIsSuppressed pins #473's global
// focus ring: exactly one top-level :focus-visible rule with a visible
// outline, and no rule anywhere that suppresses one.
//
// "Top-level" is checked by tracking brace depth over the comment-stripped
// stylesheet: a :focus-visible rule declared only inside an @media block
// would not give every interactive element a ring on every viewport, so it
// must not satisfy this guard.
func TestConsole_HasOneGlobalFocusRingAndNoneIsSuppressed(t *testing.T) {
	css, err := assetsFS.ReadFile("assets/console.css")
	if err != nil {
		t.Fatalf("read console.css: %v", err)
	}
	stripped := cssCommentPattern.ReplaceAllString(string(css), "")

	topLevelFocusVisible := 0
	depth := 0
	selectorStart := 0
	for i, r := range stripped {
		switch r {
		case '{':
			if depth == 0 {
				selector := strings.TrimSpace(stripped[selectorStart:i])
				closeAt := matchingBrace(stripped, i)
				if closeAt < 0 {
					t.Fatalf("unmatched { at byte %d in console.css", i)
				}
				if selector == ":focus-visible" {
					topLevelFocusVisible++
					decls := stripped[i+1 : closeAt]
					if !strings.Contains(decls, "outline: 2px solid") {
						t.Errorf(`the top-level :focus-visible rule does not contain "outline: 2px solid": %q`, decls)
					}
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
	if topLevelFocusVisible != 1 {
		t.Errorf("console.css has %d top-level :focus-visible rules, want exactly 1", topLevelFocusVisible)
	}

	for _, m := range cssRulePattern.FindAllStringSubmatch(stripped, -1) {
		decls := m[2]
		if strings.Contains(decls, "outline: none") || strings.Contains(decls, "outline: 0") {
			t.Errorf("selector %q suppresses the focus outline (%q) — nothing may hide focus once it is visible",
				strings.TrimSpace(m[1]), decls)
		}
	}
}

// matchingBrace returns the index of the '}' that closes the '{' at open,
// counting nested braces. -1 if css has no matching close.
func matchingBrace(css string, open int) int {
	depth := 0
	for i := open; i < len(css); i++ {
		switch css[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// TestOutcomeBar_GrowLadderMatchesTheStylesheet is the stylesheet/Go seam for
// #473's shrunk grow ladder: console.css must carry exactly one
// .oseg[data-grow="N"] rule for every N in [1, growSteps] and none beyond
// it, or a segment whose Grow lands outside the rules the stylesheet ships
// paints at zero width — the exact CSP failure the Segment.Grow doc comment
// describes.
func TestOutcomeBar_GrowLadderMatchesTheStylesheet(t *testing.T) {
	if growSteps > 40 {
		t.Fatalf("growSteps is %d, want at most 40 — #473 shrank the ladder, it did not grow it", growSteps)
	}

	css, err := assetsFS.ReadFile("assets/console.css")
	if err != nil {
		t.Fatalf("read console.css: %v", err)
	}
	stripped := cssCommentPattern.ReplaceAllString(string(css), "")

	for n := 1; n <= growSteps; n++ {
		want := `.oseg[data-grow="` + strconv.Itoa(n) + `"] { flex-grow: ` + strconv.Itoa(n) + `; }`
		if !strings.Contains(stripped, want) {
			t.Errorf("console.css has no rule %q for step %d of growSteps", want, n)
		}
	}
	beyond := `.oseg[data-grow="` + strconv.Itoa(growSteps+1) + `"]`
	if strings.Contains(stripped, beyond) {
		t.Errorf("console.css has a rule for %s, one step beyond growSteps (%d) — the ladder and the const have drifted", beyond, growSteps)
	}

	rules := strings.Count(stripped, `.oseg[data-grow="`)
	if rules != growSteps {
		t.Errorf("console.css carries %d .oseg[data-grow] rules, want exactly growSteps (%d)", rules, growSteps)
	}

	// Real segment shapes, not the literal range: growWeight's own clamp
	// already guarantees every Grow lands in [1, growSteps], so a check that
	// only stayed inside that range would be tautological here — it can never
	// fail (review finding #473 cycle 1 item 1). Each expected Grow below is
	// worked by hand from NewOutcomeBar's own floor-and-share formula at
	// growSteps=40 and minSegmentPercent=2.5, then asserted EXACTLY, so a
	// change to growWeight's rounding — e.g. truncating instead of rounding —
	// shifts a real value by a step this test catches even though the shifted
	// value still lands inside [1, growSteps]:
	//   - 1 success vs 9999 failure: floor=2.5, remaining=95.
	//     success width 2.5+95*0.0001=2.5095 -> round(2.5095*0.4)=round(1.0038)=1.
	//     failure width 2.5+95*0.9999=97.4905 -> round(38.9962)=39.
	//   - 50 vs 50: floor=2.5, remaining=95; width 2.5+95*0.5=50 ->
	//     round(20.0)=20 for both.
	//   - eight outcomes of 1 each: nonZero=8, 100/8=12.5 does not undercut
	//     the 2.5 floor, remaining=100-2.5*8=80; width 2.5+80*0.125=12.5 ->
	//     round(5.0)=5 for each of the eight.
	// Confirmed falsifiable: with growWeight's "+ 0.5" rounding removed
	// (truncating instead of rounding), the 9999-failure segment's Grow
	// becomes 38 instead of 39 (int(38.9962) truncates below the step
	// round(38.9962) reaches) and this block fails; reverted after confirming.
	cases := []struct {
		bar  OutcomeBar
		want map[jobs.Outcome]int
	}{
		{
			bar:  NewOutcomeBar([]OutcomeCount{{Outcome: jobs.OutcomeSuccess, Count: 1}, {Outcome: jobs.OutcomeFailure, Count: 9999}}),
			want: map[jobs.Outcome]int{jobs.OutcomeSuccess: 1, jobs.OutcomeFailure: 39},
		},
		{
			bar:  NewOutcomeBar([]OutcomeCount{{Outcome: jobs.OutcomeSuccess, Count: 50}, {Outcome: jobs.OutcomeFailure, Count: 50}}),
			want: map[jobs.Outcome]int{jobs.OutcomeSuccess: 20, jobs.OutcomeFailure: 20},
		},
		{
			bar: NewOutcomeBar([]OutcomeCount{
				{Outcome: jobs.OutcomeSuccess, Count: 1},
				{Outcome: jobs.OutcomeFailure, Count: 1},
				{Outcome: jobs.OutcomeTimeout, Count: 1},
				{Outcome: jobs.OutcomeDeniedByPolicy, Count: 1},
				{Outcome: jobs.OutcomeCancelled, Count: 1},
				{Outcome: jobs.OutcomeUnreachable, Count: 1},
				{Outcome: jobs.OutcomeVersionRefused, Count: 1},
				{Outcome: jobs.OutcomeUnsupported, Count: 1},
			}),
			want: map[jobs.Outcome]int{
				jobs.OutcomeSuccess: 5, jobs.OutcomeFailure: 5, jobs.OutcomeTimeout: 5,
				jobs.OutcomeDeniedByPolicy: 5, jobs.OutcomeCancelled: 5, jobs.OutcomeUnreachable: 5,
				jobs.OutcomeVersionRefused: 5, jobs.OutcomeUnsupported: 5,
			},
		},
	}
	for _, c := range cases {
		if len(c.bar.Segments) != len(c.want) {
			t.Errorf("bar produced %d segments, want %d", len(c.bar.Segments), len(c.want))
		}
		for _, seg := range c.bar.Segments {
			want, ok := c.want[seg.Outcome]
			if !ok {
				t.Errorf("segment %s (outcome %v) is not in this bar's expected set", seg.Label, seg.Outcome)
				continue
			}
			if seg.Grow != want {
				t.Errorf("segment %s (width %.4f%%) got Grow %d, want %d", seg.Label, seg.Width, seg.Grow, want)
			}
			gotRule := `.oseg[data-grow="` + strconv.Itoa(seg.Grow) + `"]`
			if !strings.Contains(stripped, gotRule) {
				t.Errorf("segment %s renders data-grow=%d, but console.css has no %s rule — it would paint at zero width",
					seg.Label, seg.Grow, gotRule)
			}
		}
	}
}
