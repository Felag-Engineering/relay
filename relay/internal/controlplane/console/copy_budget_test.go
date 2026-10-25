package console

// copy_budget_test.go holds the Console to 00-foundations.md's "Standing notes
// and situational messages" as amended for #849: every visible note is one
// sentence of about fifteen words, no screen carries an "About this screen"
// disclosure (D31), and each screen carries a word budget so explanatory
// prose cannot creep back one helpful sentence at a time.
//
// The scanner below is hand-rolled rather than golang.org/x/net/html: that
// module is only an indirect dependency of this one, and promoting it would
// edit go.mod. It is strict instead of forgiving. A tag-stack mismatch is an
// error naming both tags and the byte offset, because a scanner that silently
// misattributes text is a budget test that silently passes.
//
// What is enforced, stated so the guard claims no more than it does. Every
// element of a rendered page falls in exactly one of these:
//
//   - measured: explanatory prose. Counts toward the screen's budget and is
//     capped per element. A <p> is measured by default, whatever its class, so
//     a new paragraph is a note until somebody argues otherwise below.
//   - bounded: data, or the annotation of a value. Capped per element, not
//     budgeted: a bounded p.<class> (p.dim, p.back, ...) can hold a note of up
//     to maxNoteWords that no screen budget counts. That is a residual of this
//     guard, stated here rather than hidden.
//   - exempt: recorded data a Relay author did not write (an approval summary,
//     a diff row) or a sentence the capability layer owns (the deny block's
//     BoundaryExplanation). An exempt element's template source may hold no
//     literal word on any branch: only actions (and a diff row's arrow), so
//     the exemption cannot shelter a label somebody wrote.
//   - a value: text inside td, dd, dt, th, code, pre, a, label or a heading is
//     a datum or a name, not prose. <dd> is exempt on purpose: it is a value
//     cell, and a note placed in one is the one place this guard cannot see it.
//   - unclassified: ANY other run of eight or more words — in an <li>, a
//     <summary>, a <div>, a bare container — fails the test. A new kind of
//     element cannot carry prose past the budget by being new.
//
// Inline tags (b, i, em, span, ...) with no measured, bounded or exempt class
// are transparent: text split by them is one run, so a bolded lead clause
// cannot be what keeps a sentence under the eight-word floor.
//
// Class names are matched on the element that carries them (tag.class), never
// by the class alone, so a <span> cannot borrow what a <p> is allowed.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"html"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"text/template/parse"
	"time"
	"unicode"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/policyview"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// Per-element and per-screen limits (00-foundations.md as amended for #849).
const (
	// maxSourceWords caps a measured element in template source on its
	// longest branch path, each output action counted as one word. It is 18,
	// not 15, because the two ruled Approval grant card sentences are 18.
	maxSourceWords = 18
	// maxTitleWords caps a title or aria-label: a tooltip is a note nobody
	// budgets, so it is held to the one-sentence rule itself.
	maxTitleWords = 15
	// maxGoNoteWords caps a note written as a Go string.
	maxGoNoteWords = 20
	// maxHeadingWords caps a POST result page's heading, whose refusal
	// reason an operator needs in order to act.
	maxHeadingWords = 30
	// maxNoteWords is the rendered cap on one visible note. The rule is
	// "about fifteen words"; the slack is for an inline value — a rendered
	// timestamp is two tokens, a count or a name one.
	maxNoteWords = 20
)

// measuredClasses are the elements whose text is explanatory prose: each one
// counts toward its screen's budget and is held to maxNoteWords. Keyed by
// "tag.class". A <p> whose FIRST class is in none of these maps is measured
// too — an unknown paragraph is presumed to be prose until classified.
var measuredClasses = map[string]bool{
	"p.note": true, "p.gap": true, "p.lede": true, "p.kindnote": true,
	"p.scoped":  true,
	"p.lanekey": true,
	"span.note": true, "span.gap": true,
	"span.jcnote": true, "span.phint": true,
	"div.evnote": true, "p.fielderr": true, "p.unfilterednote": true, "div.fhint": true,
	"p.confirmq": true,
}

// boundedClasses are held to maxNoteWords but not budgeted: each is data, or
// the annotation of a value, rather than a note about the screen. Keyed by
// "tag.class"; the reason is the test's own documentation of why the element
// is not a note.
var boundedClasses = map[string]string{
	"p.dim":         "an honest absence or a value's annotation",
	"span.dim":      "an honest absence or a value's annotation",
	"div.sub":       "a value's annotation",
	"caption.tcap":  "a table caption",
	"span.wmsg":     "live-status words, one shown at a time",
	"span.evlive":   "live-status words, one shown at a time",
	"span.rnlive":   "live-status words, one shown at a time",
	"div.clabel":    "a cluster's data label",
	"p.mode":        "Fleet distribution line: counts",
	"p.rncount":     "a count",
	"p.rolestate":   "Accounts role and state data",
	"span.unattrib": "what stands in the requester slot when the trail recorded none: a value, a trail defect named",
	"span.overcap":  "a Plan's over-cap verdict: a state, drawn where the cap arithmetic is",
	"ul.truths":     "Day one's state facts (each li of ul.truths)",
	// Leaves of header lines that are values: counts, state names and a
	// timestamp, no sentence. Surfaced when inline tags stopped splitting a run
	// (#849 cycle 3). The header containers are deliberately not bounded, so a
	// note nested in one is still measured.
	"span.ssline": "Fleet wall header: a count and a grouping key",
	"span.gcount": "a Fleet group's Node count",
	"span.gdev":   "a Fleet group header chip: a count and a state name",
	"span.ssfig":  "Fleet System-state headline: a count and what it counts",
	"span.seen":   "Node detail header: liveness and last seen",
	// A plain chip (no CSS of its own): which part of a finished Job's dispatch
	// record the trail lacks (#887). Two branches, one ever shown.
	"span.outcomeunk": "a Job's recording state chip: a state name, not a note",
	// Fleet's relative render time beside Refresh: "rendered 12 min ago, Refresh to
	// re-read" at most, a value that ages rather than a note.
	"span.asat": "how old the page is: a relative time beside Refresh",
}

// exemptClasses are not measured at all, keyed by "tag.class". denynote is
// exempt only when its text IS one of the capability layer's
// BoundaryExplanation strings; any other denynote (the Console's own clip
// note) is measured.
var exemptClasses = map[string]string{
	"p.summary":  "Relay-authored approval summary, recorded data",
	"p.denynote": "the capability layer's shared refusal bytes (00 'The deny block')",
}

// valueTags hold a value or a name, not prose: text inside one is never
// reported as unclassified. dd is here deliberately (see the header).
var valueTags = map[string]bool{
	"td": true, "dd": true, "dt": true, "th": true, "code": true, "pre": true, "a": true,
	"label": true, "h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
}

// minUnclassifiedRun is the shortest run of words outside every classified
// element that fails the test. Below it a run is a label or a fragment.
const minUnclassifiedRun = 8

// barePContainers are the classes whose bare <p> children are prose (the
// nearest classed ancestor decides).
var barePContainers = map[string]bool{
	"placeholder": true, "empty": true, "firststep": true, "cancelresult": true,
}

// barePSkipped are the classes whose bare <p> children are data or a secret:
// an approval decision line, and the reveal-once token page (its bare <p>s are
// the reveal-once instruction, the secret itself and navigation — 15
// "plaintext is shown once" — none of them a note). A note nested inside one
// is still measured.
var barePSkipped = map[string]bool{"jobapproval": true, "minted": true}

// noteish is the class shape that must be classified: a span or div whose
// class reads like a note and is in no map is a note nobody budgeted.
var noteish = regexp.MustCompile(`note|hint|lede|gap|msg`)

// boundaryExplanations are the capability layer's shared refusal sentences,
// the only denynote text the budget exempts.
func boundaryExplanations() []string {
	return []string{
		capability.RefusalExplanation(jobs.OutcomeDeniedByPolicy),
		capability.VerdictExplanation(capability.VerdictDeny),
	}
}

type proseKind int

const (
	kindNone proseKind = iota
	kindMeasured
	kindBounded
	kindExempt
	kindSkipped
	kindDenynote // measured unless its text is a boundary explanation
)

// proseElem is one measured or bounded element of rendered content.
type proseElem struct {
	Tag, Class string
	Text       string
	Words      int
	Bounded    bool // per-element cap only, not budgeted
	Offset     int
}

func (e proseElem) String() string {
	where := "visible"
	if e.Bounded {
		where = "bounded"
	}
	return fmt.Sprintf("%s.%s (%s, %d words): %q", e.Tag, e.Class, where, e.Words, e.Text)
}

// copyTag matches one start or end tag, with quoted attribute values allowed
// to contain '>'.
var copyTag = regexp.MustCompile(`<(/?)([a-zA-Z][a-zA-Z0-9]*)((?:[^>"']|"[^"]*"|'[^']*')*)>`)

var htmlComment = regexp.MustCompile(`(?s)<!--.*?-->`)

// classAttr and titleAttr accept single- and double-quoted values: HTML does,
// and a quote style the scan skips is a place prose can hide.
var classAttr = regexp.MustCompile(`\bclass=(?:"([^"]*)"|'([^']*)')`)

// classesOf returns the classes in a tag's attribute text.
func classesOf(attrs string) []string {
	cm := classAttr.FindStringSubmatch(attrs)
	if cm == nil {
		return nil
	}
	return strings.Fields(cm[1] + cm[2])
}

var voidTags = map[string]bool{
	"br": true, "img": true, "input": true, "meta": true, "link": true, "hr": true, "wbr": true,
	"col": true, "source": true, "area": true, "base": true, "embed": true, "param": true, "track": true,
}

// blockTags separate words: text either side of one never runs together.
var blockTags = map[string]bool{
	"p": true, "div": true, "li": true, "ul": true, "ol": true, "section": true, "details": true,
	"summary": true, "h1": true, "h2": true, "h3": true, "h4": true, "td": true, "th": true, "tr": true,
	"dl": true, "dt": true, "dd": true, "table": true, "caption": true, "form": true, "br": true,
}

// inlineTags are transparent to a run of prose: a bolded lead clause, an
// emphasised word or a span splits no sentence in two, so their text joins the
// enclosing element's run. An inline tag that carries a measured, bounded or
// exempt class is not transparent: it is classified in its own right.
var inlineTags = map[string]bool{
	"b": true, "i": true, "em": true, "strong": true, "span": true, "small": true,
	"abbr": true, "time": true, "s": true, "u": true, "mark": true, "q": true, "cite": true,
}

// countWords counts tokens holding a letter or a digit, so "·" and "—" are
// not words and a rendered timestamp is two.
func countWords(s string) int {
	n := 0
	for _, f := range strings.Fields(s) {
		if strings.IndexFunc(f, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }) >= 0 {
			n++
		}
	}
	return n
}

type openElem struct {
	tag     string
	classes []string
	offset  int
	kind    proseKind
	class   string // the class that classified it
	collect *strings.Builder
	own     strings.Builder // text directly inside, when nothing classifies it
}

// proseOf measures rendered content. It returns every measured and bounded
// element, the location of every element that should have been classified
// and was not, and an error on any markup it cannot attribute with certainty.
func proseOf(content string) (elems []proseElem, unclassified []string, err error) {
	content = htmlComment.ReplaceAllStringFunc(content, func(m string) string { return strings.Repeat(" ", len(m)) })
	var stack []*openElem
	pos := 0

	// collector is the outermost classified element on the stack: a measured
	// element nested in another counts once, as part of the outer one.
	collector := func() *openElem {
		for _, e := range stack {
			if e.kind != kindNone && e.kind != kindSkipped {
				return e
			}
		}
		return nil
	}
	// accountedFor reports whether text here is already classified: collected
	// by a measured, bounded or exempt element, or inside a value or a
	// skipped data paragraph.
	accountedFor := func() bool {
		if collector() != nil {
			return true
		}
		for _, e := range stack {
			if valueTags[e.tag] || e.kind == kindSkipped {
				return true
			}
		}
		return false
	}
	var rootText strings.Builder
	appendText := func(s string) {
		if c := collector(); c != nil && c.collect != nil {
			c.collect.WriteString(s)
		}
		if accountedFor() {
			return
		}
		// The run belongs to the nearest enclosing element that is not a bare
		// inline one: `<li><b>seven words</b> <i>seven</i></li>` is one run.
		for i := len(stack) - 1; i >= 0; i-- {
			if inlineTags[stack[i].tag] && stack[i].kind == kindNone {
				continue
			}
			stack[i].own.WriteString(s)
			return
		}
		rootText.WriteString(s)
	}
	reportRun := func(e *openElem) {
		text := strings.Join(strings.Fields(e.own.String()), " ")
		if n := countWords(text); n >= minUnclassifiedRun {
			unclassified = append(unclassified, fmt.Sprintf(
				"byte %d: <%s class=%q> carries a %d-word run that no measured class collects: %q",
				e.offset, e.tag, strings.Join(e.classes, " "), n, text))
		}
	}

	for _, m := range copyTag.FindAllStringSubmatchIndex(content, -1) {
		appendText(html.UnescapeString(content[pos:m[0]]))
		pos = m[1]
		closing := content[m[2]:m[3]] == "/"
		tag := strings.ToLower(content[m[4]:m[5]])
		attrs := content[m[6]:m[7]]
		if blockTags[tag] {
			appendText(" ")
		}
		if voidTags[tag] {
			continue
		}
		if closing {
			if len(stack) == 0 {
				return nil, nil, fmt.Errorf("byte %d: </%s> closes nothing", m[0], tag)
			}
			top := stack[len(stack)-1]
			if top.tag != tag {
				return nil, nil, fmt.Errorf("byte %d: </%s> closes <%s> opened at byte %d", m[0], tag, top.tag, top.offset)
			}
			stack = stack[:len(stack)-1]
			reportRun(top)
			if top.collect == nil {
				continue
			}
			text := strings.Join(strings.Fields(top.collect.String()), " ")
			kind := top.kind
			if kind == kindDenynote {
				kind = kindMeasured
				for _, b := range boundaryExplanations() {
					if b != "" && text == strings.Join(strings.Fields(b), " ") {
						kind = kindExempt
					}
				}
			}
			if kind == kindMeasured || kind == kindBounded {
				elems = append(elems, proseElem{
					Tag: top.tag, Class: top.class, Text: text, Words: countWords(text),
					Bounded: kind == kindBounded, Offset: top.offset,
				})
			}
			continue
		}

		classes := classesOf(attrs)
		e := &openElem{tag: tag, classes: classes, offset: m[0]}
		if collector() == nil {
			e.kind, e.class = classify(tag, classes, stack)
			if e.kind == kindNone && tag == "p" && len(classes) == 0 {
				unclassified = append(unclassified, fmt.Sprintf("byte %d: a bare <p> with no classified container", m[0]))
			}
			if e.kind == kindNone && (tag == "span" || tag == "div") {
				for _, c := range classes {
					if noteish.MatchString(c) {
						unclassified = append(unclassified, fmt.Sprintf("byte %d: <%s class=%q> reads like a note and is in no map", m[0], tag, c))
					}
				}
			}
			if e.kind != kindNone && e.kind != kindSkipped {
				e.collect = &strings.Builder{}
			}
		}
		stack = append(stack, e)
	}
	appendText(html.UnescapeString(content[pos:]))
	if len(stack) > 0 {
		top := stack[len(stack)-1]
		return nil, nil, fmt.Errorf("<%s> opened at byte %d is never closed", top.tag, top.offset)
	}
	if n := countWords(rootText.String()); n >= minUnclassifiedRun {
		unclassified = append(unclassified, fmt.Sprintf("a %d-word run outside every element: %q", n, strings.Join(strings.Fields(rootText.String()), " ")))
	}
	return elems, unclassified, nil
}

// classify decides what an element's text is, from its own tag and classes
// and, for a bare <p>, its nearest classed ancestor. Every lookup is keyed by
// tag.class: a class means what it means on the element the Console gave it
// to, and nowhere else.
func classify(tag string, classes []string, stack []*openElem) (proseKind, string) {
	if tag == "li" && len(stack) > 0 {
		parent := stack[len(stack)-1]
		if parent.tag == "ul" && len(parent.classes) > 0 && parent.classes[0] == "truths" {
			return kindBounded, "truths"
		}
	}
	if tag == "p" {
		if len(classes) == 0 {
			for i := len(stack) - 1; i >= 0; i-- {
				if len(stack[i].classes) == 0 {
					continue
				}
				for _, c := range stack[i].classes {
					if barePContainers[c] {
						return kindMeasured, c
					}
					if barePSkipped[c] {
						return kindSkipped, c
					}
				}
				break
			}
			return kindNone, ""
		}
		first := classes[0]
		key := "p." + first
		switch {
		case first == "denynote":
			return kindDenynote, first
		case exemptClasses[key] != "":
			return kindExempt, first
		case boundedClasses[key] != "":
			return kindBounded, first
		default:
			// A known measured class, or an unknown one: both are prose.
			return kindMeasured, first
		}
	}
	for _, c := range classes {
		if measuredClasses[tag+"."+c] {
			return kindMeasured, c
		}
	}
	for _, c := range classes {
		if exemptClasses[tag+"."+c] != "" {
			return kindExempt, c
		}
		if boundedClasses[tag+"."+c] != "" && (tag != "ul" || c != "truths") {
			return kindBounded, c
		}
	}
	return kindNone, ""
}

// --- T1: the scanner measures what it should -------------------------------

func TestCopyBudget_CounterMeasuresWhatItShould(t *testing.T) {
	deny := boundaryExplanations()[0]
	content := `<p class="note">One two three.</p>` +
		`<p class="newthing">four five</p>` +
		`<p class="mode">12 Nodes · 3 groups</p>` +
		`<span class="note"><b>node:</b> set · <b>state:</b> derived</span>` +
		`<span class="dim">an annotation</span>` +
		`<p class="denynote">` + html.EscapeString(deny) + `</p>` +
		`<p class="denynote">Shown to the first 2 KB.</p>` +
		`<div class="placeholder"><p>Pin two Nodes.</p></div>` +
		`<section class="panel"><p>an orphan paragraph</p></section>` +
		`<section class="panel minted"><p>the secret</p></section>` +
		`<p class="note">outer <span class="phint">inner words</span></p>`
	elems, unclassified, err := proseOf(content)
	if err != nil {
		t.Fatalf("proseOf: %v", err)
	}
	got := map[string]int{}
	var bounded int
	for _, e := range elems {
		switch {
		case e.Bounded:
			bounded++
		default:
			got[e.Text] = e.Words
		}
	}
	want := map[string]int{
		"One two three.":             3,
		"four five":                  2, // an unknown first class is presumed prose
		"node: set · state: derived": 4, // "·" is not a word
		"Shown to the first 2 KB.":   6, // the Console's own clip note is measured
		"Pin two Nodes.":             3, // a bare <p> in a placeholder is prose
		"outer inner words":          3, // a nested element counts once, in the outer one
	}
	for text, n := range want {
		if got[text] != n {
			t.Errorf("%q measured %d words, want %d (all measured: %v)", text, got[text], n, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("measured %d visible elements, want %d: %v", len(got), len(want), got)
	}
	if bounded != 2 {
		t.Errorf("bounded elements = %d, want 2 (span.dim and p.mode)", bounded)
	}
	if len(unclassified) != 1 || !strings.Contains(unclassified[0], "bare <p>") {
		t.Errorf("unclassified = %v, want exactly the orphan bare <p> (the minted page's is skipped)", unclassified)
	}

	// Prose cannot hide in an element the scanner was not told about: a run of
	// eight or more words outside every measured, bounded, exempt or value
	// element is reported, whatever its tag, class or quote style.
	long := "one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty twenty-one twenty-two twenty-three twenty-four twenty-five twenty-six"
	for name, snippet := range map[string]string{
		"li":                 `<ul><li>` + long + `</li></ul>`,
		"summary":            `<details><summary>` + long + `</summary></details>`,
		"unknown div":        `<div class="caveat">` + long + `</div>`,
		"single-quoted div":  `<div class='caveat'>` + long + `</div>`,
		"bare container":     `<section class="panel">` + long + `</section>`,
		"a class borrowed":   `<span class="back">` + long + `</span>`,
		"a span in a li":     `<ul><li><span>` + long + `</span></li></ul>`,
		"text at the root":   long,
		"a nested bare span": `<div class="wrap"><div><span>` + long + `</span></div></div>`,
		"a lead clause split by inline tags": `<ul><li><b>one two three four five six seven</b> <i>one two three four five six seven</i> ` +
			`<em>one two three four five six seven</em> <span>one two three four five six</span></li></ul>`,
	} {
		if _, unclassified, err := proseOf(snippet); err != nil || len(unclassified) == 0 {
			t.Errorf("%s: a 27-word run went unreported (unclassified=%v, err=%v)", name, unclassified, err)
		}
	}
	// The same split-by-inline-tags prose, in template source, where no fixture
	// renders it: every branch is read, so an {{if false}} body is no hiding place.
	split := `<ul><li><b>one two three four five six seven</b> <i>one two three four five six seven</i> ` +
		`<em>one two three four five six seven</em> <span>one two three four five six</span></li></ul>`
	for name, text := range map[string]string{
		"source, always":       split,
		"source, {{if false}}": `{{if false}}` + split + `{{end}}`,
	} {
		if runs := templateRuns(templateSource{"fixture.go", 1, text}); len(runs) == 0 {
			t.Errorf("%s: a 27-word run split by inline tags went unreported in template source", name)
		}
	}
	// Inline tags join a run; they do not make a short one long. A bounded span
	// inside a li is accounted for by its own class and stays out of the run.
	if _, unclassified, _ := proseOf(`<ul><li><b>one two three</b> <i>four five six seven</i></li></ul>`); len(unclassified) != 0 {
		t.Errorf("a seven-word run split by inline tags was reported: %v", unclassified)
	}
	if runs := templateRuns(templateSource{"fixture.go", 1, `<ul><li><b>one two three</b> <i>four five six seven</i></li></ul>`}); len(runs) != 0 {
		t.Errorf("a seven-word source run split by inline tags was reported: %v", runs)
	}
	if _, unclassified, _ := proseOf(`<ul><li><b>one two three four</b> <span class="dim">one two three four five six seven eight</span></li></ul>`); len(unclassified) != 0 {
		t.Errorf("a bounded span was folded into the surrounding run: %v", unclassified)
	}
	// A measured element in single quotes counts, and a long p.mode is measured
	// as a bounded element for the per-element cap rather than skipped.
	if elems, _, _ := proseOf(`<p class='note'>` + long + `</p>`); len(elems) != 1 || elems[0].Words != 26 {
		t.Errorf("a single-quoted class went unmeasured: %v", elems)
	}
	if elems, _, _ := proseOf(`<p class="mode">` + long + `</p>`); len(elems) != 1 || !elems[0].Bounded || elems[0].Words != 26 {
		t.Errorf("a long p.mode was not seen: %v", elems)
	}
	// Values are not prose: a long run inside them is not reported.
	for _, tag := range []string{"td", "dd", "dt", "th", "code", "pre", "a", "label", "h3"} {
		if _, unclassified, err := proseOf(`<` + tag + `>` + long + `</` + tag + `>`); err != nil || len(unclassified) != 0 {
			t.Errorf("a long run inside <%s> was reported as prose (unclassified=%v, err=%v)", tag, unclassified, err)
		}
	}
	// A run just under the threshold is a label or a fragment, not a note.
	if _, unclassified, _ := proseOf(`<ul><li>one two three four five six seven</li></ul>`); len(unclassified) != 0 {
		t.Errorf("a seven-word run was reported: %v", unclassified)
	}
	// A rendered tooltip is a note nobody budgets, in either quote style.
	for _, attr := range []string{`title="` + long + `"`, `title='` + long + `'`, `aria-label="` + long + `"`} {
		if got := longAttributes(`<span ` + attr + `>x</span>`); len(got) != 1 {
			t.Errorf("a 26-word %s was not reported: %v", attr[:5], got)
		}
	}

	// A tag-stack mismatch names both tags and the offset; an unclosed
	// element is an error too. Neither may be measured quietly.
	if _, _, err := proseOf(`<p class="note">a <b>b</p></b>`); err == nil ||
		!strings.Contains(err.Error(), "</p>") || !strings.Contains(err.Error(), "<b>") || !strings.Contains(err.Error(), "byte") {
		t.Errorf("a crossed tag stack returned %v, want an error naming </p>, <b> and the byte offset", err)
	}
	if _, _, err := proseOf(`<p class="note">x`); err == nil {
		t.Error("an unclosed element was measured instead of refused")
	}
	if _, _, err := proseOf(`x</p>`); err == nil {
		t.Error("a close tag with nothing open was measured instead of refused")
	}
	// A quoted attribute may hold '>' without ending the tag.
	if elems, _, err := proseOf(`<p class="note" title="a > b">one</p>`); err != nil || len(elems) != 1 || elems[0].Words != 1 {
		t.Errorf("a '>' inside a quoted attribute broke the scan: %v %v", elems, err)
	}
	// A note-shaped class in no map is reported, not silently ignored.
	if _, unclassified, _ := proseOf(`<span class="newhint">x</span>`); len(unclassified) != 1 {
		t.Errorf("a note-shaped class in no map was not reported: %v", unclassified)
	}
	if n := countWords("12:00:00Z — 2026-08-25 · Node's"); n != 3 {
		t.Errorf("countWords = %d, want 3", n)
	}
}

// longAttributes reports every rendered title, aria-label, aria-description,
// placeholder or alt over maxTitleWords: a tooltip is a note nobody budgets.
func longAttributes(content string) []string {
	var out []string
	for _, m := range titleAttr.FindAllStringSubmatch(content, -1) {
		value := html.UnescapeString(m[2] + m[3])
		if n := countWords(value); n > maxTitleWords {
			out = append(out, fmt.Sprintf("%s is %d words, over %d: %q", m[1], n, maxTitleWords, value))
		}
	}
	return out
}

// --- T2: every screen is within its budget ----------------------------------

// copyBudgetFixture is the sweep fixture with every Node's
// certificate validity recorded and node-web-1's Policy reported: the state a
// healthy Relay is in, so each screen's budget is its standing copy and not a
// situational message the fixture happened to provoke.
func copyBudgetFixture() Deps {
	d := sweepFixture()
	nodes := append([]registry.Node(nil), fleetNodes(d)...)
	for i := range nodes {
		nodes[i].CertNotAfter = testNow.Add(30 * 24 * time.Hour)
	}
	d = withFleet(d, nodes...)
	return withPolicy(d, map[string]policyview.Snapshot{
		"node-web-1": reportedSnapshot(policyview.Snapshot{AllowedOperations: []string{"service.restart"}}, testNow.Add(-90*time.Second)),
	})
}

// copyBudgets is each screen's word budget for explanatory prose. Each is the
// measured count rounded up to a multiple of five, so a screen has at most
// four words of slack. A count over its budget is a copy problem: cut, do not
// raise.
//
// Fleet, Compare and Access carry no standing prose, so their budget is zero:
// the guard still fails on any note that appears (00-foundations.md, D34).
// Access draws its OAuth sentence only when OAuth is configured; the fixture
// leaves it off.
var copyBudgets = map[string]int{
	"/console/{$}":                     0,
	"/console/nodes/{node_id}":         20,
	"/console/activity":                10,
	"/console/jobs/{job_id}":           60,
	"/console/compare":                 0,
	"/console/accounts":                0,
	"/console/accounts/{account_name}": 20,
	"/console/new-account":             5,
	"/console/access":                  0,
	"day one":                          75,

	"/console/accounts/{account_id}/disable":                  20,
	"/console/accounts/{account_id}/lower":                    20,
	"/console/accounts/{account_id}/tokens/{token_id}/revoke": 20,
}

// budgetPage is one page the budget test renders.
type budgetPage struct {
	key, path string
	h         http.Handler
}

func budgetPages(t *testing.T) []budgetPage {
	t.Helper()
	d := copyBudgetFixture()
	h := newTestHandler(d, accounts.RoleAdmin)
	var pages []budgetPage
	for _, r := range routesFor(d, accounts.RoleAdmin) {
		if r.Method != http.MethodGet || r.Path == "/console/events" || r.Path == LoginPath || strings.Contains(r.Path, "{path...}") {
			continue
		}
		path, _ := fixturePath(r, fixtureIDs)
		if r.Path == "/console/compare" {
			path += "?nodes=node-web-1,node-web-3"
		}
		pages = append(pages, budgetPage{r.Path, path, h})
	}
	pages = append(pages, budgetPage{"day one", "/console/", newTestHandler(dayOneDeps(), accounts.RoleAdmin)})
	return pages
}

func TestCopyBudget_EveryScreenIsWithinItsBudget(t *testing.T) {
	walked := map[string]bool{}
	for _, pg := range budgetPages(t) {
		walked[pg.key] = true
		budget, ok := copyBudgets[pg.key]
		if !ok {
			t.Errorf("%s has no copy budget: add one to copyBudgets, set from what it renders", pg.key)
			continue
		}
		rec := get(t, pg.h, pg.path)
		if rec.Code != http.StatusOK {
			t.Errorf("%s (%s) = %d, want 200 — a budget measured on an error page proves nothing", pg.key, pg.path, rec.Code)
			continue
		}
		content := contentOf(rec.Body.String())
		elems, unclassified, err := proseOf(content)
		if err != nil {
			t.Fatalf("%s (%s): the scanner cannot attribute this page's text: %v", pg.key, pg.path, err)
		}
		for _, u := range unclassified {
			t.Errorf("%s (%s): %s — classify it in copy_budget_test.go or cut it", pg.key, pg.path, u)
		}
		var visible int
		var listing []string
		for _, e := range elems {
			if e.Bounded {
				continue
			}
			listing = append(listing, "  "+e.String())
			visible += e.Words
		}
		if budget > 0 && visible == 0 {
			t.Errorf("%s measured no prose at all against a budget of %d — this guard is not running", pg.key, budget)
		}
		if visible > budget {
			t.Errorf("%s renders %d visible words, over its budget of %d — cut copy, do not raise the budget:\n%s",
				pg.key, visible, budget, strings.Join(listing, "\n"))
		}
		if budget-visible >= 5 {
			t.Errorf("%s's visible budget %d is %d above the %d words it renders: lower it", pg.key, budget, budget-visible, visible)
		}
		if strings.Contains(content, `<details class="about"`) {
			t.Errorf("%s renders an About disclosure, which no screen carries", pg.key)
		}
	}
	for key := range copyBudgets {
		if !walked[key] {
			t.Errorf("copyBudgets has an entry for %s, which no walked page renders: remove it", key)
		}
	}
}

// --- T3: every visible note is one short sentence ---------------------------

// sweepPage is one page T3 renders, with a name for failure messages.
type sweepPage struct {
	name, path string
	h          http.Handler
	status     int
}

func noteSweepPages(t *testing.T) []sweepPage {
	t.Helper()
	var pages []sweepPage
	for _, fixture := range []struct {
		name string
		d    Deps
	}{{"sweep", sweepFixture()}, {"budget", copyBudgetFixture()}} {
		for _, role := range []accounts.Role{accounts.RoleAdmin, accounts.RoleOperator, accounts.RoleViewer} {
			h := newTestHandler(fixture.d, role)
			for _, path := range walkableScreens(routesFor(fixture.d, role), fixtureIDs) {
				pages = append(pages, sweepPage{fixture.name + "/" + string(role), path, h, http.StatusOK})
			}
		}
	}
	add := func(name, path string, d Deps, role accounts.Role, status int) {
		pages = append(pages, sweepPage{name, path, newTestHandler(d, role), status})
	}
	sweep := sweepFixture()
	for _, q := range []string{"?window=fortnight", "?kind=nonesuch", "?q=nginx", "?outcome=failure", "?ac=0"} {
		add("activity", "/console/activity"+q, sweep, accounts.RoleAdmin, http.StatusOK)
	}
	running := cancelDeps(&fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "p", "a")}}, &fakeCanceller{})
	running.Events = newFakeEvents()
	add("running now", "/console/activity", running, accounts.RoleOperator, http.StatusOK)
	add("activity, first run", "/console/activity", dayOneDeps(), accounts.RoleAdmin, http.StatusOK)
	for _, q := range []string{"?window=fortnight", "?kind=nonesuch"} {
		add("access", "/console/access"+q, sweep, accounts.RoleAdmin, http.StatusOK)
	}
	for _, q := range []string{"?filter=node:role=nonesuch", "?filter=foo", "?filter=tag:pci", "?group=nonesuch"} {
		add("fleet", "/console/"+q, sweep, accounts.RoleAdmin, http.StatusOK)
	}
	add("fleet, no validity", "/console/", sweepFixture(), accounts.RoleAdmin, http.StatusOK)
	unwatched := dayOneDeps()
	unwatched.Events = nil
	add("day one, unwatched", "/console/", unwatched, accounts.RoleViewer, http.StatusOK)
	add("day one, untrusted", "/console/", withFleet(renderableDeps()), accounts.RoleAdmin, http.StatusOK)

	add("compare, truncated", "/console/compare?nodes=node-web-1,node-web-2,node-web-3,node-db-1,nope", sweep, accounts.RoleAdmin, http.StatusOK)
	add("compare, one", "/console/compare?nodes=node-web-1", sweep, accounts.RoleAdmin, http.StatusOK)
	add("node missing", "/console/nodes/nope", sweep, accounts.RoleAdmin, http.StatusNotFound)
	add("node offline", "/console/nodes/node-db-1", sweep, accounts.RoleAdmin, http.StatusOK)
	add("node unreported", "/console/nodes/node-web-1", withPolicy(withFleet(renderableDeps(), registry.Node{NodeID: "node-web-1", Connected: true}),
		map[string]policyview.Snapshot{"node-web-1": reportedSnapshot(policyview.Snapshot{PolicyFingerprint: "sha256:snapfp"}, testNow)}), accounts.RoleAdmin, http.StatusOK)
	revoked := withFleet(renderableDeps(), registry.Node{NodeID: "node-gone", RevokedAt: testNow.Add(-time.Hour)})
	add("node revoked, unrecorded", "/console/nodes/node-gone", revoked, accounts.RoleAdmin, http.StatusOK)
	revoked.Audit = fakeAudit{records: []audit.Record{{Kind: audit.KindNodeRevoke, NodeID: "node-gone", Principal: "alice:admin", Timestamp: testNow.Add(-time.Hour)}}}
	add("node revoked, no reason", "/console/nodes/node-gone", revoked, accounts.RoleAdmin, http.StatusOK)

	add("accounts, another", accountPagePath("mike"), sweep, accounts.RoleAdmin, http.StatusOK)
	self := sweepFixture()
	fa := sweepAccounts()
	fa.accounts = append(fa.accounts, accounts.Account{
		ID: testAccountID(accounts.RoleAdmin), Name: testAccountName(accounts.RoleAdmin),
		Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true,
	})
	self.Accounts = fa
	add("accounts, self", accountPagePath(testAccountName(accounts.RoleAdmin)), self, accounts.RoleAdmin, http.StatusOK)

	cancelled := oneJob(nil, jobs.RiskClassMutate)
	cancelled.Total, cancelled.Unresolved, cancelled.State = 2, 1, jobs.JobStateRunning
	cancelled.Counts = map[jobs.Outcome]int{jobs.OutcomeCancelled: 1}
	add("job, cancel requested", jobPath(""), jobDeps(&fakeQueries{
		jobs:  []capability.JobSummary{cancelled},
		tasks: []capability.TaskRow{mutateTask("node-a", jobs.OutcomeCancelled, "")},
		rows:  []capability.AuditRow{{Kind: audit.KindJobCancel, JobID: testJobID, Principal: "gleipnir:operator"}},
	}), accounts.RoleAdmin, http.StatusOK)
	read := []capability.TaskRow{{TaskID: "t", NodeID: "node-a", State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess, RiskClass: jobs.RiskClassRead}}
	add("job, read", jobPath(""), jobDeps(&fakeQueries{jobs: []capability.JobSummary{oneJob(read, jobs.RiskClassRead)}, tasks: read}), accounts.RoleAdmin, http.StatusOK)
	return pages
}

func TestCopyBudget_EveryVisibleNoteIsOneShortSentence(t *testing.T) {
	measured := 0
	for _, pg := range noteSweepPages(t) {
		rec := get(t, pg.h, pg.path)
		if rec.Code != pg.status {
			t.Errorf("%s %s = %d, want %d", pg.name, pg.path, rec.Code, pg.status)
			continue
		}
		elems, unclassified, err := proseOf(contentOf(rec.Body.String()))
		if err != nil {
			t.Fatalf("%s %s: the scanner cannot attribute this page's text: %v", pg.name, pg.path, err)
		}
		for _, u := range unclassified {
			t.Errorf("%s %s: %s — classify it in copy_budget_test.go or cut it", pg.name, pg.path, u)
		}
		for _, a := range longAttributes(contentOf(rec.Body.String())) {
			t.Errorf("%s %s: %s", pg.name, pg.path, a)
		}
		for _, e := range elems {
			measured++
			if e.Words > maxNoteWords {
				t.Errorf("%s %s: %s is over %d words — one sentence of about fifteen", pg.name, pg.path, e, maxNoteWords)
			}
		}
	}
	if measured == 0 {
		t.Fatal("swept zero visible notes — this guard is not running")
	}
}

// --- T4: template source, on every branch path ------------------------------

// templateSource is one template literal in the package's non-test source.
type templateSource struct {
	file string
	line int
	text string
}

func consoleTemplateSources(t *testing.T) []templateSource {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var out []templateSource
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var arg ast.Expr
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				if fn.Name == "newScreen" && len(call.Args) == 2 {
					arg = call.Args[1]
				}
			case *ast.SelectorExpr:
				if fn.Sel.Name == "Parse" && len(call.Args) == 1 {
					arg = call.Args[0]
				}
			}
			lit, ok := arg.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING || !strings.HasPrefix(lit.Value, "`") {
				return true
			}
			text, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatalf("%s: %v", fset.Position(lit.Pos()), err)
			}
			out = append(out, templateSource{name, fset.Position(lit.Pos()).Line, text})
			return true
		})
	}
	return out
}

var (
	tmplComment = regexp.MustCompile(`(?s)\{\{-?\s*/\*.*?\*/\s*-?\}\}`)
	tmplAction  = regexp.MustCompile(`(?s)\{\{.*?\}\}`)
	titleAttr   = regexp.MustCompile(`\b(title|aria-label|aria-description|placeholder|alt)=(?:"([^"]*)"|'([^']*)')`)
	anyTag      = regexp.MustCompile(`<[^>]*>`)
)

// blank replaces every match of re in s with spaces of the same length, so
// offsets into the result are offsets into s.
func blank(re *regexp.Regexp, s string) string {
	return re.ReplaceAllStringFunc(s, func(m string) string {
		return strings.Map(func(r rune) rune {
			if r == '\n' {
				return r
			}
			return ' '
		}, m)
	})
}

// maskActions replaces each {{…}} with X of the same length, so a tag scan
// cannot see into an action and every offset still lines up.
func maskActions(s string) string {
	return tmplAction.ReplaceAllStringFunc(s, func(m string) string { return strings.Repeat("X", len(m)) })
}

// branchTexts returns the text of every branch path through a template
// fragment: each output action and {{template}} call is the word "X", and
// an if, with or range contributes either its body or its else.
func branchTexts(t *testing.T, where, fragment string) []string {
	t.Helper()
	tree := parse.New("fragment")
	tree.Mode = parse.SkipFuncCheck
	if _, err := tree.Parse(fragment, "", "", map[string]*parse.Tree{}); err != nil {
		t.Fatalf("%s: the template fragment does not parse on its own: %v\n%s", where, err, fragment)
	}
	paths := walkBranches(t, where, tree.Root)
	return paths
}

const maxBranchPaths = 256

func walkBranches(t *testing.T, where string, list *parse.ListNode) []string {
	t.Helper()
	paths := []string{""}
	if list == nil {
		return paths
	}
	for _, n := range list.Nodes {
		var alts []string
		switch n := n.(type) {
		case *parse.TextNode:
			alts = []string{string(n.Text)}
		case *parse.ActionNode, *parse.TemplateNode:
			alts = []string{" X "}
		case *parse.IfNode:
			alts = append(walkBranches(t, where, n.List), walkBranches(t, where, n.ElseList)...)
		case *parse.WithNode:
			alts = append(walkBranches(t, where, n.List), walkBranches(t, where, n.ElseList)...)
		case *parse.RangeNode:
			alts = append(walkBranches(t, where, n.List), walkBranches(t, where, n.ElseList)...)
		default:
			alts = []string{""}
		}
		var next []string
		for _, p := range paths {
			for _, a := range alts {
				next = append(next, p+a)
			}
		}
		if len(next) > maxBranchPaths {
			t.Fatalf("%s: more than %d branch paths — split the element", where, maxBranchPaths)
		}
		paths = next
	}
	return paths
}

// longestPath is the most words any branch path through fragment renders.
func longestPath(t *testing.T, where, fragment string) (int, string) {
	t.Helper()
	best, bestText := 0, ""
	for _, p := range branchTexts(t, where, fragment) {
		text := html.UnescapeString(anyTag.ReplaceAllString(p, ""))
		if n := countWords(text); n > best {
			best, bestText = n, strings.Join(strings.Fields(text), " ")
		}
	}
	return best, bestText
}

// sourceElement is one measured or bounded element found in template source.
type sourceElement struct {
	where, tag, class, inner string
	exempt                   bool
}

// templateElements finds every measured, bounded and exempt element in src
// and returns its inner fragment.
func templateElements(t *testing.T, src templateSource) []sourceElement {
	t.Helper()
	text := blank(tmplComment, src.text)
	masked := maskActions(text)
	where := func(off int) string {
		return fmt.Sprintf("%s:%d", src.file, src.line+strings.Count(text[:off], "\n"))
	}
	tags := copyTag.FindAllStringSubmatchIndex(masked, -1)

	// Leniently tracked ancestors, only to classify a bare <p>: a template's
	// markup may open and close an element in different branches, so this
	// stack pops to the matching name rather than refusing.
	type anc struct {
		tag     string
		classes []string
	}
	var stack []anc
	var out []sourceElement
	for i, m := range tags {
		closing := masked[m[2]:m[3]] == "/"
		tag := strings.ToLower(masked[m[4]:m[5]])
		attrs := masked[m[6]:m[7]]
		if voidTags[tag] {
			continue
		}
		if closing {
			for j := len(stack) - 1; j >= 0; j-- {
				if stack[j].tag == tag {
					stack = stack[:j]
					break
				}
			}
			continue
		}
		classes := classesOf(attrs)
		ancestors := make([]*openElem, 0, len(stack))
		for _, a := range stack {
			ancestors = append(ancestors, &openElem{tag: a.tag, classes: a.classes})
		}
		stack = append(stack, anc{tag, classes})
		kind, class := classify(tag, classes, ancestors)
		if kind != kindMeasured && kind != kindBounded && kind != kindDenynote && kind != kindExempt {
			continue
		}
		// Pair the open tag with its close by same-name depth.
		depth, end := 0, -1
		for _, n := range tags[i+1:] {
			if strings.ToLower(masked[n[4]:n[5]]) != tag {
				continue
			}
			if masked[n[2]:n[3]] == "/" {
				if depth == 0 {
					end = n[0]
					break
				}
				depth--
			} else {
				depth++
			}
		}
		if end < 0 {
			t.Fatalf("%s: <%s class=%q> has no matching </%s> — the source scan cannot measure it", where(m[0]), tag, class, tag)
		}
		out = append(out, sourceElement{where(m[0]), tag, class, text[m[1]:end], kind == kindExempt})
	}
	return out
}

// templateRuns is the source twin of proseOf's unclassified check: every run
// of minUnclassifiedRun or more words between two tags of a template that no
// measured, bounded, exempt or value element accounts for. It reaches
// the branches no fixture renders. A run that spans an {{if}} adds its
// branches together, so it can over-count; a false positive is classified or
// split, never raised past.
func templateRuns(src templateSource) []string {
	text := blank(tmplComment, src.text)
	masked := maskActions(text)
	type frame struct {
		tag         string
		classes     []string
		accounted   bool
		transparent bool // a bare inline tag: it neither ends nor starts a run
	}
	var stack []frame
	var out []string
	var run strings.Builder
	runStart, pos := 0, 0
	flush := func() {
		seg := strings.Join(strings.Fields(html.UnescapeString(run.String())), " ")
		if n := countWords(seg); n >= minUnclassifiedRun {
			out = append(out, fmt.Sprintf("%s:%d: a %d-word run no measured class collects: %q",
				src.file, src.line+strings.Count(text[:runStart], "\n"), n, seg))
		}
		run.Reset()
	}
	for _, m := range copyTag.FindAllStringSubmatchIndex(masked, -1) {
		if len(stack) == 0 || !stack[len(stack)-1].accounted {
			if run.Len() == 0 {
				runStart = pos
			}
			run.WriteString(masked[pos:m[0]])
		}
		pos = m[1]
		closing := masked[m[2]:m[3]] == "/"
		tag := strings.ToLower(masked[m[4]:m[5]])
		if voidTags[tag] {
			flush()
			continue
		}
		if closing {
			transparent := false
			for j := len(stack) - 1; j >= 0; j-- {
				if stack[j].tag == tag {
					transparent = stack[j].transparent
					stack = stack[:j]
					break
				}
			}
			if !transparent {
				flush()
			}
			continue
		}
		classes := classesOf(masked[m[6]:m[7]])
		ancestors := make([]*openElem, 0, len(stack))
		accounted := valueTags[tag] || tag == "script" || tag == "style"
		for _, a := range stack {
			ancestors = append(ancestors, &openElem{tag: a.tag, classes: a.classes})
			accounted = accounted || a.accounted
		}
		kind, _ := classify(tag, classes, ancestors)
		transparent := inlineTags[tag] && kind == kindNone && !valueTags[tag]
		if !transparent {
			flush()
		}
		stack = append(stack, frame{tag, classes, accounted || kind != kindNone, transparent})
	}
	if len(stack) == 0 || !stack[len(stack)-1].accounted {
		if run.Len() == 0 {
			runStart = pos
		}
		run.WriteString(masked[pos:])
	}
	flush()
	return out
}

// requireNoLiteralWords fails when an exempt element's template source holds a
// literal word on any branch. An exemption is for recorded data the Relay's
// authors did not write, so what the template adds around the data is exactly
// what the exemption must not hide: a label belongs in a measured element
// beside it. Template actions and the "→" of a diff row are the only content.
func requireNoLiteralWords(t *testing.T, e sourceElement) {
	t.Helper()
	for _, path := range branchTexts(t, e.where, e.inner) {
		var words []string
		for _, f := range strings.Fields(html.UnescapeString(strings.ReplaceAll(anyTag.ReplaceAllString(path, " "), "→", " "))) {
			if f != "X" { // a template action
				words = append(words, f)
			}
		}
		if literal := strings.Join(words, " "); countWords(literal) > 0 {
			t.Errorf("%s: exempt <%s class=%q> carries Console-authored words, which the exemption would hide: %q — move them into a measured element",
				e.where, e.tag, e.class, literal)
			return
		}
	}
}

func TestCopyBudget_EveryTemplateNoteIsShortOnEveryPath(t *testing.T) {
	sources := consoleTemplateSources(t)
	if len(sources) < 15 {
		t.Fatalf("found %d template literals, want the whole Console's — the source scan is not finding them", len(sources))
	}
	elements, exempts := 0, 0
	var corpus strings.Builder
	for _, src := range sources {
		for _, e := range templateElements(t, src) {
			if e.exempt {
				exempts++
				requireNoLiteralWords(t, e)
				continue
			}
			elements++
			if n, text := longestPath(t, e.where, e.inner); n > maxSourceWords {
				t.Errorf("%s: <%s class=%q> renders %d words on its longest branch, over %d: %q",
					e.where, e.tag, e.class, n, maxSourceWords, text)
			}
		}
		for _, r := range templateRuns(src) {
			t.Errorf("%s — classify the element in copy_budget_test.go or cut it", r)
		}
		text := blank(tmplComment, src.text)
		masked := maskActions(text)
		corpus.WriteString(masked)
		for _, m := range titleAttr.FindAllStringSubmatchIndex(masked, -1) {
			where := fmt.Sprintf("%s:%d", src.file, src.line+strings.Count(text[:m[0]], "\n"))
			start, end := m[4], m[5]
			if start < 0 { // single-quoted
				start, end = m[6], m[7]
			}
			if n, value := longestPath(t, where, text[start:end]); n > maxTitleWords {
				t.Errorf("%s: %s is %d words, over %d: %q", where, text[m[2]:m[3]], n, maxTitleWords, value)
			}
		}
		for _, m := range copyTag.FindAllStringSubmatch(masked, -1) {
			tag := strings.ToLower(m[2])
			if tag != "span" && tag != "div" {
				continue
			}
			for _, c := range classesOf(m[3]) {
				if !noteish.MatchString(c) || strings.Trim(c, "X") != c {
					continue
				}
				key := tag + "." + c
				if !measuredClasses[key] && boundedClasses[key] == "" && exemptClasses[key] == "" {
					t.Errorf("%s:%d: <%s class=%q> reads like a note and is in no map — classify it", src.file, src.line, tag, c)
				}
			}
		}
	}
	if exempts < 1 {
		t.Fatalf("found %d exempt template elements, want at least 1 (p.summary) — the exemption check is not finding them", exempts)
	}
	if elements < 60 {
		t.Fatalf("measured %d template elements, want at least 60 — the source scan has stopped finding notes", elements)
	}

	// Every class a map names is used somewhere: a stale exemption is an
	// exemption waiting for a new element to borrow it.
	used := map[string]bool{}
	for _, m := range copyTag.FindAllStringSubmatch(corpus.String(), -1) {
		if m[1] == "/" {
			continue
		}
		for _, c := range classesOf(m[3]) {
			used[c] = true
			used[strings.ToLower(m[2])+"."+c] = true
		}
	}
	var named []string
	for k := range measuredClasses {
		named = append(named, k)
	}
	for _, m := range []map[string]string{boundedClasses, exemptClasses} {
		for k := range m {
			named = append(named, k)
		}
	}
	for _, m := range []map[string]bool{barePContainers, barePSkipped} {
		for k := range m {
			named = append(named, k)
		}
	}
	sort.Strings(named)
	for _, c := range named {
		if !used[c] {
			t.Errorf("copy_budget_test.go classifies %q, which no template uses: remove it", c)
		}
	}
}

// --- T5: notes written as Go strings ----------------------------------------

func TestCopyBudget_GoStringNotesAreShort(t *testing.T) {
	// Residual: a NEW Go-string note is caught only when T3 renders it.
	rows := []struct {
		name, text string
		limit      int
	}{
		{"facetRefusalHint", facetRefusalHint, maxGoNoteWords},
		{"tagFilterRefusal", tagFilterRefusal, maxGoNoteWords},
		{"filterTermExample", filterTermExample, maxGoNoteWords},
		{"selfPanelNote", selfPanelNote, maxGoNoteWords},
		{"doneSentence(role)", doneSentence(string(doneRole)), maxGoNoteWords},
		{"Role.Description(admin)", accounts.RoleAdmin.Description(), maxGoNoteWords},
		{"liveCountTitle", liveCountTitle, maxTitleWords},
		{"freezeEngagedDetail", freezeEngagedDetail, maxGoNoteWords},
		{"freezeUnreadableDetail", freezeUnreadableDetail, maxGoNoteWords},
		{"selfReportedTitle", selfReportedTitle, maxTitleWords},
		{"selfTargetRefusal", selfTargetRefusal, maxHeadingWords},
		{"lastAdminRefusal", lastAdminRefusal, maxHeadingWords},
		{"throttleMessage(1s)", throttleMessage(time.Second), maxHeadingWords},
		{"throttleMessage(30s)", throttleMessage(30 * time.Second), maxHeadingWords},
	}
	if len(rows) < 13 {
		t.Fatalf("%d rows, want at least 13", len(rows))
	}
	for _, r := range rows {
		if r.text == "" {
			t.Errorf("%s is empty, so its length proves nothing", r.name)
		}
		if n := countWords(r.text); n > r.limit {
			t.Errorf("%s is %d words, over %d: %q", r.name, n, r.limit, r.text)
		}
	}
}

// --- T6: POST result headings -----------------------------------------------

// literalWords counts the words of a string expression built from literals
// and +, counting each non-literal operand as one word.
func literalWords(e ast.Expr) int {
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return 1
		}
		s, err := strconv.Unquote(e.Value)
		if err != nil {
			return 1
		}
		return countWords(s)
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			return literalWords(e.X) + literalWords(e.Y)
		}
	case *ast.ParenExpr:
		return literalWords(e.X)
	}
	return 1
}

func TestCopyBudget_ResultHeadingsAreShort(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	headings := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			kv, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "Heading" {
				return true
			}
			headings++
			if n := literalWords(kv.Value); n > maxHeadingWords {
				t.Errorf("%s: a result heading is %d words, over %d — keep the reason an operator acts on, cut the rest",
					fset.Position(kv.Pos()), n, maxHeadingWords)
			}
			return true
		})
	}
	if headings < 15 {
		t.Fatalf("found %d result headings, want at least 15 — the scan has stopped finding them", headings)
	}
}

// --- T7: no doc voice in what renders ---------------------------------------

// docVoice is a reference to the repository's documents rather than a
// sentence an operator can use: an ADR number, a spec number, an invariant.
var docVoice = regexp.MustCompile(`ADR-\d{4}|\b[Ss]pec \d{2}\b|\binvariant #?\d`)

func TestConsole_NoDocVoiceInRenderedStrings(t *testing.T) {
	for _, s := range []string{"(ADR-0027)", "Spec 08 requires", "invariant 2"} {
		if !docVoice.MatchString(s) {
			t.Errorf("docVoice does not match %q", s)
		}
	}
	for _, s := range []string{"docs/design/console/08-approval-object.md", "specification", "invariants"} {
		if docVoice.MatchString(s) {
			t.Errorf("docVoice matches %q, which is not doc voice", s)
		}
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	literals := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		// Arguments of slog calls are logs, not copy.
		logged := map[*ast.BasicLit]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "slog" {
					ast.Inspect(call, func(m ast.Node) bool {
						if lit, ok := m.(*ast.BasicLit); ok {
							logged[lit] = true
						}
						return true
					})
				}
			}
			return true
		})
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING || logged[lit] {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			literals++
			if m := docVoice.FindString(tmplComment.ReplaceAllString(s, "")); m != "" {
				t.Errorf("%s: a string that can render carries %q — say what it means to an operator, not where it was decided",
					fset.Position(lit.Pos()), m)
			}
			return true
		})
	}
	if literals < 100 {
		t.Fatalf("scanned %d string literals — the scan is not reading the package", literals)
	}
}

// --- Ruled qualifiers -------------------------------------------------------

// TestCopyBudget_RuledQualifiersStillRender pins each qualifier #849 cut to one
// sentence and kept, where nothing else pins it: a shorter sentence that drops
// one of these makes a visible claim stronger than the truth.
func TestCopyBudget_RuledQualifiersStillRender(t *testing.T) {
	d := copyBudgetFixture()
	h := newTestHandler(d, accounts.RoleAdmin)
	for _, c := range []struct {
		why, path, want string
		h               http.Handler
	}{
		// node-db-1 is the fixture Node that carries a relay: label.
		{"invariant 7: relay: is never the Node's", "/console/nodes/node-db-1",
			"set by the Relay, never the Node", h},
		{"invariant 12: Policy comes from the Node's own engine", "/console/nodes/node-web-1",
			"from this Node's own engine, never the Relay", h},
		{"invariant 6: why a daemon trusts this CA", "/console/",
			"A daemon trusts this authority because it was installed with the CA bundle.", newTestHandler(dayOneDeps(), accounts.RoleAdmin)},
		{"10-day-one: which listener the server certificate is", "/console/",
			"This Console&#39;s certificate, re-issued about daily", newTestHandler(dayOneDeps(), accounts.RoleAdmin)},
		{"cert provenance: the expiry is unknown", "/console/nodes/node-web-1",
			"so its expiry is unknown until its next renewal", newTestHandler(sweepFixture(), accounts.RoleAdmin)},
	} {
		if body := contentOf(get(t, c.h, c.path).Body.String()); !strings.Contains(body, c.want) {
			t.Errorf("%s: %s no longer renders %q", c.why, c.path, c.want)
		}
	}
}
