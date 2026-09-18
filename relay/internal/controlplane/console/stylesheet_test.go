package console

// stylesheet_test.go guards two console.css properties #640 found broken by
// eye, neither of which the Go compiler or html/template can catch: they live
// at the seam between the stylesheet and the templates that apply its
// classes, and that seam is not typed.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	cssCommentPattern = regexp.MustCompile(`(?s)/\*.*?\*/`)
	// cssRulePattern finds INNERMOST rules only: the selector group
	// `[^{}]+` cannot itself contain a brace, so an @media wrapper (whose
	// own "body" contains further braces) can never complete a match —
	// the engine simply finds the nested rules inside it instead. This is
	// what lets one pass see rules declared inside `@media (...) { ... }`
	// alongside top-level ones with no special-casing.
	cssRulePattern  = regexp.MustCompile(`([^{}]+)\{([^{}]*)\}`)
	cssClassPattern = regexp.MustCompile(`\.([A-Za-z0-9_-]+)`)
	// cssTableElementPattern matches a compound selector that IS a td or th
	// element — "td", "td.foo", "td#foo", "td:hover", "td[data-x]" — but not
	// "tbody" or "thead", whose extra letters keep them out of the class.
	cssTableElementPattern = regexp.MustCompile(`^(?:td|th)(?:$|[.#:\[])`)
	// htmlTableCellPattern finds a <td ...> or <th ...> start tag's class
	// attribute in a Go template source string.
	htmlTableCellPattern = regexp.MustCompile(`<(?:td|th)\b[^>]*\bclass="([^"]*)"`)
)

// declaresFlexOrGrid reports whether decls (one rule's declaration block, "a:
// b; c: d") sets display to one of the four layout modes that take an
// element out of normal flow — and, for a <td> or <th>, out of TABLE layout,
// which is what item 1 (#640) is about: every sibling cell in the row loses
// its column alignment with the header above it.
func declaresFlexOrGrid(decls string) bool {
	for _, decl := range strings.Split(decls, ";") {
		kv := strings.SplitN(decl, ":", 2)
		if len(kv) != 2 || strings.TrimSpace(kv[0]) != "display" {
			continue
		}
		switch strings.TrimSpace(kv[1]) {
		case "flex", "inline-flex", "grid", "inline-grid":
			return true
		}
	}
	return false
}

// lastCompound returns sel's final compound selector — the part that names
// the element actually being styled — by splitting on whitespace and the
// descendant/child/sibling combinators (a later compound in a selector like
// ".devtable table tr td" is what CSS specificity and cascade both key off
// last). "" for an empty or malformed selector.
func lastCompound(sel string) string {
	fields := strings.FieldsFunc(sel, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '>' || r == '+' || r == '~'
	})
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// TestConsole_NoTableCellIsTakenOutOfTableLayout guards #640's item 1: a
// stylesheet class that sets display:flex/grid must never be applied to a
// <td> or <th> — flex/grid takes the cell out of TABLE layout, so every
// sibling cell in that row is displaced from the header above it. That is
// exactly how the Fleet table's STATE/LABELS/POLICY/LAST SEEN columns shifted:
// `.statecell`/`.lblcell` set display:flex in the stylesheet, and fleet.go
// applied them directly to `<td>` elements.
//
// Two passes are necessary because the bug lives at a seam the Go compiler
// never checks: the stylesheet alone is fine (a flex CLASS is ordinary), and
// a template alone is fine (a class attribute is just a string) — only
// together do they take a cell out of table layout.
func TestConsole_NoTableCellIsTakenOutOfTableLayout(t *testing.T) {
	css, err := assetsFS.ReadFile("assets/console.css")
	if err != nil {
		t.Fatalf("read console.css: %v", err)
	}
	stripped := cssCommentPattern.ReplaceAllString(string(css), "")

	flexClasses := map[string]bool{}
	flexRules := 0
	for _, m := range cssRulePattern.FindAllStringSubmatch(stripped, -1) {
		selectorGroup, decls := m[1], m[2]
		if !declaresFlexOrGrid(decls) {
			continue
		}
		flexRules++
		for _, sel := range strings.Split(selectorGroup, ",") {
			compound := lastCompound(strings.TrimSpace(sel))
			if compound == "" {
				continue
			}
			if cssTableElementPattern.MatchString(compound) {
				t.Errorf("selector %q sets display:flex/grid directly on a td/th element — that takes "+
					"the cell out of table layout; move the flex layout to a wrapper element inside "+
					"the cell instead", strings.TrimSpace(sel))
			}
			for _, cm := range cssClassPattern.FindAllStringSubmatch(compound, -1) {
				flexClasses[cm[1]] = true
			}
		}
	}
	if flexRules == 0 {
		t.Fatal("found zero display:flex/grid rules in console.css — this guard is not running")
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	tdClassAttrs := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, m := range htmlTableCellPattern.FindAllStringSubmatch(string(src), -1) {
			tdClassAttrs++
			for _, class := range strings.Fields(m[1]) {
				// A conditional class built by the template engine, e.g.
				// `class="chip{{if .X}} on{{end}}"`, is not a static token
				// this check can resolve — and every such class in this
				// package is a chip/state class, never a layout one.
				if strings.Contains(class, "{{") {
					continue
				}
				if flexClasses[class] {
					t.Errorf("%s: a <td>/<th> carries class %q, which console.css sets "+
						"display:flex/grid on — move the flex layout to a wrapper element "+
						"inside the cell, never the cell itself", name, class)
				}
			}
		}
	}
	if tdClassAttrs == 0 {
		t.Fatal("found zero <td>/<th> class attributes to check — this guard is not running")
	}
}

// TestConsole_ShellStacksAtPhoneWidth pins #640's item 2: at phone width the
// shell must stack rather than hold the sidebar beside the content, which is
// what made the document itself scroll sideways at ~400px (document
// scrollWidth 493px on Fleet and Activity, 643px on Node detail).
//
// A string pin, in the same style TestNode_RecentTasksScrollsInsideItsPanel
// uses for the stylesheet: it does not render a page at 400px (Go has no
// layout engine), it asserts the RULE that makes that rendering true exists.
func TestConsole_ShellStacksAtPhoneWidth(t *testing.T) {
	css, err := assetsFS.ReadFile("assets/console.css")
	if err != nil {
		t.Fatalf("read console.css: %v", err)
	}
	body := string(css)

	if !strings.Contains(body, "@media (max-width: 720px)") {
		t.Fatal("no @media (max-width: 720px) block — the shell has no phone-width layout at all")
	}
	for _, want := range []string{
		".app { flex-direction: column; }",
		".gbody { flex-direction: column; }",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("console.css does not contain %q — the shell (or the Fleet page's grouped "+
				"body) does not stack at phone width", want)
		}
	}
}
