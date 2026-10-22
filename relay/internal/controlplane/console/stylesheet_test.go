package console

// stylesheet_test.go guards two console.css properties #640 found broken by
// eye, neither of which the Go compiler or html/template can catch: they live
// at the seam between the stylesheet and the templates that apply its
// classes, and that seam is not typed.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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

// mediaBlock returns the declarations inside the FIRST "@media (query) {"
// block in css, matched by counting braces rather than up to the first "}":
// a naive shortest-match would stop at a nested rule's own closing brace
// (the 800px block's ".nav { ... }" rule spans several lines) and silently
// pass a pin that names a rule declared OUTSIDE the block entirely. "" if
// query's block is not found.
func mediaBlock(css, query string) string {
	open := strings.Index(css, "@media ("+query+") {")
	if open == -1 {
		return ""
	}
	start := open + len("@media ("+query+") {")
	depth := 1
	for i := start; i < len(css); i++ {
		switch css[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return css[start:i]
			}
		}
	}
	return ""
}

// TestConsole_ShellStacksAtNarrowWidth pins #640's item 2 (moved from 720px to
// 800px by #473): under the 800px breakpoint the shell must stack rather than
// hold the sidebar beside the content, which is what made the document itself
// scroll sideways at ~400px (document scrollWidth 493px on Fleet and
// Activity, 643px on Node detail). It also pins the facet rail and the feed
// timestamp column, which collapse in the same block.
//
// A string pin, in the same style TestNode_RecentTasksScrollsInsideItsPanel
// uses for the stylesheet: it does not render a page at 400px (Go has no
// layout engine), it asserts the RULE that makes that rendering true exists.
// It asserts the pinned rules are INSIDE the 800px block itself, not merely
// present somewhere in the file: a desktop rule that happens to share the
// same text (or one left behind in a different media block) would otherwise
// pass this guard without stacking anything at that width.
func TestConsole_ShellStacksAtNarrowWidth(t *testing.T) {
	css, err := assetsFS.ReadFile("assets/console.css")
	if err != nil {
		t.Fatalf("read console.css: %v", err)
	}

	block := mediaBlock(string(css), "max-width: 800px")
	if block == "" {
		t.Fatal("no @media (max-width: 800px) block — the shell has no narrow-width layout at all")
	}
	for _, want := range []string{
		".app { flex-direction: column; }",
		".gbody { flex-direction: column; }",
		".facets { width: auto;",
		".evwhen { width: auto; }",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("the @media (max-width: 800px) block does not contain %q — the shell (or a "+
				"rail or column inside it) does not stack at narrow width", want)
		}
	}
}

// declValue returns the value of prop in decls ("a: b; c: d"), and whether it
// is declared at all.
func declValue(decls, prop string) (string, bool) {
	for _, decl := range strings.Split(decls, ";") {
		kv := strings.SplitN(decl, ":", 2)
		if len(kv) == 2 && strings.TrimSpace(kv[0]) == prop {
			return strings.TrimSpace(kv[1]), true
		}
	}
	return "", false
}

var cssElementPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*`)

// compoundParts splits one compound selector into its element name ("" when it
// has none) and its class names: "th.cmpkey" is ("th", [cmpkey]).
func compoundParts(compound string) (element string, classes []string) {
	element = cssElementPattern.FindString(compound)
	for _, m := range cssClassPattern.FindAllStringSubmatch(compound, -1) {
		classes = append(classes, m[1])
	}
	return element, classes
}

// precedingCompound returns the compound before sel's last one, "" if sel has
// only one.
func precedingCompound(sel string) string {
	fields := strings.FieldsFunc(sel, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '>' || r == '+' || r == '~'
	})
	if len(fields) < 2 {
		return ""
	}
	return fields[len(fields)-2]
}

// identifierElements are the elements whose content is an identifier by
// nature, and the classes console.css gives to the ones that are not.
var (
	identifierElements = []string{"code", "pre", "kbd", "samp"}
	identifierClasses  = []string{"mono", "nodeid", "ident"}
)

func isTransforming(v string) bool {
	return v == "uppercase" || v == "lowercase" || v == "capitalize"
}

// scopedUpperRule is "an <element> inside an element carrying class
// <ancestor>" — the shape of `.panel h3`.
type scopedUpperRule struct{ ancestor, element string }

// htmlTagPattern finds every start and end tag in a template source.
var htmlTagPattern = regexp.MustCompile(`</?([A-Za-z][A-Za-z0-9]*)\b[^>]*>`)

var (
	htmlClassAttrPattern = regexp.MustCompile(`\bclass="([^"]*)"`)
	tmplActionPattern    = regexp.MustCompile(`(?s)\{\{(.*?)\}\}`)
	cssAttrContent       = regexp.MustCompile(`^attr\(\s*([A-Za-z0-9_-]+)\s*\)$`)
	goLineCommentPattern = regexp.MustCompile(`(?m)^\s*//.*$`)
	goRawStringPattern   = regexp.MustCompile("(?s)`([^`]*)`")
)

var voidElements = map[string]bool{
	"br": true, "img": true, "input": true, "source": true, "wbr": true,
	"hr": true, "meta": true, "link": true,
}

// attrRule is a pseudo-element rule that renders content: attr(<attr>) under a
// case transform; scope holds the classes of its selector's earlier compounds.
type attrRule struct {
	attr, sel string
	scope     []string
}

// reaches reports whether the rule can apply to markup in unit: always when
// the selector names no class, else when unit carries one of them.
func (r attrRule) reaches(unit string) bool {
	if len(r.scope) == 0 {
		return true
	}
	for _, m := range htmlClassAttrPattern.FindAllStringSubmatch(unit, -1) {
		for _, have := range strings.Fields(tmplActionPattern.ReplaceAllString(m[1], " ")) {
			for _, want := range r.scope {
				if have == want {
					return true
				}
			}
		}
	}
	return false
}

// tmplControlWords are the actions that emit no text of their own.
var tmplControlWords = map[string]bool{
	"if": true, "else": true, "end": true, "range": true, "with": true,
	"define": true, "template": true, "block": true, "break": true, "continue": true,
}

type htmlTag struct {
	name       string
	classes    []string
	start, end int // the tag's own extent
	closeStart int // start of the matching end tag; -1 if none was found
	closeEnd   int
	isStart    bool
}

func (t htmlTag) hasClass(c string) bool {
	for _, have := range t.classes {
		if have == c {
			return true
		}
	}
	return false
}

// scanTags lists every tag in unit and pairs each start tag with its end tag.
// An end tag closes the nearest open tag of its name; open tags skipped over
// stay unclosed (closeStart -1), which is what a template that opens the same
// tag in two {{if}} branches looks like.
func scanTags(unit string) []htmlTag {
	var tags []htmlTag
	var open []int
	for _, m := range htmlTagPattern.FindAllStringSubmatchIndex(unit, -1) {
		raw := unit[m[0]:m[1]]
		name := strings.ToLower(unit[m[2]:m[3]])
		if strings.HasPrefix(raw, "</") {
			for i := len(open) - 1; i >= 0; i-- {
				if tags[open[i]].name == name {
					tags[open[i]].closeStart, tags[open[i]].closeEnd = m[0], m[1]
					open = open[:i]
					break
				}
			}
			tags = append(tags, htmlTag{name: name, start: m[0], end: m[1], closeStart: -1})
			continue
		}
		t := htmlTag{name: name, start: m[0], end: m[1], closeStart: -1, isStart: true}
		if cm := htmlClassAttrPattern.FindStringSubmatch(raw); cm != nil {
			// A {{...}} inside the attribute is removed, not kept as a token:
			// `chip{{if .X}} on{{end}}` is "chip on" to this check.
			t.classes = strings.Fields(tmplActionPattern.ReplaceAllString(cm[1], " "))
		}
		tags = append(tags, t)
		if !voidElements[name] && !strings.HasSuffix(raw, "/>") {
			open = append(open, len(tags)-1)
		}
	}
	return tags
}

func lineOf(src string, offset int) int { return 1 + strings.Count(src[:offset], "\n") }

// identifierCaseFindings is the pure core of
// TestConsole_IdentifiersAreNeverCaseTransformed: it reads css and the Go
// template sources and reports every way an identifier can reach the screen
// case-transformed. Pass one reads the stylesheet: the identifier elements must
// be exempt, nothing may transform one, and the rules that DO transform are
// collected. Pass two walks the templates for an interpolation inside text
// those rules transform, because text-transform is inherited: an ID dropped
// into an upper-cased th, label or heading renders upper-cased however the
// stylesheet treats code.
//
// allow maps "<file> <root> <action>" to the reason that field is fixed
// vocabulary and not an identifier; usedAllow reports which entries matched.
// The guard does not model the cascade: an element is treated as reset when
// any of its classes or its tag has a reset rule, even if a later single-class
// uppercase rule would win. No element does both today; add one and this
// under-reports.
// A `{{template "x" .}}` body is not followed — components are checked where
// they are defined. roots counts the transforming elements found, so a walker
// that finds nothing cannot pass silently.
func identifierCaseFindings(css string, sources map[string]string, allow map[string]string) (findings []string, usedAllow map[string]bool, roots int) {
	usedAllow = map[string]bool{}
	stripped := cssCommentPattern.ReplaceAllString(css, "")

	upperClasses := map[string]string{} // class -> a selector that transforms it
	upperElements := map[string]string{}
	var scopedUpper []scopedUpperRule
	scopedSel := map[scopedUpperRule]string{}
	resetClasses := map[string]bool{}
	resetElements := map[string]bool{}
	var attrUpper []attrRule
	exempt := map[string]bool{} // standalone selectors declaring text-transform: none
	transformingRules, resetRules := 0, 0

	for _, m := range cssRulePattern.FindAllStringSubmatch(stripped, -1) {
		selectorGroup, decls := m[1], m[2]
		value, ok := declValue(decls, "text-transform")
		if !ok {
			continue
		}
		for _, sel := range strings.Split(selectorGroup, ",") {
			sel = strings.TrimSpace(sel)
			last := lastCompound(sel)
			if last == "" {
				continue
			}
			// A pseudo-element styles generated content, not template text.
			// One built from an attribute that transforms it is checked
			// against the templates' attribute values below.
			if strings.Contains(sel, "::") {
				if content, ok := declValue(decls, "content"); ok && isTransforming(value) {
					if am := cssAttrContent.FindStringSubmatch(content); am != nil {
						// The classes in the selector's earlier compounds scope the
						// rule: it reaches only markup that carries one of them.
						var scope []string
						for _, field := range strings.FieldsFunc(sel, func(r rune) bool { return r == ' ' || r == '>' || r == '+' || r == '~' }) {
							_, cs := compoundParts(strings.SplitN(field, "::", 2)[0])
							scope = append(scope, cs...)
						}
						attrUpper = append(attrUpper, attrRule{am[1], sel, scope})
					}
				}
				continue
			}
			element, classes := compoundParts(last)
			multi := precedingCompound(sel) != ""

			targetsIdentifier := false
			for _, e := range identifierElements {
				targetsIdentifier = targetsIdentifier || element == e
			}
			for _, c := range classes {
				for _, ic := range identifierClasses {
					targetsIdentifier = targetsIdentifier || c == ic
				}
			}

			if value == "none" {
				resetRules++
				if !multi {
					exempt[sel] = true
				}
				// A scoped reset (`.foo th`) resets that th only under .foo, so it
				// cannot stand for every th.
				if len(classes) == 0 && element != "" && !multi {
					resetElements[element] = true
				}
				for _, c := range classes {
					resetClasses[c] = true
				}
				continue
			}
			if targetsIdentifier {
				findings = append(findings, "selector "+sel+" sets text-transform: "+value+" on an identifier")
			}
			if !isTransforming(value) {
				continue
			}
			transformingRules++
			switch {
			case len(classes) > 0:
				for _, c := range classes {
					upperClasses[c] = sel
				}
			case !multi:
				upperElements[element] = sel
			default:
				_, anc := compoundParts(precedingCompound(sel))
				if len(anc) == 0 || element == "" {
					findings = append(findings, "the guard cannot model selector "+sel+" — extend it")
					continue
				}
				r := scopedUpperRule{anc[len(anc)-1], element}
				scopedUpper = append(scopedUpper, r)
				scopedSel[r] = sel
			}
		}
	}
	if transformingRules == 0 || resetRules == 0 {
		return append(findings, "found no text-transform rules in console.css — this guard is not running"), usedAllow, 0
	}
	required := append([]string{}, identifierElements...)
	for _, c := range identifierClasses {
		required = append(required, "."+c)
	}
	for _, sel := range required {
		if !exempt[sel] {
			findings = append(findings, "no rule exempts "+sel+" from text-transform (text-transform: none)")
		}
	}

	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)

	seen := map[string]bool{}
	for _, file := range names {
		src := goLineCommentPattern.ReplaceAllString(sources[file], "")
		for _, rule := range attrUpper {
			valuePattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(rule.attr) + `="([^"]*\{\{[^"]*)"`)
			for _, rs := range goRawStringPattern.FindAllStringSubmatchIndex(src, -1) {
				unit := src[rs[2]:rs[3]]
				if !rule.reaches(unit) {
					continue
				}
				for _, vm := range valuePattern.FindAllStringSubmatchIndex(unit, -1) {
					roots++
					for _, am := range tmplActionPattern.FindAllStringSubmatch(unit[vm[2]:vm[3]], -1) {
						action := strings.TrimSpace(am[1])
						word, _, _ := strings.Cut(action, " ")
						if tmplControlWords[word] {
							continue
						}
						key := file + " [" + rule.attr + "] " + action
						if _, ok := allow[key]; ok {
							usedAllow[key] = true
							continue
						}
						findings = append(findings, file+":"+strconv.Itoa(lineOf(src, rs[2]+vm[2]))+": "+rule.attr+
							" interpolates {{"+action+"}} and "+rule.sel+" renders it case-transformed; "+
							"set text-transform: none on that rule, or — only if the field is fixed vocabulary — add \""+
							key+"\" to identifierCaseAllowlist with the reason")
					}
				}
			}
		}
		for _, rs := range goRawStringPattern.FindAllStringSubmatchIndex(src, -1) {
			unit := src[rs[2]:rs[3]]
			tags := scanTags(unit)
			isReset := func(t htmlTag) bool {
				if resetElements[t.name] {
					return true
				}
				for _, c := range t.classes {
					if resetClasses[c] {
						return true
					}
				}
				return false
			}
			for i, t := range tags {
				if !t.isStart || voidElements[t.name] || isReset(t) {
					continue
				}
				root := ""
				for _, c := range t.classes {
					if _, ok := upperClasses[c]; ok {
						root = "." + c
						break
					}
				}
				selector := upperClasses[strings.TrimPrefix(root, ".")]
				if root == "" {
					if sel, ok := upperElements[t.name]; ok {
						root, selector = t.name, sel
					}
				}
				if root == "" {
					for _, r := range scopedUpper {
						if r.element != t.name {
							continue
						}
						for j := 0; j < i; j++ {
							a := tags[j]
							if a.isStart && a.closeStart >= 0 && a.start < t.start && t.start < a.closeStart && a.hasClass(r.ancestor) {
								root, selector = "."+r.ancestor+" "+t.name, scopedSel[r]
							}
						}
					}
				}
				if root == "" {
					continue
				}
				roots++
				where := file + ":" + strconv.Itoa(lineOf(src, rs[2]+t.start))
				if t.closeStart < 0 {
					findings = append(findings, where+": the guard cannot scan <"+t.name+"> ("+root+"): no matching end tag was found")
					continue
				}
				// Text inside the root, minus every tag and minus the subtrees of
				// identifier elements, which reset the case themselves.
				pos := t.end
				var text []string
				for k := i + 1; k < len(tags) && tags[k].start < t.closeStart; k++ {
					c := tags[k]
					if c.start > pos {
						text = append(text, unit[pos:c.start])
					}
					pos = c.end
					if c.isStart && isReset(c) && !voidElements[c.name] {
						if c.closeStart < 0 {
							findings = append(findings, where+": the guard cannot scan <"+c.name+"> inside "+root+": no matching end tag was found")
							continue
						}
						pos = c.closeEnd
						for k+1 < len(tags) && tags[k+1].start < c.closeEnd {
							k++
						}
					}
				}
				if pos < t.closeStart {
					text = append(text, unit[pos:t.closeStart])
				}
				for _, segment := range text {
					for _, am := range tmplActionPattern.FindAllStringSubmatch(segment, -1) {
						action := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(am[1]), "-"))
						word, _, _ := strings.Cut(action, " ")
						if tmplControlWords[word] || strings.HasPrefix(action, "/*") || strings.Contains(action, ":=") {
							continue
						}
						key := file + " " + root + " " + action
						if _, ok := allow[key]; ok {
							usedAllow[key] = true
							continue
						}
						msg := where + ": " + root + " interpolates {{" + action + "}} into text console.css " +
							"case-transforms (" + selector + "); wrap it in <span class=\"ident\">, <code> or " +
							"another identifier element, or — only if the field is fixed vocabulary — add \"" + key +
							"\" to identifierCaseAllowlist with the reason"
						if !seen[msg] {
							seen[msg] = true
							findings = append(findings, msg)
						}
					}
				}
			}
		}
	}
	return findings, usedAllow, roots
}

// identifierCaseAllowlist names the interpolations that sit in an upper-cased
// element and are NOT identifiers: fixed vocabulary, where upper-casing is the
// design. Key "<file> <root> <action>". A field is added here only after
// asking whether an operator could type or compare it, and an entry that no
// longer matches anything fails the test.
var identifierCaseAllowlist = map[string]string{
	"accounts.go .kind .Kind":       "Account kind vocabulary (human|machine); the Kind label is an upper-cased eyebrow by design (00-foundations, \"Kind label\")",
	"accounts_page.go .kind .Kind":  "Account kind vocabulary (human|machine); the Kind label is an upper-cased eyebrow by design (00-foundations, \"Kind label\")",
	"components.go .kind .":         "the kind-label component; guarded by eq \"human\"/\"machine\" in the template itself",
	"layout.go .navsec .Group":      "NavGroup constants (nav.go), fixed vocabulary",
	"compare.go .tcap len .Columns": "a count; numbers have no case",
	"fleet.go .ftitle .Title":       "facet names (State, Daemon version, Policy fingerprint, Template set); the label-key title takes the LabelKey code branch, pinned by TestFleet_RoleFacetTitleRendersAsCode",
}

// TestConsole_IdentifiersAreNeverCaseTransformed: Node ids, token ids,
// fingerprints, label keys and values, Account and token names and Operation
// names are case-sensitive, and the Console renders them as they are. The
// stylesheet half and the template half are checked together because the bug
// lives between them (see identifierCaseFindings).
func TestConsole_IdentifiersAreNeverCaseTransformed(t *testing.T) {
	css, err := assetsFS.ReadFile("assets/console.css")
	if err != nil {
		t.Fatalf("read console.css: %v", err)
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	sources := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		sources[name] = string(src)
	}

	findings, used, roots := identifierCaseFindings(string(css), sources, identifierCaseAllowlist)
	for _, f := range findings {
		t.Error(f)
	}
	if roots == 0 {
		t.Fatal("found no case-transforming elements in any template — this guard is not running")
	}
	for key, reason := range identifierCaseAllowlist {
		if !used[key] {
			t.Errorf("identifierCaseAllowlist entry %q (%s) matched nothing — delete it", key, reason)
		}
	}
}

// TestIdentifierCaseFindings_SeesThroughInheritanceAndStopsAtIdentifiers is
// the guard's own test: without it, a walker bug that finds nothing would pass
// silently on the real tree.
func TestIdentifierCaseFindings_SeesThroughInheritanceAndStopsAtIdentifiers(t *testing.T) {
	const css = `
		.panel h3 { text-transform: uppercase; }
		th { text-transform: uppercase; }
		code, pre, kbd, samp, .mono, .nodeid, .ident { text-transform: none; }`
	run := func(html string) []string {
		got, _, _ := identifierCaseFindings(css, map[string]string{"x.go": "var t = `" + html + "`"}, nil)
		return got
	}

	for _, tc := range []struct {
		name, html string
		flagged    bool
	}{
		{"interpolation in a scoped heading", `<section class="panel"><h3>X {{.Name}}</h3></section>`, true},
		{"interpolation inherited through a plain child", `<table><tr><th><span>{{.X}}</span></th></tr></table>`, true},
		{"identifier wrapper resets the case", `<section class="panel"><h3>X <span class="ident">{{.Name}}</span></h3></section>`, false},
		{"code resets the case", `<table><tr><th><code>{{.Name}}</code></th></tr></table>`, false},
		{"heading outside any panel", `<h3>{{.Name}}</h3>`, false},
		{"control action only", `<table><tr><th>{{if .A}}x{{end}}</th></tr></table>`, false},
	} {
		if got := run(tc.html); (len(got) > 0) != tc.flagged {
			t.Errorf("%s: findings = %v, want flagged=%v", tc.name, got, tc.flagged)
		}
	}

	// A pseudo-element built from an attribute transforms the attribute's
	// value, so an interpolated identifier there is a finding (the compare
	// view's Node ID in data-label); a literal caption or a reset rule is not.
	const attrCSS = `table.cards td[data-label]::before { content: attr(data-label); text-transform: TRANSFORM; }
		th { text-transform: uppercase; } code, pre, kbd, samp, .mono, .nodeid, .ident { text-transform: none; }`
	for _, tc := range []struct {
		name, transform, html string
		flagged               bool
	}{
		{"interpolated data-label under uppercase", "uppercase", `<table class="cards"><td data-label="{{.ID}}">x</td></table>`, true},
		{"literal data-label under uppercase", "uppercase", `<table class="cards"><td data-label="Last seen">x</td></table>`, false},
		{"interpolated data-label under text-transform: none", "none", `<table class="cards"><td data-label="{{.ID}}">x</td></table>`, false},
		{"interpolated data-label in a table the rule does not scope to", "uppercase", `<table class="cmp"><td data-label="{{.ID}}">x</td></table>`, false},
	} {
		css := strings.Replace(attrCSS, "TRANSFORM", tc.transform, 1)
		got, _, _ := identifierCaseFindings(css, map[string]string{"x.go": "var t = `" + tc.html + "`"}, nil)
		if (len(got) > 0) != tc.flagged {
			t.Errorf("%s: findings = %v, want flagged=%v", tc.name, got, tc.flagged)
		}
	}

	// The exemption itself is checked: a stylesheet that stops exempting an
	// identifier element is a finding even with no template at all.
	got, _, _ := identifierCaseFindings(".panel h3 { text-transform: uppercase; }\n.ident { text-transform: none; }", nil, nil)
	if len(got) == 0 {
		t.Error("a stylesheet that does not exempt code, pre and the identifier classes passed")
	}
}

// TestConsole_NoChipModifierCollidesWithABareClass: `.chip.attempt` is a chip
// modifier; a bare `.attempt` rule elsewhere (a list-row layout) matches the
// chip too and leaks its box into it — which made the Access "succeeded" chip a
// tall box with no horizontal padding. A chip modifier's name must be unique to
// the chip.
func TestConsole_NoChipModifierCollidesWithABareClass(t *testing.T) {
	css, err := assetsFS.ReadFile("assets/console.css")
	if err != nil {
		t.Fatalf("read console.css: %v", err)
	}
	stripped := cssCommentPattern.ReplaceAllString(string(css), "")

	modifiers := map[string]bool{}
	var compounds []string
	for _, m := range cssRulePattern.FindAllStringSubmatch(stripped, -1) {
		for _, sel := range strings.Split(m[1], ",") {
			for _, field := range strings.FieldsFunc(sel, func(r rune) bool {
				return r == ' ' || r == '\t' || r == '\n' || r == '>' || r == '+' || r == '~'
			}) {
				compounds = append(compounds, field)
				_, classes := compoundParts(field)
				for i, c := range classes {
					if c == "chip" && i+1 < len(classes) {
						modifiers[classes[i+1]] = true
					}
				}
			}
		}
	}
	if len(modifiers) == 0 {
		t.Fatal("found no .chip.X modifiers in console.css — this guard is not running")
	}
	for _, compound := range compounds {
		_, classes := compoundParts(compound)
		hasChip := false
		for _, c := range classes {
			hasChip = hasChip || c == "chip"
		}
		if hasChip {
			continue
		}
		for _, c := range classes {
			if modifiers[c] {
				t.Errorf("selector compound %q carries class .%s, which is also a .chip.%s modifier — "+
					"the rule matches the chip too; rename one of them", compound, c, c)
			}
		}
	}
}
