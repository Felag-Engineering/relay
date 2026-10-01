package console

import (
	"strings"
	"testing"
	"text/template"
)

// TestPluralFamiliesKeepOppositeContracts pins what the #550 rename cannot
// enforce on its own.
//
// Renaming fleet.go's helper to countOf stops the two from COLLIDING, but
// nothing stops a later edit from quietly making one behave like the other —
// and because the template idiom is `{{.N}} {{plural .N …}}`, the number and
// the word arrive from two separate pieces. A swap in either direction is
// therefore invisible in the source and shows up only in rendered output, as
// a doubled count ("3 3 calls") or a missing one ("Accounts called earlier").
//
// So this asserts both contracts AND one rendered example from each family,
// because the definitions being right does not prove the call sites read them
// right — which was the whole of #550.
func TestPluralFamiliesKeepOppositeContracts(t *testing.T) {
	t.Run("countOf returns the number and the word", func(t *testing.T) {
		if got, want := countOf(3, "Node", "Nodes"), "3 Nodes"; got != want {
			t.Errorf("countOf(3) = %q, want %q", got, want)
		}
		if got, want := countOf(1, "Node", "Nodes"), "1 Node"; got != want {
			t.Errorf("countOf(1) = %q, want %q", got, want)
		}
		// Zero is the boundary no call site reaches TODAY -- every one of them
		// sits behind a guard that has already excluded it (collapseNote's
		// foldedRows == 0 return and buildGroup's switch arms). It is
		// pinned anyway because that reachability is the call sites' property,
		// not countOf's: the natural off-by-one here is `n <= 1`, which is
		// invisible at n of 1 and 3 and would render "1 Nodes" -- the exact
		// product-reads-as-a-bug string screen.go's comment exists to prevent.
		if got, want := countOf(0, "Node", "Nodes"), "0 Nodes"; got != want {
			t.Errorf("countOf(0) = %q, want %q", got, want)
		}
	})

	t.Run("template plural returns the word alone", func(t *testing.T) {
		fn, ok := screenFuncs["plural"].(func(int, string, string) string)
		if !ok {
			t.Fatalf("screenFuncs[\"plural\"] is %T, want func(int, string, string) string", screenFuncs["plural"])
		}
		if got, want := fn(3, "Node", "Nodes"), "Nodes"; got != want {
			t.Errorf("plural(3) = %q, want %q — a number here means it grew countOf's contract", got, want)
		}
		if got, want := fn(1, "Node", "Nodes"), "Node"; got != want {
			t.Errorf("plural(1) = %q, want %q", got, want)
		}
		if got, want := fn(0, "Node", "Nodes"), "Nodes"; got != want {
			t.Errorf("plural(0) = %q, want %q", got, want)
		}
	})

	// The rendered halves. Each asserts the count appears EXACTLY ONCE: the
	// failure #550 documents is arithmetic that reads fine in isolation, so
	// "contains the count" is not enough — "3 3 calls" contains it too.
	t.Run("a Go call site renders one count", func(t *testing.T) {
		got := collapseNote(3, 2, "strip")
		if !strings.Contains(got, "3 calls") {
			t.Errorf("collapseNote lost its count: %q", got)
		}
		if strings.Contains(got, "3 3") {
			t.Errorf("collapseNote doubled its count: %q", got)
		}
	})

	t.Run("a template call site renders one count", func(t *testing.T) {
		// The exact idiom used at all 32 template call sites: the caller
		// supplies the number, plural supplies only the word.
		tmpl := template.Must(template.New("t").Funcs(screenFuncs).
			Parse(`{{.N}} {{plural .N "call" "calls"}}`))
		var sb strings.Builder
		if err := tmpl.Execute(&sb, struct{ N int }{3}); err != nil {
			t.Fatalf("execute: %v", err)
		}
		if got, want := sb.String(), "3 calls"; got != want {
			t.Errorf("rendered %q, want %q", got, want)
		}
	})
}
