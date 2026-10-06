package astguard

import (
	"go/parser"
	"go/token"
	"reflect"
	"testing"
)

const rcJobsImport = `import "` + jobsImportPath + `"` + "\n"

func parseFixture(t *testing.T, src string) []string {
	t.Helper()
	return parseFixtureAllowed(t, src, nil)
}

func parseFixtureAllowed(t *testing.T, src string, allowed map[string]string) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", src, 0)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return RiskClassViolations("fixture.go", file, allowed)
}

// TestRiskClassViolations_Fixtures is the acceptance test that the guard
// fails when an adapter names a risk class constant, or sets a class by any
// route, to construct an Action (#878, invariant 13).
func TestRiskClassViolations_Fixtures(t *testing.T) {
	t.Run("fires", func(t *testing.T) {
		cases := map[string]string{
			"action literal sets RiskClassRead": `package p
` + rcJobsImport + `func f() jobs.Action { return jobs.Action{RiskClass: jobs.RiskClassRead} }`,
			"action literal sets a value naming no constant": `package p
` + rcJobsImport + `func f(d struct{ Risk jobs.RiskClass }) jobs.Action { return jobs.Action{RiskClass: d.Risk} }`,
			"action literal sets a conversion": `package p
` + rcJobsImport + `func f() jobs.Action { return jobs.Action{RiskClass: jobs.RiskClass(2)} }`,
			"aliased import": `package p
import j "` + jobsImportPath + `"
func f() j.Action { return j.Action{RiskClass: j.RiskClassMutate} }`,
			"field assignment": `package p
` + rcJobsImport + `func f(act *jobs.Action) { act.RiskClass = jobs.RiskClassMutate }`,
			"field assignment of a non-constant": `package p
func f(act *struct{ RiskClass int }, v int) { act.RiskClass = v }`,
			"package-level var": `package p
` + rcJobsImport + `var c = jobs.RiskClassMutate`,
			"function returning a constant, not allowed": `package p
` + rcJobsImport + `func f() jobs.RiskClass { return jobs.RiskClassMutate }`,
			"unkeyed action literal": `package p
` + rcJobsImport + `func f() jobs.Action { return jobs.Action{jobs.ActionRawExec} }`,
			"dot import": `package p
import . "` + jobsImportPath + `"
func f() Action { return Action{} }`,
			"elided element of a slice of actions": `package p
` + rcJobsImport + `func f(d struct{ Risk jobs.RiskClass }) []jobs.Action { return []jobs.Action{{RiskClass: d.Risk}} }`,
			"elided value of a map of action pointers": `package p
` + rcJobsImport + `func f(d struct{ Risk jobs.RiskClass }) map[string]*jobs.Action { return map[string]*jobs.Action{"a": {RiskClass: d.Risk}} }`,
		}
		for name, src := range cases {
			if got := parseFixture(t, src); len(got) == 0 {
				t.Errorf("%s: expected a violation, got none", name)
			}
		}
	})

	t.Run("does not fire", func(t *testing.T) {
		cases := map[string]string{
			"equality and inequality comparisons": `package p
` + rcJobsImport + `func f(c jobs.RiskClass) bool { return c == jobs.RiskClassRead || jobs.RiskClassMutate != c }`,
			"display function": `package p
` + rcJobsImport + `func f(c jobs.RiskClass) string { return jobs.RiskClassName(c) }`,
			"the type and a conversion": `package p
` + rcJobsImport + `var c jobs.RiskClass
func f(n int) string { return jobs.RiskClassName(jobs.RiskClass(n)) }`,
			"RiskClass key of a local row type": `package p
type row struct{ RiskClass string }
func f() row { return row{RiskClass: "read"} }`,
			"action literal without a class": `package p
` + rcJobsImport + `func f() jobs.Action { return jobs.Action{Kind: jobs.ActionRawExec, OperationName: "x"} }`,
			"elided action without a class": `package p
` + rcJobsImport + `func f() []jobs.Action { return []jobs.Action{{OperationName: "x"}} }`,
			"elided element of a local row type": `package p
type row struct{ RiskClass string }
func f() []row { return []row{{RiskClass: "read"}} }`,
		}
		for name, src := range cases {
			if got := parseFixture(t, src); len(got) != 0 {
				t.Errorf("%s: unexpected violations: %v", name, got)
			}
		}
	})

	t.Run("an allowed function may name a constant", func(t *testing.T) {
		src := `package p
` + rcJobsImport + `func riskOf() jobs.RiskClass { return jobs.RiskClassMutate }
type T struct{}
func (t *T) M() jobs.RiskClass { return jobs.RiskClassRead }`
		allowed := map[string]string{"riskOf": "display", "T.M": "display"}
		if got := parseFixtureAllowed(t, src, allowed); len(got) != 0 {
			t.Errorf("unexpected violations: %v", got)
		}
		if got := parseFixtureAllowed(t, src, map[string]string{"riskOf": "display"}); len(got) != 1 {
			t.Errorf("method T.M not in allowed: want 1 violation, got %v", got)
		}
	})

	t.Run("a switch case is a known false positive", func(t *testing.T) {
		src := `package p
` + rcJobsImport + `func f(c jobs.RiskClass) {
	switch c {
	case jobs.RiskClassRead:
	}
}`
		if got := parseFixture(t, src); len(got) == 0 {
			t.Error("a switch case on a class constant is expected to fire; widen the allowlist, not the rule")
		}
	})
}

func TestRiskClassConstantFuncs(t *testing.T) {
	src := `package p
` + rcJobsImport + `func a(c jobs.RiskClass) bool { return c == jobs.RiskClassRead }
func b() jobs.RiskClass { return jobs.RiskClassMutate }
type T struct{}
func (t *T) m() jobs.RiskClass { return jobs.RiskClassRead }
var pkg = jobs.RiskClassMutate`
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"T.m", "b"}
	if got := RiskClassConstantFuncs(file); !reflect.DeepEqual(got, want) {
		t.Errorf("RiskClassConstantFuncs = %v, want %v", got, want)
	}
}
