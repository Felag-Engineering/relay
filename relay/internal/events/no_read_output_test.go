package events

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// toolCallEventAllowedFields is the exact, closed field set
// ToolCallEvent may carry. An unlisted field fails the build — the same
// fail-closed shape as no_dispatch_test.go's unclassified-file rule.
var toolCallEventAllowedFields = map[string]bool{
	"Tool":               true,
	"Account":            true,
	"AccountID":          true,
	"Arguments":          true,
	"ArgumentsTruncated": true,
}

// resultShapedFieldNames is a case-insensitive denylist of field-name (and
// field-type-expression) substrings that would smuggle read output onto any
// struct in this package, layered on top of
// TestToolCallEventFieldsAreExactlyAllowed so "add the field to the
// allowlist" still fails the build for a result-shaped field.
var resultShapedFieldNames = []string{
	"result", "results", "output", "stdout", "stderr", "content",
	"body", "payload", "truncatedoutput", "exitcode", "noderesult",
}

func thisDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(thisFile)
}

// nonTestGoFiles returns every non-test .go file name in dir. Fails closed:
// an empty result means the guard inspected zero files, which is not "the
// package is clean" — it is the guard itself being broken.
func nonTestGoFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%s): %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		t.Fatal("nonTestGoFiles found zero non-test .go files — the guard would silently inspect nothing")
	}
	return names
}

// structFields AST-locates a top-level `type name struct { ... }`
// declaration in file and returns its field names, or ok=false if no such
// type exists in file.
func structFields(file *ast.File, name string) (fields []*ast.Field, ok bool) {
	for _, decl := range file.Decls {
		gd, isGen := decl.(*ast.GenDecl)
		if !isGen || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, isType := spec.(*ast.TypeSpec)
			if !isType || ts.Name.Name != name {
				continue
			}
			st, isStruct := ts.Type.(*ast.StructType)
			if !isStruct {
				continue
			}
			return st.Fields.List, true
		}
	}
	return nil, false
}

// TestToolCallEventFieldsAreExactlyAllowed AST-locates `type ToolCallEvent
// struct` in events.go and asserts its field-name set equals exactly
// toolCallEventAllowedFields.
func TestToolCallEventFieldsAreExactlyAllowed(t *testing.T) {
	dir := thisDir(t)
	fset := token.NewFileSet()
	path := filepath.Join(dir, "events.go")
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parser.ParseFile(%s): %v", path, err)
	}

	fields, ok := structFields(file, "ToolCallEvent")
	if !ok {
		t.Fatal("events.go does not declare type ToolCallEvent struct — TestToolCallEventFieldsAreExactlyAllowed has nothing to check")
	}
	for _, msg := range fieldAllowlistViolations("ToolCallEvent", fields, toolCallEventAllowedFields) {
		t.Error(msg)
	}
}

func fieldAllowlistViolations(typeName string, fields []*ast.Field, allowed map[string]bool) []string {
	var violations []string
	seen := map[string]bool{}
	for _, f := range fields {
		for _, n := range f.Names {
			seen[n.Name] = true
			if !allowed[n.Name] {
				violations = append(violations, fmt.Sprintf(
					"%s has field %q, which is not on the exact allowlist (%v) — ADR-0025", typeName, n.Name, allowed))
			}
		}
	}
	for name := range allowed {
		if !seen[name] {
			violations = append(violations, fmt.Sprintf("%s is missing required field %q", typeName, name))
		}
	}
	return violations
}

// TestEventStructNamesNoResultShapedField is belt-and-braces on top of
// TestToolCallEventFieldsAreExactlyAllowed: over EVERY struct type declared
// in this package's non-test files, reject any field whose name or
// type-expression text matches resultShapedFieldNames, case-insensitively.
func TestEventStructNamesNoResultShapedField(t *testing.T) {
	dir := thisDir(t)
	fset := token.NewFileSet()
	for _, name := range nonTestGoFiles(t, dir) {
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", path, err)
		}
		for _, msg := range resultShapedFieldViolations(name, file, fset) {
			t.Error(msg)
		}
	}
}

func resultShapedFieldViolations(fileName string, file *ast.File, fset *token.FileSet) []string {
	var violations []string
	ast.Inspect(file, func(n ast.Node) bool {
		st, ok := n.(*ast.StructType)
		if !ok {
			return true
		}
		for _, f := range st.Fields.List {
			typeText := exprString(fset, f.Type)
			for _, denied := range resultShapedFieldNames {
				if strings.Contains(strings.ToLower(typeText), denied) {
					violations = append(violations, fmt.Sprintf(
						"%s: a struct field's TYPE (%s) matches the result-shaped denylist entry %q",
						fileName, typeText, denied))
				}
			}
			for _, n := range f.Names {
				lower := strings.ToLower(n.Name)
				for _, denied := range resultShapedFieldNames {
					if strings.Contains(lower, denied) {
						violations = append(violations, fmt.Sprintf(
							"%s: field %q matches the result-shaped denylist entry %q (ADR-0025)",
							fileName, n.Name, denied))
					}
				}
			}
		}
		return true
	})
	return violations
}

func exprString(fset *token.FileSet, expr ast.Expr) string {
	var buf strings.Builder
	// A minimal, dependency-free renderer: identifiers, selectors, and the
	// handful of composite forms (map/slice/pointer) this package's fields
	// actually use. It only needs to be good enough to substring-match the
	// denylist, not to reproduce exact Go syntax.
	switch e := expr.(type) {
	case *ast.Ident:
		buf.WriteString(e.Name)
	case *ast.SelectorExpr:
		buf.WriteString(exprString(fset, e.X))
		buf.WriteString(".")
		buf.WriteString(e.Sel.Name)
	case *ast.StarExpr:
		buf.WriteString("*")
		buf.WriteString(exprString(fset, e.X))
	case *ast.MapType:
		buf.WriteString("map[")
		buf.WriteString(exprString(fset, e.Key))
		buf.WriteString("]")
		buf.WriteString(exprString(fset, e.Value))
	case *ast.ArrayType:
		buf.WriteString("[]")
		buf.WriteString(exprString(fset, e.Elt))
	default:
		fmt.Fprintf(&buf, "%T", expr)
	}
	return buf.String()
}

// TestExactlyFourPublishMethods AST-walks bus.go for methods on *Bus whose
// name starts with "Publish": asserts the set is exactly the four
// publishers, and that none of them mentions GapEvent — gap has no
// publisher, so the bus is the only thing that can say a gap happened, and
// it only says so when it actually evicted or changed epoch (see the
// Kind doc comment on KindGap).
func TestExactlyFourPublishMethods(t *testing.T) {
	dir := thisDir(t)
	fset := token.NewFileSet()
	path := filepath.Join(dir, "bus.go")
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parser.ParseFile(%s): %v", path, err)
	}

	got := publishMethods(file)
	want := map[string]bool{"PublishRegistry": true, "PublishJob": true, "PublishToolCall": true, "PublishEnrollment": true}

	for name := range got {
		if !want[name] {
			t.Errorf("unexpected Publish* method on *Bus: %s — exactly four publishers are allowed", name)
		}
	}
	for name := range want {
		if _, ok := got[name]; !ok {
			t.Errorf("missing expected Publish* method on *Bus: %s", name)
		}
	}

	for name, mentionsGap := range got {
		if mentionsGap {
			t.Errorf("%s mentions GapEvent — gap must never have a publisher; it is synthesised only inside Subscribe/trySend", name)
		}
	}
}

// publishMethods returns, for every method on *Bus (or Bus) whose name
// starts with "Publish", whether its body's source mentions the identifier
// "GapEvent".
func publishMethods(file *ast.File) map[string]bool {
	methods := map[string]bool{}
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv == nil || len(fd.Recv.List) != 1 || !strings.HasPrefix(fd.Name.Name, "Publish") {
			continue
		}
		if !receiverIsBus(fd.Recv.List[0].Type) {
			continue
		}
		mentionsGap := false
		ast.Inspect(fd, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "GapEvent" {
				mentionsGap = true
			}
			return true
		})
		methods[fd.Name.Name] = mentionsGap
	}
	return methods
}

func receiverIsBus(expr ast.Expr) bool {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == "Bus"
}

// TestGuards_Fixtures runs each structural rule above against small,
// synthetic sources rather than this package's real files, proving each
// rule actually fires (and that a legitimate declaration does not).
func TestGuards_Fixtures(t *testing.T) {
	t.Run("ToolCallEvent field allowlist", func(t *testing.T) {
		fset := token.NewFileSet()

		extra, err := parser.ParseFile(fset, "extra.go", `package events
type ToolCallEvent struct {
	Tool               string
	Account            string
	AccountID          string
	Arguments          map[string]string
	ArgumentsTruncated bool
	Extra              string
}
`, 0)
		if err != nil {
			t.Fatal(err)
		}
		fields, ok := structFields(extra, "ToolCallEvent")
		if !ok {
			t.Fatal("fixture did not declare ToolCallEvent")
		}
		if msgs := fieldAllowlistViolations("ToolCallEvent", fields, toolCallEventAllowedFields); len(msgs) == 0 {
			t.Error("expected an unlisted-field violation for Extra, got none")
		}

		exact, err := parser.ParseFile(fset, "exact.go", `package events
type ToolCallEvent struct {
	Tool               string
	Account            string
	AccountID          string
	Arguments          map[string]string
	ArgumentsTruncated bool
}
`, 0)
		if err != nil {
			t.Fatal(err)
		}
		fields, ok = structFields(exact, "ToolCallEvent")
		if !ok {
			t.Fatal("fixture did not declare ToolCallEvent")
		}
		if msgs := fieldAllowlistViolations("ToolCallEvent", fields, toolCallEventAllowedFields); len(msgs) != 0 {
			t.Errorf("exact field set flagged: %v", msgs)
		}
	})

	t.Run("result-shaped field denylist", func(t *testing.T) {
		fset := token.NewFileSet()

		bad, err := parser.ParseFile(fset, "bad.go", `package events
type JobEvent struct {
	JobID  string
	Stdout []byte
}
`, 0)
		if err != nil {
			t.Fatal(err)
		}
		if msgs := resultShapedFieldViolations("bad.go", bad, fset); len(msgs) == 0 {
			t.Error("expected a result-shaped-field violation for Stdout, got none")
		}

		badType, err := parser.ParseFile(fset, "bad_type.go", `package events
type JobEvent struct {
	JobID string
	Outcomes map[string]NodeResult
}
`, 0)
		if err != nil {
			t.Fatal(err)
		}
		if msgs := resultShapedFieldViolations("bad_type.go", badType, fset); len(msgs) == 0 {
			t.Error("expected a result-shaped-field violation for a NodeResult-typed field, got none")
		}

		good, err := parser.ParseFile(fset, "good.go", `package events
type JobEvent struct {
	JobID string
	Nodes int
}
`, 0)
		if err != nil {
			t.Fatal(err)
		}
		if msgs := resultShapedFieldViolations("good.go", good, fset); len(msgs) != 0 {
			t.Errorf("legitimate fields flagged: %v", msgs)
		}
	})

	t.Run("exactly four publish methods", func(t *testing.T) {
		fset := token.NewFileSet()

		src := `package events
func (b *Bus) PublishRegistry(e RegistryEvent) {}
func (b *Bus) PublishJob(e JobEvent) {}
func (b *Bus) PublishToolCall(e ToolCallEvent) {}
func (b *Bus) PublishEnrollment(e EnrollmentEvent) {}
func (b *Bus) publish(kind Kind, ev Event) {}
`
		file, err := parser.ParseFile(fset, "fixture.go", src, 0)
		if err != nil {
			t.Fatal(err)
		}
		got := publishMethods(file)
		if len(got) != 4 {
			t.Errorf("want exactly 4 Publish* methods, got %d: %v", len(got), got)
		}

		gapSrc := `package events
func (b *Bus) PublishGap(reason GapReason) {
	_ = GapEvent{Reason: reason}
}
`
		gapFile, err := parser.ParseFile(fset, "gap_fixture.go", gapSrc, 0)
		if err != nil {
			t.Fatal(err)
		}
		gapMethods := publishMethods(gapFile)
		if !gapMethods["PublishGap"] {
			t.Fatal("fixture PublishGap should mention GapEvent")
		}
	})
}

// TestGuardInspectsFiles is the fail-closed check on the file-discovery
// helper itself (no_dispatch_test.go:139's precedent): a guard whose file
// walk silently finds nothing is not "the package is clean", it is broken.
func TestGuardInspectsFiles(t *testing.T) {
	dir := thisDir(t)
	names := nonTestGoFiles(t, dir)
	if len(names) < 2 {
		t.Fatalf("expected to find events.go and bus.go, found: %v", names)
	}
	found := map[string]bool{}
	for _, n := range names {
		found[n] = true
	}
	if !found["events.go"] || !found["bus.go"] {
		t.Fatalf("expected events.go and bus.go among the discovered files, got: %v", names)
	}
}
