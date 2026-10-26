package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// label_writes_guard_test.go pins that each label table has exactly the write
// sites its namespace's writer owns (invariant 7, ADR-0006, ADR-0050):
//
//   - tag_labels is mutated in AppendWithTagWrite and nowhere else;
//   - node_labels is rewritten through replaceLabels in Upsert only, and
//     relay_labels in SetRelayLabels only;
//   - replaceLabels, whose SQL names its table through fmt.Sprintf and so never
//     contains the literal "tag_labels", is never handed the tag table;
//   - nsTag appears only in table() and getNode, the read side.
//
// It is an AST pass over the package's non-test files, matching by exact name.

// labelWriteViolations returns one line per breach of the rules above in the
// non-test .go files of dir.
func labelWriteViolations(dir string) ([]string, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	var out []string
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil, err
		}
		base := filepath.Base(path)
		for _, decl := range file.Decls {
			fn := ""
			switch d := decl.(type) {
			case *ast.FuncDecl:
				fn = d.Name.Name
			case *ast.GenDecl:
				// The namespace constants themselves are declared here.
				if d.Tok == token.CONST {
					continue
				}
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.BasicLit:
					if x.Kind != token.STRING {
						return true
					}
					s, err := strconv.Unquote(x.Value)
					if err != nil {
						return true
					}
					upper := strings.ToUpper(s)
					mutates := strings.Contains(upper, "INSERT") || strings.Contains(upper, "UPDATE") || strings.Contains(upper, "DELETE")
					if mutates && strings.Contains(s, "tag_labels") && fn != "AppendWithTagWrite" {
						out = append(out, base+": "+fn+" mutates tag_labels")
					}
				case *ast.CallExpr:
					id, ok := x.Fun.(*ast.Ident)
					if !ok || id.Name != "replaceLabels" || len(x.Args) < 3 {
						return true
					}
					switch tableArg(x.Args[2]) {
					case "nsNode":
						if fn != "Upsert" {
							out = append(out, base+": "+fn+" rewrites node_labels")
						}
					case "nsRelay":
						if fn != "SetRelayLabels" {
							out = append(out, base+": "+fn+" rewrites relay_labels")
						}
					default:
						out = append(out, base+": "+fn+" hands replaceLabels a table other than nsNode or nsRelay")
					}
				case *ast.Ident:
					if x.Name == "nsTag" && fn != "table" && fn != "getNode" {
						out = append(out, base+": "+fn+" names nsTag")
					}
				}
				return true
			})
		}
	}
	sort.Strings(out)
	return out, nil
}

// tableArg returns "nsNode" for the expression nsNode.table() and so on, or ""
// for any other shape.
func tableArg(e ast.Expr) string {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "table" {
		return ""
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return id.Name
}

// TestLabelTables_EachHasOneWriteSite runs the pass over the real package.
//
// MUTATION: write tag_labels from any other function, route it through
// replaceLabels, or name nsTag outside the read side, and this goes red.
func TestLabelTables_EachHasOneWriteSite(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	got, err := labelWriteViolations(filepath.Dir(thisFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("label table write sites breach the per-namespace writers:\n%s", strings.Join(got, "\n"))
	}
}

// TestLabelTables_Fixtures arms the pass: a guard nobody has seen fail is one
// that might not run.
func TestLabelTables_Fixtures(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("legit.go", `package store

func (a *x) AppendWithTagWrite() { exec("INSERT INTO tag_labels (a) VALUES (?)") }
func (r *x) Upsert()             { replaceLabels(ctx, tx, nsNode.table(), id, m) }
func (r *x) SetRelayLabels()     { replaceLabels(ctx, tx, nsRelay.table(), id, m) }
func (ns ns) table() string      { _ = nsTag; return "tag_labels" }
func getNode()                   { _ = nsTag; _ = "SELECT key, value FROM tag_labels" }
`)
	write("bad_sql.go", `package store

func elsewhere() { exec("DELETE FROM tag_labels WHERE node_id = ?") }
`)
	write("bad_replace.go", `package store

func routeAround() { replaceLabels(ctx, tx, nsTag.table(), id, m) }
func swapped()     { replaceLabels(ctx, tx, nsNode.table(), id, m) }
func viaVar()      { replaceLabels(ctx, tx, someTable, id, m) }
`)
	write("bad_ns.go", `package store

func leaks() { _ = nsTag }
`)
	// A _test.go file never counts.
	write("ignored_test.go", `package store

func inTest() { exec("INSERT INTO tag_labels (a) VALUES (?)"); _ = nsTag }
`)

	got, err := labelWriteViolations(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"bad_ns.go: leaks names nsTag",
		"bad_replace.go: routeAround hands replaceLabels a table other than nsNode or nsRelay",
		"bad_replace.go: routeAround names nsTag",
		"bad_replace.go: swapped rewrites node_labels",
		"bad_replace.go: viaVar hands replaceLabels a table other than nsNode or nsRelay",
		"bad_sql.go: elsewhere mutates tag_labels",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("violations:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
