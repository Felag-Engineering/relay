package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var rawAuditInsert = regexp.MustCompile(`(?i)INSERT\s+INTO\s+audit\b`)

// auditInsertViolations returns a description of every place in src (one Go
// file) that writes to the audit table other than through insertChained.
func auditInsertViolations(t *testing.T, name string, src any) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	var out []string
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Name.Name == "insertChained" {
				continue
			}
			ast.Inspect(d, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.Ident:
					if x.Name == "insertAuditSQL" {
						out = append(out, name+": "+d.Name.Name+" references insertAuditSQL")
					}
				case *ast.BasicLit:
					if x.Kind == token.STRING {
						if s, err := strconv.Unquote(x.Value); err == nil && rawAuditInsert.MatchString(s) {
							out = append(out, name+": "+d.Name.Name+" holds a raw INSERT INTO audit")
						}
					}
				}
				return true
			})
		case *ast.GenDecl:
			ast.Inspect(d, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.ValueSpec:
					for _, id := range x.Names {
						if id.Name == "insertAuditSQL" {
							return false // the one declaration allowed to spell the INSERT
						}
					}
				case *ast.Ident:
					if x.Name == "insertAuditSQL" {
						out = append(out, name+": a package-level declaration references insertAuditSQL")
					}
				case *ast.BasicLit:
					if x.Kind == token.STRING {
						if s, err := strconv.Unquote(x.Value); err == nil && rawAuditInsert.MatchString(s) {
							out = append(out, name+": a package-level string holds a raw INSERT INTO audit")
						}
					}
				}
				return true
			})
		}
	}
	return out
}

// TestInsertAuditSQL_OnlyReferencedByInsertChained protects the property the
// audit chain depends on: every audit row is appended through insertChained.
// A second writer — #887's CreateTask transaction is the likely one — that
// spelled its own INSERT would write a row with no chain position, and only
// the verifier, in production, would notice. Fail it here instead.
func TestInsertAuditSQL_OnlyReferencedByInsertChained(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, v := range auditInsertViolations(t, name, src) {
			t.Error(v)
		}
	}
	if checked == 0 {
		t.Fatal("no source files found: the guard is not looking at anything")
	}
}

func TestAuditInsertGuard_ReportsAnOffendingFunction(t *testing.T) {
	cases := map[string]struct {
		src  string
		want int
	}{
		"reference outside insertChained": {`package p
func sneaky() { exec(insertAuditSQL) }`, 1},
		"raw literal":         {"package p\nfunc sneaky() { exec(`INSERT INTO audit (a) VALUES (1)`) }", 1},
		"other table is fine": {"package p\nfunc ok() { exec(`INSERT INTO audit_shape_alert (a) VALUES (1)`) }", 0},
		"insertChained is the allowed home": {`package p
func insertChained() { exec(insertAuditSQL) }`, 0},
		"package-level reference elsewhere": {"package p\nvar sneaky = insertAuditSQL", 1},
		"package-level raw literal":         {"package p\nvar sneaky = `INSERT INTO audit (a) VALUES (1)`", 1},
		"the const declaration is allowed":  {"package p\nconst insertAuditSQL = `INSERT INTO audit (a) VALUES (1)`", 0},
	}
	for name, c := range cases {
		if got := auditInsertViolations(t, "x.go", c.src); len(got) != c.want {
			t.Errorf("%s: %d violations %v, want %d", name, len(got), got, c.want)
		}
	}
}
