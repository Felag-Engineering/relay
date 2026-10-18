package main

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestFreezeReleaseReason_DefaultsWhenUnset(t *testing.T) {
	t.Setenv("RELAY_FREEZE_RELEASE_REASON", "")
	if got := freezeReleaseReason(); got != defaultFreezeReleaseReason {
		t.Errorf("empty: reason = %q, want the default", got)
	}
	t.Setenv("RELAY_FREEZE_RELEASE_REASON", "maintenance over")
	if got := freezeReleaseReason(); got != "maintenance over" {
		t.Errorf("set: reason = %q, want the operator's note", got)
	}
}

// TestFreezeReleaseReason_IsTheOnlyEnvironmentRead pins ADR-0043 decision 6:
// in the untagged build the Relay reads its environment in exactly two places,
// and neither reads a setting — the Freeze lever's operator note, and the
// retired-name refusal, which only refuses.
func TestFreezeReleaseReason_IsTheOnlyEnvironmentRead(t *testing.T) {
	envCalls := map[string]map[string]bool{
		"os":      {"Getenv": true, "LookupEnv": true, "Environ": true, "ExpandEnv": true},
		"syscall": {"Getenv": true, "Environ": true},
	}

	root := filepath.Join("..", "..") // the relay module
	var dirs []string
	dirs = append(dirs, ".")
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() != "relaytest" {
			dirs = append(dirs, path)
		}
		if d.IsDir() && d.Name() == "relaytest" {
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := build.Default
	ctx.BuildTags = nil
	fset := token.NewFileSet()
	hits := map[string]int{}
	for _, dir := range dirs {
		entries, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range entries {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			ok, err := ctx.MatchFile(filepath.Dir(file), filepath.Base(file))
			if err != nil || !ok {
				continue
			}
			f, err := parser.ParseFile(fset, file, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", file, err)
			}
			local := map[string]string{} // local name -> package path
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if strings.HasSuffix(p, "/relaytest") {
					t.Errorf("%s imports relaytest from non-test code", file)
				}
				name := filepath.Base(p)
				if imp.Name != nil {
					name = imp.Name.Name
				}
				local[name] = p
			}
			// The two sanctioned reads, keyed; every other reference to a
			// banned function — called or merely referenced — is a finding.
			allowed := map[*ast.SelectorExpr]string{}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch {
				case filepath.ToSlash(file) == "freeze_signal.go" && isPkgSel(sel, local, "os", "LookupEnv") &&
					argsOf(call) == `("RELAY_FREEZE_RELEASE_REASON")`:
					allowed[sel] = sanctionedFreeze
				case filepath.ToSlash(file) == "main.go" && sel.Sel.Name == "RefuseRetiredEnv" && len(call.Args) == 1:
					if inner, ok := call.Args[0].(*ast.CallExpr); ok {
						if s, ok := inner.Fun.(*ast.SelectorExpr); ok && len(inner.Args) == 0 && isPkgSel(s, local, "os", "Environ") {
							allowed[s] = sanctionedRefuse
						}
					}
				}
				return true
			})
			ast.Inspect(f, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok || !envCalls[local[id.Name]][sel.Sel.Name] {
					return true
				}
				if key, ok := allowed[sel]; ok {
					hits[key]++
					return true
				}
				pos := fset.Position(sel.Pos())
				t.Errorf("unexpected environment read: %s:%d %s.%s", filepath.ToSlash(file), pos.Line, local[id.Name], sel.Sel.Name)
				return true
			})
		}
	}

	for _, key := range []string{sanctionedFreeze, sanctionedRefuse} {
		if hits[key] != 1 {
			t.Errorf("%s read %d times, want exactly once", key, hits[key])
		}
	}
}

const (
	sanctionedFreeze = `freeze_signal.go os.LookupEnv("RELAY_FREEZE_RELEASE_REASON")`
	sanctionedRefuse = `main.go relayconfig.RefuseRetiredEnv(os.Environ())`
)

// isPkgSel reports whether sel is pkgPath.name, resolved through the file's imports.
func isPkgSel(sel *ast.SelectorExpr, local map[string]string, pkgPath, name string) bool {
	id, ok := sel.X.(*ast.Ident)
	return ok && local[id.Name] == pkgPath && sel.Sel.Name == name
}

// argsOf renders a call's arguments when they are a lone string literal or empty.
func argsOf(call *ast.CallExpr) string {
	if len(call.Args) == 1 {
		if lit, ok := call.Args[0].(*ast.BasicLit); ok {
			return "(" + lit.Value + ")"
		}
	}
	if len(call.Args) == 0 {
		return "()"
	}
	return "(...)"
}
