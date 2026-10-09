package logctx

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// globalSlogCalls are the package-level log/slog functions that write through
// the process-global logger. Debug and DebugContext are deliberately not
// listed: they never emit at the default Info level, and converting the four
// remaining sites would thread a logger through unrelated signatures (#902).
var globalSlogCalls = map[string]bool{
	"Info": true, "Warn": true, "Error": true,
	"InfoContext": true, "WarnContext": true, "ErrorContext": true,
	"Log": true, "LogAttrs": true,
}

// globalSlogCallsIn reports file:line for every call to a package-level
// log/slog logging function in src, resolving the import's local name so an
// aliased import is caught too.
func globalSlogCallsIn(name string, src any) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return nil, err
	}
	locals := map[string]bool{}
	for _, imp := range f.Imports {
		if path, _ := strconv.Unquote(imp.Path.Value); path != "log/slog" {
			continue
		}
		local := "slog"
		if imp.Name != nil {
			local = imp.Name.Name
		}
		locals[local] = true
	}
	if len(locals) == 0 {
		return nil, nil
	}
	var hits []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !globalSlogCalls[sel.Sel.Name] {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && locals[id.Name] && id.Obj == nil {
			hits = append(hits, fmt.Sprintf("%s:%d: slog.%s", name, fset.Position(call.Pos()).Line, sel.Sel.Name))
		}
		return true
	})
	return hits, nil
}

// TestNoGlobalSlogInInternal fails on any non-test call to the global slog
// logging functions under relay/internal: a component logs through a logger it
// was handed, so its lines carry the request, principal and Job ids.
//
// It lives in logctx because relay/internal has no root package to hold a
// cross-package guard, logctx owns the logging convention this enforces, and a
// copy in each of the packages involved would drift. A failure names the
// offending file and line, so reporting under logctx does not mislead. This
// follows the established pattern of one AST guard walking source it does not
// own (capability's no_verdicts_test.go).
func TestNoGlobalSlogInInternal(t *testing.T) {
	root := ".."
	var hits []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		h, err := globalSlogCallsIn(path, nil)
		hits = append(hits, h...)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(hits)
	for _, h := range hits {
		t.Errorf("global slog call (inject a *slog.Logger): %s", h)
	}
}

func TestNoGlobalSlogGuardActuallyFires(t *testing.T) {
	const planted = `package p

import (
	"context"
	"log/slog"
	lg "log/slog"
)

func f(l *slog.Logger) {
	l.Info("fine: a method on an injected logger")
	slog.Debug("fine: debug is out of scope")
	slog.Warn("planted")
	lg.ErrorContext(context.Background(), "planted via alias")
}
`
	hits, err := globalSlogCallsIn("planted.go", planted)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 {
		t.Errorf("planted source: got %v, want exactly the Warn and the aliased ErrorContext", hits)
	}
}
