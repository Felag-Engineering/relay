package main

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/ca"
)

// testCAs holds one in-memory CA per CA directory, so a test that restarts the composition
// root against the same directory meets the same CA, as a restarted Relay does.
var testCAs sync.Map

// testStartupFiles stands in for openStartupFiles in the in-process suites. The real check
// refuses every temporary directory a test can make (sticky, or the test's own, and a test
// may run as root), so the CA is generated in memory and a configured gate file is parsed
// without the check. The check itself is hostfile's table test, and the shippable binary
// meets it on the separate-uid harness.
func testStartupFiles(t testing.TB, cfg Config) startupFiles {
	t.Helper()
	fresh, err := ca.Generate()
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	got, _ := testCAs.LoadOrStore(cfg.CADir, fresh)
	files := startupFiles{ca: got.(*ca.CA)}
	if cfg.ApprovalGatePath == "" {
		files.gate, err = approval.NewGate(nil)
	} else {
		var data []byte
		if data, err = os.ReadFile(cfg.ApprovalGatePath); err == nil {
			files.gate, err = approval.Parse(data)
		}
	}
	if err != nil {
		t.Fatalf("load gate: %v", err)
	}
	return files
}

// TestStartup_UnloadableGateFileRefuses is RC-35 at the composition root: a configured gate
// file that cannot be loaded refuses start before anything is built, and the server cannot be
// built without a gate read through the check, so no path runs ungated.
func TestStartup_UnloadableGateFileRefuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		path func(t *testing.T) string
	}{
		{"absent", func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.json") }},
		{"malformed", func(t *testing.T) string {
			p := filepath.Join(t.TempDir(), "gates.json")
			if err := os.WriteFile(p, []byte(`{"rules": [`), 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{"a directory", func(t *testing.T) string { return t.TempDir() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseTestConfig(t)
			cfg.CADir = filepath.Join(t.TempDir(), "ca")
			cfg.ApprovalGatePath = tc.path(t)
			files, err := openStartupFiles(cfg)
			if err == nil {
				t.Fatal("openStartupFiles accepted an unloadable gate file")
			}
			if !strings.Contains(err.Error(), "approval gate") {
				t.Errorf("err = %v, want it to name the approval gate", err)
			}
			if files.gate != nil || files.ca != nil {
				t.Errorf("openStartupFiles returned material alongside its refusal")
			}
			if _, err := os.Stat(cfg.CADir); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the CA directory was touched before the gate refused (stat err = %v)", err)
			}
		})
	}

	t.Run("newServer without a gate", func(t *testing.T) {
		cfg := baseTestConfig(t)
		files := testStartupFiles(t, cfg)
		files.gate = nil
		srv, deps, err := newServer(cfg, files)
		if err == nil || srv != nil || deps != nil {
			t.Fatalf("newServer with no gate = %v, %v, %v; want a refusal", srv, deps, err)
		}
	})
}

// TestStartupFiles_OnlyTheCheckBuildsThem pins that no production file in this package hands
// the composition root a CA or gate the start-time check did not read: a startupFiles literal
// with fields appears only in openStartupFiles, and newServer is called only from main, with
// openStartupFiles' result.
func TestStartupFiles_OnlyTheCheckBuildsThem(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	newServerCalls := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, _ := decl.(*ast.FuncDecl)
			fnName := ""
			if fn != nil {
				fnName = fn.Name.Name
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.CompositeLit:
					allowed := name == "startup_files.go" && fnName == "openStartupFiles"
					if id, ok := v.Type.(*ast.Ident); ok && id.Name == "startupFiles" && len(v.Elts) != 0 && !allowed {
						t.Errorf("%s: %s builds a startupFiles with fields; only openStartupFiles may", name, fnName)
					}
				case *ast.CallExpr:
					id, ok := v.Fun.(*ast.Ident)
					if !ok || id.Name != "newServer" {
						return true
					}
					newServerCalls++
					arg, _ := v.Args[len(v.Args)-1].(*ast.Ident)
					if fnName != "main" || arg == nil || arg.Name != "files" {
						t.Errorf("%s: %s calls newServer; only main may, with openStartupFiles' result", name, fnName)
					}
				}
				return true
			})
		}
	}
	if newServerCalls != 1 {
		t.Errorf("found %d production call(s) to newServer, want exactly 1 (main)", newServerCalls)
	}
}
