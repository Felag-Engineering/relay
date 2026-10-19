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
	// The store's directory is a test temp directory, which the check refuses; the
	// recheck is hostfile's, proven on the harness (TestStart_RefusesGroupReadableStateOrKey).
	files := startupFiles{ca: got.(*ca.CA), recheckStore: func() error { return nil }}
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

// TestStartup_RefusedGateRefusesBeforeTheCA: a configured gate file that is absent, or that
// the file check refuses, refuses start before the CA directory is touched, and the server
// cannot be built without a gate read through the check. In-process, every file a test can
// make is refused by the check itself (sticky /tmp, the test's own uid, or root), so a
// malformed gate reaching the parser is proven on the harness instead
// (TestStart_RefusesMalformedGateFile, RC-35).
func TestStartup_RefusedGateRefusesBeforeTheCA(t *testing.T) {
	for _, tc := range []struct {
		name string
		path func(t *testing.T) string
	}{
		{"absent", func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.json") }},
		{"refused by the file check", func(t *testing.T) string {
			p := filepath.Join(t.TempDir(), "gates.json")
			if err := os.WriteFile(p, []byte(`{"rules": []}`), 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseTestConfig(t)
			cfg.CADir = filepath.Join(t.TempDir(), "ca")
			cfg.ApprovalGatePath = tc.path(t)
			files, err := openStartupFiles(cfg)
			if err == nil {
				t.Fatal("openStartupFiles accepted a gate file it could not load")
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
// the composition root a CA, gate or store check the start-time check did not supply: a
// startupFiles literal with fields, or an assignment to one of its fields, appears only in
// openStartupFiles; newServerWithHooks is called only from newServer; and newServer is called
// only from main, with the value main's one openStartupFiles call returned.
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
	newServerCalls, withHooksCalls, filesFromCheck, filesAssigned := 0, 0, 0, 0
	fields := map[string]bool{"ca": true, "gate": true, "recheckStore": true}
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
			allowed := name == "startup_files.go" && fnName == "openStartupFiles"
			ast.Inspect(decl, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.CompositeLit:
					if id, ok := v.Type.(*ast.Ident); ok && id.Name == "startupFiles" && len(v.Elts) != 0 && !allowed {
						t.Errorf("%s: %s builds a startupFiles with fields; only openStartupFiles may", name, fnName)
					}
				case *ast.AssignStmt:
					for i, lhs := range v.Lhs {
						if sel, ok := lhs.(*ast.SelectorExpr); ok && fields[sel.Sel.Name] && !allowed {
							t.Errorf("%s: %s assigns .%s; only openStartupFiles fills a startupFiles", name, fnName, sel.Sel.Name)
						}
						if id, ok := lhs.(*ast.Ident); ok && id.Name == "files" && fnName == "main" {
							filesAssigned++
							if len(v.Rhs) == 1 {
								if call, ok := v.Rhs[0].(*ast.CallExpr); ok {
									if f, ok := call.Fun.(*ast.Ident); ok && f.Name == "openStartupFiles" && i == 0 {
										filesFromCheck++
									}
								}
							}
						}
					}
				case *ast.CallExpr:
					id, ok := v.Fun.(*ast.Ident)
					if ok && id.Name == "newServerWithHooks" {
						withHooksCalls++
						if fnName != "newServer" {
							t.Errorf("%s: %s calls newServerWithHooks; only newServer may", name, fnName)
						}
					}
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
	if newServerCalls != 1 || withHooksCalls != 1 {
		t.Errorf("found %d production call(s) to newServer and %d to newServerWithHooks, want exactly 1 each", newServerCalls, withHooksCalls)
	}
	if filesFromCheck != 1 || filesAssigned != 1 {
		t.Errorf("main assigns files %d time(s), %d from openStartupFiles; want exactly once, from openStartupFiles", filesAssigned, filesFromCheck)
	}
}
