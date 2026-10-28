package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// RC-11 for the composition root: a Control API route that writes Relay
// configuration (invariant 11) could be registered on the shared mux from
// package main, where the live configuration is in reach, and would never
// appear in api.Routes() or package mcp's tool list. This test pins every place
// that registers a handler on a mux, in package main and in the control-plane
// server, so a new registration site fails here until a human adds it below.

// registrationSites lists, per Go source file in the package, each call that
// registers a handler (Handle, HandleFunc) and each call that hands a mux to a
// registrar, as "<file> <Type>.<func>: <call>(<first argument>)". A hand-off is
// a mux identifier (mux, consoleMux) or a zero-argument .Mux() call passed to a
// method or package-qualified call. It reads the syntax only: it does not
// resolve types, so a mux renamed to something else, reached through a getter
// not named Mux or a struct field, or handed to a bare function call such as
// register(srv.Mux()), escapes the hand-off half.
func registrationSites(t *testing.T, fset *token.FileSet, name string, file *ast.File, handOffs bool) []string {
	t.Helper()
	var sites []string
	for _, decl := range file.Decls {
		fn := ""
		if f, ok := decl.(*ast.FuncDecl); ok {
			fn = f.Name.Name
			if recv := funcReceiverType(f); recv != "" {
				fn = recv + "." + fn
			}
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch {
			case sel.Sel.Name == "Handle" || sel.Sel.Name == "HandleFunc":
				sites = append(sites, name+" "+fn+": "+types.ExprString(call.Fun)+"("+registrationArg(call.Args[0])+")")
			case handOffs:
				for _, arg := range call.Args {
					if handed, ok := muxHandOff(arg); ok {
						sites = append(sites, name+" "+fn+": "+types.ExprString(call.Fun)+"("+handed+")")
					}
				}
			}
			return true
		})
	}
	return sites
}

// muxHandOff reports whether arg hands over a mux, and renders it.
func muxHandOff(arg ast.Expr) (string, bool) {
	switch a := arg.(type) {
	case *ast.Ident:
		return a.Name, a.Name == "mux" || a.Name == "consoleMux"
	case *ast.CallExpr:
		sel, ok := a.Fun.(*ast.SelectorExpr)
		if ok && len(a.Args) == 0 && sel.Sel.Name == "Mux" {
			return types.ExprString(a), true
		}
	}
	return "", false
}

func registrationArg(e ast.Expr) string {
	if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		if s, err := strconv.Unquote(lit.Value); err == nil {
			return strconv.Quote(s)
		}
	}
	return types.ExprString(e)
}

// sourceFiles parses the non-test Go files of dir.
func sourceFiles(t *testing.T, dir string) (*token.FileSet, map[string]*ast.File) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%s): %v", dir, err)
	}
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", name, err)
		}
		files[name] = file
	}
	if len(files) == 0 {
		t.Fatalf("no Go source files in %s", dir)
	}
	return fset, files
}

var mutatingPattern = regexp.MustCompile(`^(POST|PUT|PATCH|DELETE) `)

// Proves RC-11.
func TestMuxRegistrationsAreTheKnownSites(t *testing.T) {
	collect := func(dir string, handOffs bool) (sites, mutating []string) {
		fset, files := sourceFiles(t, dir)
		for name, file := range files {
			sites = append(sites, registrationSites(t, fset, name, file, handOffs)...)
			ast.Inspect(file, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if s, err := strconv.Unquote(lit.Value); err == nil && mutatingPattern.MatchString(s) {
						mutating = append(mutating, name+": "+lit.Value)
					}
				}
				return true
			})
		}
		sort.Strings(sites)
		return sites, mutating
	}

	// Every site is a read or a mount of a package that has its own RC-11
	// checks: the Control API through api.Register (its routes are api.Routes(),
	// classified in package api), the MCP server (its tools, in package mcp), the
	// Console through console.Register, and the metrics and ping reads. The
	// slog handler method in reload_log.go is the one call named Handle that is
	// not a mux.
	t.Run("package main", func(t *testing.T) {
		got, mutating := collect(".", true)
		want := []string{
			`control_surfaces.go apiSurface.Mount: api.Register(mux)`,
			`control_surfaces.go consoleSurface.Mount: console.Register(consoleMux)`,
			`control_surfaces.go consoleSurface.Mount: console.Secure(consoleMux)`,
			`control_surfaces.go consoleSurface.Mount: mux.Handle("/console/")`,
			`control_surfaces.go mcpSurface.Mount: mux.Handle("/mcp")`,
			`control_surfaces.go metricsSurface.Mount: mux.Handle("GET /metrics")`,
			// The loop that mounts each control surface: its routes are the entries
			// above and their packages' own RC-11 checks.
			`main.go newServerWithHooks: s.Mount(controlSrv.Mux())`,
			`reload_log.go swapHandler.Handle: s.handler().Handle(ctx)`,
		}
		if !slices.Equal(got, want) {
			t.Errorf("handler registrations in package main changed:\n  got:  %q\n  want: %q\n"+
				"a route registered here bypasses api.Routes() and the mcp tool list, where RC-11 is checked; "+
				"add it to this list only after a human has decided it cannot write Relay configuration (invariant 11)", got, want)
		}
		if len(mutating) != 0 {
			t.Errorf("package main names a mutating route pattern %q; the Control API's writes are api.Routes(), registered by api.Register (RC-11)", mutating)
		}
	})

	t.Run("control-plane server", func(t *testing.T) {
		got, mutating := collect("../../internal/controlplane", false)
		want := []string{
			`server.go New: mux.HandleFunc("GET /api/v1/ping")`,
			`server.go New: public.Handle("/")`,
			// The fixed root redirect: it writes nothing and reads nothing from
			// the request, and every method but GET and HEAD goes on to "/".
			`server.go New: public.Handle("/{$}")`,
			`server.go New: public.Handle(ProtectedResourceMetadataPath)`,
			// The health bit: a GET that reads one bit, writes nothing and names no
			// configuration (RC-11, invariant 11).
			`server.go New: public.Handle(health.Pattern)`,
		}
		if !slices.Equal(got, want) {
			t.Errorf("handler registrations in the control-plane server changed:\n  got:  %q\n  want: %q\n"+
				"a route registered here bypasses api.Routes() and the mcp tool list, where RC-11 is checked (invariant 11)", got, want)
		}
		if len(mutating) != 0 {
			t.Errorf("the control-plane server names a mutating route pattern %q (RC-11)", mutating)
		}
	})

	t.Run("negative control: a settings route in a Mount body is seen", func(t *testing.T) {
		const snippet = `package main

func (apiSurface) Mount(mux *http.ServeMux, d surfaceDeps) {
	mux.HandleFunc("POST /api/v1/settings", writeSettings)
}
`
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "control_surfaces.go", snippet, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile: %v", err)
		}
		got := registrationSites(t, fset, "control_surfaces.go", file, true)
		want := []string{`control_surfaces.go apiSurface.Mount: mux.HandleFunc("POST /api/v1/settings")`}
		if !slices.Equal(got, want) {
			t.Errorf("the scan saw %q in a Mount body that registers a settings route, want %q; it would let that route through", got, want)
		}
	})

	t.Run("negative control: a mux handed to a registrar as a call is seen", func(t *testing.T) {
		const snippet = `package main

func newServerWithHooks() {
	settings.Register(controlSrv.Mux())
}
`
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "main.go", snippet, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile: %v", err)
		}
		got := registrationSites(t, fset, "main.go", file, true)
		want := []string{`main.go newServerWithHooks: settings.Register(controlSrv.Mux())`}
		if !slices.Equal(got, want) {
			t.Errorf("the scan saw %q for a mux handed to a registrar as a call, want %q; it would let a registrar in another package through", got, want)
		}
	})

	t.Run("a zero-argument call that is not Mux is not a hand-off", func(t *testing.T) {
		const snippet = `package main

func newServerWithHooks() {
	x.Register(srv.Handler())
}
`
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "main.go", snippet, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile: %v", err)
		}
		if got := registrationSites(t, fset, "main.go", file, true); len(got) != 0 {
			t.Errorf("the scan saw %q for a call that hands over no mux, want none; the hand-off match is Mux() only", got)
		}
	})
}
