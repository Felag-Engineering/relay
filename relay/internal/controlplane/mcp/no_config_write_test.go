package mcp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
)

// no_config_write_test.go is RC-11's MCP half: no tool writes Relay
// configuration (invariant 11). RC-11 is an absence, so it is asserted three
// ways, the first of which is a reviewer-visible classification and the other
// two of which do not depend on anyone classifying correctly:
//
//  1. every entry point is filed under the runtime object it writes, or none
//     if it only reads, and no runtime object is configuration. Read-access
//     audit records are not configuration writes;
//  2. the package cannot reach the configuration loader, or the file and
//     process primitives a write to the configuration file would need;
//  3. no type reachable from the constructor's seams carries a configuration
//     type.

const (
	mcpPackage    = "github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
	relayModule   = "github.com/Felag-Engineering/relay/relay/"
	configPackage = relayModule + "internal/relayconfig"
)

// runtimeObjects is the closed set of things an MCP entry point may write.
// Configuration, whether the security floor or an operator setting, is not a
// member and under RC-11 and RC-32 may never become one.
var runtimeObjects = map[string]bool{
	"Enrollment Token": true, "Node revocation": true, "Freeze": true, "Account": true,
	"API Token": true, "Job": true, "approval Request": true, "Approval grant": true,
}

// toolWrites files every MCP entry point under what it writes; "" is a read.
// The classification is the author's, kept here so a reviewer sees each write
// named. An entry point added without an entry fails, and so does a stale one.
var toolWrites = map[string]string{
	"list_nodes":      "",
	"describe_node":   "",
	"list_operations": "",
	"get_job":         "",
	"tasks/get":       "",
	"run_operation":   "Job",
	"raw_exec":        "Job",
	"cancel_job":      "Job",
	"tasks/cancel":    "Job",
	"approve_request": "approval Request",
}

// TestMCP_NoToolWritesATag is ADR-0050 decision 2 for MCP: only a human Account
// writes a tag, so no tool does. No registered tool is named for a tag, and no
// tool is filed as writing one.
func TestMCP_NoToolWritesATag(t *testing.T) {
	live := liveRegisteredToolNames(t)
	if len(live) == 0 {
		t.Fatal("liveRegisteredToolNames reported no tools; the check proved nothing")
	}
	for name := range live {
		if strings.Contains(strings.ToLower(name), "tag") {
			t.Errorf("a live tool is named %q; no MCP tool writes a tag (ADR-0050)", name)
		}
	}
	for name, writes := range toolWrites {
		if strings.Contains(strings.ToLower(writes), "tag") || strings.Contains(strings.ToLower(name), "tag") {
			t.Errorf("toolWrites files %q under %q; no MCP tool writes a tag (ADR-0050)", name, writes)
		}
	}
}

// TestNoToolWritesConfiguration is RC-11 for MCP: no tool writes Relay
// configuration. See the header above for how the absence is asserted.
func TestNoToolWritesConfiguration(t *testing.T) {
	t.Run("every tool writes a runtime object or nothing", func(t *testing.T) {
		found := collectMCPEntryPoints(t)
		if len(found) == 0 {
			t.Fatal("collectMCPEntryPoints found no registration site; the classification proved nothing")
		}
		seen := map[string]bool{}
		for _, f := range found {
			seen[f.name] = true
			writes, ok := toolWrites[f.name]
			switch {
			case !ok:
				t.Errorf("%s:%d registers %q, which is not classified in toolWrites; file it under the runtime object it writes, or \"\" if it only reads (RC-11, RC-32)", f.file, f.line, f.name)
			case writes != "" && !runtimeObjects[writes]:
				t.Errorf("%s:%d: %q writes %q, which is not a runtime object; Relay configuration is never written over MCP (RC-11, RC-32)", f.file, f.line, f.name, writes)
			}
		}
		var stale []string
		for name := range toolWrites {
			if !seen[name] {
				stale = append(stale, name)
			}
		}
		sort.Strings(stale)
		for _, name := range stale {
			t.Errorf("toolWrites classifies %q, which no registration site declares", name)
		}
		for name := range liveRegisteredToolNames(t) {
			if _, ok := toolWrites[name]; !ok {
				t.Errorf("a live ListTools call reports %q, which is not classified in toolWrites (RC-11, RC-32)", name)
			}
		}
	})

	t.Run("no entry point other than a tool is declared", func(t *testing.T) {
		_, thisFile, _, ok := runtime.Caller(0)
		if !ok {
			t.Fatal("runtime.Caller failed")
		}
		dir := filepath.Dir(thisFile)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		fset := token.NewFileSet()
		parsed := 0
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			parsed++
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "AddResource", "AddResourceTemplate", "AddPrompt":
					t.Errorf("%s:%d: an MCP entry point other than a tool is not classified by this guard (RC-11)", name, fset.Position(call.Pos()).Line)
				}
				return true
			})
		}
		if parsed == 0 {
			t.Fatal("no non-test source file parsed; the check proved nothing")
		}
	})

	t.Run("the configuration loader is not reachable", func(t *testing.T) {
		deps := goList(t, "-deps")
		if !deps[mcpPackage] {
			t.Fatalf("go list -deps did not list %s; the check would pass vacuously", mcpPackage)
		}
		if deps[configPackage] {
			t.Errorf("%s is reachable from MCP; no tool may reach Relay configuration (RC-11, invariant 11)", configPackage)
		}
	})

	t.Run("no file or process primitive is imported", func(t *testing.T) {
		// Reads this package's own non-test files only: the requeststate
		// subpackage, and a file write delegated to another Relay package this
		// one imports, are not seen here. The reachability check above and the
		// adapter-boundary lint rule cover part of that.
		imports := goList(t, "-f", "{{join .Imports \"\\n\"}}")
		for _, banned := range []string{"os", "os/exec", "io/ioutil", "syscall"} {
			if imports[banned] {
				t.Errorf("MCP imports %q; an adapter that needs file or process access is a design question under invariant 11, not something to add quietly (RC-11)", banned)
			}
		}
	})

	t.Run("no seam carries a configuration type", func(t *testing.T) {
		// New takes the six seams and the options; serverOptions is what the
		// options fill, and reaches the approval decider and the tool-call
		// observer, which come in through options and not through parameters.
		for _, root := range []reflect.Type{reflect.TypeOf(New), reflect.TypeOf(serverOptions{})} {
			hits, named := findConfigTypes(root)
			for _, hit := range hits {
				t.Errorf("%s reaches a configuration type: %s (RC-11, invariant 11)", root, hit)
			}
			if named < 2 {
				t.Errorf("the walk visited %d Relay types from %s; it is not seeing the seams", named, root)
			}
		}
	})

	t.Run("the type walk finds a configuration type", func(t *testing.T) {
		hits, _ := findConfigTypes(reflect.TypeOf(struct{ F func() *approval.Gate }{}))
		if len(hits) != 1 {
			t.Errorf("walk of a type returning *approval.Gate found %v, want exactly one hit", hits)
		}
	})
}

// goList runs go list in this package's directory with the given arguments and
// returns the lines of its output as a set. GOFLAGS is cleared so an inherited
// flag such as -mod=vendor cannot change the answer.
func goList(t *testing.T, args ...string) map[string]bool {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	cmd := exec.Command("go", append([]string{"list"}, append(args, ".")...)...)
	cmd.Dir = filepath.Dir(thisFile)
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list %v: %v\n%s", args, err, out)
	}
	set := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			set[line] = true
		}
	}
	if len(set) == 0 {
		t.Fatalf("go list %v printed nothing", args)
	}
	return set
}

// isConfigType reports whether t is a type that carries Relay configuration:
// anything in relayconfig, the operator settings, or the approval gate. It
// matches on package path and name strings.
func isConfigType(t reflect.Type) bool {
	pkg, name := t.PkgPath(), t.Name()
	switch {
	case pkg == configPackage || strings.HasPrefix(pkg, configPackage+"/"):
		return true
	case pkg == relayModule+"internal/capability":
		return name == "OperatorSettings" || name == "OperatorSettingsSource" || name == "StaticOperatorSettings"
	case pkg == relayModule+"internal/approval":
		return name == "Gate"
	}
	return false
}

// findConfigTypes walks the type graph reachable from root: elements, map keys
// and values, function parameters and results, struct fields (exported or
// not), interface methods, and the exported method set of every named type. It
// descends only into types of the Relay module, because the standard library
// and third-party types cannot refer to Relay packages. It returns the path to
// each configuration type found and the number of Relay named types visited.
func findConfigTypes(root reflect.Type) (hits []string, named int) {
	seen := map[reflect.Type]bool{}
	var walk func(t reflect.Type, path string)
	walk = func(t reflect.Type, path string) {
		if seen[t] {
			return
		}
		seen[t] = true
		if t.Name() != "" {
			if !strings.HasPrefix(t.PkgPath(), relayModule) {
				return
			}
			named++
			if isConfigType(t) {
				hits = append(hits, path+" is "+t.PkgPath()+"."+t.Name())
			}
		}
		switch t.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Chan:
			walk(t.Elem(), path+"[]")
		case reflect.Map:
			walk(t.Key(), path+"[key]")
			walk(t.Elem(), path+"[]")
		case reflect.Func:
			for i := 0; i < t.NumIn(); i++ {
				walk(t.In(i), path+"(arg)")
			}
			for i := 0; i < t.NumOut(); i++ {
				walk(t.Out(i), path+"(ret)")
			}
		case reflect.Struct:
			for i := 0; i < t.NumField(); i++ {
				walk(t.Field(i).Type, path+"."+t.Field(i).Name)
			}
		case reflect.Interface:
			for i := 0; i < t.NumMethod(); i++ {
				walk(t.Method(i).Type, path+"."+t.Method(i).Name)
			}
		}
		if t.Name() != "" && t.Kind() != reflect.Interface {
			for _, recv := range []reflect.Type{t, reflect.PointerTo(t)} {
				for i := 0; i < recv.NumMethod(); i++ {
					walk(recv.Method(i).Type, path+"."+recv.Method(i).Name)
				}
			}
		}
	}
	walk(root, root.String())
	return hits, named
}
