package api

import (
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

// no_config_write_test.go is RC-11's Control API half: no route writes Relay
// configuration (invariant 11). RC-11 is an absence, so it is asserted three
// ways, the first of which is a reviewer-visible classification and the other
// two of which do not depend on anyone classifying correctly:
//
//  1. every route is filed under the runtime object it writes, or none if it
//     only reads, and no runtime object is configuration;
//  2. the package cannot reach the configuration loader, or the file and
//     process primitives a write to the configuration file would need;
//  3. no type reachable from Deps carries a configuration type.

const (
	apiPackage    = "github.com/Felag-Engineering/relay/relay/internal/controlplane/api"
	relayModule   = "github.com/Felag-Engineering/relay/relay/"
	configPackage = relayModule + "internal/relayconfig"
)

// runtimeObjects is the closed set of things a Control API route may write.
// Configuration, whether the security floor or an operator setting, is not a
// member and under RC-11 and RC-32 may never become one.
var runtimeObjects = map[string]bool{
	"Enrollment Token": true, "Node revocation": true, "Freeze": true, "Account": true,
	"API Token": true, "Job": true, "approval Request": true,
	"Tag": true,
}

// routeWrites files every route under what it writes; "" is a read. The
// classification is the author's, kept here so a reviewer sees each write
// named. A route added without an entry fails, and so does a stale entry.
var routeWrites = map[string]string{
	"POST /api/v1/enrollment-tokens":        "Enrollment Token",
	"DELETE /api/v1/enrollment-tokens/{id}": "Enrollment Token",
	"GET /api/v1/nodes/{node_id}":           "",
	"POST /api/v1/nodes/{node_id}/revoke":   "Node revocation",
	"POST /api/v1/freeze/engage":            "Freeze",
	"POST /api/v1/freeze/release":           "Freeze",
	"POST /api/v1/nodes/{node_id}/tags":     "Tag",
	"POST /api/v1/tags":                     "Tag",
	"POST /api/v1/accounts":                 "Account",
	"GET /api/v1/accounts":                  "",
	"GET /api/v1/accounts/{id}":             "",
	"POST /api/v1/accounts/{id}/role":       "Account",
	"POST /api/v1/accounts/{id}/enable":     "Account",
	"POST /api/v1/accounts/{id}/disable":    "Account",
	"POST /api/v1/accounts/{id}/tokens":     "API Token",
	"GET /api/v1/accounts/{id}/tokens":      "",
	"DELETE /api/v1/api-tokens/{token_id}":  "API Token",
	"POST /api/v1/operations":               "Job",
	"POST /api/v1/raw-exec":                 "Job",
	"GET /api/v1/jobs/{id}":                 "",
	"POST /api/v1/jobs/{id}/cancel":         "Job",
	"GET /api/v1/approvals":                 "",
	"GET /api/v1/approvals/{id}":            "",
	"POST /api/v1/approvals/{id}/decision":  "approval Request",
}

// TestNoRouteWritesConfiguration is RC-11 for the Control API: no route writes
// Relay configuration. See the header above for how the absence is asserted.
//
// Proves AP-5.
func TestNoRouteWritesConfiguration(t *testing.T) {
	t.Run("every route writes a runtime object or nothing", func(t *testing.T) {
		served := map[string]bool{}
		for _, r := range Routes() {
			pattern := r.Pattern()
			served[pattern] = true
			writes, ok := routeWrites[pattern]
			switch {
			case !ok:
				t.Errorf("route %q is not classified in routeWrites; file it under the runtime object it writes, or \"\" if it only reads (RC-11, RC-32)", pattern)
			case writes != "" && !runtimeObjects[writes]:
				t.Errorf("route %q writes %q, which is not a runtime object; Relay configuration is never written over the Control API (RC-11, RC-32)", pattern, writes)
			case r.Method == "GET" && writes != "":
				t.Errorf("route %q is a GET filed as writing %q", pattern, writes)
			case r.Method != "GET" && writes == "":
				t.Errorf("route %q is a %s filed as a read; say what it writes (RC-11)", pattern, r.Method)
			}
		}
		var stale []string
		for pattern := range routeWrites {
			if !served[pattern] {
				stale = append(stale, pattern)
			}
		}
		sort.Strings(stale)
		for _, pattern := range stale {
			t.Errorf("routeWrites classifies %q, which Routes() does not serve", pattern)
		}
		if len(served) == 0 {
			t.Fatal("Routes() is empty; the classification proved nothing")
		}
	})

	t.Run("the configuration loader is not reachable", func(t *testing.T) {
		deps := goList(t, "-deps")
		if !deps[apiPackage] {
			t.Fatalf("go list -deps did not list %s; the check would pass vacuously", apiPackage)
		}
		if deps[configPackage] {
			t.Errorf("%s is reachable from the Control API; no route may reach Relay configuration (RC-11, invariant 11)", configPackage)
		}
	})

	t.Run("no file or process primitive is imported", func(t *testing.T) {
		// Reads this package's own non-test files only: a subpackage, or a file
		// write delegated to another Relay package the adapter imports, is not
		// seen here. The reachability check above and the adapter-boundary lint
		// rule cover part of that.
		imports := goList(t, "-f", "{{join .Imports \"\\n\"}}")
		for _, banned := range []string{"os", "os/exec", "io/ioutil", "syscall"} {
			if imports[banned] {
				t.Errorf("the Control API imports %q; an adapter that needs file or process access is a design question under invariant 11, not something to add quietly (RC-11)", banned)
			}
		}
	})

	t.Run("no seam carries a configuration type", func(t *testing.T) {
		hits, named := findConfigTypes(reflect.TypeOf(Deps{}))
		for _, hit := range hits {
			t.Errorf("Deps reaches a configuration type: %s (RC-11, invariant 11)", hit)
		}
		if named < 2 {
			t.Errorf("the walk visited %d Relay types from Deps; it is not seeing the seams", named)
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
