package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// packaging_drift_test.go keeps relay/packaging/relay.env.example honest
// against the code (#362).
//
// It exists because the drift it prevents had ALREADY HAPPENED on the other
// side of the repo: the daemon's env.example was missing four environment
// variables added after it was written, and nothing noticed for several
// milestones. A sample config is the first thing an operator copies, and one
// that silently omits a setting does not read as incomplete — it reads as
// though the setting does not exist.
//
// This is the discipline the OpenAPI drift gate already applies to the Control
// API: publish the surface, then make the publication a build-time obligation
// rather than a good intention.
//
// It checks COVERAGE, not values. Every operator-facing RELAY_* the code reads
// must be mentioned somewhere in the sample, commented out or not. What a
// default should be is a judgement the sample makes; whether an operator can
// discover the setting exists at all is not.

// envNamePattern matches a whole RELAY_* environment-variable name, so a
// comparison is against the complete token and never a prefix of a longer one.
var envNamePattern = regexp.MustCompile(`RELAY_[A-Z0-9_]+`)

// envExemptions are RELAY_* names deliberately absent from the operator-facing
// sample. Each carries a reason, because "add it to the exemption list" is the
// easy way to defeat this test.
var envExemptions = map[string]string{
	// Build-time stamps injected by the linker, never set by an operator.
	"RELAY_BUILD_VERSION": "build stamp",
	"RELAY_BUILD_COMMIT":  "build stamp",
	"RELAY_BUILD_DATE":    "build stamp",
	// Only exists under the `devharness` build tag, which is a test binary and
	// is never shipped.
	"RELAY_DEVHARNESS_SOCKET": "devharness build tag only, absent from a release binary",
}

func TestRelayEnvExampleCoversTheConfigSurface(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

	sample, err := os.ReadFile(filepath.Join(dir, "..", "..", "packaging", "relay.env.example"))
	if err != nil {
		t.Fatalf("read relay.env.example: %v — the sample config is part of the shipped surface; "+
			"if it moved, move this test with it rather than deleting it", err)
	}
	// Tokenize the sample rather than substring-matching it. A substring check
	// is satisfied by any LONGER name that happens to contain the one being
	// looked for, so a typo in the sample ("RELAY_HOSTNAMEX=") would silently
	// pass while shipping a setting no operator can use. Set membership on
	// extracted tokens is exact.
	sampleNames := map[string]bool{}
	for _, m := range envNamePattern.FindAllString(string(sample), -1) {
		sampleNames[m] = true
	}

	found := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%s): %v", dir, err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, isLit := n.(*ast.BasicLit)
			if !isLit || lit.Kind != token.STRING {
				return true
			}
			v, err := strconv.Unquote(lit.Value)
			if err != nil || !strings.HasPrefix(v, "RELAY_") || v == "RELAY_" {
				return true
			}
			found[v] = name
			return true
		})
	}

	if len(found) == 0 {
		t.Fatal("no RELAY_* environment variables found in cmd/relay — this test is scanning nothing")
	}

	for name, file := range found {
		if _, exempt := envExemptions[name]; exempt {
			continue
		}
		if !sampleNames[name] {
			t.Errorf("%s is read by %s but appears nowhere in relay/packaging/relay.env.example.\n"+
				"An operator copying that sample cannot discover a setting it never mentions. Add it "+
				"(commented out is fine, with a line saying what it does and why it is set here rather "+
				"than being reachable from the API), or add it to envExemptions with a reason.",
				name, file)
		}
	}
}

// TestRelayEnvExemptionsAreReal stops the exemption list from becoming the
// place drift hides. An exemption for a variable the code no longer reads is
// stale, and the next person adding one has no way to tell.
func TestRelayEnvExemptionsAreReal(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(thisFile), "..", "..")

	var all strings.Builder
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil //nolint:nilerr // an unreadable entry is not this test's subject
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		all.Write(b)
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk %s: %v", root, walkErr)
	}
	treeNames := map[string]bool{}
	for _, m := range envNamePattern.FindAllString(all.String(), -1) {
		treeNames[m] = true
	}

	for name, why := range envExemptions {
		if !treeNames[name] {
			t.Errorf("envExemptions lists %q (%q) but nothing in the Go tree references it — "+
				"a stale exemption is where the next real drift hides", name, why)
		}
	}
}
