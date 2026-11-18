package capability

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const relayModule = "github.com/Felag-Engineering/relay/relay/"

// The capability layer reaches neither the wire protocol nor the database
// directly or through any package it imports. It checks the transitive closure
// of the layer's production imports, which the depguard capability-imports
// rule does not.
// Proves EX-47.
func TestCapabilityLayerImportsNoWireProtocolOrDatabasePackage(t *testing.T) {
	deps := goListDeps(t)

	if !deps[relayModule+"internal/jobs"] {
		t.Fatal("the dependency list does not hold the jobs package; the list is not seeing the layer's imports")
	}
	for _, banned := range []string{
		relayModule + "internal/relay/v1",
		relayModule + "internal/store",
		"database/sql",
	} {
		if deps[banned] {
			t.Errorf("the capability layer depends on %q, directly or transitively", banned)
		}
	}
	for dep := range deps {
		if strings.HasPrefix(dep, "google.golang.org/grpc") ||
			strings.HasPrefix(dep, "google.golang.org/protobuf") ||
			strings.Contains(dep, "sqlite") {
			t.Errorf("the capability layer depends on %q, directly or transitively", dep)
		}
	}
}

// goListDeps runs go list -deps in this package's directory and returns the
// import paths of the package's production dependency closure as a set.
// GOFLAGS is cleared so an inherited flag such as -mod=vendor cannot change the
// answer.
func goListDeps(t *testing.T) map[string]bool {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	cmd := exec.Command("go", "list", "-deps", ".")
	cmd.Dir = filepath.Dir(thisFile)
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, out)
	}
	set := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			set[line] = true
		}
	}
	return set
}
