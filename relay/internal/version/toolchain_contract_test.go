package version

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// toolchain_contract_test.go pins the Go toolchain this module is tested with
// to the one relay/go.mod names (issue #667).
//
// The `go` directive is a FLOOR, not a pin: under GOTOOLCHAIN=auto the go
// command upgrades past it and never downgrades to it. So a developer with a
// newer Go installed silently tests the Relay on a toolchain CI never runs,
// and finds out through whatever changed between the two — issue #572 is the
// worked example, where net/http's ServeMux started answering 301 where the
// suite expects 307. The Makefile exports GOTOOLCHAIN for every `make` target,
// but the bare `cd relay && go build ./... && go test ./...` loop AGENTS.md
// documents never goes through make and cannot be reached that way. This test
// is what covers it: it turns a mystery failure somewhere in the suite into
// one line naming the cause.
//
// It lives in the build-identity package because that is what it asserts —
// which build this is. It is hermetic: it reads one committed file — the
// repository's only go.mod, found through this package's repoRoot constant,
// exactly as the registry's daemon-version contract test reads
// daemon/Cargo.toml — and runs no binary.

// directive returns the single-argument value of the named top-level go.mod
// directive, or "". Hand-parsed to match the sibling contract tests in this
// module, which read their manifests the same way; golang.org/x/mod is already
// a direct dependency here, so this is a style match, not a necessity.
//
// A trailing line comment is tolerated (`go 1.25.12 // keep in sync`), so this
// agrees with the Makefile's awk on every legal go.mod.
func directive(gomod, name string) string {
	for _, line := range strings.Split(gomod, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == name {
			return fields[1]
		}
	}
	return ""
}

// majorMinor reduces a Go version ("go1.25.12", "1.25.12", "1.26rc1") to its
// "1.25" release series, reporting false for anything it cannot read — a devel
// toolchain ("devel go1.27-abc1234"), say.
func majorMinor(version string) (string, bool) {
	parts := strings.SplitN(strings.TrimPrefix(version, "go"), ".", 3)
	if len(parts) < 2 {
		return "", false
	}
	major, minor := leadingDigits(parts[0]), leadingDigits(parts[1])
	if major == "" || minor == "" {
		return "", false
	}
	return major + "." + minor, true
}

func leadingDigits(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return s[:i]
		}
	}
	return s
}

// TestRunningToolchainMatchesGoMod fails when this test binary was built by a
// Go release series other than the one relay/go.mod declares.
//
// The comparison is on major.minor only: a 1.25.13 box is not the skew anyone
// is chasing, and the differences that bite — #572's ServeMux behaviour among
// them — arrive with a release series, not a patch.
//
// Everything that could make the guard vanish instead of run is fatal: a guard
// that skips itself when it cannot read the manifest is worth nothing.
func TestRunningToolchainMatchesGoMod(t *testing.T) {
	path := filepath.Join(repoRoot, "relay", "go.mod")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read relay/go.mod: %v", err)
	}
	declared := directive(string(raw), "go")
	if declared == "" {
		t.Fatal("relay/go.mod has no `go` directive")
	}

	want, ok := majorMinor(declared)
	if !ok {
		t.Fatalf("relay/go.mod declares `go %s`, which is not a Go version", declared)
	}
	got, ok := majorMinor(runtime.Version())
	if !ok {
		// The one legitimate skip: a toolchain built from source reports
		// "devel go1.27-abc1234" and names no release series, so there is
		// nothing to compare it against.
		t.Skipf("running toolchain %q is not a numbered release; nothing to compare against", runtime.Version())
	}
	if got == want {
		return
	}
	t.Errorf("this test binary was built by %s, but relay/go.mod declares `go %s` — the Relay is expected to build and test on the go%s series, which is what CI runs.\n"+
		"A `go` directive is only a floor, so a newer toolchain on PATH is used silently, and the suite then fails on whatever changed between the two: issue #572 is the known one, where net/http's ServeMux answers 301 where the tests expect 307.\n"+
		"Remedy: run the gates through `make` (it exports GOTOOLCHAIN derived from this same directive), or set GOTOOLCHAIN=go%s yourself — the first run downloads that toolchain. `GOTOOLCHAIN=local` opts out and reinstates this failure.",
		runtime.Version(), declared, want, declared)
}
