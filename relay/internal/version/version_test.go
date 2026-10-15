package version

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/semver"
)

// repoRoot is this package's directory walked back up to the repository root
// (relay/internal/version -> relay/internal -> relay -> .).
const repoRoot = "../../.."

// pkg is this package's import path — the -X symbol prefix the Makefile must use.
const pkg = "github.com/Felag-Engineering/relay/relay/internal/version"

// makeVar returns the right-hand side of a simple `NAME := value` assignment
// in makefile. Enough for the single-line, literal assignments this test
// reads; it is not a make parser.
func makeVar(makefile, name string) (string, bool) {
	for _, line := range strings.Split(makefile, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), name)
		if !ok {
			continue
		}
		rest = strings.TrimSpace(rest)
		if value, ok := strings.CutPrefix(rest, ":="); ok {
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}

// --------------------------------------------------------------------------
// Without ldflags: the compiled-in defaults.
// --------------------------------------------------------------------------

func TestDefaults_AreSelfDescribingAndValidSemver(t *testing.T) {
	// This test binary is itself built without -ldflags, so the package
	// variables hold their defaults here.
	if Version != DefaultVersion {
		t.Errorf("Version = %q, want the unstamped default %q", Version, DefaultVersion)
	}
	if Commit != DefaultUnknown || BuildDate != DefaultUnknown {
		t.Errorf("Commit/BuildDate = %q/%q, want %q/%q", Commit, BuildDate, DefaultUnknown, DefaultUnknown)
	}
	// The default must never look like a real release, and must never be a
	// string a semver parser chokes on.
	if !semver.IsValid("v" + Version) {
		t.Errorf("default Version %q is not valid semver", Version)
	}
	if semver.Prerelease("v"+Version) == "" {
		t.Errorf("default Version %q must be a prerelease so it can never be mistaken for a release", Version)
	}
}

// An empty ldflags VALUE must degrade to the default, not to a blank version —
// the same rule daemon/src/version.rs's `stamp!` macro applies. init() calls
// orDefault at package load, which cannot be re-run here, so the unit is
// tested directly and the linked-binary proof lives in
// TestEmptyLdflagsValueFallsBackToDefaults below.
func TestOrDefault(t *testing.T) {
	if got := orDefault("", DefaultVersion); got != DefaultVersion {
		t.Errorf("orDefault(%q, %q) = %q, want the default", "", DefaultVersion, got)
	}
	if got := orDefault("0.0.9", DefaultVersion); got != "0.0.9" {
		t.Errorf("orDefault(%q, %q) = %q, want the stamped value", "0.0.9", DefaultVersion, got)
	}
}

func TestString_CarriesAllThreeFields(t *testing.T) {
	got := String()
	if !strings.HasPrefix(got, "relay ") {
		t.Errorf("String() = %q, want it to start with %q", got, "relay ")
	}
	for _, part := range []string{Version, Commit, BuildDate} {
		if !strings.Contains(got, part) {
			t.Errorf("String() = %q, missing %q", got, part)
		}
	}
}

// --------------------------------------------------------------------------
// With ldflags: the Makefile's -X targets must actually reach these variables.
// --------------------------------------------------------------------------

// TestMakefileLdflagsTargetThisPackage is the hermetic half of the stamping
// guard: a typo in the Makefile's -X symbol path is silently ignored by the Go
// linker (it does not error on an unknown symbol), so a stamped build would
// quietly report "0.0.0-unknown" forever. This asserts every -X target in the
// Makefile names a variable that actually exists in this package.
func TestMakefileLdflagsTargetThisPackage(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	// Expand the one make variable the -X flags are written in terms of, so
	// this test reads the same symbol paths the linker will.
	makefile := string(raw)
	pkgVar, ok := makeVar(makefile, "VERSION_PKG")
	if !ok {
		t.Fatal("Makefile declares no VERSION_PKG")
	}
	if pkgVar != pkg {
		t.Errorf("Makefile VERSION_PKG = %q, want this package's import path %q", pkgVar, pkg)
	}
	makefile = strings.ReplaceAll(makefile, "$(VERSION_PKG)", pkgVar)

	want := map[string]bool{
		pkg + ".Version":   false,
		pkg + ".Commit":    false,
		pkg + ".BuildDate": false,
	}

	for _, field := range strings.Split(makefile, "-X ")[1:] {
		flag := strings.Fields(field)[0]
		symbol, value, ok := strings.Cut(flag, "=")
		if !ok {
			t.Errorf("Makefile has an -X flag with no '=': %q", flag)
			continue
		}
		// Guard the VALUE side too: make expands an undefined variable to the
		// empty string, so `$(BUILD_VERSIONN)` links a blank version with no
		// error anywhere. init()'s fallback stops that from shipping a blank
		// string, but the stamp would still be silently lost — so every
		// $(VAR) used here must be a variable the Makefile actually declares.
		if inner, ok := strings.CutPrefix(value, "$("); ok {
			name := strings.TrimSuffix(inner, ")")
			if _, declared := makeVar(makefile, name); !declared {
				t.Errorf("Makefile stamps %s with $(%s), which it never declares; "+
					"make would expand it to the empty string and the stamp would be lost", symbol, name)
			}
		}
		seen, known := want[symbol]
		if !known {
			t.Errorf("Makefile -X targets unknown symbol %q; %s declares no such variable", symbol, pkg)
			continue
		}
		if seen {
			t.Errorf("Makefile -X targets %q more than once", symbol)
		}
		want[symbol] = true
	}
	for symbol, seen := range want {
		if !seen {
			t.Errorf("Makefile never stamps %q", symbol)
		}
	}

	// The flags must also actually be handed to the relay build.
	if !strings.Contains(makefile, `-ldflags "$(GO_LDFLAGS)" -o bin/relay`) {
		t.Error("build-relay does not pass $(GO_LDFLAGS) to go build")
	}
}

// TestLdflagsStampReachesTheBinary is the end-to-end half: it links the real
// `relay` binary with the same -X flags the Makefile uses and asserts
// `relay --version` reports them. This proves the whole chain — variable
// names, symbol path, and the --version flag handling in cmd/relay — rather
// than just the Makefile's text.
func TestLdflagsStampReachesTheBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("links a binary; skipped under -short")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH")
	}

	got := buildAndReportVersion(t, "9.9.9-test+gdeadbeef", "deadbeefcafe", "2026-01-02")
	want := "relay 9.9.9-test+gdeadbeef (commit deadbeefcafe, built 2026-01-02)"
	if got != want {
		t.Errorf("relay --version = %q, want %q", got, want)
	}
}

// TestEmptyLdflagsValueFallsBackToDefaults is the linked-binary proof for the
// hole TestMakefileLdflagsTargetThisPackage cannot see: the symbol paths can be
// perfect while the VALUES are empty (make expands an undefined variable to the
// empty string, and the linker accepts `-X pkg.Version=` without complaint).
// Before init() normalised them, that produced a binary reporting a blank
// version AND silently dropped relay_build_info from /metrics.
func TestEmptyLdflagsValueFallsBackToDefaults(t *testing.T) {
	if testing.Short() {
		t.Skip("links a binary; skipped under -short")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH")
	}

	got := buildAndReportVersion(t, "", "", "")
	want := "relay " + DefaultVersion + " (commit " + DefaultUnknown + ", built " + DefaultUnknown + ")"
	if got != want {
		t.Errorf("relay --version with empty -X values = %q, want the unstamped defaults %q", got, want)
	}
}

// buildAndReportVersion links the real relay binary with the given -X values
// and returns the trimmed output of `relay --version`.
func buildAndReportVersion(t *testing.T, version, commit, date string) string {
	t.Helper()
	ldflags := "-X " + pkg + ".Version=" + version +
		" -X " + pkg + ".Commit=" + commit +
		" -X " + pkg + ".BuildDate=" + date

	bin := filepath.Join(t.TempDir(), "relay")
	build := exec.Command("go", "build", "-ldflags", ldflags, "-o", bin, "../../cmd/relay")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	out, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("relay --version: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}
