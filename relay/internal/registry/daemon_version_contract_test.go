package registry

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/mod/semver"
)

// This file is the CROSS-TOOLCHAIN half of issue #249: the relay-daemon's
// build-stamped version (daemon/src/version.rs, derived by
// scripts/build-version.sh) is the sole input to this package's ADR-0014
// minimum-version gate. Nothing in the Rust toolchain can see this gate and
// nothing in the Go toolchain compiles the daemon, so the coupling is only as
// good as the assertions here.
//
// These tests are hermetic: they read the committed daemon/Cargo.toml and run
// the committed scripts/build-version.sh. No network, no built binaries.

// repoRoot is this package's directory walked back up to the repository root
// (relay/internal/registry -> relay/internal -> relay -> .).
const repoRoot = "../../.."

// cargoPackageVersion extracts the [package] version from daemon/Cargo.toml —
// the semantic version both binaries are stamped from.
func cargoPackageVersion(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, "daemon", "Cargo.toml"))
	if err != nil {
		t.Fatalf("read daemon/Cargo.toml: %v", err)
	}
	inPackage := false
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case strings.HasPrefix(line, "[package]"):
			inPackage = true
		case strings.HasPrefix(line, "["):
			inPackage = false
		case inPackage && strings.HasPrefix(line, "version"):
			_, rhs, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			return strings.Trim(strings.TrimSpace(rhs), `"`)
		}
	}
	t.Fatal("daemon/Cargo.toml has no [package] version")
	return ""
}

// numericCore strips any prerelease suffix from a version, leaving `X.Y.Z` —
// what dev builds report ahead of the `-0.dev` marker (issue #261: a target
// of "0.1.0-beta" yields dev builds stamped "0.1.0-0.dev...").
func numericCore(base string) string {
	core, _, _ := strings.Cut(base, "-")
	return core
}

// TestDaemonVersionSchemeIsValidGateInput pins every form the relay-daemon can
// report to the two properties this gate needs: it parses, and it orders the
// way an operator expects.
func TestDaemonVersionSchemeIsValidGateInput(t *testing.T) {
	base := cargoPackageVersion(t)
	core := numericCore(base)

	// The four shapes daemon/src/version.rs and scripts/build-version.sh can
	// produce. Keep in sync with those two files.
	release := base                      // clean build of the exact vX tag
	devUnstamped := core + "-0.dev"      // plain `cargo build`, no stamp
	dev := core + "-0.dev+g0a0f22f03dcf" // stamped non-release build
	devDirty := dev + ".dirty"           // stamped build of a dirty tree
	forms := []string{release, devUnstamped, dev, devDirty}

	for _, v := range forms {
		if !ValidVersion(v) {
			t.Errorf("ValidVersion(%q) = false; the daemon would fail the gate outright", v)
		}
	}

	// Ordering, the point of the scheme: a dev build of X is BELOW X, so a
	// Relay requiring >= X refuses to dispatch to it. That is the fail-closed
	// direction.
	for _, v := range []string{devUnstamped, dev, devDirty} {
		if !Outdated(v, release) {
			t.Errorf("Outdated(%q, %q) = false; a dev build must sort below the release it precedes", v, release)
		}
	}
	if Outdated(release, release) {
		t.Errorf("Outdated(%q, %q) = true; an exact release build must satisfy its own minimum", release, release)
	}
	if Outdated(release, devUnstamped) {
		t.Errorf("Outdated(%q, %q) = true; the release must sort above its own dev prereleases", release, devUnstamped)
	}

	// Build metadata is comparison-neutral (semver §10). It carries identity
	// only — which is exactly why dirtiness is ALSO expressed as the `-0.dev`
	// prerelease above and never by the `.dirty` suffix alone.
	if Outdated(dev, devUnstamped) || Outdated(devDirty, dev) {
		t.Error("build metadata must not affect gate ordering")
	}
	if Outdated(release+"+gdeadbeef", release) {
		t.Errorf("%q must compare equal to %q", release+"+gdeadbeef", release)
	}

	// The trap this scheme exists to avoid: `git describe` after tag vX yields
	// "X-14-gabc1234", a PRERELEASE of X, so a build made 14 commits AFTER the
	// X release would be flagged outdated against X. Asserted, not assumed —
	// if this ever stops holding, the rationale in daemon/src/version.rs and
	// docs/operations/version-stamping.md needs revisiting.
	describeForm := base + "-14-g0a0f22f03dcf"
	if !Outdated(describeForm, release) {
		t.Errorf("expected the git-describe form %q to sort below %q (that is why it is not used)", describeForm, release)
	}
}

// cmp orders two bare versions with the gate's real comparator —
// golang.org/x/mod/semver, v-normalized exactly as Outdated does it.
func cmp(a, b string) int {
	return semver.Compare(normalize(a), normalize(b))
}

// TestNumericDevMarkerSortsBelowEveryShippableBase is issue #261's Definition
// of Done, EXECUTED against the gate's real comparator rather than derived
// from the semver spec: for every base this project intends to ship — plain
// and prerelease alike — the `-0.dev` dev marker of that base's numeric core
// must sort strictly below the base, in every stamped form the build can
// produce. The property that makes this hold is that `0.dev`'s LEADING
// identifier is numeric, and x/mod/semver orders numeric identifiers below
// all alphanumeric ones; every additional identifier stays AFTER `0.dev`, so
// the numeric-first comparison always decides.
func TestNumericDevMarkerSortsBelowEveryShippableBase(t *testing.T) {
	bases := []string{
		"0.0.9",        // the current milestone
		"0.1.0-beta",   // the next target — the exact case the old scheme inverted
		"0.1.0-beta.1", // dotted prerelease form
		"0.1.0-rc.1",   // rc form (DoD-required)
		"0.1.0",        // the plain release after the prereleases
		"1.0.0",        // eventually
	}
	for _, base := range bases {
		devForms := []string{
			numericCore(base) + "-0.dev",                    // unstamped
			numericCore(base) + "-0.dev+g0a0f22f03dcf",      // stamped, git identity as build metadata
			numericCore(base) + "-0.dev+g0a0f22f03dcf.dirty",
			// Defense in depth: even carried as PRERELEASE identifiers rather
			// than metadata, anything after `0.dev` must not flip the order.
			numericCore(base) + "-0.dev.g0a0f22f03dcf",
		}
		for _, dev := range devForms {
			if c := cmp(dev, base); c >= 0 {
				t.Errorf("semver.Compare(%q, %q) = %d, want < 0: the dev build must sort below the release it precedes", dev, base, c)
			}
			if !Outdated(dev, base) {
				t.Errorf("Outdated(%q, %q) = false: the gate must refuse a dev build against min-daemon-version = %q (fail-closed)", dev, base, base)
			}
		}
	}

	// The full chain around the next milestone: a dev build of the 0.1.0 line
	// sorts below the beta, which sorts below the final release.
	chain := []string{"0.1.0-0.dev", "0.1.0-beta", "0.1.0"}
	for i := 0; i+1 < len(chain); i++ {
		if c := cmp(chain[i], chain[i+1]); c >= 0 {
			t.Errorf("semver.Compare(%q, %q) = %d, want < 0 (chain %v must be strictly ascending)", chain[i], chain[i+1], c, chain)
		}
	}

	// Pin the defect this scheme replaced (issue #261): appending `-dev` to a
	// prerelease target INVERTS the gate — `beta-dev` is a single identifier
	// lexically greater than `beta`, so the unreleased dev build passed a
	// min-daemon-version = 0.1.0-beta gate fail-open. If this assertion ever
	// fails, x/mod/semver's ordering changed and the whole scheme needs review.
	if c := cmp("0.1.0-beta-dev+g0a0f22f03dcf", "0.1.0-beta"); c <= 0 {
		t.Errorf("semver.Compare(0.1.0-beta-dev..., 0.1.0-beta) = %d; the #261 defect this test pins no longer reproduces — revisit the scheme rationale", c)
	}
}

// TestBuildVersionScriptOutputPassesTheGate runs the real stamping script and
// checks its output against the real gate. In a checkout with no tags — which
// is the normal state of a fresh clone, and of this repository today — this
// exercises the untagged fallback path specifically: it must still yield a
// version the gate accepts, never an invalid string that fails ValidVersion.
func TestBuildVersionScriptOutputPassesTheGate(t *testing.T) {
	script := filepath.Join(repoRoot, "scripts", "build-version.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("stat %s: %v", script, err)
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not on PATH")
	}

	out, err := exec.Command(bash, script).CombinedOutput()
	if err != nil {
		t.Fatalf("build-version.sh: %v\n%s", err, out)
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) != 3 {
		t.Fatalf("build-version.sh printed %d fields, want 3 (version commit date): %q", len(fields), out)
	}
	version, commit, date := fields[0], fields[1], fields[2]

	if !ValidVersion(version) {
		t.Errorf("build-version.sh produced %q, which fails ValidVersion — a daemon stamped with it would fail the gate", version)
	}
	// The stamp must be either exactly daemon/Cargo.toml's version (a release
	// build) or the `-0.dev` prerelease of its numeric core (any dev build):
	// that is what makes the Rust-side
	// `reported_version_is_the_release_or_its_numeric_dev_prerelease`
	// assertion and this gate agree about what "0.0.9" means.
	base := cargoPackageVersion(t)
	if dev := numericCore(base) + "-0.dev"; version != base &&
		version != dev && !strings.HasPrefix(version, dev+"+") {
		t.Errorf("build-version.sh produced %q, which is neither %q nor its %q dev prerelease", version, base, dev)
	}
	if commit == "" || date == "" {
		t.Errorf("build-version.sh produced empty commit/date: %q/%q", commit, date)
	}
	if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`).MatchString(date) {
		t.Errorf("build-version.sh build date = %q, want YYYY-MM-DD", date)
	}
}

// TestReleaseTagMatchesCargoVersion guards the direction the dev-marker
// scheme's own release discipline invites: bumping daemon/Cargo.toml to the
// NEXT version while HEAD still carries the tag being released.
//
// The failure is silent and worse than forgetting to bump. With Cargo.toml at
// 0.0.10 and HEAD tagged v0.0.9, the exact-tag branch of build-version.sh never
// fires — the tag is v0.0.9, the base is 0.0.10 — so the artifact published
// under the v0.0.9 release reports `0.0.10-0.dev+g<sha>`: a prerelease of a
// version that has not shipped. Nothing errors. The gate then admits it against
// min=0.0.9 because 0.0.10-0.dev sorts ABOVE 0.0.9, not because it IS 0.0.9,
// and the release artifact is not self-identifying.
//
// So: whenever HEAD carries any v-prefixed tag, one of them must be exactly
// `v<Cargo.toml version>`. Skipped in a tagless clone (the normal state of a
// fresh checkout, of CI's shallow clone, and of this repository today), which
// is why the CD job in #250 must additionally reject any release artifact whose
// stamped version contains `-0.dev`.
func TestReleaseTagMatchesCargoVersion(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	cmd := exec.Command("git", "tag", "--points-at", "HEAD")
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		t.Skip("not a git checkout, or HEAD is unborn")
	}

	// Only v-prefixed tags are release tags; anything else (a `nightly` marker,
	// say) is not a claim about the version and is ignored — matching what
	// build-version.sh looks for.
	var releaseTags []string
	for _, tag := range strings.Fields(string(out)) {
		if strings.HasPrefix(tag, "v") {
			releaseTags = append(releaseTags, tag)
		}
	}
	if len(releaseTags) == 0 {
		t.Skip("HEAD carries no release tag; nothing to reconcile")
	}

	want := "v" + cargoPackageVersion(t)
	for _, tag := range releaseTags {
		if tag == want {
			return
		}
	}
	t.Errorf("HEAD carries release tag(s) %v but daemon/Cargo.toml declares %s: "+
		"the build stamped for this tag would report a %q prerelease instead of the release version. "+
		"Either bump daemon/Cargo.toml to match the tag, or move the tag.",
		releaseTags, want, numericCore(cargoPackageVersion(t))+"-0.dev")
}
