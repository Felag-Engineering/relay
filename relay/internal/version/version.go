// Package version carries the Relay binary's build identity: which build this
// is (ADR-0014).
//
// The three variables below are the ONLY mutable state here, and they are
// mutable solely so the linker can set them: `make build` passes
// `-ldflags -X <this package>.Version=...` (and Commit/BuildDate), derived by
// scripts/build-version.sh. A build produced without those flags — `go build
// ./...`, `go test`, `go run` — keeps the defaults, which are deliberately
// self-describing rather than a plausible-looking fake version.
//
// The version scheme is shared with the relay-daemon and documented once, in
// daemon/src/version.rs and docs/operations/version-stamping.md. The short
// form: the semantic version comes from daemon/Cargo.toml (the release the
// tree is developing toward); a clean, exactly-tagged build reports it bare
// ("0.0.9", or "0.1.0-beta" — exactly the target), every other build reports
// the target's numeric core as a `-0.dev` prerelease with the commit as build
// metadata ("0.0.9-0.dev+g<sha>[.dirty]"). The dev marker's leading NUMERIC
// identifier is what keeps a dev build sorted below a prerelease target
// (0.1.0-0.dev < 0.1.0-beta).
//
// This package holds no fleet-visible contract: only the relay-daemon's
// version is compared by the ADR-0014 minimum-version gate. It has no
// dependencies beyond fmt by design — it is imported by the composition root
// and injected outward (main.go passes the values to the metrics build-info
// gauge), never imported by the packages that expose them.
package version

import "fmt"

// The unstamped defaults. DefaultVersion is valid semver so that it can never
// be mistaken for a real release and never trips a semver parser; it is not,
// and must not be, used as a substitute for the daemon's version.
const (
	DefaultVersion = "0.0.0-unknown"
	DefaultUnknown = "unknown"
)

// Version, Commit, and BuildDate are set at link time by
// `go build -ldflags "-X ..."` (see the Makefile's GO_LDFLAGS). The defaults
// apply to any unstamped build.
var (
	Version   = DefaultVersion
	Commit    = DefaultUnknown
	BuildDate = DefaultUnknown
)

// init restores the defaults if the linker stamped an EMPTY value. `-X
// pkg.Version=` is accepted silently by the Go linker, and make expands an
// undefined variable to the empty string, so a single typo in the Makefile's
// GO_LDFLAGS right-hand side (`$(BUILD_VERSIONN)`) would otherwise ship a
// binary reporting a blank version — and would silently drop relay_build_info
// from /metrics, which is gated on a non-empty Version. Degrading to the
// honest "unidentified build" value is the same rule the relay-daemon applies
// on its side (the `stamp!` macro in daemon/src/version.rs treats an empty
// stamp as absent); the two binaries must not disagree about this.
func init() {
	Version = orDefault(Version, DefaultVersion)
	Commit = orDefault(Commit, DefaultUnknown)
	BuildDate = orDefault(BuildDate, DefaultUnknown)
}

// orDefault returns fallback when v is empty.
func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// String is the one-line human banner printed by `relay --version` and
// embedded in the startup log line.
func String() string {
	return fmt.Sprintf("relay %s (commit %s, built %s)", Version, Commit, BuildDate)
}
