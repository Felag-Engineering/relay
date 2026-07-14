package registry

import "golang.org/x/mod/semver"

// Outdated reports whether a Node's reported daemon version is below the
// Relay's configured minimum (ADR-0014). An empty minimum means the gate is
// off — always false. A malformed or empty reported version fails CLOSED:
// it is treated as outdated whenever a minimum is configured. A malformed
// minimum is treated defensively — a misconfigured gate must never silently
// flag the whole fleet as outdated — so it returns false.
func Outdated(reported, minimum string) bool {
	if minimum == "" {
		return false
	}
	normMinimum := normalize(minimum)
	if !semver.IsValid(normMinimum) {
		return false
	}
	normReported := normalize(reported)
	if !semver.IsValid(normReported) {
		return true
	}
	return semver.Compare(normReported, normMinimum) < 0
}

// ValidVersion reports whether v is a valid semver version, accepting both
// bare ("0.1.0") and "v"-prefixed ("v0.1.0") forms. Used by startup config
// validation of min_daemon_version.
func ValidVersion(v string) bool {
	return semver.IsValid(normalize(v))
}

// normalize prepends the "v" that golang.org/x/mod/semver requires; relay-
// daemons report bare versions (e.g. "0.1.0").
func normalize(v string) string {
	if v != "" && v[0] != 'v' {
		return "v" + v
	}
	return v
}
