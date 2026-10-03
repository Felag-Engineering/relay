package relaytest

import "os"

// E2ERequiredEnv names the switch `make test-integration` and `make test-crossbinary` set to
// "1". Under it a real-binary e2e test whose binary is not configured FAILS instead of
// skipping: those targets exist to run these tests, so a suite that skipped all of them (a
// wrong path, an unset variable) would otherwise be a passed gate that ran nothing. A bare
// `go test` leaves it unset, and the tests skip as they always have.
const E2ERequiredEnv = "RELAY_E2E_REQUIRED"

// skipFataler is the slice of testing.TB SkipMissingBin uses — narrowed so the required
// branch can be proven against a recorder rather than by failing a real test.
type skipFataler interface {
	Helper()
	Skip(args ...any)
	Fatalf(format string, args ...any)
}

// SkipMissingBin is the one way an e2e test reacts to its binary not being configured: it
// skips with msg, unless E2ERequiredEnv is "1", in which case it fails with msg.
func SkipMissingBin(t skipFataler, msg string) {
	t.Helper()
	if os.Getenv(E2ERequiredEnv) == "1" {
		t.Fatalf("%s — but %s=1 (set by make), so a missing binary is a failure, not a skip", msg, E2ERequiredEnv)
		return
	}
	t.Skip(msg)
}
