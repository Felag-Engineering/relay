package accounts_test

import (
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts/accountstest"
)

// TestRepositoryConformance runs the shared last-enabled-admin conformance
// suite (#653) against this package's own in-memory Repository. The same
// suite runs against internal/store's sqliteAccounts
// (store.TestSQLiteAccountsConformance) — one case table proving both
// implementations carry the rule identically.
//
// An external (accounts_test) package rather than an internal one: the
// memory Repository the suite needs is unexported and lives in a _test.go
// file (memory_test.go), and an internal test file here importing
// accountstest — which imports accounts back — is a genuine import cycle
// from the Go toolchain's point of view. NewMemoryRepositoryForConformanceTest
// is the exported (test-only) seam that lets this external package reach it.
func TestRepositoryConformance(t *testing.T) {
	accountstest.RunRepositoryConformance(t, func(t *testing.T) accounts.Repository {
		return accounts.NewMemoryRepositoryForConformanceTest()
	})
}
