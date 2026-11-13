package registry_test

import (
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/registry"
	"github.com/Felag-Engineering/relay/relay/internal/registry/registrytest"
)

// TestRepositoryConformance runs the shared registry.Repository conformance
// suite against InMemory. The same suite runs against internal/store's
// sqliteRegistry (store.TestSQLiteRegistryConformance), so every package that
// tests against this fake is testing against behaviour the production store
// is proven to share.
//
// An external (registry_test) package because registrytest imports registry:
// an internal test file importing it back is an import cycle.
//
// Its ClockSkew_* subtests prove the in-memory half of NC-37's storage;
// RecordHeartbeat_RoundTripsAndTouchesNothingElse and Connected_IsNotInferredFromLastSeen
// prove NC-11; ReadBack_DeclinesMalformedSelfReportedFields proves NC-22;
// Upsert_UpdatePreservesRelayKnowledge proves NC-24; Upsert_UpdateOverwritesNodeRootedFields
// proves NC-25.
//
// Proves NC-11, NC-22, NC-24, NC-25, NC-37.
func TestRepositoryConformance(t *testing.T) {
	registrytest.RunRepositoryConformance(t, func(t *testing.T, cfg registrytest.Config) registry.Repository {
		return registry.NewInMemory(
			registry.WithMaxNodes(cfg.MaxNodes),
			registry.WithMinDaemonVersion(cfg.MinDaemonVersion),
		)
	})
}
