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
func TestRepositoryConformance(t *testing.T) {
	registrytest.RunRepositoryConformance(t, func(t *testing.T, cfg registrytest.Config) registry.Repository {
		return registry.NewInMemory(
			registry.WithMaxNodes(cfg.MaxNodes),
			registry.WithMinDaemonVersion(cfg.MinDaemonVersion),
		)
	})
}
