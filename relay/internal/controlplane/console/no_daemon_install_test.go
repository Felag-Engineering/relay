package console

import (
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/relaytest/installguard"
)

// TestConsole_NoRouteInstallsADaemon is DI-18 for the Console, an absence asserted over
// the route table: no route is named for installing, configuring or upgrading a daemon.
// Invariant 14: the Relay never pushes binaries and a daemon is upgraded only by the
// customer's config management.
//
// Proves DI-18.
func TestConsole_NoRouteInstallsADaemon(t *testing.T) {
	routes := Routes(renderableDeps())
	if len(routes) == 0 {
		t.Fatal("Routes() is empty; the check proved nothing")
	}
	sawRoot := false
	for _, r := range routes {
		pattern := r.Pattern()
		if pattern == "GET /console/{$}" {
			sawRoot = true
		}
		if hits := installguard.Hits(pattern); len(hits) > 0 {
			t.Errorf("Console route %q is named for %v; no Relay surface installs, configures or upgrades a daemon (DI-18, invariant 14)", pattern, hits)
		}
	}
	if !sawRoot {
		t.Error("Routes() lacks the Console root route; the table is not the real one")
	}
}
