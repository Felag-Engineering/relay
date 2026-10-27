package api

import (
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/relaytest/installguard"
)

// TestNoRouteInstallsADaemon is DI-18 for the Control API, an absence asserted over the
// route table: no route is named for installing, configuring or upgrading a daemon, and
// every write a route makes is filed under a runtime object that is none of those.
// Invariant 14: the Relay never pushes binaries and a daemon is upgraded only by the
// customer's config management.
//
// Proves DI-18.
func TestNoRouteInstallsADaemon(t *testing.T) {
	routes := Routes()
	if len(routes) == 0 {
		t.Fatal("Routes() is empty; the check proved nothing")
	}
	for _, r := range routes {
		pattern := r.Pattern()
		if hits := installguard.Hits(pattern); len(hits) > 0 {
			t.Errorf("route %q is named for %v; no Relay surface installs, configures or upgrades a daemon (DI-18, invariant 14)", pattern, hits)
		}
		// The classification the configuration guard beside this one keeps: what a
		// route writes is a runtime object, never a daemon install.
		if object := routeWrites[pattern]; object != "" && !runtimeObjects[object] {
			t.Errorf("route %q writes %q, which is not a runtime object (DI-18)", pattern, object)
		}
	}
	if len(runtimeObjects) == 0 {
		t.Fatal("runtimeObjects is empty; the write check proved nothing")
	}
	for object := range runtimeObjects {
		if hits := installguard.Hits(object); len(hits) > 0 {
			t.Errorf("runtime object %q is named for %v; no route writes a daemon install (DI-18, invariant 14)", object, hits)
		}
	}
}
