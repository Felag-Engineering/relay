package mcp

import (
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/relaytest/installguard"
)

// TestNoToolInstallsADaemon is DI-18 for MCP, an absence asserted over the registered
// surface: no tool, whether registered unconditionally or only when an optional seam is
// wired, is named for installing, configuring or upgrading a daemon, and everything a
// tool writes is filed under a runtime object that is none of those. Invariant 14: the
// Relay never pushes binaries and a daemon is upgraded only by the customer's config
// management.
//
// Proves DI-18.
func TestNoToolInstallsADaemon(t *testing.T) {
	names := liveRegisteredToolNames(t)
	for _, e := range collectMCPEntryPoints(t) {
		names[e.name] = true
	}
	if !names["run_operation"] {
		t.Fatalf("the registered names %v lack run_operation; the walk is not seeing the real surface", names)
	}
	for name := range names {
		if hits := installguard.Hits(name); len(hits) > 0 {
			t.Errorf("MCP tool %q is named for %v; no Relay surface installs, configures or upgrades a daemon (DI-18, invariant 14)", name, hits)
		}
	}

	// What each tool writes is classified once, for the configuration guard beside this
	// one (no_config_write_test.go); the same classification shows that no tool's write
	// is a daemon install.
	for tool, object := range toolWrites {
		if object != "" && !runtimeObjects[object] {
			t.Errorf("tool %q writes %q, which is not a runtime object (DI-18)", tool, object)
		}
	}
	if len(runtimeObjects) == 0 {
		t.Fatal("runtimeObjects is empty; the write check proved nothing")
	}
	for object := range runtimeObjects {
		if hits := installguard.Hits(object); len(hits) > 0 {
			t.Errorf("runtime object %q is named for %v; no tool writes a daemon install (DI-18, invariant 14)", object, hits)
		}
	}
}
