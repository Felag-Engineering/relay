package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNewServer_Smoke verifies that the composition root is constructible from
// a test. It proves that newServer wires all dependencies — including the
// previously-unreachable revocation.Service — without needing a live listener.
func TestNewServer_Smoke(t *testing.T) {
	cfg := Config{
		Addr:                ":0",
		CADir:               t.TempDir(),
		StorePath:           filepath.Join(t.TempDir(), "relay.db"),
		Hostname:            "localhost",
		EnrollIPRate:        5,
		EnrollIPBurst:       3,
		EnrollGlobalRate:    50,
		EnrollGlobalBurst:   10,
		EnrollMaxTrackedIPs: 100000,
		MaxNodes:            110000,
	}

	srv, deps, err := newServer(cfg)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	if srv == nil {
		t.Fatal("newServer returned nil srv")
	}
	if deps == nil {
		t.Fatal("newServer returned nil deps")
	}
	if deps.revocation == nil {
		t.Fatal("deps.revocation is nil")
	}
	if deps.registry == nil {
		t.Fatal("deps.registry is nil")
	}
	if deps.ca == nil {
		t.Fatal("deps.ca is nil")
	}
	if deps.store == nil {
		t.Fatal("deps.store is nil")
	}
	if deps.jobs == nil {
		t.Fatal("deps.jobs is nil")
	}
	if deps.tasks == nil {
		t.Fatal("deps.tasks is nil")
	}
	if deps.audit == nil {
		t.Fatal("deps.audit is nil")
	}
	t.Cleanup(func() { deps.store.Close() }) //nolint:errcheck

	// Not started, so Stop is a safe no-op cleanup.
	t.Cleanup(srv.Stop)
}

// TestEnvOr verifies the helper returns the env value when set and the fallback
// when absent or empty.
func TestEnvOr(t *testing.T) {
	const key = "RELAY_TEST_ENV_OR_KEY"

	t.Run("absent returns fallback", func(t *testing.T) {
		os.Unsetenv(key)
		if got := envOr(key, "default"); got != "default" {
			t.Errorf("got %q, want %q", got, "default")
		}
	})

	t.Run("empty returns fallback", func(t *testing.T) {
		t.Setenv(key, "")
		if got := envOr(key, "default"); got != "default" {
			t.Errorf("got %q, want %q", got, "default")
		}
	})

	t.Run("set returns env value", func(t *testing.T) {
		t.Setenv(key, "from-env")
		if got := envOr(key, "default"); got != "from-env" {
			t.Errorf("got %q, want %q", got, "from-env")
		}
	})
}
