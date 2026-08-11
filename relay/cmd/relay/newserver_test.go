package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
)

// baseTestConfig returns a Config with the same non-control-plane fields as
// TestNewServer_Smoke, suitable as a starting point for tests that vary the
// control-plane fields.
func baseTestConfig(t *testing.T) Config {
	t.Helper()
	return Config{
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
		ReadBlastCap:        10000,
		MutateBlastCap:      100,
	}
}

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
		ReadBlastCap:        10000,
		MutateBlastCap:      100,
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
	if deps.control != nil {
		t.Fatal("deps.control should be nil when Config.ControlEnabled is false (default)")
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

// TestNewServer_ControlEnabled_SeedsIdentityAndAuthenticates verifies that
// enabling the control plane brings up a listener whose only credential is a
// per-Account API Token (#298, ADR-0023).
//
// This replaces the previous "requires a credential hash file" test: there is
// no longer a credential in Relay configuration to be missing or malformed.
// What must hold instead is that the identity substrate is established at
// startup — the founding admin Account is seeded, so `relay bootstrap-token`
// has something to mint against and the control plane is never up with no way
// to authenticate to it.
func TestNewServer_ControlEnabled_SeedsIdentityAndAuthenticates(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.ControlEnabled = true
	cfg.ControlAddr = ":0"

	srv, deps, err := newServer(cfg)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	t.Cleanup(func() { deps.store.Close() }) //nolint:errcheck
	t.Cleanup(srv.Stop)

	if deps.control == nil {
		t.Fatal("deps.control should be non-nil when ControlEnabled")
	}

	admin, err := deps.store.Accounts().GetByName(context.Background(), accounts.FoundingAdminName)
	if err != nil {
		t.Fatalf("founding admin account not seeded at startup: %v", err)
	}
	if !admin.Enabled || admin.Role != accounts.RoleAdmin {
		t.Errorf("founding admin = %+v, want an enabled admin", admin)
	}
}

// TestNewServer_MinDaemonVersion verifies the ADR-0014 startup validation: a
// malformed min-daemon-version refuses startup (no listener/store ever
// opened), empty leaves the gate off, and a valid semver value is accepted.
func TestNewServer_MinDaemonVersion(t *testing.T) {
	t.Run("malformed value refuses startup", func(t *testing.T) {
		cfg := baseTestConfig(t)
		cfg.MinDaemonVersion = "not-a-version"

		srv, deps, err := newServer(cfg)
		if err == nil {
			t.Fatal("expected newServer to error on a malformed min-daemon-version")
		}
		if srv != nil || deps != nil {
			t.Fatal("newServer should return nil srv/deps on error")
		}
	})

	t.Run("empty value leaves the gate off", func(t *testing.T) {
		cfg := baseTestConfig(t)
		cfg.MinDaemonVersion = ""

		srv, deps, err := newServer(cfg)
		if err != nil {
			t.Fatalf("newServer: %v", err)
		}
		t.Cleanup(func() { deps.store.Close() }) //nolint:errcheck
		t.Cleanup(srv.Stop)
	})

	t.Run("valid value is accepted", func(t *testing.T) {
		cfg := baseTestConfig(t)
		cfg.MinDaemonVersion = "1.2.0"

		srv, deps, err := newServer(cfg)
		if err != nil {
			t.Fatalf("newServer: %v", err)
		}
		t.Cleanup(func() { deps.store.Close() }) //nolint:errcheck
		t.Cleanup(srv.Stop)
	})
}

// TestListeners_Independent verifies that the node-plane gRPC listener keeps
// serving after the control-plane listener is shut down: the two listeners
// have independent lifecycles, as required by the acceptance criteria (a
// crash or shutdown on one plane never affects the other).
func TestListeners_Independent(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.ControlEnabled = true
	cfg.ControlAddr = ":0"

	srv, deps, err := newServer(cfg)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	t.Cleanup(func() { deps.store.Close() }) //nolint:errcheck
	t.Cleanup(srv.Stop)

	nodeLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen (node-plane): %v", err)
	}
	go func() { _ = srv.Serve(nodeLis) }()

	controlLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen (control-plane): %v", err)
	}
	go func() { _ = deps.control.Serve(controlLis) }()

	// Shut down the control plane only.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := deps.control.Shutdown(ctx); err != nil {
		t.Fatalf("control.Shutdown: %v", err)
	}

	// The control-plane listener is now closed: new connections fail.
	if _, err := http.Get("https://" + controlLis.Addr().String() + "/api/v1/ping"); err == nil { //nolint:noctx
		t.Fatal("expected control-plane request to fail after Shutdown")
	}

	// The node-plane gRPC listener must still accept TCP connections.
	conn, err := net.DialTimeout("tcp", nodeLis.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("node-plane listener did not survive control-plane Shutdown: %v", err)
	}
	conn.Close() //nolint:errcheck
}
