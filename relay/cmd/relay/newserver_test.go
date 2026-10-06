package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/ca"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodestate"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

// baseTestConfig returns a Config with the same non-control-plane fields as
// TestNewServer_Smoke, suitable as a starting point for tests that vary the
// control-plane fields.
func baseTestConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Addr:                 ":0",
		CADir:                t.TempDir(),
		StorePath:            filepath.Join(t.TempDir(), "relay.db"),
		Hostname:             "localhost",
		EnrollIPRate:         5,
		EnrollIPBurst:        3,
		EnrollGlobalRate:     50,
		EnrollGlobalBurst:    10,
		EnrollMaxTrackedIPs:  100000,
		MaxNodes:             110000,
		ReadBlastCap:         10000,
		MutateBlastCap:       100,
		CertExpiringFraction: nodestate.DefaultCertExpiringFraction,
	}
}

// TestNewServer_Smoke verifies that the composition root is constructible from
// a test. It proves that newServer wires all dependencies — including the
// previously-unreachable revocation.Service — without needing a live listener.
func TestNewServer_Smoke(t *testing.T) {
	cfg := Config{
		Addr:                 ":0",
		CADir:                t.TempDir(),
		StorePath:            filepath.Join(t.TempDir(), "relay.db"),
		Hostname:             "localhost",
		EnrollIPRate:         5,
		EnrollIPBurst:        3,
		EnrollGlobalRate:     50,
		EnrollGlobalBurst:    10,
		EnrollMaxTrackedIPs:  100000,
		MaxNodes:             110000,
		ReadBlastCap:         10000,
		MutateBlastCap:       100,
		CertExpiringFraction: nodestate.DefaultCertExpiringFraction,
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

// TestCertExpiringFraction_RefusesAnInvalidValue is ADR-0034's startup guard
// (#414): there is deliberately no "off" value for the state:cert-expiring
// warning window, so a fraction outside (0, 1] must refuse startup rather
// than silently leaving the alarm disabled.
func TestCertExpiringFraction_RefusesAnInvalidValue(t *testing.T) {
	for _, frac := range []float64{0, -0.1, 1.1} {
		cfg := baseTestConfig(t)
		cfg.CertExpiringFraction = frac

		srv, deps, err := newServer(cfg)
		if err == nil {
			t.Errorf("cert-expiring-fraction %v: newServer succeeded, want a refusal", frac)
			continue
		}
		if srv != nil || deps != nil {
			t.Errorf("cert-expiring-fraction %v: newServer returned non-nil srv/deps on error", frac)
		}
	}
}

// TestCertExpiringFractionFromEnv_UnparsableRefusesRatherThanFallsBack is the
// parseConfig-level half of the same guard (#414 security review, F3): an
// unparsable RELAY_CERT_EXPIRING_FRACTION used to log a warning and silently
// keep the flag default, contradicting relay.env.example's documented
// "refuses to start outside (0, 1]" — a typo like "0.o5" would silently swap
// in a different alarm threshold than the operator wrote. It must now return
// a value that itself refuses TestCertExpiringFraction_RefusesAnInvalidValue's
// (0, 1] check, not the fallback.
func TestCertExpiringFractionFromEnv_UnparsableRefusesRatherThanFallsBack(t *testing.T) {
	const fallback = 0.25
	for _, env := range []string{"0.o5", "not-a-number", "  ", "1,5"} {
		got := certExpiringFractionFromEnv(env, fallback)
		if got == fallback {
			t.Errorf("certExpiringFractionFromEnv(%q, %v) = %v, want a value outside (0, 1] "+
				"(the fallback must not be used for an unparsable value)", env, fallback, got)
		}
		if got > 0 && got <= 1 {
			t.Errorf("certExpiringFractionFromEnv(%q, %v) = %v, which is inside (0, 1] and would "+
				"NOT refuse startup", env, fallback, got)
		}
	}
}

func TestCertExpiringFractionFromEnv_EmptyUsesFallback(t *testing.T) {
	if got := certExpiringFractionFromEnv("", 0.25); got != 0.25 {
		t.Errorf("certExpiringFractionFromEnv(\"\", 0.25) = %v, want 0.25 (the fallback)", got)
	}
}

func TestCertExpiringFractionFromEnv_ValidValuePassesThrough(t *testing.T) {
	if got := certExpiringFractionFromEnv("0.5", 0.25); got != 0.5 {
		t.Errorf("certExpiringFractionFromEnv(\"0.5\", 0.25) = %v, want 0.5", got)
	}
}

// TestCertExpiringWindow_IsOneValueAcrossSurfaces is the wiring-level guard
// that a zero-value capability.StateEval never reaches production: the window
// newServer computes once from ca.LeafValidity must be what BOTH the Control
// API (which resolves through the capability layer's own Plan) and the MCP
// surface (which renders state_labels) agree a Node's certificate falls
// inside — for the identical Node, in the same request.
//
// If either surface were wired with its own window (or the zero value),
// state:cert-expiring would mean one thing in a Selector and another on a
// tool's output, which is exactly the drift #414's acceptance criteria forbid.
func TestCertExpiringWindow_IsOneValueAcrossSurfaces(t *testing.T) {
	const fraction = 0.5 // half of LeafValidity: comfortably inside or outside, no edge-rounding
	f := startRelay(t, WithControlPlane(), WithConfig(func(c *Config) {
		c.CertExpiringFraction = fraction
	}))

	if _, err := f.Deps.registry.Upsert(registry.Report{NodeID: "node-cert"}); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	// Just inside a 50%-of-LeafValidity window.
	notAfter := time.Now().Add(ca.LeafValidity/2 - time.Minute)
	if err := f.Deps.registry.RecordEnrollment("node-cert",
		registry.Certificate{Fingerprint: "fp-cert", NotAfter: notAfter}, time.Now()); err != nil {
		t.Fatalf("RecordEnrollment: %v", err)
	}

	// The Control API resolves through the SAME capability.Service Plan
	// threads a Selector resolution through (service.go's stateEval).
	resp := controlAPIRequest(t, f.Client(), http.MethodPost, f.ControlBase+"/api/v1/operations",
		f.Credential, map[string]any{"operation": "system.facts", "selector": "state:cert-expiring", "plan": true})
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("plan status = %d, want 200", resp.StatusCode)
	}
	var plan struct {
		Matched int `json:"matched"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&plan); err != nil {
		t.Fatalf("decode plan: %v", err)
	}
	if plan.Matched != 1 {
		t.Fatalf("state:cert-expiring matched %d Nodes through the Control API, want 1 — the capability layer's window disagrees with newServer's", plan.Matched)
	}

	// The MCP surface, over the SAME Node.
	session := relaytest.Connect(t, f.ControlBase, f.Client())
	res := relaytest.CallTool(t, session, "describe_node", map[string]any{"node_id": "node-cert"})
	if res.IsError {
		t.Fatalf("describe_node returned IsError; content = %+v", res.Content)
	}
	var out mcp.DescribeNodeOutput
	if err := json.Unmarshal([]byte(mcpToolText(t, res)), &out); err != nil {
		t.Fatalf("decode MCP output: %v", err)
	}
	found := false
	for _, l := range out.StateLabels {
		if l == "state:cert-expiring" {
			found = true
		}
	}
	if !found {
		t.Errorf("MCP describe_node state_labels = %v, want state:cert-expiring — the MCP surface's window disagrees with the Control API's", out.StateLabels)
	}
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

func TestClampedStepUpWindow(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"above the maximum is clamped", 2 * time.Hour, 15 * time.Minute},
		{"the maximum passes", 15 * time.Minute, 15 * time.Minute},
		{"below the maximum passes", 5 * time.Minute, 5 * time.Minute},
	} {
		if got := clampedStepUpWindow(tc.in); got != tc.want {
			t.Errorf("%s: clampedStepUpWindow(%v) = %v, want %v", tc.name, tc.in, got, tc.want)
		}
	}
}
