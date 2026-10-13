//go:build integration

// Package main: mcp_execution_e2e_test.go proves the #154 production
// execution flip end to end: a real relay-daemon subprocess, enrolled and
// connected over the real mTLS Tunnel, executes a Task dispatched by an MCP
// run_operation call driven through newServer's OWN production wiring
// (Config.ControlEnabled=true, no injected test taskSink) — exactly what a
// live deployment does, unlike tunnel_dispatch_e2e_test.go's startDaemonNode
// harness (ControlEnabled=false, a test taskSink injected directly).
//
// RB3 (plan review): relaytest.FixturePolicy and bootstrapCredential are
// reused directly; only the startTCPServer/startDaemonNode-shaped SETUP
// SEQUENCE is duplicated inline here, because those hardcode
// ControlEnabled=false and inject a test sink — exactly what this test must
// not do.
//
// Skip condition: RELAY_DAEMON_BIN env var not set (mirrors
// tunnel_dispatch_e2e_test.go). Run via: make test-integration.
package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

// TestMCPExecution_RealDaemon_E2E drives #154's acceptance criterion: a real
// daemon connects and an MCP run_operation(system.facts) call returns a real
// per-Node result end to end, proving the production tunnel sink (set by
// newServer only because Config.ControlEnabled here) round-trips a real
// TaskResult back through dispatch.Router to the capability pipeline's
// caller, and that the dispatch is audited.
func TestMCPExecution_RealDaemon_E2E(t *testing.T) {
	daemonBin := os.Getenv("RELAY_DAEMON_BIN")
	if daemonBin == "" {
		relaytest.SkipMissingBin(t, "RELAY_DAEMON_BIN not set; skipping real-daemon e2e (run via make test-integration)")
	}

	ctx := context.Background()

	// The whole point of this test is that newServer's OWN wiring dispatches:
	// no injected test taskSink, so deps.tunnel.sink and deps.dispatch must
	// have been wired by the control plane being enabled (the #154 flip).
	f := startRelay(t, WithControlPlane(), WithTCPNodePlane())
	deps := f.Deps

	// Seed an Enrollment Token scoped relay:env=test — the daemon's
	// relay: label after enrollment, which the run_operation selector below
	// targets (ADR-0006, invariant 7).
	_, plaintext, err := deps.tokens.Create(ctx, []string{"relay:env=test"}, time.Hour)
	if err != nil {
		t.Fatalf("seed Enrollment Token: %v", err)
	}

	relaytest.StartDaemon(t, relaytest.DaemonConfig{
		Bin:        daemonBin,
		NodeAddr:   f.NodeAddr,
		CAPath:     relaytest.WriteTempFile(t, "ca-bundle-*.pem", string(deps.ca.Bundle())),
		Token:      plaintext,
		StateDir:   t.TempDir(),
		PolicyPath: relaytest.WriteTempFile(t, "policy-*.toml", relaytest.FixturePolicy),
		Hostname:   "mcp-execution-e2e-node",
	})

	// Block on the live Tunnel via deps.dispatch: this is the sync point,
	// since no test sink is injected here.
	nodeID, err := deps.dispatch.WaitForAny(30 * time.Second)
	if err != nil {
		t.Fatalf("WaitForAny: daemon did not complete Hello->Ping handshake within 30s: %v", err)
	}

	session := relaytest.Connect(t, f.ControlBase, f.Client())

	res := relaytest.CallTool(t, session, "run_operation", map[string]any{
		"operation":    "system.facts",
		"selector":     "relay:env=test",
		"wait_seconds": 300,
	})
	if res.IsError {
		t.Fatalf("run_operation returned IsError=true; content = %+v", res.Content)
	}
	if len(res.Content) == 0 {
		t.Fatal("run_operation: CallToolResult.Content is empty")
	}
	tc, ok := res.Content[0].(*sdkmcp.TextContent)
	if !ok {
		t.Fatalf("run_operation: Content[0] = %T, want *sdkmcp.TextContent", res.Content[0])
	}
	var out mcp.ExecutionOutput
	if err := json.Unmarshal([]byte(tc.Text), &out); err != nil {
		t.Fatalf("json.Unmarshal(%q): %v", tc.Text, err)
	}

	if len(out.Results) != 1 {
		t.Fatalf("run_operation: got %d per-Node results, want exactly 1 (for node %q): %+v", len(out.Results), nodeID, out.Results)
	}
	result := out.Results[0]
	if result.NodeID != nodeID {
		t.Errorf("result.NodeID = %q, want %q", result.NodeID, nodeID)
	}
	// SUCCESS (not UNREACHABLE/UNSPECIFIED) proves the production sink
	// round-tripped the daemon's real TaskResult back to the Execution's caller —
	// the whole point of the #154 flip.
	if result.Outcome != "success" {
		t.Fatalf("result.Outcome = %q, want %q; stderr=%q", result.Outcome, "success", result.Stderr)
	}
	if hostname := relaytest.FactHostname(result.Stdout); hostname == "" {
		t.Errorf("run_operation(system.facts): stdout carries no non-empty hostname= fact: %q", result.Stdout)
	}

	if out.JobID == "" {
		t.Fatal("run_operation: JobID is empty")
	}
	records, err := deps.audit.ByJob(ctx, out.JobID)
	if err != nil {
		t.Fatalf("deps.audit.ByJob(%q): %v", out.JobID, err)
	}
	if len(records) == 0 {
		t.Errorf("deps.audit.ByJob(%q): got 0 records, want at least 1 (every dispatch is audited, #102)", out.JobID)
	}
}
