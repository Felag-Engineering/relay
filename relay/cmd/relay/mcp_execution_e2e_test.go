//go:build integration

// Package main: mcp_execution_e2e_test.go proves the #154 production
// execution flip end to end: a real relay-daemon subprocess, enrolled and
// connected over the real mTLS Tunnel, executes a Task dispatched by an MCP
// run_operation call driven through newServer's OWN production wiring
// (Config.ControlEnabled=true, no injected test taskSink) — exactly what a
// live deployment does, unlike tunnel_dispatch_e2e_test.go's startDaemonNode
// harness (ControlEnabled=false, a test taskSink injected directly).
//
// RB3 (plan review): fixturePolicy, writeCredentialHashFile, and
// controlAPITestCredential are reused directly (now via relaytest, same
// package import already compiled alongside this integration-tagged file);
// only the startTCPServer/startDaemonNode-shaped SETUP SEQUENCE is
// duplicated inline here, because those hardcode ControlEnabled=false and
// inject a test sink — exactly what this test must not do.
//
// Skip condition: RELAY_DAEMON_BIN env var not set (mirrors
// tunnel_dispatch_e2e_test.go). Run via: make test-integration.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
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
		t.Skip("RELAY_DAEMON_BIN not set; skipping real-daemon e2e (run via make test-integration)")
	}

	ctx := context.Background()

	cfg := baseTestConfig(t)
	cfg.Addr = "127.0.0.1:0"
	cfg.ControlEnabled = true
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.ControlCredentialHashFile = relaytest.WriteCredentialHashFile(t)

	srv, deps, err := newServer(cfg)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	t.Cleanup(func() { deps.store.Close() }) //nolint:errcheck
	// deliberately NOT injecting a test taskSink: newServer itself must have
	// wired deps.tunnel.sink + deps.dispatch because cfg.ControlEnabled is
	// true (the #154 flip) — that is exactly what this test proves.

	nodeLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen (node-plane): %v", err)
	}
	nodeAddr := nodeLis.Addr().String()
	go srv.Serve(nodeLis) //nolint:errcheck
	t.Cleanup(srv.GracefulStop)

	controlLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen (control-plane): %v", err)
	}
	go func() { _ = deps.control.Serve(controlLis) }()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = deps.control.Shutdown(shutdownCtx)
	})

	// Seed an Enrollment Token scoped relay:env=test — the daemon's
	// relay: label after enrollment, which the run_operation selector below
	// targets (ADR-0006, invariant 7).
	_, plaintext, err := deps.tokens.Create(ctx, []string{"relay:env=test"}, time.Hour)
	if err != nil {
		t.Fatalf("seed Enrollment Token: %v", err)
	}

	caFile := relaytest.WriteTempFile(t, "ca-bundle-*.pem", string(deps.ca.Bundle()))
	policyPath := relaytest.WriteTempFile(t, "policy-*.toml", relaytest.FixturePolicy)
	stateDir := t.TempDir()

	env := append(os.Environ(),
		"RELAY_ADDR=https://"+nodeAddr,
		"RELAY_ENROLLMENT_TOKEN="+plaintext,
		"RELAY_CA_BUNDLE_PATH="+caFile,
		"RELAY_ENROLL_ENDPOINT=https://"+nodeAddr,
		"RELAY_STATE_DIR="+stateDir,
		"RELAY_POLICY_PATH="+policyPath,
		"RELAY_DOMAIN=localhost",
		"HOSTNAME=mcp-execution-e2e-node",
		// Disable rustls provider conflict on some environments.
		"RUST_LOG=warn",
	)
	cmd := exec.Command(daemonBin, "--relay", "https://"+nodeAddr)
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		t.Fatalf("start daemon: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
	})

	// Block on the live Tunnel via deps.dispatch (appDeps.dispatch's whole
	// reason for existing, per the plan): this is the sync point, replacing
	// startDaemonNode's poll-the-test-dispatcher loop, since no test sink is
	// injected here.
	nodeID, err := deps.dispatch.WaitForAny(30 * time.Second)
	if err != nil {
		t.Fatalf("WaitForAny: daemon did not complete Hello->Ping handshake within 30s: %v", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(deps.ca.Bundle()) {
		t.Fatal("AppendCertsFromPEM(deps.ca.Bundle()) returned false")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"},
	}
	authed := &http.Client{Transport: relaytest.BearerRoundTripper{Base: transport, Token: relaytest.ControlCredential}}

	session := relaytest.Connect(t, "https://"+controlLis.Addr().String(), authed)

	res := relaytest.CallTool(t, session, "run_operation", map[string]any{
		"operation": "system.facts",
		"selector":  "relay:env=test",
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
	// round-tripped the daemon's real TaskResult back to capSvc's caller —
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
