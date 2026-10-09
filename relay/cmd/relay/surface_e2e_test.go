//go:build integration

// Package main: surface_e2e_test.go is #121's milestone-proving integration
// test — it proves the FULL v0.0.6 acceptance matrix ("Control
// Surfaces: MCP & First API Slice") end to end, driven ONLY through the
// public surfaces a real client would use: a real MCP SDK client over HTTPS
// (run_operation/raw_exec/describe_node/list_nodes) and real /api/v1 HTTPS
// calls (token mint/revoke, Node revoke, Freeze engage/release) — against
// real relay-daemon subprocesses, with newServer wired for production
// (Config.ControlEnabled=true, the #154 path this repo's other e2e suites
// already prove piecewise). This file adds no assertion path that reaches
// into deps.capability directly (unlike control_api_e2e_test.go's Freeze
// probe) — deps.audit reads and the direct node-plane Enroll RPC (for the
// deterministic revoked-token negative) are the only non-MCP/non-HTTP
// observation points, both read-only/negative-only, never part of the
// dispatch/authz assertion path itself.
//
// #113 (compose dev-fleet) note: #113 is still OPEN as of this issue. A
// future compose-based dev-fleet harness can reuse, wholesale: the
// token-scope -> distinct relay: label pattern used here to stand up
// alpha/beta/fresh Nodes; the launchDaemon env recipe (RELAY_ADDR/
// RELAY_ENROLLMENT_TOKEN/RELAY_CA_BUNDLE_PATH/RELAY_STATE_DIR/
// RELAY_POLICY_PATH, one HOSTNAME + one RELAY_STATE_DIR per Node); the
// waitForConnectedNodes(deps.dispatch.ConnectedNodes()) readiness poll; the
// pollDescribeReported poll for the daemon's post-connect PolicySnapshot
// (#151); and the public-surface (MCP + HTTPS) assertion shapes throughout.
// No compose file is added here — #113's own scope.
//
// Skip condition: RELAY_DAEMON_BIN env var not set (mirrors every other file
// in this package). Run via: make test-integration.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	relayv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

// verdictsByNode indexes a mcp.PlanOutput's Verdicts by NodeID for
// order-independent assertions (ADR-0006: never assume slice order).
func verdictsByNode(p mcp.PlanOutput) map[string]mcp.PerNodeVerdict {
	m := make(map[string]mcp.PerNodeVerdict, len(p.Verdicts))
	for _, v := range p.Verdicts {
		m[v.NodeID] = v
	}
	return m
}

// resultsByNode indexes a []mcp.PerNodeResult by NodeID, the run_operation/
// raw_exec sibling of verdictsByNode.
func resultsByNode(results []mcp.PerNodeResult) map[string]mcp.PerNodeResult {
	m := make(map[string]mcp.PerNodeResult, len(results))
	for _, r := range results {
		m[r.NodeID] = r
	}
	return m
}

// stringSlicesEqual reports whether a and b hold the same strings in the
// same order — used for RawAllowPatterns/RawDenyPatterns, which the daemon
// reports (and this test asserts) verbatim in relaytest.FixturePolicy's own order.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// startSurfaceHarness boots the real Relay composition root (newServer) with
// the control plane enabled for production execution (Config.ControlEnabled
// = true, the #154 flip): a real TCP node-plane gRPC listener (daemon
// subprocesses need a real socket, mirroring mcp_execution_e2e_test.go — not
// startControlAPIServer's bufconn, which only wraps gRPC's dialer) and a real
// TCP control-plane HTTPS listener. Returns deps, the node-plane address, the
// control-plane base URL, an authenticated *http.Client (the founding admin's
// bootstrap credential baked in via relaytest.BearerRoundTripper — usable for
// both MCP and /api/v1 calls), a plain TLS-trusting *http.Client carrying no
// credential (for the auth-negative subtest), and that credential's plaintext
// for the calls that pass it explicitly. Skips the test if RELAY_DAEMON_BIN is
// unset.
func startSurfaceHarness(t *testing.T) (deps *appDeps, nodeAddr, controlBase string, authed, plain *http.Client, credential string) {
	t.Helper()
	if os.Getenv("RELAY_DAEMON_BIN") == "" {
		relaytest.SkipMissingBin(t, "RELAY_DAEMON_BIN not set; skipping real-daemon e2e (run via make test-integration)")
	}

	// baseTestConfig's enrollment limits (IPBurst: 3) suit the 1-2-Enroll
	// tests; this harness enrolls three real daemon subprocesses plus a
	// deliberately-failing fourth attempt, all from the same loopback IP.
	// Generous limits here so that negative assertion sees the real
	// PermissionDenied decision, never a rate-limit false positive from this
	// test's own enrollment volume.
	f := startRelay(t, WithControlPlane(), WithTCPNodePlane(), WithConfig(func(c *Config) {
		c.EnrollIPRate = 100
		c.EnrollIPBurst = 50
		c.EnrollGlobalRate = 1000
		c.EnrollGlobalBurst = 500
	}))

	// Deliberately NOT injecting a test taskSink: newServer itself wires
	// deps.tunnel.sink + deps.dispatch because the control plane is enabled —
	// the same production path mcp_execution_e2e_test.go proves, exercised
	// here through the full v0.0.6 acceptance matrix.
	return f.Deps, f.NodeAddr, f.ControlBase, f.Client(), f.ClientFor(""), f.Credential
}

// launchDaemon starts a real relay-daemon subprocess against nodeAddr,
// enrolling with token, with its own fresh RELAY_STATE_DIR and HOSTNAME (so
// distinct calls model distinct fleet Nodes, never reusing on-disk identity).
// The subprocess is killed and reaped via t.Cleanup.
func launchDaemon(t *testing.T, nodeAddr, caFile, policyPath, token, hostname string) *exec.Cmd {
	t.Helper()
	handle := relaytest.StartDaemon(t, relaytest.DaemonConfig{
		Bin:        os.Getenv("RELAY_DAEMON_BIN"),
		NodeAddr:   nodeAddr,
		CAPath:     caFile,
		Token:      token,
		StateDir:   t.TempDir(),
		PolicyPath: policyPath,
		Hostname:   hostname,
	})
	return handle.Cmd()
}

// waitForConnectedNodes polls deps.dispatch.ConnectedNodes() (the live
// Tunnel registry, dispatch.Router's whole reason for existing per the plan)
// until at least n Nodes are connected, or fails the test at deadline.
// Renamed from the plan's "waitForConnected" to avoid colliding with
// fleet_e2e_test.go's existing helper of that name (same package, same
// integration build; different signature — devharness-socket-driven, not
// deps.dispatch-driven).
func waitForConnectedNodes(t *testing.T, deps *appDeps, n int, deadline time.Duration) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	for {
		connected := deps.dispatch.ConnectedNodes()
		if len(connected) >= n {
			return connected
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timeout: only %d/%d Nodes connected within %s: %v", len(connected), n, deadline, connected)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// pollDescribeReported calls describe_node for nodeID until
// effective_policy.reported==true (the daemon's post-connect PolicySnapshot,
// #151, captured by tunnel.go's snapshotFromProto just after Hello->Ping),
// or fails the test at deadline. A real product bug here (reported never
// becoming true against a real daemon) is a security-relevant finding on the
// Policy-display surface, per this issue's instructions — it must never be
// papered over by loosening this poll into a single non-retried call.
func pollDescribeReported(t *testing.T, session *sdkmcp.ClientSession, nodeID string, deadline time.Duration) mcp.DescribeNodeOutput {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	for {
		res := relaytest.CallTool(t, session, "describe_node", map[string]any{"node_id": nodeID})
		var out mcp.DescribeNodeOutput
		relaytest.DecodeToolJSON(t, res, &out)
		if out.EffectivePolicy.Reported {
			return out
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timeout: describe_node(%s) never reached effective_policy.reported==true within %s", nodeID, deadline)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// dialNodeTCP opens a *grpc.ClientConn against a real TCP node-plane
// address with the given client TLS config (ServerName forced to
// "localhost" to match the server certificate SAN) — the real-TCP twin of
// lifecycle_e2e_test.go's dialTLS, which only dials a bufconn.Listener.
// conn.Close is registered as a t.Cleanup.
func dialNodeTCP(t *testing.T, addr string, tlsCfg *tls.Config) *grpc.ClientConn {
	t.Helper()
	tlsCfg.ServerName = "localhost"
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// nodeIDForLabel finds the single connected Node whose relay: label key
// equals value, failing the test if there is none or more than one — used
// to recover the beta Node's Relay-assigned node_id (needed for the final
// audit_attribution subtest's node revoke) from its relay:node=beta scope
// label, since the Relay never lets a caller choose a Node's own id.
func nodeIDForLabel(t *testing.T, deps *appDeps, key, value string) string {
	t.Helper()
	var found string
	for _, n := range deps.registry.List() {
		if n.RelayLabels[key] != value {
			continue
		}
		if found != "" {
			t.Fatalf("nodeIDForLabel(%s=%s): multiple Nodes match: %s and %s", key, value, found, n.NodeID)
		}
		found = n.NodeID
	}
	if found == "" {
		t.Fatalf("nodeIDForLabel(%s=%s): no Node found", key, value)
	}
	return found
}

// TestSurfaceE2E_v006Acceptance proves the full v0.0.6 milestone acceptance
// matrix end to end, through the public surfaces only, against a shared
// harness + 3 real relay-daemon subprocesses total (2 baseline: relay:
// env=test with relay:node=alpha/beta; 1 fresh, minted mid-test over
// /api/v1). Subtests are ORDERED (t.Run runs them in declaration order) and
// share state (session, connected Node set, the facts_fanout Job id) — see
// each subtest's own comment for why its position in the sequence matters.
func TestSurfaceE2E_v006Acceptance(t *testing.T) {
	deps, nodeAddr, controlBase, authed, plain, credential := startSurfaceHarness(t)
	ctx := context.Background()

	caFile := relaytest.WriteTempFile(t, "ca-bundle-*.pem", string(deps.ca.Bundle()))
	policyPath := relaytest.WriteTempFile(t, "policy-*.toml", relaytest.FixturePolicy)

	_, tokenAlpha, err := deps.tokens.Create(ctx, []string{"relay:env=test", "relay:node=alpha"}, time.Hour)
	if err != nil {
		t.Fatalf("seed alpha Enrollment Token: %v", err)
	}
	_, tokenBeta, err := deps.tokens.Create(ctx, []string{"relay:env=test", "relay:node=beta"}, time.Hour)
	if err != nil {
		t.Fatalf("seed beta Enrollment Token: %v", err)
	}

	launchDaemon(t, nodeAddr, caFile, policyPath, tokenAlpha, "surface-e2e-alpha")
	launchDaemon(t, nodeAddr, caFile, policyPath, tokenBeta, "surface-e2e-beta")

	connected := waitForConnectedNodes(t, deps, 2, 45*time.Second)
	if len(connected) != 2 {
		t.Fatalf("waitForConnectedNodes: got %d Nodes, want exactly 2 (bounded baseline fleet): %v", len(connected), connected)
	}
	connectedSet := map[string]bool{connected[0]: true, connected[1]: true}

	// Recovered up front (before any revoke) so audit_attribution (LAST) can
	// use it without re-scanning the registry after beta's own revoke.
	nodeBetaID := nodeIDForLabel(t, deps, "node", "beta")

	session := relaytest.Connect(t, controlBase, authed)

	var factsJobID string

	// (1) facts_fanout: run_operation(system.facts, relay:env=test) fans out
	// to both baseline Nodes; per-Node success plus a real hostname fact.
	t.Run("facts_fanout", func(t *testing.T) {
		res := relaytest.CallTool(t, session, "run_operation", map[string]any{
			"operation":    "system.facts",
			"selector":     "relay:env=test",
			"wait_seconds": 300,
		})
		if res.IsError {
			t.Fatalf("run_operation(system.facts): IsError=true; content = %+v", res.Content)
		}
		var out mcp.ExecutionOutput
		relaytest.DecodeToolJSON(t, res, &out)

		if len(out.Results) != 2 {
			t.Fatalf("facts_fanout: got %d results, want 2: %+v", len(out.Results), out.Results)
		}
		byNode := map[string]mcp.PerNodeResult{}
		for _, r := range out.Results {
			byNode[r.NodeID] = r
		}
		for nodeID := range connectedSet {
			r, ok := byNode[nodeID]
			if !ok {
				t.Errorf("facts_fanout: no result for connected Node %s: %+v", nodeID, out.Results)
				continue
			}
			if r.Outcome != "success" {
				t.Errorf("facts_fanout: node %s outcome = %q, want success; stderr=%q", nodeID, r.Outcome, r.Stderr)
			}
			if relaytest.FactHostname(r.Stdout) == "" {
				t.Errorf("facts_fanout: node %s stdout carries no non-empty hostname= fact: %q", nodeID, r.Stdout)
			}
		}
		if out.JobID == "" {
			t.Fatal("facts_fanout: JobID is empty")
		}
		factsJobID = out.JobID
	})

	// (2) describe_node_policy (#151-unblocked): per connected Node, poll
	// describe_node until the daemon's post-connect PolicySnapshot has
	// arrived, then assert the EXACT relaytest.FixturePolicy shape (C1/C2: set
	// equality on AllowedOperations — NOT opvocab's full vocabulary — and
	// the exact raw_exec allow/deny patterns, in relaytest.FixturePolicy's own order).
	t.Run("describe_node_policy", func(t *testing.T) {
		wantAllowed := map[string]bool{"file.read": true, "system.facts": true, "service.restart": true}
		wantRawAllow := []string{
			`^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$`,
			`^/bin/sleep [0-9]+$`,
		}
		wantRawDeny := []string{"--force", `\brm\b`}

		for nodeID := range connectedSet {
			t.Run(nodeID, func(t *testing.T) {
				out := pollDescribeReported(t, session, nodeID, 30*time.Second)
				ep := out.EffectivePolicy

				if !ep.RawExecEnabled {
					t.Error("RawExecEnabled = false, want true")
				}

				gotAllowed := map[string]bool{}
				for _, op := range ep.AllowedOperations {
					gotAllowed[op] = true
				}
				if len(gotAllowed) != len(wantAllowed) {
					t.Errorf("AllowedOperations = %v, want EXACTLY %v (C1: the loaded policy TOML has three [[operation]] entries, not opvocab's full vocabulary)", ep.AllowedOperations, wantAllowed)
				}
				for op := range wantAllowed {
					if !gotAllowed[op] {
						t.Errorf("AllowedOperations missing %q: got %v", op, ep.AllowedOperations)
					}
				}
				if gotAllowed["pkg.install"] {
					t.Error("AllowedOperations contains pkg.install, want it absent — relaytest.FixturePolicy declares no such [[operation]] (C1)")
				}

				if !stringSlicesEqual(ep.RawAllowPatterns, wantRawAllow) {
					t.Errorf("RawAllowPatterns = %v, want %v", ep.RawAllowPatterns, wantRawAllow)
				}
				if !stringSlicesEqual(ep.RawDenyPatterns, wantRawDeny) {
					t.Errorf("RawDenyPatterns = %v, want %v", ep.RawDenyPatterns, wantRawDeny)
				}

				if ep.PolicyFingerprint == "" {
					t.Error("EffectivePolicy.PolicyFingerprint is empty, want set")
				}
				if ep.PolicyFingerprint != out.PolicyFingerprint {
					t.Errorf("EffectivePolicy.PolicyFingerprint (%q) != top-level PolicyFingerprint (%q)", ep.PolicyFingerprint, out.PolicyFingerprint)
				}
			})
		}
	})

	// (3) raw_exec_allowed_denied_and_typed: /bin/sleep 1 matches the
	// raw_exec allow pattern (success); /bin/echo hello matches NO allow
	// pattern, so it is refused by ADR-0002's DEFAULT-DENY, not by a
	// [[deny]] rule (C2) — denied_by_policy either way on the wire. A
	// structured Operation (system.facts) still succeeds afterward.
	t.Run("raw_exec_allowed_denied_and_typed", func(t *testing.T) {
		sleepRes := relaytest.CallTool(t, session, "raw_exec", map[string]any{
			"argv": []string{"/bin/sleep", "1"}, "selector": "relay:env=test", "wait_seconds": 300,
		})
		if sleepRes.IsError {
			t.Fatalf("raw_exec(/bin/sleep 1): IsError=true; content = %+v", sleepRes.Content)
		}
		var sleepOut mcp.RunOrPlanOutput
		relaytest.DecodeToolJSON(t, sleepRes, &sleepOut)
		sleepByNode := resultsByNode(sleepOut.Results)
		for nodeID := range connectedSet {
			if r, ok := sleepByNode[nodeID]; !ok || r.Outcome != "success" {
				t.Errorf("raw_exec(/bin/sleep 1) on %s: result = %+v (present=%v), want success", nodeID, r, ok)
			}
		}

		echoRes := relaytest.CallTool(t, session, "raw_exec", map[string]any{
			"argv": []string{"/bin/echo", "hello"}, "selector": "relay:env=test", "wait_seconds": 300,
		})
		if echoRes.IsError {
			t.Fatalf("raw_exec(/bin/echo hello): IsError=true; content = %+v", echoRes.Content)
		}
		var echoOut mcp.RunOrPlanOutput
		relaytest.DecodeToolJSON(t, echoRes, &echoOut)
		echoByNode := resultsByNode(echoOut.Results)
		for nodeID := range connectedSet {
			if r, ok := echoByNode[nodeID]; !ok || r.Outcome != "denied_by_policy" {
				t.Errorf("raw_exec(/bin/echo hello) on %s: result = %+v (present=%v), want denied_by_policy", nodeID, r, ok)
			}
		}

		factsRes := relaytest.CallTool(t, session, "run_operation", map[string]any{
			"operation": "system.facts", "selector": "relay:env=test", "wait_seconds": 300,
		})
		if factsRes.IsError {
			t.Fatalf("run_operation(system.facts): IsError=true; content = %+v", factsRes.Content)
		}
		var factsOut mcp.ExecutionOutput
		relaytest.DecodeToolJSON(t, factsRes, &factsOut)
		for _, r := range factsOut.Results {
			if r.Outcome != "success" {
				t.Errorf("run_operation(system.facts) on %s: outcome = %q, want success", r.NodeID, r.Outcome)
			}
		}
	})

	// (4) plan_vs_apply (acceptance criterion): on the unchanged fleet, a
	// plan=true verdict must match a subsequent real run's outcome, per
	// NodeID, for both an allowed action (system.facts) and a denied one
	// (raw_exec /bin/echo — DEFAULT-DENY, per (3) above).
	t.Run("plan_vs_apply", func(t *testing.T) {
		t.Run("allow", func(t *testing.T) {
			planRes := relaytest.CallTool(t, session, "run_operation", map[string]any{
				"operation": "system.facts", "selector": "relay:env=test", "plan": true,
			})
			if planRes.IsError {
				t.Fatalf("run_operation(plan=true): IsError=true; content = %+v", planRes.Content)
			}
			var planOut mcp.RunOrPlanOutput
			relaytest.DecodeToolJSON(t, planRes, &planOut)
			if planOut.JobID != "" || len(planOut.Results) != 0 {
				t.Errorf("run_operation(plan=true) left job_id/results non-empty: %+v", planOut)
			}
			if planOut.Plan == nil {
				t.Fatal("run_operation(plan=true): plan field is nil")
			}

			applyRes := relaytest.CallTool(t, session, "run_operation", map[string]any{
				"operation": "system.facts", "selector": "relay:env=test", "wait_seconds": 300,
			})
			if applyRes.IsError {
				t.Fatalf("run_operation(plan=false): IsError=true; content = %+v", applyRes.Content)
			}
			var applyOut mcp.RunOrPlanOutput
			relaytest.DecodeToolJSON(t, applyRes, &applyOut)

			verdicts := verdictsByNode(*planOut.Plan)
			outcomes := resultsByNode(applyOut.Results)
			for nodeID := range connectedSet {
				if v := verdicts[nodeID]; v.Verdict != "allow" {
					t.Errorf("node %s: plan verdict = %+v, want allow", nodeID, v)
				}
				if o := outcomes[nodeID]; o.Outcome != "success" {
					t.Errorf("node %s: real outcome = %+v, want success", nodeID, o)
				}
			}
		})

		t.Run("deny", func(t *testing.T) {
			planRes := relaytest.CallTool(t, session, "raw_exec", map[string]any{
				"argv": []string{"/bin/echo", "x"}, "selector": "relay:env=test", "plan": true,
			})
			if planRes.IsError {
				t.Fatalf("raw_exec(plan=true): IsError=true; content = %+v", planRes.Content)
			}
			var planOut mcp.RunOrPlanOutput
			relaytest.DecodeToolJSON(t, planRes, &planOut)
			if planOut.JobID != "" || len(planOut.Results) != 0 {
				t.Errorf("raw_exec(plan=true) left job_id/results non-empty: %+v", planOut)
			}
			if planOut.Plan == nil {
				t.Fatal("raw_exec(plan=true): plan field is nil")
			}

			applyRes := relaytest.CallTool(t, session, "raw_exec", map[string]any{
				"argv": []string{"/bin/echo", "x"}, "selector": "relay:env=test", "wait_seconds": 300,
			})
			if applyRes.IsError {
				t.Fatalf("raw_exec(plan=false): IsError=true; content = %+v", applyRes.Content)
			}
			var applyOut mcp.RunOrPlanOutput
			relaytest.DecodeToolJSON(t, applyRes, &applyOut)

			verdicts := verdictsByNode(*planOut.Plan)
			outcomes := resultsByNode(applyOut.Results)
			for nodeID := range connectedSet {
				if v := verdicts[nodeID]; v.Verdict != "deny" {
					t.Errorf("node %s: plan verdict = %+v, want deny", nodeID, v)
				}
				if o := outcomes[nodeID]; o.Outcome != "denied_by_policy" {
					t.Errorf("node %s: real outcome = %+v, want denied_by_policy", nodeID, o)
				}
			}
		})
	})

	// (5) freeze_over_api (acceptance criterion): engage over the API stops a
	// real MCP dispatch (the distinct "frozen" tool error) while plan=true
	// keeps working (advisory, per ADR-0013); release with a reason restores
	// dispatch. Must run before api_token_lifecycle so a later dispatch on
	// the fresh Node is never mistaken for a residual freeze effect.
	t.Run("freeze_over_api", func(t *testing.T) {
		engageResp := controlAPIRequest(t, authed, http.MethodPost, controlBase+"/api/v1/freeze/engage", credential, nil)
		defer engageResp.Body.Close() //nolint:errcheck
		if engageResp.StatusCode != http.StatusOK {
			t.Fatalf("freeze engage status = %d, want %d", engageResp.StatusCode, http.StatusOK)
		}

		frozenRes := relaytest.CallTool(t, session, "run_operation", map[string]any{
			"operation": "system.facts", "selector": "relay:env=test",
		})
		if !frozenRes.IsError {
			t.Fatal("run_operation while frozen: IsError = false, want true")
		}
		if text := relaytest.ToolErrorText(t, frozenRes); !strings.Contains(text, "the Relay is frozen") {
			t.Errorf("run_operation while frozen error = %q, want it to contain %q", text, "the Relay is frozen")
		}

		planRes := relaytest.CallTool(t, session, "run_operation", map[string]any{
			"operation": "system.facts", "selector": "relay:env=test", "plan": true,
		})
		if planRes.IsError {
			t.Fatalf("run_operation(plan=true) while frozen: IsError=true, want false (advisory); content = %+v", planRes.Content)
		}
		var planOut mcp.RunOrPlanOutput
		relaytest.DecodeToolJSON(t, planRes, &planOut)
		if planOut.Plan == nil || planOut.Plan.WouldBeRejected == nil || planOut.Plan.WouldBeRejected.Reason != "frozen" {
			t.Fatalf("run_operation(plan=true) while frozen: plan = %+v, want would_be_rejected.reason=frozen", planOut.Plan)
		}
		if len(planOut.Plan.Verdicts) == 0 {
			t.Error("run_operation(plan=true) while frozen: verdicts is empty, want non-empty (Plan still queries while frozen)")
		}

		noReasonResp := controlAPIRequest(t, authed, http.MethodPost, controlBase+"/api/v1/freeze/release",
			credential, map[string]string{"reason": ""})
		defer noReasonResp.Body.Close() //nolint:errcheck
		if noReasonResp.StatusCode != http.StatusBadRequest {
			t.Fatalf("freeze release without reason status = %d, want %d", noReasonResp.StatusCode, http.StatusBadRequest)
		}

		releaseResp := controlAPIRequest(t, authed, http.MethodPost, controlBase+"/api/v1/freeze/release",
			credential, map[string]string{"reason": "e2e resolved"})
		defer releaseResp.Body.Close() //nolint:errcheck
		if releaseResp.StatusCode != http.StatusOK {
			t.Fatalf("freeze release status = %d, want %d", releaseResp.StatusCode, http.StatusOK)
		}

		restoredRes := relaytest.CallTool(t, session, "run_operation", map[string]any{
			"operation": "system.facts", "selector": "relay:env=test", "wait_seconds": 300,
		})
		if restoredRes.IsError {
			t.Fatalf("run_operation after release: IsError=true; content = %+v", restoredRes.Content)
		}
		var restoredOut mcp.ExecutionOutput
		relaytest.DecodeToolJSON(t, restoredRes, &restoredOut)
		if len(restoredOut.Results) != 2 {
			t.Fatalf("run_operation after release: got %d results, want 2: %+v", len(restoredOut.Results), restoredOut.Results)
		}
		for _, r := range restoredOut.Results {
			if r.Outcome != "success" {
				t.Errorf("run_operation after release: node %s outcome = %q, want success", r.NodeID, r.Outcome)
			}
		}
	})

	// (6) api_token_lifecycle (3rd/fresh daemon): mint a scoped Enrollment
	// Token over /api/v1, enroll a fresh daemon with it, see it appear with
	// the token's own relay: labels, revoke the token, then prove the
	// revoked plaintext can no longer enroll (direct node-plane Enroll RPC —
	// the one deterministic negative that needs a real gRPC status code, not
	// an MCP/HTTP surface).
	t.Run("api_token_lifecycle", func(t *testing.T) {
		mintResp := controlAPIRequest(t, authed, http.MethodPost, controlBase+"/api/v1/enrollment-tokens",
			credential, map[string]any{
				"scope":       []string{"relay:env=test", "relay:node=fresh"},
				"ttl_seconds": 3600,
			})
		defer mintResp.Body.Close() //nolint:errcheck
		if mintResp.StatusCode != http.StatusCreated {
			t.Fatalf("mint status = %d, want %d", mintResp.StatusCode, http.StatusCreated)
		}
		var minted mintTokenAPIResponse
		if err := json.NewDecoder(mintResp.Body).Decode(&minted); err != nil {
			t.Fatalf("decode mint response: %v", err)
		}
		if minted.ID == "" || minted.Token == "" {
			t.Fatalf("mint response missing id/token: %+v", minted)
		}

		launchDaemon(t, nodeAddr, caFile, policyPath, minted.Token, "surface-e2e-fresh")
		freshConnected := waitForConnectedNodes(t, deps, 3, 45*time.Second)
		if len(freshConnected) != 3 {
			t.Fatalf("waitForConnectedNodes: got %d Nodes, want exactly 3 (bounded fleet): %v", len(freshConnected), freshConnected)
		}

		listRes := relaytest.CallTool(t, session, "list_nodes", map[string]any{"selector": "relay:node=fresh"})
		if listRes.IsError {
			t.Fatalf("list_nodes(relay:node=fresh): IsError=true; content = %+v", listRes.Content)
		}
		var listOut mcp.ListNodesOutput
		relaytest.DecodeToolJSON(t, listRes, &listOut)
		if len(listOut.Nodes) != 1 {
			t.Fatalf("list_nodes(relay:node=fresh): got %d Nodes, want exactly 1: %+v", len(listOut.Nodes), listOut.Nodes)
		}
		fresh := listOut.Nodes[0]
		if fresh.RelayLabels["env"] != "test" || fresh.RelayLabels["node"] != "fresh" {
			t.Errorf("fresh Node RelayLabels = %v, want env=test node=fresh", fresh.RelayLabels)
		}

		revokeResp := controlAPIRequest(t, authed, http.MethodDelete,
			controlBase+"/api/v1/enrollment-tokens/"+minted.ID, credential, nil)
		defer revokeResp.Body.Close() //nolint:errcheck
		if revokeResp.StatusCode != http.StatusNoContent {
			t.Fatalf("revoke status = %d, want %d", revokeResp.StatusCode, http.StatusNoContent)
		}

		conn := dialNodeTCP(t, nodeAddr, &tls.Config{RootCAs: relaytest.CertPool(t, deps.ca.Bundle())})
		csrPEM, _ := relaytest.NewCSR(t, "ignored-cn-revoked-token")
		enrollCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := relayv1.NewEnrollmentClient(conn).Enroll(enrollCtx, &relayv1.EnrollRequest{
			EnrollmentToken: minted.Token,
			Csr:             csrPEM,
			Facts:           &relayv1.Facts{Hostname: "surface-e2e-revoked-attempt", Os: "linux"},
		})
		if err == nil {
			t.Fatal("expected Enroll with a revoked token to fail, got nil error")
		}
		if code := status.Code(err); code != codes.PermissionDenied {
			t.Errorf("Enroll with revoked token: code = %v, want %v", code, codes.PermissionDenied)
		}
	})

	// (7) auth_negative (acceptance criterion): every MCP call and every
	// /api/v1 route this issue exercises is refused without the credential.
	t.Run("auth_negative", func(t *testing.T) {
		t.Run("mcp", func(t *testing.T) {
			const initializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
			post := func(token string) *http.Response {
				t.Helper()
				req, err := http.NewRequest(http.MethodPost, controlBase+"/mcp", strings.NewReader(initializeBody))
				if err != nil {
					t.Fatalf("NewRequest: %v", err)
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Accept", "application/json, text/event-stream")
				if token != "" {
					req.Header.Set("Authorization", "Bearer "+token)
				}
				resp, err := plain.Do(req)
				if err != nil {
					t.Fatalf("Do: %v", err)
				}
				return resp
			}

			noCredResp := post("")
			defer noCredResp.Body.Close() //nolint:errcheck
			if noCredResp.StatusCode != http.StatusUnauthorized {
				t.Errorf("no credential: status = %d, want %d", noCredResp.StatusCode, http.StatusUnauthorized)
			}

			wrongCredResp := post("wrong-" + credential)
			defer wrongCredResp.Body.Close() //nolint:errcheck
			if wrongCredResp.StatusCode != http.StatusUnauthorized {
				t.Errorf("wrong credential: status = %d, want %d", wrongCredResp.StatusCode, http.StatusUnauthorized)
			}
		})

		t.Run("api", func(t *testing.T) {
			cases := []struct {
				method string
				path   string
				body   any
			}{
				{http.MethodPost, "/api/v1/enrollment-tokens", map[string]any{"scope": []string{"relay:env=test"}, "ttl_seconds": 3600}},
				{http.MethodDelete, "/api/v1/enrollment-tokens/does-not-matter", nil},
				{http.MethodPost, "/api/v1/nodes/does-not-matter/revoke", nil},
				{http.MethodPost, "/api/v1/freeze/engage", nil},
				{http.MethodPost, "/api/v1/freeze/release", map[string]string{"reason": "x"}},
			}
			for _, tc := range cases {
				t.Run(tc.method+" "+tc.path, func(t *testing.T) {
					resp := controlAPIRequest(t, plain, tc.method, controlBase+tc.path, "", tc.body)
					defer resp.Body.Close() //nolint:errcheck
					if resp.StatusCode != http.StatusUnauthorized {
						t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
					}
				})
			}
		})
	})

	// (8) audit_attribution (LAST — tears down beta's Tunnel, so it must not
	// disrupt any earlier subtest): revoke beta, the one lifecycle action not
	// yet exercised, then assert every Kind this run produced is present at
	// least once, attributed to the single seeded principal
	// ("founding-admin:admin" — the MCP Authenticator.Middleware and the API
	// principal() helper inject the same FoundingAdmin, ADR-0009 invariant
	// 10: one capability layer, one Principal source), and that the
	// successful freeze_release carries the reason this run supplied.
	t.Run("audit_attribution", func(t *testing.T) {
		const revokeReason = "e2e: node beta retired"
		revokeResp := controlAPIRequest(t, authed, http.MethodPost,
			controlBase+"/api/v1/nodes/"+nodeBetaID+"/revoke", credential,
			map[string]string{"reason": revokeReason})
		defer revokeResp.Body.Close() //nolint:errcheck
		if revokeResp.StatusCode != http.StatusNoContent {
			t.Fatalf("node revoke status = %d, want %d", revokeResp.StatusCode, http.StatusNoContent)
		}

		records, err := deps.audit.List(ctx)
		if err != nil {
			t.Fatalf("deps.audit.List: %v", err)
		}
		if len(records) == 0 {
			t.Fatal("deps.audit.List: got 0 records")
		}

		const wantPrincipal = "founding-admin:admin"
		wantKinds := []string{
			audit.KindDispatch, audit.KindPlan, audit.KindTokenMint, audit.KindTokenRevoke,
			audit.KindNodeRevoke, audit.KindFreezeEngage, audit.KindFreezeRelease,
		}
		seenKind := make(map[string]bool, len(wantKinds))
		var sawFreezeRelease, sawNodeRevoke bool
		for _, r := range records {
			seenKind[r.Kind] = true
			if r.Principal != wantPrincipal {
				t.Errorf("record kind=%s id=%s has Principal=%q, want %q", r.Kind, r.ID, r.Principal, wantPrincipal)
			}
			if r.Kind == audit.KindFreezeRelease {
				sawFreezeRelease = true
				if r.Reason != "e2e resolved" {
					t.Errorf("freeze_release Reason = %q, want %q", r.Reason, "e2e resolved")
				}
			}
			// #487: the irreversible rung says WHY, end to end and through the
			// real store — not just in the handler's unit test.
			//
			// SCOPED TO THE NODE (#557). node_revoke is no longer one record per
			// run: revoking an Enrollment Token now cascades a record per Node it
			// enrolled, each carrying a DERIVED reason naming the token rather
			// than this operator's sentence. An unscoped loop matches whichever
			// of those came last and compares the wrong record — which is exactly
			// how this assertion failed when the cascade landed.
			if r.Kind == audit.KindNodeRevoke && r.NodeID == nodeBetaID {
				sawNodeRevoke = true
				if r.Reason != revokeReason {
					t.Errorf("node_revoke Reason for the directly-revoked Node = %q, want %q",
						r.Reason, revokeReason)
				}
			}
		}
		for _, k := range wantKinds {
			if !seenKind[k] {
				t.Errorf("no audit record of Kind=%q found among %d records", k, len(records))
			}
		}
		if !sawFreezeRelease {
			t.Error("no KindFreezeRelease record found to check Reason on")
		}
		if !sawNodeRevoke {
			t.Error("no KindNodeRevoke record found to check Reason on")
		}

		if factsJobID == "" {
			t.Fatal("factsJobID is empty (facts_fanout subtest did not run or record it)")
		}
		jobRecords, err := deps.audit.ByJob(ctx, factsJobID)
		if err != nil {
			t.Fatalf("deps.audit.ByJob(%q): %v", factsJobID, err)
		}
		if len(jobRecords) == 0 {
			t.Errorf("deps.audit.ByJob(%q): got 0 records, want at least 1 (every dispatch is audited, #102)", factsJobID)
		}
		dispatches, intents := 0, 0
		for _, r := range jobRecords {
			// One dispatch_intent per Job (#887) plus the per-Node outcome rows.
			if r.Kind != audit.KindDispatch && r.Kind != audit.KindDispatchIntent {
				t.Errorf("audit record for JobID=%q has Kind=%q, want %q or %q", factsJobID, r.Kind, audit.KindDispatch, audit.KindDispatchIntent)
			}
			if r.Kind == audit.KindDispatch {
				dispatches++
			}
			if r.Kind == audit.KindDispatchIntent {
				intents++
			}
			if r.Principal != wantPrincipal {
				t.Errorf("audit record for JobID=%q has Principal=%q, want %q", factsJobID, r.Principal, wantPrincipal)
			}
		}
		if dispatches == 0 {
			t.Errorf("deps.audit.ByJob(%q): no %q outcome record among %d record(s)", factsJobID, audit.KindDispatch, len(jobRecords))
		}
		if intents != 1 {
			t.Errorf("deps.audit.ByJob(%q): %d %q records, want exactly 1", factsJobID, intents, audit.KindDispatchIntent)
		}
	})
}
