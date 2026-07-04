//go:build integration

// Package main: tunnel_dispatch_e2e_test.go exercises the end-to-end Task
// dispatch path using a real relay-daemon subprocess.
//
// Acceptance criteria (v0.0.3):
//
//	(a) file.read of a temp file → SUCCESS + stdout == file contents.
//	(b) service.restart sshd → DENIED_BY_POLICY (fixture policy only allows nginx).
//
// The test stands up a real TCP listener (not bufconn) so the daemon subprocess
// can dial it. It uses the live enrollment flow: the daemon self-enrolls on first
// connect using RELAY_ENROLLMENT_TOKEN + RELAY_CA_BUNDLE_PATH.
//
// Skip condition: RELAY_DAEMON_BIN env var not set.
// This test is behind //go:build integration so `make test` (hermetic) stays green.
// Run via: make test-integration (or manually: cd relay && RELAY_DAEMON_BIN=...
// go test -tags integration ./cmd/relay/...)
package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
)

// fixturePolicy is the TOML policy the daemon subprocess will load.
// It allows file.read (wildcard, except /etc/shadow), service.restart for
// nginx only (sshd denied by default), and raw_exec for systemctl status/restart.
const fixturePolicy = `
[[operation]]
name = "file.read"
allowed_args = [["*"]]

[[deny]]
name = "file.read"
args = [["/etc/shadow"]]

[[operation]]
name = "system.facts"
allowed_args = []

[[operation]]
name = "service.restart"
allowed_args = [["nginx"]]

[raw_exec]
allow = ["^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$"]
deny  = ["--force", "\\brm\\b"]
`

// startTCPServer starts a real TCP listener on 127.0.0.1:0, runs the Relay
// gRPC server on it, and returns the listener address plus appDeps.
// srv.GracefulStop is registered as t.Cleanup.
func startTCPServer(t *testing.T) (string, *appDeps) {
	t.Helper()
	cfg := Config{
		Addr:                "127.0.0.1:0",
		CADir:               t.TempDir(),
		Hostname:            "localhost",
		EnrollIPRate:        100,
		EnrollIPBurst:       50,
		EnrollGlobalRate:    1000,
		EnrollGlobalBurst:   500,
		EnrollMaxTrackedIPs: 100000,
		MaxNodes:            110000,
	}
	srv, deps, err := newServer(cfg)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := lis.Addr().String()
	go srv.Serve(lis) //nolint:errcheck
	t.Cleanup(srv.GracefulStop)
	return addr, deps
}

func TestTunnelDispatch_E2E(t *testing.T) {
	daemonBin := os.Getenv("RELAY_DAEMON_BIN")
	if daemonBin == "" {
		t.Skip("RELAY_DAEMON_BIN not set; skipping real-daemon e2e (run via make test-integration)")
	}

	// -----------------------------------------------------------------------
	// Infrastructure: start the Relay on a real TCP listener.
	// -----------------------------------------------------------------------
	ctx := context.Background()
	addr, deps := startTCPServer(t)

	// -----------------------------------------------------------------------
	// Attach dispatcher (test-only sink) before the daemon connects.
	// -----------------------------------------------------------------------
	disp := newDispatcher()
	deps.tunnel.sink = disp

	// -----------------------------------------------------------------------
	// Seed Enrollment Token.
	// -----------------------------------------------------------------------
	_, plaintext, err := deps.tokens.Create(ctx, []string{"relay:env=test"}, time.Hour)
	if err != nil {
		t.Fatalf("seed Enrollment Token: %v", err)
	}

	// -----------------------------------------------------------------------
	// Write policy file (mode 0600, set_permissions-style via os.Chmod).
	// -----------------------------------------------------------------------
	caBundle := deps.ca.Bundle()
	caFile, err := os.CreateTemp(t.TempDir(), "ca-bundle-*.pem")
	if err != nil {
		t.Fatalf("create CA bundle temp file: %v", err)
	}
	if _, err := caFile.Write(caBundle); err != nil {
		t.Fatalf("write CA bundle: %v", err)
	}
	caFile.Close()
	if err := os.Chmod(caFile.Name(), 0600); err != nil {
		t.Fatalf("chmod CA bundle: %v", err)
	}

	policyFile, err := os.CreateTemp(t.TempDir(), "policy-*.toml")
	if err != nil {
		t.Fatalf("create policy temp file: %v", err)
	}
	if _, err := policyFile.WriteString(fixturePolicy); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	policyFile.Close()
	if err := os.Chmod(policyFile.Name(), 0600); err != nil {
		t.Fatalf("chmod policy: %v", err)
	}

	// -----------------------------------------------------------------------
	// Write a temp content file for the file.read test.
	// -----------------------------------------------------------------------
	contentFile, err := os.CreateTemp(t.TempDir(), "content-*.txt")
	if err != nil {
		t.Fatalf("create content file: %v", err)
	}
	wantContent := []byte("hello from e2e dispatch test\n")
	if _, err := contentFile.Write(wantContent); err != nil {
		t.Fatalf("write content: %v", err)
	}
	contentFile.Close()
	if err := os.Chmod(contentFile.Name(), 0600); err != nil {
		t.Fatalf("chmod content file: %v", err)
	}

	// -----------------------------------------------------------------------
	// Launch the daemon subprocess with enrollment env vars.
	// -----------------------------------------------------------------------
	stateDir := t.TempDir()
	daemonCmd := exec.Command(daemonBin, "--relay", "https://"+addr)
	daemonCmd.Env = append(os.Environ(),
		"RELAY_ADDR=https://"+addr,
		"RELAY_ENROLLMENT_TOKEN="+plaintext,
		"RELAY_CA_BUNDLE_PATH="+caFile.Name(),
		"RELAY_ENROLL_ENDPOINT=https://"+addr,
		"RELAY_STATE_DIR="+stateDir,
		"RELAY_POLICY_PATH="+policyFile.Name(),
		"RELAY_DOMAIN=localhost",
		"HOSTNAME=e2e-test-node",
		// Disable rustls provider conflict on some environments.
		"RUST_LOG=warn",
	)
	if err := daemonCmd.Start(); err != nil {
		t.Fatalf("start daemon: %v", err)
	}
	t.Cleanup(func() {
		daemonCmd.Process.Kill() //nolint:errcheck
		daemonCmd.Wait()         //nolint:errcheck
	})

	// -----------------------------------------------------------------------
	// Wait for the daemon to complete Hello→Ping handshake (registry sync).
	// Poll deps.registry.Get until the node appears, with a 30 s deadline.
	// The dispatcher.waitForNode sync is secondary; registry is authoritative.
	// -----------------------------------------------------------------------
	var nodeID string
	regCtx, regCancel := context.WithTimeout(ctx, 30*time.Second)
	defer regCancel()
	for {
		select {
		case <-regCtx.Done():
			t.Fatalf("timeout: daemon did not complete Hello→Ping handshake within 30 s")
		case <-time.After(100 * time.Millisecond):
			// Search registry for the first node with hostname "e2e-test-node".
			// We don't know the Relay-assigned node_id yet.
		}
		// Walk registered nodes: the registry doesn't expose a list-by-hostname
		// API, so we use the dispatcher as the sync point instead.
		d := disp
		d.mu.Lock()
		for id := range d.senders {
			nodeID = id
		}
		d.mu.Unlock()
		if nodeID != "" {
			break
		}
	}

	// Confirm the dispatcher also has the node.
	if err := disp.waitForNode(nodeID, 5*time.Second); err != nil {
		t.Fatalf("waitForNode: %v", err)
	}

	disp.mu.Lock()
	resultCh := disp.results[nodeID]
	disp.mu.Unlock()
	if resultCh == nil {
		t.Fatal("no result channel for node")
	}

	// -----------------------------------------------------------------------
	// (a) file.read of a temp file → SUCCESS + stdout == file contents.
	// -----------------------------------------------------------------------
	fileReadTask := &gleipnirv1.RelayMessage{
		Body: &gleipnirv1.RelayMessage_Task{
			Task: &gleipnirv1.TaskRequest{
				TaskId:         "e2e-file-read-1",
				TimeoutSeconds: 10,
				Action: &gleipnirv1.TaskRequest_Operation{
					Operation: &gleipnirv1.Operation{
						Name: "file.read",
						Args: map[string]string{"path": contentFile.Name()},
					},
				},
			},
		},
	}
	if err := disp.Dispatch(nodeID, fileReadTask); err != nil {
		t.Fatalf("Dispatch file.read: %v", err)
	}
	select {
	case result := <-resultCh:
		if result.TaskId != "e2e-file-read-1" {
			t.Errorf("TaskId: got %q, want %q", result.TaskId, "e2e-file-read-1")
		}
		if result.Outcome != gleipnirv1.Outcome_OUTCOME_SUCCESS {
			t.Errorf("file.read outcome: got %v, want SUCCESS; stderr=%q",
				result.Outcome, result.Stderr)
		}
		if string(result.Stdout) != string(wantContent) {
			t.Errorf("file.read stdout: got %q, want %q", result.Stdout, wantContent)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout: no result for file.read task")
	}

	// -----------------------------------------------------------------------
	// (b) service.restart sshd → DENIED_BY_POLICY (not in allowed_args).
	// -----------------------------------------------------------------------
	sshdTask := &gleipnirv1.RelayMessage{
		Body: &gleipnirv1.RelayMessage_Task{
			Task: &gleipnirv1.TaskRequest{
				TaskId:         "e2e-sshd-deny-1",
				TimeoutSeconds: 10,
				Action: &gleipnirv1.TaskRequest_Operation{
					Operation: &gleipnirv1.Operation{
						Name: "service.restart",
						Args: map[string]string{"unit": "sshd"},
					},
				},
			},
		},
	}
	if err := disp.Dispatch(nodeID, sshdTask); err != nil {
		t.Fatalf("Dispatch service.restart sshd: %v", err)
	}
	select {
	case result := <-resultCh:
		if result.TaskId != "e2e-sshd-deny-1" {
			t.Errorf("TaskId: got %q, want %q", result.TaskId, "e2e-sshd-deny-1")
		}
		if result.Outcome != gleipnirv1.Outcome_OUTCOME_DENIED_BY_POLICY {
			t.Errorf("service.restart sshd outcome: got %v, want DENIED_BY_POLICY; stderr=%q",
				result.Outcome, result.Stderr)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout: no result for service.restart sshd task")
	}
}
