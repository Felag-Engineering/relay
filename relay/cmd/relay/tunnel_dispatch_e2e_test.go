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
// startDaemonNode below is the shared harness for this file and
// tunnel_control_e2e_test.go's v0.0.4 acceptance tests: it boots the Relay,
// attaches the dispatcher sink, seeds an Enrollment Token, writes the CA
// bundle + policy files, launches the daemon subprocess, and waits for the
// Hello→Ping registration sync point.
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
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

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

// e2eNode is the handle returned by startDaemonNode: everything a v0.0.4
// acceptance test needs to dispatch Tasks/TaskCancel/PolicyQuery over the real
// mTLS Tunnel and read back TaskResult/PolicyVerdict, plus the on-disk state
// needed to assert on the registry and to restart the daemon in place.
type e2eNode struct {
	disp       *dispatcher
	nodeID     string
	deps       *appDeps
	stateDir   string
	policyPath string
	caPath     string
	addr       string

	daemonBin string
	env       []string
	cmd       *exec.Cmd

	// restart kills the current daemon subprocess and relaunches it against
	// the SAME stateDir/policyPath/addr, so it reconnects as the same Node
	// (its identity is persisted under stateDir). Blocks until the dispatcher
	// observes re-registration or fails the test on timeout.
	restart func()
}

// resultCh returns the node's TaskResult channel (created at registration).
func (n *e2eNode) resultCh() chan *gleipnirv1.TaskResult {
	n.disp.mu.Lock()
	defer n.disp.mu.Unlock()
	return n.disp.results[n.nodeID]
}

// verdictCh returns the node's PolicyVerdict channel (created at registration).
func (n *e2eNode) verdictCh() chan *gleipnirv1.PolicyVerdict {
	n.disp.mu.Lock()
	defer n.disp.mu.Unlock()
	return n.disp.verdicts[n.nodeID]
}

// startDaemonNode boots the Relay on a real TCP listener, attaches the
// dispatcher sink, seeds an Enrollment Token, writes the CA bundle and the
// given Policy TOML to disk, launches a real relay-daemon subprocess against
// them, and blocks until the Hello→Ping handshake completes (the dispatcher
// registration is the sync point). Skips the test if RELAY_DAEMON_BIN is unset.
func startDaemonNode(t *testing.T, policyTOML string) *e2eNode {
	t.Helper()
	daemonBin := os.Getenv("RELAY_DAEMON_BIN")
	if daemonBin == "" {
		t.Skip("RELAY_DAEMON_BIN not set; skipping real-daemon e2e (run via make test-integration)")
	}

	ctx := context.Background()
	addr, deps := startTCPServer(t)

	disp := newDispatcher()
	deps.tunnel.sink = disp

	_, plaintext, err := deps.tokens.Create(ctx, []string{"relay:env=test"}, time.Hour)
	if err != nil {
		t.Fatalf("seed Enrollment Token: %v", err)
	}

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

	policyPath := relaytest.WriteTempFile(t, "policy-*.toml", policyTOML)
	stateDir := t.TempDir()

	env := append(os.Environ(),
		"RELAY_ADDR=https://"+addr,
		"RELAY_ENROLLMENT_TOKEN="+plaintext,
		"RELAY_CA_BUNDLE_PATH="+caFile.Name(),
		"RELAY_ENROLL_ENDPOINT=https://"+addr,
		"RELAY_STATE_DIR="+stateDir,
		"RELAY_POLICY_PATH="+policyPath,
		"RELAY_DOMAIN=localhost",
		"HOSTNAME=e2e-test-node",
		// Disable rustls provider conflict on some environments.
		"RUST_LOG=warn",
	)

	launch := func() *exec.Cmd {
		cmd := exec.Command(daemonBin, "--relay", "https://"+addr)
		cmd.Env = env
		if err := cmd.Start(); err != nil {
			t.Fatalf("start daemon: %v", err)
		}
		t.Cleanup(func() {
			cmd.Process.Kill() //nolint:errcheck
			cmd.Wait()         //nolint:errcheck
		})
		return cmd
	}

	cmd := launch()

	// Wait for the daemon to complete Hello→Ping handshake (registry sync).
	// Poll the dispatcher until the node appears, with a 30 s deadline. We
	// don't know the Relay-assigned node_id yet, so watch disp.senders directly.
	var nodeID string
	regCtx, regCancel := context.WithTimeout(ctx, 30*time.Second)
	defer regCancel()
	for nodeID == "" {
		select {
		case <-regCtx.Done():
			t.Fatalf("timeout: daemon did not complete Hello→Ping handshake within 30 s")
		case <-time.After(100 * time.Millisecond):
		}
		disp.mu.Lock()
		for id := range disp.senders {
			nodeID = id
		}
		disp.mu.Unlock()
	}
	if err := disp.waitForNode(nodeID, 5*time.Second); err != nil {
		t.Fatalf("waitForNode: %v", err)
	}

	node := &e2eNode{
		disp:       disp,
		nodeID:     nodeID,
		deps:       deps,
		stateDir:   stateDir,
		policyPath: policyPath,
		caPath:     caFile.Name(),
		addr:       addr,
		daemonBin:  daemonBin,
		env:        env,
		cmd:        cmd,
	}
	node.restart = func() {
		if err := node.cmd.Process.Kill(); err != nil {
			t.Fatalf("kill daemon for restart: %v", err)
		}
		node.cmd.Wait() //nolint:errcheck

		// Wait for the dispatcher to deregister the old sender before
		// relaunching, so the re-registration poll below cannot spuriously
		// observe the stale (pre-restart) registration.
		deregCtx, deregCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer deregCancel()
		for {
			disp.mu.Lock()
			_, present := disp.senders[nodeID]
			disp.mu.Unlock()
			if !present {
				break
			}
			select {
			case <-deregCtx.Done():
				t.Fatalf("timeout: dispatcher did not deregister %q after kill", nodeID)
			case <-time.After(10 * time.Millisecond):
			}
		}

		node.cmd = launch()
		if err := disp.waitForNode(nodeID, 30*time.Second); err != nil {
			t.Fatalf("waitForNode after restart: %v", err)
		}
	}
	return node
}

func TestTunnelDispatch_E2E(t *testing.T) {
	node := startDaemonNode(t, relaytest.FixturePolicy)
	resultCh := node.resultCh()
	if resultCh == nil {
		t.Fatal("no result channel for node")
	}

	// -----------------------------------------------------------------------
	// (a) file.read of a temp file → SUCCESS + stdout == file contents.
	// -----------------------------------------------------------------------
	wantContent := "hello from e2e dispatch test\n"
	contentPath := relaytest.WriteTempFile(t, "content-*.txt", wantContent)

	fileReadTask := &gleipnirv1.RelayMessage{
		Body: &gleipnirv1.RelayMessage_Task{
			Task: &gleipnirv1.TaskRequest{
				TaskId:         "e2e-file-read-1",
				TimeoutSeconds: 10,
				Action: &gleipnirv1.TaskRequest_Operation{
					Operation: &gleipnirv1.Operation{
						Name: "file.read",
						Args: map[string]string{"path": contentPath},
					},
				},
			},
		},
	}
	if err := node.disp.Dispatch(node.nodeID, fileReadTask); err != nil {
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
		if string(result.Stdout) != wantContent {
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
	if err := node.disp.Dispatch(node.nodeID, sshdTask); err != nil {
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
