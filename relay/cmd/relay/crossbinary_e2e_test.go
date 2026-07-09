//go:build integration

// Package main: crossbinary_e2e_test.go is the #112 acceptance test — the
// first CI test where the real `relay` Go binary and the real `relay-daemon`
// Rust binary talk over loopback TCP as two OS processes, neither of which is
// driven in-process. Every other e2e test (tunnel_dispatch_e2e_test.go,
// tunnel_control_e2e_test.go) runs the Relay in-process via newServer and
// injects a test taskSink directly in Go; this file instead drives an
// out-of-process `relay` binary through the devharness.go control socket
// (//go:build devharness — RELAY_BIN here must be built with that tag), so
// the daemon subprocess enrolls against, and is dispatched to, over the real
// mTLS wire on both ends.
//
// Flow: start relay binary -> create_token over the devharness socket ->
// read the CA bundle directly from disk (no get_ca op; plan-review
// BLOCKING-1) -> start relay-daemon binary against the real endpoint ->
// wait_node -> get_node (fingerprint + labels) -> dispatch file.read
// (allowed) -> dispatch service.restart sshd (denied by fixturePolicy). The
// Relay never evaluates Policy itself (ADR-0011): the DENIED_BY_POLICY
// verdict below comes from the daemon's live engine over the real wire.
//
// Skip condition: RELAY_BIN or RELAY_DAEMON_BIN env var not set.
// Run via: make test-crossbinary (builds both binaries first).
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a mutex-guarded bytes.Buffer: both subprocess log captures
// are written to concurrently (by the OS pipe copy) and read concurrently
// (by the readiness poll and, on failure, dumpLogs).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// freeLoopbackAddr binds 127.0.0.1:0, reads the OS-assigned port, and closes
// the listener, returning the address string for a subprocess to bind next.
// This has an inherent, low-probability TOCTOU window (plan-review SUGG-4):
// another process could grab the port before the relay subprocess binds it.
// startRelaySubprocess retries on a fresh port to absorb that rather than
// flake CI.
func freeLoopbackAddr() (string, error) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer lis.Close()
	return lis.Addr().String(), nil
}

// startRelaySubprocess launches relayBin with RELAY_DEVHARNESS_SOCKET set to
// sockPath, and blocks until it logs "relay listening" (the same readiness
// signal scripts/smoke-test.sh uses). storePath is passed as --store-path (so
// a caller can restart the Relay against the SAME on-disk store, proving
// persistence survives restart — fleet_e2e_test.go). extraEnv is appended to
// the subprocess environment (e.g. RELAY_READ_BLAST_CAP/RELAY_MUTATE_BLAST_CAP
// for the over-cap tests); nil is fine.
//
// addr controls port reuse across a restart: "" allocates a fresh free port
// on every attempt (the #112 behavior — absorbs a rare port collision on a
// brand-new port). A non-empty addr is instead reused UNCHANGED across every
// attempt: the caller (e.g. a crash-mid-Job restart) needs the daemon to
// re-dial the exact same address, so this function must never silently
// reallocate a different port out from under it — only the bind/listen/
// startup attempt itself is retried, to absorb TIME_WAIT after a kill -9.
//
// The returned exited channel is fed by the single goroutine below that owns
// c.Wait() for the lifetime of the returned *exec.Cmd: os/exec.Cmd.Wait may
// only ever be called once (a second concurrent call races the first for the
// same goroutineErr send and blocks forever, since only one send ever
// happens). Every caller that later kills this subprocess MUST reap it via
// `<-exited`, never via a second cmd.Wait().
func startRelaySubprocess(t *testing.T, relayBin, caDir, storePath, sockPath, addr string, extraEnv []string) (cmd *exec.Cmd, log *syncBuffer, gotAddr string, exited chan error) {
	t.Helper()
	const maxAttempts = 3
	const startupTimeout = 10 * time.Second

	fixedAddr := addr != ""

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		a := addr
		if !fixedAddr {
			var err error
			a, err = freeLoopbackAddr()
			if err != nil {
				t.Fatalf("allocate free loopback port: %v", err)
			}
		}

		logBuf := &syncBuffer{}
		c := exec.Command(relayBin, "--addr", a, "--ca-dir", caDir, "--hostname", "localhost", "--store-path", storePath)
		c.Env = append(append(os.Environ(), "RELAY_DEVHARNESS_SOCKET="+sockPath), extraEnv...)
		c.Stdout = logBuf
		c.Stderr = logBuf
		if err := c.Start(); err != nil {
			t.Fatalf("start relay (attempt %d): %v", attempt, err)
		}

		exitedAttempt := make(chan error, 1)
		go func() { exitedAttempt <- c.Wait() }()

		ready := false
		deadline := time.After(startupTimeout)
	pollLoop:
		for {
			if strings.Contains(logBuf.String(), "relay listening") {
				ready = true
				break pollLoop
			}
			select {
			case werr := <-exitedAttempt:
				lastErr = fmt.Errorf("relay exited before listening (attempt %d): %v\n%s", attempt, werr, logBuf.String())
				break pollLoop
			case <-deadline:
				c.Process.Kill() //nolint:errcheck
				<-exitedAttempt
				lastErr = fmt.Errorf("relay did not report listening within %v (attempt %d, likely port collision or lingering TIME_WAIT)\n%s",
					startupTimeout, attempt, logBuf.String())
				break pollLoop
			case <-time.After(50 * time.Millisecond):
			}
		}

		if ready {
			return c, logBuf, a, exitedAttempt
		}
	}
	t.Fatalf("failed to start relay after %d attempts: %v", maxAttempts, lastErr)
	return nil, nil, "", nil
}

// waitForSocket polls until path exists or deadline expires.
func waitForSocket(t *testing.T, path string, deadline time.Duration) {
	t.Helper()
	end := time.Now().Add(deadline)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(end) {
			t.Fatalf("devharness socket %q did not appear within %v", path, deadline)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// harnessClient is a trivial newline-delimited-JSON client for the devharness
// control socket (relay/cmd/relay/devharness.go). It deliberately does not
// import that file's types (this test compiles under -tags integration only,
// not devharness) — the wire format is plain JSON precisely so the client
// stays this simple.
type harnessClient struct {
	conn net.Conn
	r    *bufio.Reader
}

func dialHarness(t *testing.T, sockPath string) *harnessClient {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.Dial("unix", sockPath)
		if err == nil {
			return &harnessClient{conn: conn, r: bufio.NewReader(conn)}
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial devharness socket %q: %v", sockPath, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// send writes req as one JSON line and returns the decoded JSON response
// line, or an error. Unlike call/callRaw it takes no *testing.T and never
// fails a test itself — it is the shared primitive both build on, and the
// only one safe to use from a goroutine other than the one running the test
// (a fleet e2e scenario that issues a blocking run_job on a second connection
// concurrently with the main goroutine — fleet_e2e_test.go — must never call
// t.Fatalf off-goroutine: testing.T's FailNow contract requires it be called
// only from the test's own goroutine).
func (c *harnessClient) send(req map[string]any) (map[string]any, error) {
	line, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal devharness request %v: %w", req, err)
	}
	line = append(line, '\n')
	if _, err := c.conn.Write(line); err != nil {
		return nil, fmt.Errorf("write devharness request %v: %w", req, err)
	}
	respLine, err := c.r.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("read devharness response to %v: %w", req, err)
	}
	var resp map[string]any
	if err := json.Unmarshal(respLine, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal devharness response %q: %w", respLine, err)
	}
	return resp, nil
}

// call sends req and returns the decoded JSON response line. It fails the
// test if the request cannot be sent/decoded, or if the response carries a
// non-empty "error" field.
func (c *harnessClient) call(t *testing.T, req map[string]any) map[string]any {
	t.Helper()
	resp, err := c.send(req)
	if err != nil {
		t.Fatal(err)
	}
	if errMsg, ok := resp["error"]; ok {
		if s, ok := errMsg.(string); ok && s != "" {
			t.Fatalf("devharness op %q failed: %s", req["op"], s)
		}
	}
	return resp
}

// callRaw is identical to call except it does NOT inspect or fail on the
// response's "error" field — it returns the raw decoded response for the
// caller to assert on. Use this for refusal-expecting run_job calls (over-cap,
// Freeze engaged): unlike every other devharness op, run_job's refusal
// channel IS the response's "error" field, not a transport-level failure, so
// call's auto-failing semantics would wrongly fail these tests. Every other
// call — including every #112 usage and non-refusal fleet calls — keeps
// using call.
func (c *harnessClient) callRaw(t *testing.T, req map[string]any) map[string]any {
	t.Helper()
	resp, err := c.send(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestCrossBinary_RelayDaemonLoopback is the #112 acceptance test: the real
// relay and relay-daemon binaries, two separate OS processes, talking over
// real loopback TCP with real mTLS — enroll -> registry (with fingerprint and
// labels) -> allowed Operation succeeds -> denied Operation refused.
func TestCrossBinary_RelayDaemonLoopback(t *testing.T) {
	relayBin := os.Getenv("RELAY_BIN")
	daemonBin := os.Getenv("RELAY_DAEMON_BIN")
	if relayBin == "" || daemonBin == "" {
		t.Skip("RELAY_BIN and/or RELAY_DAEMON_BIN not set; skipping cross-binary e2e (run via make test-crossbinary)")
	}

	caDir := t.TempDir()
	sockPath := filepath.Join(t.TempDir(), "devharness.sock")
	storePath := filepath.Join(t.TempDir(), "relay.db")

	relayCmd, relayLog, addr, relayExited := startRelaySubprocess(t, relayBin, caDir, storePath, sockPath, "", nil)
	t.Cleanup(func() {
		if relayCmd.Process != nil {
			relayCmd.Process.Kill() //nolint:errcheck
		}
		<-relayExited
		os.Remove(sockPath)
	})

	var daemonCmd *exec.Cmd
	daemonLog := &syncBuffer{}
	// Dump both binaries' captured logs on any failure (acceptance #3), not
	// just a t.Fatalf inside this func — t.Cleanup runs even after Fatalf
	// unwinds the goroutine.
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		t.Logf("--- relay log ---\n%s", relayLog.String())
		if daemonCmd != nil {
			t.Logf("--- relay-daemon log ---\n%s", daemonLog.String())
		}
	})

	waitForSocket(t, sockPath, 5*time.Second)
	harness := dialHarness(t, sockPath)

	tokenResp := harness.call(t, map[string]any{
		"op":          "create_token",
		"labels":      []string{"relay:env=test"},
		"ttl_seconds": 3600,
	})
	token, _ := tokenResp["token"].(string)
	if token == "" {
		t.Fatal("create_token: empty token in response")
	}

	// Read the CA bundle directly off disk (no get_ca op; plan-review
	// BLOCKING-1). ca.Open (internal/ca/ca.go, certFileName "ca-cert.pem")
	// writes it during newServer, strictly before installDevHarness opens the
	// socket we just dialed, so it is guaranteed to be present by now.
	caCertPath := filepath.Join(caDir, "ca-cert.pem")
	caBundle, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("read CA bundle %q: %v", caCertPath, err)
	}
	if len(caBundle) == 0 {
		t.Fatal("CA bundle is empty")
	}

	policyPath := writeTempFile(t, "policy-*.toml", fixturePolicy)
	stateDir := t.TempDir()

	env := append(os.Environ(),
		"RELAY_ADDR=https://"+addr,
		"RELAY_ENROLLMENT_TOKEN="+token,
		"RELAY_CA_BUNDLE_PATH="+caCertPath,
		"RELAY_ENROLL_ENDPOINT=https://"+addr,
		"RELAY_STATE_DIR="+stateDir,
		"RELAY_POLICY_PATH="+policyPath,
		"RELAY_DOMAIN=localhost",
		"HOSTNAME=e2e-crossbinary-node",
		// Disable rustls provider conflict on some environments (matches
		// startDaemonNode in tunnel_dispatch_e2e_test.go).
		"RUST_LOG=warn",
	)

	daemonCmd = exec.Command(daemonBin, "--relay", "https://"+addr)
	daemonCmd.Env = env
	daemonCmd.Stdout = daemonLog
	daemonCmd.Stderr = daemonLog
	if err := daemonCmd.Start(); err != nil {
		t.Fatalf("start relay-daemon: %v", err)
	}
	t.Cleanup(func() {
		if daemonCmd.Process != nil {
			daemonCmd.Process.Kill() //nolint:errcheck
		}
		daemonCmd.Wait() //nolint:errcheck
	})

	nodeResp := harness.call(t, map[string]any{
		"op":              "wait_node",
		"timeout_seconds": 30,
	})
	nodeID, _ := nodeResp["node_id"].(string)
	if nodeID == "" {
		t.Fatal("wait_node: empty node_id in response")
	}

	// -------------------------------------------------------------------
	// Registry presence: fingerprint + labels (ADR-0002/0006 drift
	// visibility; report-only, no write-back).
	// -------------------------------------------------------------------
	getNodeResp := harness.call(t, map[string]any{"op": "get_node", "node_id": nodeID})
	fingerprint, _ := getNodeResp["policy_fingerprint"].(string)
	if fingerprint == "" {
		t.Error("get_node: policy_fingerprint is empty")
	}
	if _, ok := getNodeResp["node_labels"]; !ok {
		t.Error("get_node: node_labels missing from response")
	}
	relayLabels, _ := getNodeResp["relay_labels"].(map[string]any)
	if relayLabels["env"] != "test" {
		t.Errorf("get_node: relay_labels[env] = %v, want %q (stamped from create_token's scope)",
			relayLabels["env"], "test")
	}

	// -------------------------------------------------------------------
	// Allowed Operation: file.read of a temp file -> SUCCESS + matching
	// stdout (mirrors tunnel_dispatch_e2e_test.go:285-329).
	// -------------------------------------------------------------------
	wantContent := "hello from cross-binary e2e dispatch\n"
	contentPath := writeTempFile(t, "content-*.txt", wantContent)
	readResp := harness.call(t, map[string]any{
		"op":              "dispatch",
		"node_id":         nodeID,
		"task_id":         "crossbinary-file-read-1",
		"operation":       "file.read",
		"args":            map[string]string{"path": contentPath},
		"timeout_seconds": 15,
	})
	if outcome, _ := readResp["outcome"].(string); outcome != "OUTCOME_SUCCESS" {
		t.Errorf("file.read outcome: got %v, want OUTCOME_SUCCESS; stderr=%v", readResp["outcome"], readResp["stderr"])
	}
	if stdout, _ := readResp["stdout"].(string); stdout != wantContent {
		t.Errorf("file.read stdout: got %q, want %q", stdout, wantContent)
	}

	// -------------------------------------------------------------------
	// Denied Operation: service.restart sshd -> DENIED_BY_POLICY (fixture
	// allows only nginx; mirrors tunnel_dispatch_e2e_test.go:331-362). The
	// verdict comes from the daemon's live Policy engine over the real wire,
	// never from the Relay (ADR-0011).
	// -------------------------------------------------------------------
	denyResp := harness.call(t, map[string]any{
		"op":              "dispatch",
		"node_id":         nodeID,
		"task_id":         "crossbinary-sshd-deny-1",
		"operation":       "service.restart",
		"args":            map[string]string{"unit": "sshd"},
		"timeout_seconds": 15,
	})
	if outcome, _ := denyResp["outcome"].(string); outcome != "OUTCOME_DENIED_BY_POLICY" {
		t.Errorf("service.restart sshd outcome: got %v, want OUTCOME_DENIED_BY_POLICY; stderr=%v",
			denyResp["outcome"], denyResp["stderr"])
	}
}
