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
// Flow: start relay binary -> create_token over the devharness socket, which
// returns the join string from the mint -> start relay-daemon binary with only
// that join string (it carries the address and the CA fingerprint the daemon
// pins; no CA file is handed over) -> wait_node -> get_node (fingerprint + labels) -> dispatch file.read
// (allowed) -> dispatch service.restart sshd (denied by relaytest.FixturePolicy). The
// Relay never evaluates Policy itself (ADR-0011): the DENIED_BY_POLICY
// verdict below comes from the daemon's live engine over the real wire.
//
// Skip condition: RELAY_BIN or RELAY_DAEMON_BIN env var not set.
// Run via: make test-crossbinary (builds both binaries first).
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// crossbinaryGate names the make target these suites run under, for the skip ledger.
const crossbinaryGate = "test-crossbinary"

// harnessSocketPath is where a layout's Relay serves its devharness socket: the group-shared
// IO directory, never the state directory.
func harnessSocketPath(layout *relaytest.RelayLayout) string {
	return filepath.Join(layout.IODir(), "devharness.sock")
}

// relayCADir is where a layout's Relay keeps its CA.
func relayCADir(layout *relaytest.RelayLayout) string {
	return filepath.Join(layout.StateDir(), "ca")
}

// relaySubprocessEnv is the whole environment of a Relay started through a layout: nothing of
// the test's own temp or coverage directories, which the separate uid could not write.
func relaySubprocessEnv(extra ...string) []string {
	return append([]string{"PATH=" + os.Getenv("PATH"), "HOME=/"}, extra...)
}

// startRelaySubprocess launches relayBin through layout (relaytest.RelayLayout: as a separate
// uid where the host allows it) against a fresh read-only relay.toml (listen address, the
// layout's CA directory and store, then extraTOML), with RELAY_DEVHARNESS_SOCKET at
// harnessSocketPath in an otherwise filtered environment, and blocks until it logs "relay
// listening" (the same readiness signal scripts/smoke-test.sh uses). Restarting through the
// SAME layout reuses the same on-disk CA and store, proving persistence survives restart —
// fleet_e2e_test.go. extraTOML is appended to the file (e.g. a [reach] table for the over-cap
// tests); "" is fine.
//
// addr controls port reuse across a restart: "" allocates a fresh free port
// on every attempt (the #112 behavior — absorbs a rare port collision on a
// brand-new port). A non-empty addr is instead reused UNCHANGED across every
// attempt: the caller (e.g. a crash-mid-Job restart) needs the daemon to
// re-dial the exact same address, so this function must never silently
// reallocate a different port out from under it — only the bind/listen/
// startup attempt itself is retried, to absorb TIME_WAIT after a kill -9.
//
// The Relay is ended only through the returned process (Kill, Signal), never by signalling
// the process the test started: as a separate uid that is sudo, which cannot relay SIGKILL.
func startRelaySubprocess(t *testing.T, layout *relaytest.RelayLayout, relayBin, addr, extraTOML string) (proc *relaytest.RelayProcess, gotAddr string) {
	t.Helper()
	return startRelaySubprocessWithHostname(t, layout, relayBin, addr, "localhost", extraTOML)
}

// startRelaySubprocessWithHostname is startRelaySubprocess with tls.hostname set to
// hostname instead of "localhost": the one name (or IP address) the Relay's server
// certificate and join strings carry.
func startRelaySubprocessWithHostname(t *testing.T, layout *relaytest.RelayLayout, relayBin, addr, hostname, extraTOML string) (proc *relaytest.RelayProcess, gotAddr string) {
	t.Helper()
	const maxAttempts = 3
	const startupTimeout = 10 * time.Second

	fixedAddr := addr != ""
	bin := layout.InstallBinary(t, relayBin)
	env := relaySubprocessEnv("RELAY_DEVHARNESS_SOCKET=" + harnessSocketPath(layout))

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

		cfgPath := layout.WriteConfig(t, fmt.Sprintf(
			"[node_plane]\nlisten_address = %q\n\n[ca]\ndir = %q\n\n[store]\npath = %q\n\n[tls]\nhostname = %q\n\n%s",
			a, relayCADir(layout), filepath.Join(layout.StateDir(), "relay.db"), hostname, extraTOML))
		p, err := layout.Start(t, bin, env, "--config", cfgPath)
		if err != nil {
			t.Fatalf("start relay (attempt %d): %v", attempt, err)
		}

		ready := false
		deadline := time.After(startupTimeout)
	pollLoop:
		for {
			if strings.Contains(p.Log(), "relay listening") {
				ready = true
				break pollLoop
			}
			select {
			case <-p.Done():
				lastErr = fmt.Errorf("relay exited before listening (attempt %d): %v\n%s", attempt, p.Err(), p.Log())
				break pollLoop
			case <-deadline:
				p.Kill() //nolint:errcheck
				<-p.Done()
				lastErr = fmt.Errorf("relay did not report listening within %v (attempt %d, likely port collision or lingering TIME_WAIT)\n%s",
					startupTimeout, attempt, p.Log())
				break pollLoop
			case <-time.After(50 * time.Millisecond):
			}
		}

		if ready {
			// build-relay-devharness compiles this Relay with -race. The race detector
			// reports to the log and lets the process run on, and every caller ends it
			// with SIGKILL, so its race exit status is never seen: the report in the log
			// is the only evidence. Registered before the caller's kill cleanup, so it
			// runs after it, on the complete log.
			t.Cleanup(func() {
				if log := p.Log(); strings.Contains(log, "WARNING: DATA RACE") {
					t.Errorf("relay subprocess reported a data race:\n%s", log)
				}
			})
			return p, a
		}
	}
	t.Fatalf("failed to start relay after %d attempts: %v", maxAttempts, lastErr)
	return nil, ""
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
		relaytest.SkipMissingBin(t, "RELAY_BIN and/or RELAY_DAEMON_BIN not set; skipping cross-binary e2e (run via make test-crossbinary)")
	}

	layout := relaytest.NewRelayLayout(t, crossbinaryGate)
	sockPath := harnessSocketPath(layout)

	relayProc, _ := startRelaySubprocess(t, layout, relayBin, "", "")
	t.Cleanup(func() {
		relayProc.Kill() //nolint:errcheck
		<-relayProc.Done()
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
		t.Logf("--- relay log ---\n%s", relayProc.Log())
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
	joinString, _ := tokenResp["join_string"].(string)
	if joinString == "" {
		t.Fatal("create_token: empty join_string in response")
	}

	// The shared fixture plus the one allow rule the template pack needs: the
	// rule lives with this suite (relaytest.FixtureTemplatePolicyRule) because
	// other suites assert FixturePolicy's rule set exactly.
	policyPath := relaytest.WriteTempFile(t, "policy-*.toml",
		relaytest.FixturePolicy+relaytest.FixtureTemplatePolicyRule)
	templateRoot := relaytest.WriteTemplatePack(t, relaytest.FixtureTemplatePack)
	stateDir := t.TempDir()

	env := append(os.Environ(),
		"RELAY_STATE_DIR="+stateDir,
		"RELAY_POLICY_PATH="+policyPath,
		"RELAY_TEMPLATE_DIR="+templateRoot,
		"RELAY_SERVER_NAME=localhost",
		"HOSTNAME=e2e-crossbinary-node",
		// Disable rustls provider conflict on some environments (matches
		// startDaemonNode in tunnel_dispatch_e2e_test.go).
		"RUST_LOG=warn",
	)

	// The Node enrolls in the process that reads the join string; the daemon then
	// starts with no join string anywhere in its environment.
	relaytest.JoinDaemon(t, daemonBin, env, stateDir, joinString, daemonLog)

	daemonCmd = exec.Command(daemonBin)
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
	// #291/ADR-0021: the template-set fingerprint travels beside the Policy
	// fingerprint on Hello, over the same real wire, and the registry records
	// it — the drift signal an operator confirms a template rollout with.
	templateFingerprint, _ := getNodeResp["template_set_fingerprint"].(string)
	if len(templateFingerprint) != 64 {
		t.Errorf("get_node: template_set_fingerprint = %q, want a 64-hex digest of the loaded pack",
			templateFingerprint)
	}
	if templateFingerprint == fingerprint {
		t.Error("get_node: template_set_fingerprint equals policy_fingerprint; the two must be domain-separated")
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
	contentPath := relaytest.WriteTempFile(t, "content-*.txt", wantContent)
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
	// Template Operation (ADR-0021, #291): a template loaded from a local
	// root-owned file runs over the real wire like a Native Operation — and a
	// name this Node has NOT loaded reports OUTCOME_UNSUPPORTED, never a
	// failure and never a Policy denial (nothing ran; Policy was never asked).
	// -------------------------------------------------------------------
	tmplResp := harness.call(t, map[string]any{
		"op":              "dispatch",
		"node_id":         nodeID,
		"task_id":         "crossbinary-template-1",
		"operation":       "e2e.template",
		"timeout_seconds": 15,
	})
	if outcome, _ := tmplResp["outcome"].(string); outcome != "OUTCOME_SUCCESS" {
		t.Errorf("template outcome: got %v, want OUTCOME_SUCCESS; stderr=%v",
			tmplResp["outcome"], tmplResp["stderr"])
	}
	if stdout, _ := tmplResp["stdout"].(string); stdout != "template-ran\n" {
		t.Errorf("template stdout: got %q, want %q", stdout, "template-ran\n")
	}

	unsupportedResp := harness.call(t, map[string]any{
		"op":              "dispatch",
		"node_id":         nodeID,
		"task_id":         "crossbinary-template-missing-1",
		"operation":       "not.loaded.here",
		"timeout_seconds": 15,
	})
	if outcome, _ := unsupportedResp["outcome"].(string); outcome != "OUTCOME_UNSUPPORTED" {
		t.Errorf("missing-template outcome: got %v, want OUTCOME_UNSUPPORTED; stderr=%v",
			unsupportedResp["outcome"], unsupportedResp["stderr"])
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
