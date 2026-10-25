package relaytest

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// joinTimeout bounds one `relay-daemon join`. The daemon gives its own
// enrollment 60 seconds and prints the reason when that runs out, so this one is
// longer: Go must not kill join just before it can say why.
const joinTimeout = 90 * time.Second

// DaemonConfig configures a real relay-daemon subprocess launched by
// StartDaemon. JoinString reaches the daemon only on the standard input of
// `relay-daemon join`; StateDir and PolicyPath map onto the daemon's env
// (RELAY_STATE_DIR/RELAY_POLICY_PATH). The Node's Relay address and the CA
// fingerprint it pins come from the join string alone, never a CA file or a
// separate address, and never from the daemon's environment. Hostname becomes HOSTNAME, so distinct calls
// model distinct fleet Nodes (never reusing on-disk identity unless the caller
// deliberately reuses StateDir/Hostname, e.g. for a restart). LogWriter, if
// non-nil, captures the subprocess's combined stdout/stderr; nil discards it.
type DaemonConfig struct {
	Bin string
	// JoinString is the join string from the Enrollment Token mint response.
	JoinString string
	StateDir   string
	PolicyPath string
	Hostname   string
	LogWriter  io.Writer
	// TemplateDir, when set, is the daemon's RELAY_TEMPLATE_DIR: the root it
	// loads Template Operations from (WriteTemplatePack returns one).
	TemplateDir string
}

// DaemonHandle is a launched relay-daemon subprocess. Kill is registered as
// a t.Cleanup by StartDaemon.
type DaemonHandle struct {
	t   *testing.T
	cfg DaemonConfig
	env []string
	cmd *exec.Cmd
}

// StartDaemon enrolls a Node with `relay-daemon join` (the join string on
// standard input), then launches a real relay-daemon subprocess per cfg and
// blocks until the process has started (not until it has connected — that sync
// point is the caller's own, e.g. polling a dispatcher or a devharness socket).
// It returns once the Node is enrolled. Skips the test if cfg.Bin is empty (RELAY_DAEMON_BIN unset — the
// convention every e2e caller uses), or fails it under RELAY_E2E_REQUIRED=1
// (SkipMissingBin). The subprocess is killed and reaped via
// t.Cleanup.
func StartDaemon(t *testing.T, cfg DaemonConfig) *DaemonHandle {
	t.Helper()
	if cfg.Bin == "" {
		SkipMissingBin(t, "RELAY_DAEMON_BIN not set; skipping real-daemon e2e (run via make test-integration)")
	}

	env := append(withoutDaemonAddressing(os.Environ()),
		"RELAY_STATE_DIR="+cfg.StateDir,
		"RELAY_POLICY_PATH="+cfg.PolicyPath,
		"RELAY_SERVER_NAME=localhost",
		"HOSTNAME="+cfg.Hostname,
		// Disable rustls provider conflict on some environments.
		"RUST_LOG=warn",
	)
	if cfg.TemplateDir != "" {
		env = append(env, "RELAY_TEMPLATE_DIR="+cfg.TemplateDir)
	}

	JoinDaemon(t, cfg.Bin, env, cfg.StateDir, cfg.JoinString, cfg.LogWriter)

	h := &DaemonHandle{t: t, cfg: cfg, env: env}
	h.Launch()
	t.Cleanup(h.Kill)
	return h
}

// JoinDaemon runs `bin join` with env and joinString on its standard input, and
// fails the test unless it exits 0 and leaves an identity in stateDir. The
// string never reaches an argument or the environment. join's combined output is
// also written to log when non-nil; it never contains the join string.
func JoinDaemon(t *testing.T, bin string, env []string, stateDir, joinString string, log io.Writer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), joinTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "join")
	cmd.Env = env
	cmd.Stdin = strings.NewReader(joinString + "\n")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if log != nil {
		log.Write(out.Bytes())
	}
	if err != nil {
		t.Fatalf("relay-daemon join: %v\n%s", err, out.String())
	}
	// Exit 0 is also what join says on a Node that already holds an identity, in
	// which case the daemon would start unconfigured and the test would time out
	// far from the cause.
	if _, statErr := os.Stat(filepath.Join(stateDir, "node_id")); statErr != nil {
		t.Fatalf("relay-daemon join exited 0 but left no identity in %s (%v); a host identity or environment file may be in the way:\n%s",
			stateDir, statErr, out.String())
	}
}

// Launch starts a fresh relay-daemon subprocess from h's env, replacing any
// previous h.cmd. Callers that need to relaunch after a Kill should use
// Relaunch instead, unless they need to interleave other work between the
// two (e.g. waiting for the dispatcher to deregister the old connection).
func (h *DaemonHandle) Launch() {
	h.t.Helper()
	h.launch(nil, h.env)
}

func (h *DaemonHandle) launch(args, env []string) {
	h.t.Helper()
	cmd := exec.Command(h.cfg.Bin, args...)
	cmd.Env = env
	if h.cfg.LogWriter != nil {
		cmd.Stdout = h.cfg.LogWriter
		cmd.Stderr = h.cfg.LogWriter
	}
	if err := cmd.Start(); err != nil {
		h.t.Fatalf("start relay-daemon (%s): %v", h.cfg.Hostname, err)
	}
	h.cmd = cmd
}

// Kill stops the daemon subprocess, if still running, and reaps it. Safe to
// call more than once (e.g. once explicitly mid-test, once again via
// t.Cleanup).
func (h *DaemonHandle) Kill() {
	if h.cmd == nil || h.cmd.Process == nil {
		return
	}
	h.cmd.Process.Kill()
	h.cmd.Wait()
}

// Relaunch kills the current daemon subprocess (if any) and starts a fresh
// one against the SAME env — same StateDir, so the same persisted identity
// and dedup markers — modeling a config-management restart. The env carries no
// join string and no Relay address, so the daemon dials the address and trusts
// the CA persisted at enrollment (ADR-0031 decision 4, DI-44).
func (h *DaemonHandle) Relaunch() {
	h.Kill()
	h.Launch()
}

// withoutDaemonAddressing drops every variable that could hand the daemon an
// address, a CA or a credential, so a test runner's own environment cannot mask
// what the join string carries.
func withoutDaemonAddressing(env []string) []string {
	strip := []string{
		"RELAY_ADDRESS=", "RELAY_ENROLL_ADDRESS=", "RELAY_JOIN=",
		"RELAY_ENROLLMENT_TOKEN=", "RELAY_CA_BUNDLE_PATH=",
	}
	var out []string
	for _, kv := range env {
		drop := false
		for _, p := range strip {
			if strings.HasPrefix(kv, p) {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, kv)
		}
	}
	return out
}

// Cmd returns the *exec.Cmd of the most recent Launch, for callers that need
// direct access to the live process (e.g. to preserve an existing signature
// that returns it).
func (h *DaemonHandle) Cmd() *exec.Cmd {
	return h.cmd
}
