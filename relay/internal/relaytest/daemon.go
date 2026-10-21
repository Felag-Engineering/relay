package relaytest

import (
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// DaemonConfig configures a real relay-daemon subprocess launched by
// StartDaemon. JoinString, StateDir and PolicyPath map onto the daemon's env
// (RELAY_JOIN/RELAY_STATE_DIR/RELAY_POLICY_PATH): the daemon gets its Relay
// address and the CA fingerprint it pins from the join string alone, never a
// CA file or a separate address. Hostname becomes HOSTNAME, so distinct calls
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

// StartDaemon launches a real relay-daemon subprocess per cfg and blocks
// until the process has started (not until it has enrolled/connected — that
// sync point is the caller's own, e.g. polling a dispatcher or a devharness
// socket). Skips the test if cfg.Bin is empty (RELAY_DAEMON_BIN unset — the
// convention every e2e caller uses), or fails it under RELAY_E2E_REQUIRED=1
// (SkipMissingBin). The subprocess is killed and reaped via
// t.Cleanup.
func StartDaemon(t *testing.T, cfg DaemonConfig) *DaemonHandle {
	t.Helper()
	if cfg.Bin == "" {
		SkipMissingBin(t, "RELAY_DAEMON_BIN not set; skipping real-daemon e2e (run via make test-integration)")
	}

	env := append(withoutDaemonAddressing(os.Environ()),
		"RELAY_JOIN="+cfg.JoinString,
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

	h := &DaemonHandle{t: t, cfg: cfg, env: env}
	h.Launch()
	t.Cleanup(h.Kill)
	return h
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
// and dedup markers — modeling a config-management restart.
func (h *DaemonHandle) Relaunch() {
	h.Kill()
	h.Launch()
}

// RelaunchWithoutJoinOrAddress kills the current daemon subprocess and starts
// a fresh one against the SAME StateDir with no RELAY_JOIN and no Relay address
// in its argv or environment: a steady-state env file after the join string was
// removed, so the daemon must dial the address and trust the CA it persisted at
// enrollment (ADR-0031 decision 4, DI-38). It models a config-management
// restart of an enrolled Node.
func (h *DaemonHandle) RelaunchWithoutJoinOrAddress() {
	h.Kill()
	var env []string
	for _, kv := range h.env {
		if !strings.HasPrefix(kv, "RELAY_JOIN=") {
			env = append(env, kv)
		}
	}
	h.launch(nil, env)
}

// withoutDaemonAddressing drops every variable that could hand the daemon an
// address, a CA or a credential other than the join string, so a test runner's
// own environment cannot mask what the join string carries.
func withoutDaemonAddressing(env []string) []string {
	strip := []string{
		"RELAY_ADDR=", "RELAY_ENROLL_ENDPOINT=", "RELAY_JOIN=",
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
