package relaytest

import (
	"io"
	"os"
	"os/exec"
	"testing"
)

// DaemonConfig configures a real relay-daemon subprocess launched by
// StartDaemon. Bin, NodeAddr, CAPath, Token, StateDir, and PolicyPath map
// directly onto the daemon's enrollment env (RELAY_ADDR/
// RELAY_ENROLLMENT_TOKEN/RELAY_CA_BUNDLE_PATH/RELAY_ENROLL_ENDPOINT/
// RELAY_STATE_DIR/RELAY_POLICY_PATH); Hostname becomes HOSTNAME, so distinct
// calls model distinct fleet Nodes (never reusing on-disk identity unless the
// caller deliberately reuses StateDir/Hostname, e.g. for a restart).
// LogWriter, if non-nil, captures the subprocess's combined stdout/stderr;
// nil discards it (the daemon's own stdout/stderr, as before this helper
// existed).
type DaemonConfig struct {
	Bin        string
	NodeAddr   string
	CAPath     string
	Token      string
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

	env := append(os.Environ(),
		"RELAY_ADDR=https://"+cfg.NodeAddr,
		"RELAY_ENROLLMENT_TOKEN="+cfg.Token,
		"RELAY_CA_BUNDLE_PATH="+cfg.CAPath,
		"RELAY_ENROLL_ENDPOINT=https://"+cfg.NodeAddr,
		"RELAY_STATE_DIR="+cfg.StateDir,
		"RELAY_POLICY_PATH="+cfg.PolicyPath,
		"RELAY_DOMAIN=localhost",
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
	cmd := exec.Command(h.cfg.Bin, "--relay", "https://"+h.cfg.NodeAddr)
	cmd.Env = h.env
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

// Cmd returns the *exec.Cmd of the most recent Launch, for callers that need
// direct access to the live process (e.g. to preserve an existing signature
// that returns it).
func (h *DaemonHandle) Cmd() *exec.Cmd {
	return h.cmd
}
