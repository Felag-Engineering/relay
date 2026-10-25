//go:build integration

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/enroll"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// joinedNode is a real daemon enrolled against a real Relay with nothing but a
// join string from the mint response.
type joinedNode struct {
	fr       *fleetRelay
	daemon   *relaytest.DaemonHandle
	join     enroll.JoinString
	stateDir string
	nodeID   string
}

// enrollWithJoinStringOnly mints through the devharness create_token op and
// enrolls a Node with `relay-daemon join`, the join string on its standard input
// and nowhere else: no CA file, no Relay address, no separate token, and no join
// string in the daemon's environment.
func enrollWithJoinStringOnly(t *testing.T, hostname string) *joinedNode {
	t.Helper()
	relayBin, daemonBin := skipUnlessFleetBins(t)

	fr := startFleetRelay(t, relayBin, "")
	raw := createFleetJoinString(t, fr.harness, "relay:env=test")
	join, err := enroll.DecodeJoinString(raw)
	if err != nil {
		t.Fatalf("mint response's join_string does not decode: %v", err)
	}

	policyPath := relaytest.WriteTempFile(t, "policy-*.toml", relaytest.FixturePolicy)
	stateDir := t.TempDir()
	daemonLog := &syncBuffer{}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("relay log:\n%s\ndaemon log:\n%s", fr.proc.Log(), daemonLog.String())
		}
	})

	daemon := relaytest.StartDaemon(t, relaytest.DaemonConfig{
		Bin:        daemonBin,
		JoinString: raw,
		StateDir:   stateDir,
		PolicyPath: policyPath,
		Hostname:   hostname,
		LogWriter:  daemonLog,
	})
	nodeID := waitForConnected(t, fr.harness, 1)[0]
	return &joinedNode{fr: fr, daemon: daemon, join: join, stateDir: stateDir, nodeID: nodeID}
}

// dispatchFileRead proves the Node runs a Task over its Tunnel.
func (n *joinedNode) dispatchFileRead(t *testing.T, taskID string) {
	t.Helper()
	wantContent := "hello from join string e2e dispatch\n"
	contentPath := relaytest.WriteTempFile(t, "content-*.txt", wantContent)
	resp := n.fr.harness.call(t, map[string]any{
		"op":              "dispatch",
		"node_id":         n.nodeID,
		"task_id":         taskID,
		"operation":       "file.read",
		"args":            map[string]string{"path": contentPath},
		"timeout_seconds": 15,
	})
	if outcome, _ := resp["outcome"].(string); outcome != "OUTCOME_SUCCESS" {
		t.Errorf("file.read outcome: got %v, want OUTCOME_SUCCESS; stderr=%v", resp["outcome"], resp["stderr"])
	}
}

// pemDER returns the DER of the single certificate in path.
func pemDER(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("%s does not hold exactly one PEM certificate", path)
	}
	return block.Bytes
}

// TestCrossBinary_JoinStringEnrolls proves `relay-daemon join`, given only the
// join string from the mint response on standard input, enrolls: it dials the
// join string's address, pins the Relay's CA from its fingerprint, and writes
// that CA and the address into its state directory, so no CA path is configured
// by hand, and neither the join string nor its token lands on disk. It runs
// under make test-crossbinary with the real relay and relay-daemon binaries.
// Proves DI-42, DI-43.
func TestCrossBinary_JoinStringEnrolls(t *testing.T) {
	n := enrollWithJoinStringOnly(t, "join-string-node")

	got := pemDER(t, filepath.Join(n.stateDir, "ca_bundle.pem"))
	want := pemDER(t, n.fr.caCertPath)
	if !bytes.Equal(got, want) {
		t.Error("persisted ca_bundle.pem is not the Relay's CA certificate")
	}
	fp := n.join.CAFingerprint()
	if sum := sha256.Sum256(got); !bytes.Equal(sum[:], fp[:]) {
		t.Error("persisted CA does not match the join string's fingerprint")
	}

	persisted, err := os.ReadFile(filepath.Join(n.stateDir, "relay_addr"))
	if err != nil {
		t.Fatalf("read persisted relay_addr: %v", err)
	}
	if got, want := strings.TrimSpace(string(persisted)), "https://"+n.join.RelayAddress(); got != want {
		t.Fatalf("persisted relay_addr = %q, want %q (the join string's address)", got, want)
	}

	// The join string is written nowhere: no file under the state directory holds
	// the token or the glp_join_ prefix.
	token := n.join.EnrollmentToken()
	err = filepath.WalkDir(n.stateDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if bytes.Contains(data, []byte(token)) || bytes.Contains(data, []byte("glp_join_")) {
			t.Errorf("%s holds the join string or its token", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the state directory: %v", err)
	}

	n.dispatchFileRead(t, "join-string-file-read-1")
}

// TestCrossBinary_RestartWithoutJoinOrAddrUsesPersistedState proves the daemon
// reads no join string: a restart with no RELAY_JOIN anywhere in its
// environment, and no RELAY_ADDRESS or --relay, connects using the CA and
// address persisted at enrollment (ADR-0031 decision 4), and the running
// daemon's environment holds neither RELAY_JOIN nor the token.
// Proves DI-43, DI-44, EN-8, EN-30, EN-32.
func TestCrossBinary_RestartWithoutJoinOrAddrUsesPersistedState(t *testing.T) {
	n := enrollWithJoinStringOnly(t, "persisted-state-node")

	n.daemon.Kill()
	waitForNodeConnected(t, n.fr.harness, n.nodeID, false)

	n.daemon.Relaunch()
	waitForNodeConnected(t, n.fr.harness, n.nodeID, true)

	// The process environment is what a file.read of /proc/<pid>/environ returns.
	environ, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", n.daemon.Cmd().Process.Pid))
	if err != nil {
		t.Fatalf("read the daemon's environment: %v", err)
	}
	if bytes.Contains(environ, []byte("RELAY_JOIN=")) || bytes.Contains(environ, []byte(n.join.EnrollmentToken())) {
		t.Error("the running daemon's environment holds the join string or its token")
	}

	n.dispatchFileRead(t, "persisted-state-file-read-1")
}
