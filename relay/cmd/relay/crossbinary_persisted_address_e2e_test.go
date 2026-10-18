//go:build integration

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// TestCrossBinary_RestartUsesPersistedAddress proves the daemon persists the
// Node-plane Relay address at enrollment and dials it on a later start that
// carries no RELAY_ADDR and no --relay (ADR-0031 decision 4). It runs under
// make test-crossbinary with the real relay and relay-daemon binaries.
func TestCrossBinary_RestartUsesPersistedAddress(t *testing.T) {
	relayBin, daemonBin := skipUnlessFleetBins(t)

	fr := startFleetRelay(t, relayBin, "")
	token := createFleetToken(t, fr.harness, "relay:env=test")

	policyPath := relaytest.WriteTempFile(t, "policy-*.toml", relaytest.FixturePolicy)
	stateDir := t.TempDir()
	daemonLog := &syncBuffer{}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("relay log:\n%s\ndaemon log:\n%s", fr.log.String(), daemonLog.String())
		}
	})

	daemon := relaytest.StartDaemon(t, relaytest.DaemonConfig{
		Bin:        daemonBin,
		NodeAddr:   fr.addr,
		CAPath:     fr.caCertPath,
		Token:      token,
		StateDir:   stateDir,
		PolicyPath: policyPath,
		Hostname:   "persisted-addr-node",
		LogWriter:  daemonLog,
	})
	nodeID := waitForConnected(t, fr.harness, 1)[0]

	persisted, err := os.ReadFile(filepath.Join(stateDir, "relay_addr"))
	if err != nil {
		t.Fatalf("read persisted relay_addr: %v", err)
	}
	if got, want := strings.TrimSpace(string(persisted)), "https://"+fr.addr; got != want {
		t.Fatalf("persisted relay_addr = %q, want %q", got, want)
	}

	daemon.Kill()
	waitForNodeConnected(t, fr.harness, nodeID, false)

	daemon.RelaunchWithoutAddress()
	waitForNodeConnected(t, fr.harness, nodeID, true)

	wantContent := "hello from persisted-address e2e dispatch\n"
	contentPath := relaytest.WriteTempFile(t, "content-*.txt", wantContent)
	resp := fr.harness.call(t, map[string]any{
		"op":              "dispatch",
		"node_id":         nodeID,
		"task_id":         "persisted-addr-file-read-1",
		"operation":       "file.read",
		"args":            map[string]string{"path": contentPath},
		"timeout_seconds": 15,
	})
	if outcome, _ := resp["outcome"].(string); outcome != "OUTCOME_SUCCESS" {
		t.Errorf("file.read outcome: got %v, want OUTCOME_SUCCESS; stderr=%v", resp["outcome"], resp["stderr"])
	}
}
