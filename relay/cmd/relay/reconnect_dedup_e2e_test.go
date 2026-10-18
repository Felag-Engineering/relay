//go:build integration

// Package main: reconnect_dedup_e2e_test.go is the v0.0.7 #190 acceptance
// test — the milestone's headline: "killing and restarting the Relay:
// daemons reconnect, dedup holds, no Task double-runs." It complements
// TestFleetE2E_CrashMidJobNeverDoubleRuns (fleet_e2e_test.go): that test
// proves dedup survives a daemon Relaunch after a crash-mid-Job; this one
// proves the daemon's own in-process reconnect loop (#176) — the daemon is
// launched ONCE and never killed or relaunched, only the Relay is — still
// rides ADR-0004 dedup-across-reconnect without a second execution.
//
// Skip condition: RELAY_BIN or RELAY_DAEMON_BIN env var not set.
// Run via: make test-crossbinary (builds both binaries first).
package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// TestFleetE2E_RelayRestartDaemonReconnects_DedupHolds dispatches a slow,
// side-effecting Raw Exec, kills the Relay while the Task is durably
// in-flight, restarts the Relay on the SAME store/addr/CA, and confirms the
// daemon reconnects entirely on its own (no Relaunch) and the reconciled
// resend resolves via the daemon's dedup path rather than a second real
// execution.
func TestFleetE2E_RelayRestartDaemonReconnects_DedupHolds(t *testing.T) {
	relayBin, daemonBin := skipUnlessFleetBins(t)

	fr := startFleetRelay(t, relayBin, "")

	// marker records every execution's side effect (echo) so the test can
	// prove exactly-once at the Node; script sleeps well past the Relay
	// restart so the Task is still in flight when it is killed.
	marker := relaytest.WriteTempFile(t, "marker-*.txt", "")
	script := relaytest.WriteTempFile(t, "slowmark-*.sh", "#!/bin/sh\necho run >> \"$1\"\nsleep \"$2\"\n")
	if err := os.Chmod(script, 0o700); err != nil {
		t.Fatalf("chmod %q executable: %v", script, err)
	}

	// A custom Raw Exec Policy: FixturePolicy has no side-effecting command,
	// so this test needs its own, regex-anchored to the exact runtime paths
	// (invariant #1: argv-only, no /bin/sh -c).
	allow := "^" + regexp.QuoteMeta(script) + " " + regexp.QuoteMeta(marker) + " 30$"
	// TOML LITERAL string (single-quoted): QuoteMeta already backslash-escapes
	// the path's dots, and a TOML basic (double-quoted) string would try to
	// interpret those backslashes as escapes and fail to parse ("Unescaped
	// '\' in a string"). A literal string takes the regex verbatim, which is
	// exactly what's wanted here. Contrast FixturePolicy, which hand-writes
	// "\\b" in a basic string precisely because that string needs the escape.
	policyBody := "[raw_exec]\nallow = ['" + allow + "']\ndeny = []\n"
	policyPath := relaytest.WriteTempFile(t, "policy-*.toml", policyBody)

	join := createFleetJoinString(t, fr.harness, "relay:env=test")
	stateDir := t.TempDir()
	startDaemonSubprocess(t, daemonBin, join, stateDir, policyPath, "fleet-reconnect-node")
	nodeIDs := waitForConnected(t, fr.harness, 1)
	nodeID := nodeIDs[0]

	// Fire the slow Job on a SECOND connection so the blocking run_job call
	// doesn't stall the main goroutine; the response is never read (mirrors
	// TestFleetE2E_CrashMidJobNeverDoubleRuns).
	h2 := dialHarness(t, fr.sockPath)
	go func() {
		_, _ = h2.send(map[string]any{
			"op":       "run_job",
			"selector": "relay:env=test",
			"raw_exec": []string{script, marker, "30"},
		})
	}()

	jobID := waitForInFlightJobID(t, fr.harness)

	// Kill the Relay the instant the Task is known in flight — no
	// time.Sleep here (unlike TestFleetE2E_CrashMidJobNeverDoubleRuns):
	// list_inflight already only surfaces a Task once MarkDispatched is
	// durably committed, so there is nothing further to wait for before a
	// truthful crash, and the no-sleeps-as-synchronization DoD is satisfied
	// without it.
	fr.proc.Kill() //nolint:errcheck

	// Restart the Relay on the SAME store/addr/CA dir — its persisted store
	// still has the Task Dispatched with no Result. The daemon is never
	// touched: this is the case #176 unlocked, its own reconnect loop must
	// re-dial on its own.
	fr.restart(t, "")

	// waitForNodeConnected's shared 15s deadline may be tight for a
	// reconnect racing the daemon's own backoff (base 1s/cap 30s) plus
	// fr.restart's up-to-3 relaunch attempts, so poll with a more generous,
	// still event-based ceiling dedicated to this wait.
	deadline := time.Now().Add(60 * time.Second)
	for {
		resp := fr.harness.call(t, map[string]any{"op": "get_node", "node_id": nodeID})
		if connected, _ := resp["connected"].(bool); connected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("get_node(%s).connected did not become true before deadline (daemon never reconnected on its own)", nodeID)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Poll query_job until the reconciled Task reaches resolved.
	var task map[string]any
	deadline = time.Now().Add(60 * time.Second)
	for {
		jobResp := fr.harness.call(t, map[string]any{"op": "query_job", "job_id": jobID})
		tasks := toMapSlice(jobResp["tasks"])
		if len(tasks) == 1 && tasks[0]["state"] == "resolved" {
			task = tasks[0]
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("query_job(%s): Task did not reach resolved before deadline; last tasks = %v", jobID, tasks)
		}
		time.Sleep(200 * time.Millisecond)
	}

	if task["outcome"] != "OUTCOME_SUCCESS" {
		t.Errorf("reconciled Task outcome = %v, want OUTCOME_SUCCESS (the daemon's benign dedup result)", task["outcome"])
	}
	stderr, _ := task["stderr"].(string)
	const dedupSignal = "already processed"
	if !strings.Contains(stderr, dedupSignal) {
		t.Errorf("reconciled Task stderr = %q, want it to contain %q (daemon dedup signal — proof the Task was NOT re-run)",
			stderr, dedupSignal)
	}

	// Node-side exactly-once: the marker script's echo only ever ran once,
	// even though the Relay resent the in-flight Task on reconnect.
	markerContent, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("read marker file %q: %v", marker, err)
	}
	var lines int
	for _, line := range strings.Split(strings.TrimRight(string(markerContent), "\n"), "\n") {
		if line != "" {
			lines++
		}
	}
	if lines != 1 {
		t.Errorf("marker file %q has %d non-empty line(s), want exactly 1 (Node-side exactly-once); content = %q", marker, lines, markerContent)
	}
}
