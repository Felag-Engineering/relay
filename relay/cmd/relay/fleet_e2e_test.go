//go:build integration

// Package main: fleet_e2e_test.go is the v0.0.5 [8/8]/#103 acceptance suite —
// it extends the #112 cross-binary devharness (crossbinary_e2e_test.go) to
// drive the full capability pipeline (Selector -> authz -> blast-cap -> Job
// engine -> dispatch -> audit, ADR-0009/0010) over real mTLS Tunnels against
// real relay-daemon subprocesses, proving the v0.0.5 acceptance
// end-to-end: over-cap rejection (both risk classes), a Job spanning an
// offline Node, Freeze-stops-dispatch and cancel-kills-in-flight, Jobs/Tasks/
// audit surviving a Relay restart, and — the hardest one — a Relay crash
// mid-Job never double-running a Task (ADR-0004).
//
// This is the ONLY harness that runs the Relay as a separate OS process (the
// devharness control socket over relay/cmd/relay/devharness.go, //go:build
// devharness), which is required to `kill -9` it for a truthful crash test;
// an in-process newServer "restart" cannot model a crash mid-fsync. Every
// scenario stands up its own Relay so blast caps/topology stay scenario-
// local, mirroring how each existing e2e test calls a fresh harness.
//
// Skip condition: RELAY_BIN or RELAY_DAEMON_BIN env var not set.
// Run via: make test-crossbinary (builds both binaries first).
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

// fleetRelay is one scenario's Relay subprocess plus the devharness
// connection to it. restart kills and relaunches the Relay against the SAME
// store/address/CA dir (Jobs/Tasks/audit survival, crash-mid-Job).
type fleetRelay struct {
	relayBin   string
	harness    *harnessClient
	cmd        *exec.Cmd
	exited     chan error
	log        *syncBuffer
	addr       string
	caDir      string
	caCertPath string
	storePath  string
	sockPath   string
}

// startFleetRelay launches a fresh Relay subprocess (with extraEnv, e.g.
// RELAY_READ_BLAST_CAP/RELAY_MUTATE_BLAST_CAP for the over-cap tests) and
// dials its devharness control socket.
func startFleetRelay(t *testing.T, relayBin string, extraEnv []string) *fleetRelay {
	t.Helper()
	caDir := t.TempDir()
	sockPath := filepath.Join(t.TempDir(), "devharness.sock")
	storePath := filepath.Join(t.TempDir(), "relay.db")

	cmd, log, addr, exited := startRelaySubprocess(t, relayBin, caDir, storePath, sockPath, "", extraEnv)
	fr := &fleetRelay{
		relayBin:  relayBin,
		cmd:       cmd,
		exited:    exited,
		log:       log,
		addr:      addr,
		caDir:     caDir,
		storePath: storePath,
		sockPath:  sockPath,
	}
	t.Cleanup(func() {
		if fr.cmd.Process != nil {
			fr.cmd.Process.Kill() //nolint:errcheck
		}
		<-fr.exited
		os.Remove(sockPath)
	})

	waitForSocket(t, sockPath, 5*time.Second)

	caCertPath := filepath.Join(caDir, "ca-cert.pem")
	if _, err := os.Stat(caCertPath); err != nil {
		t.Fatalf("CA bundle %q missing: %v", caCertPath, err)
	}

	fr.caCertPath = caCertPath
	fr.harness = dialHarness(t, sockPath)
	return fr
}

// restart kills the current Relay subprocess (SIGKILL — a real crash, not a
// graceful shutdown) and relaunches it against the SAME store path, address,
// and CA dir, then redials the devharness socket. Jobs/Tasks/audit persist in
// storePath across this; only the in-memory Router/capSvc are rebuilt.
func (r *fleetRelay) restart(t *testing.T, extraEnv []string) {
	t.Helper()
	if r.cmd.Process != nil {
		r.cmd.Process.Kill() //nolint:errcheck
	}
	<-r.exited
	os.Remove(r.sockPath)

	cmd, log, addr, exited := startRelaySubprocess(t, r.relayBin, r.caDir, r.storePath, r.sockPath, r.addr, extraEnv)
	r.cmd = cmd
	r.exited = exited
	r.log = log
	r.addr = addr

	waitForSocket(t, r.sockPath, 5*time.Second)
	r.harness = dialHarness(t, r.sockPath)
}

// createFleetToken mints an Enrollment Token scoped to labels via the
// devharness create_token op.
func createFleetToken(t *testing.T, harness *harnessClient, labels ...string) string {
	t.Helper()
	resp := harness.call(t, map[string]any{
		"op":          "create_token",
		"labels":      labels,
		"ttl_seconds": 3600,
	})
	token, _ := resp["token"].(string)
	if token == "" {
		t.Fatal("create_token: empty token in response")
	}
	return token
}

// startDaemonSubprocess launches a relay-daemon against relayAddr, enrolling
// with token, using stateDir/policyPath/hostname — the same environment
// shape as crossbinary_e2e_test.go's daemon launch. Its persisted identity
// and dedup markers (daemon/src/dedup.rs) survive a Relaunch against the SAME
// stateDir, which is what the crash-mid-Job test depends on. The daemon has
// no reconnect loop of its own (daemon/src/main.rs): when the Relay's stream
// drops, the process exits, so Relaunch is how a config-management restart is
// modeled here.
func startDaemonSubprocess(t *testing.T, daemonBin, relayAddr, caCertPath, token, stateDir, policyPath, hostname string) *relaytest.DaemonHandle {
	t.Helper()
	return relaytest.StartDaemon(t, relaytest.DaemonConfig{
		Bin:        daemonBin,
		NodeAddr:   relayAddr,
		CAPath:     caCertPath,
		Token:      token,
		StateDir:   stateDir,
		PolicyPath: policyPath,
		Hostname:   hostname,
		LogWriter:  &syncBuffer{},
	})
}

// waitForConnected polls list_connected until at least n Nodes are present,
// returning their node_ids.
func waitForConnected(t *testing.T, harness *harnessClient, n int) []string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp := harness.call(t, map[string]any{"op": "list_connected"})
		nodeIDs := toStringSlice(resp["node_ids"])
		if len(nodeIDs) >= n {
			return nodeIDs
		}
		if time.Now().After(deadline) {
			t.Fatalf("list_connected: got %d node(s) %v, want >= %d before deadline", len(nodeIDs), nodeIDs, n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// waitForNodeConnected polls get_node(nodeID).connected until it equals want.
func waitForNodeConnected(t *testing.T, harness *harnessClient, nodeID string, want bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp := harness.call(t, map[string]any{"op": "get_node", "node_id": nodeID})
		connected, _ := resp["connected"].(bool)
		if connected == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("get_node(%s).connected = %v, want %v before deadline", nodeID, connected, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// waitForFrozen polls get_freeze until it equals want.
func waitForFrozen(t *testing.T, harness *harnessClient, want bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp := harness.call(t, map[string]any{"op": "get_freeze"})
		frozen, _ := resp["frozen"].(bool)
		if frozen == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("get_freeze = %v, want %v before deadline", frozen, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// waitForInFlightJobID polls list_inflight until some Task is in flight and
// returns its job_id. Service.Run blocks until every matched Node's Task
// reaches a terminal state, so a caller can never learn a long-running Job's
// ID from run_job's own response while it is still in flight on another
// connection — list_inflight (TaskRepository.InFlight, ADR-0004) is the only
// way to discover it early enough to cancel it, or to keep polling the SAME
// Job across a Relay restart (crash-mid-Job).
func waitForInFlightJobID(t *testing.T, harness *harnessClient) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp := harness.call(t, map[string]any{"op": "list_inflight"})
		for _, tk := range toMapSlice(resp["tasks"]) {
			if jobID, _ := tk["job_id"].(string); jobID != "" {
				return jobID
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("list_inflight: no in-flight task appeared before deadline")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// nodeByRelayLabel returns the node_id among nodeIDs whose relay_labels[key]
// == value (bare key, no "relay:" prefix — registry.Node.RelayLabels strips
// it, ADR-0006).
func nodeByRelayLabel(t *testing.T, harness *harnessClient, nodeIDs []string, key, value string) string {
	t.Helper()
	for _, id := range nodeIDs {
		resp := harness.call(t, map[string]any{"op": "get_node", "node_id": id})
		labels, _ := resp["relay_labels"].(map[string]any)
		if s, ok := labels[key].(string); ok && s == value {
			return id
		}
	}
	t.Fatalf("no connected node among %v has relay label %s=%s", nodeIDs, key, value)
	return ""
}

// toStringSlice converts a decoded JSON []any of strings (e.g. node_ids) into
// a []string, dropping any non-string element.
func toStringSlice(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// toMapSlice converts a decoded JSON []any of objects (e.g. results/tasks/
// audit) into a []map[string]any, dropping any non-object element.
func toMapSlice(v any) []map[string]any {
	arr, _ := v.([]any)
	out := make([]map[string]any, 0, len(arr))
	for _, e := range arr {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// auditHasKind reports whether a query_audit response contains at least one
// record of the given Kind ("dispatch", "refusal", "freeze_engage", or
// "freeze_release").
func auditHasKind(resp map[string]any, kind string) bool {
	for _, rec := range toMapSlice(resp["audit"]) {
		if k, _ := rec["kind"].(string); k == kind {
			return true
		}
	}
	return false
}

// assertCapRefusal asserts resp is a blast-radius cap refusal (run_job's
// "error" field, populated before any Node's Task was ever created — the
// dispatcher is never reached on a refusal) mentioning wantClass ("read" or
// "mutate").
func assertCapRefusal(t *testing.T, resp map[string]any, wantClass string) {
	t.Helper()
	errMsg, _ := resp["error"].(string)
	if errMsg == "" {
		t.Fatalf("run_job: expected a blast-cap refusal, got response %v", resp)
	}
	if !strings.Contains(errMsg, "blast-radius cap exceeded") {
		t.Errorf("run_job error = %q, want a blast-radius cap refusal", errMsg)
	}
	if !strings.Contains(errMsg, wantClass) {
		t.Errorf("run_job error = %q, want it to mention risk class %q", errMsg, wantClass)
	}
	if results := toMapSlice(resp["results"]); len(results) != 0 {
		t.Errorf("run_job results = %v, want empty (the dispatcher — and so any Task — is never reached on a cap refusal)", results)
	}
}

func skipUnlessFleetBins(t *testing.T) (relayBin, daemonBin string) {
	t.Helper()
	relayBin = os.Getenv("RELAY_BIN")
	daemonBin = os.Getenv("RELAY_DAEMON_BIN")
	if relayBin == "" || daemonBin == "" {
		relaytest.SkipMissingBin(t, "RELAY_BIN and/or RELAY_DAEMON_BIN not set; skipping fleet e2e (run via make test-crossbinary)")
	}
	return relayBin, daemonBin
}

// TestFleetE2E_OverCapRejectedBothClasses is acceptance criterion 1: a
// Selector matching more Nodes than the applicable cap is rejected before any
// Task runs — for a read Operation, Raw Exec (which always takes the
// mutate-cap, ADR-0012), and a mutate Operation.
func TestFleetE2E_OverCapRejectedBothClasses(t *testing.T) {
	relayBin, daemonBin := skipUnlessFleetBins(t)

	fr := startFleetRelay(t, relayBin, []string{"RELAY_READ_BLAST_CAP=1", "RELAY_MUTATE_BLAST_CAP=1"})

	tokenA := createFleetToken(t, fr.harness, "relay:env=test", "relay:nodeid=a")
	tokenB := createFleetToken(t, fr.harness, "relay:env=test", "relay:nodeid=b")
	policyPath := relaytest.WriteTempFile(t, "policy-*.toml", relaytest.FixturePolicy)
	startDaemonSubprocess(t, daemonBin, fr.addr, fr.caCertPath, tokenA, t.TempDir(), policyPath, "fleet-overcap-a")
	startDaemonSubprocess(t, daemonBin, fr.addr, fr.caCertPath, tokenB, t.TempDir(), policyPath, "fleet-overcap-b")
	waitForConnected(t, fr.harness, 2)

	readResp := fr.harness.callRaw(t, map[string]any{
		"op":         "run_job",
		"selector":   "relay:env=test",
		"operation":  "file.read",
		"args":       map[string]string{"path": "/etc/hostname"},
		"risk_class": "read",
	})
	assertCapRefusal(t, readResp, "read")

	rawResp := fr.harness.callRaw(t, map[string]any{
		"op":       "run_job",
		"selector": "relay:env=test",
		"raw_exec": []string{"/usr/bin/systemctl", "status", "nginx"},
	})
	assertCapRefusal(t, rawResp, "mutate")

	mutateResp := fr.harness.callRaw(t, map[string]any{
		"op":         "run_job",
		"selector":   "relay:env=test",
		"operation":  "service.restart",
		"args":       map[string]string{"unit": "nginx"},
		"risk_class": "mutate",
	})
	assertCapRefusal(t, mutateResp, "mutate")

	auditResp := fr.harness.call(t, map[string]any{"op": "query_audit"})
	if !auditHasKind(auditResp, "refusal") {
		t.Errorf("query_audit: no refusal record found among %v", auditResp["audit"])
	}
}

// TestFleetE2E_JobSpanningOfflineNode is acceptance criterion 2: a Job
// spanning an offline Node reports unreachable for it and real results for
// the rest — no store-and-forward (ADR-0004).
func TestFleetE2E_JobSpanningOfflineNode(t *testing.T) {
	relayBin, daemonBin := skipUnlessFleetBins(t)

	fr := startFleetRelay(t, relayBin, nil)

	tokenA := createFleetToken(t, fr.harness, "relay:env=test", "relay:nodeid=a")
	tokenB := createFleetToken(t, fr.harness, "relay:env=test", "relay:nodeid=b")
	policyPath := relaytest.WriteTempFile(t, "policy-*.toml", relaytest.FixturePolicy)
	startDaemonSubprocess(t, daemonBin, fr.addr, fr.caCertPath, tokenA, t.TempDir(), policyPath, "fleet-offline-a")
	daemonB := startDaemonSubprocess(t, daemonBin, fr.addr, fr.caCertPath, tokenB, t.TempDir(), policyPath, "fleet-offline-b")

	nodeIDs := waitForConnected(t, fr.harness, 2)
	nodeA := nodeByRelayLabel(t, fr.harness, nodeIDs, "nodeid", "a")
	nodeB := nodeByRelayLabel(t, fr.harness, nodeIDs, "nodeid", "b")

	daemonB.Kill()
	waitForNodeConnected(t, fr.harness, nodeB, false)

	wantContent := "hello from fleet offline-node e2e\n"
	contentPath := relaytest.WriteTempFile(t, "content-*.txt", wantContent)
	resp := fr.harness.call(t, map[string]any{
		"op":         "run_job",
		"selector":   "relay:env=test",
		"operation":  "file.read",
		"args":       map[string]string{"path": contentPath},
		"risk_class": "read",
	})
	jobID, _ := resp["job_id"].(string)
	if jobID == "" {
		t.Fatal("run_job: empty job_id in response")
	}
	results := toMapSlice(resp["results"])
	if len(results) != 2 {
		t.Fatalf("run_job results = %v, want 2 entries", results)
	}
	outcomeByNode := make(map[string]string, len(results))
	for _, r := range results {
		nodeID, _ := r["node_id"].(string)
		outcome, _ := r["outcome"].(string)
		outcomeByNode[nodeID] = outcome
	}
	if outcomeByNode[nodeA] != "OUTCOME_SUCCESS" {
		t.Errorf("node A outcome = %q, want OUTCOME_SUCCESS", outcomeByNode[nodeA])
	}
	if outcomeByNode[nodeB] != "OUTCOME_UNREACHABLE" {
		t.Errorf("node B outcome = %q, want OUTCOME_UNREACHABLE", outcomeByNode[nodeB])
	}

	jobResp := fr.harness.call(t, map[string]any{"op": "query_job", "job_id": jobID})
	var foundB bool
	for _, tk := range toMapSlice(jobResp["tasks"]) {
		if tk["node_id"] != nodeB {
			continue
		}
		foundB = true
		if tk["state"] != "resolved" {
			t.Errorf("node B task state = %v, want resolved (never dispatched, ADR-0004)", tk["state"])
		}
		if tk["outcome"] != "OUTCOME_UNREACHABLE" {
			t.Errorf("node B task outcome = %v, want OUTCOME_UNREACHABLE", tk["outcome"])
		}
	}
	if !foundB {
		t.Fatalf("query_job: no task found for node B (%s) among %v", nodeB, jobResp["tasks"])
	}
}

// TestFleetE2E_FreezeStopsDispatch_And_CancelKillsInflightAndUndispatched is
// acceptance criterion 3: Freeze refuses a subsequent dispatch before any
// Task is sent, and Job cancel kills an in-flight Task while stopping an
// undispatched one.
func TestFleetE2E_FreezeStopsDispatch_And_CancelKillsInflightAndUndispatched(t *testing.T) {
	relayBin, daemonBin := skipUnlessFleetBins(t)

	fr := startFleetRelay(t, relayBin, nil)

	tokenA := createFleetToken(t, fr.harness, "relay:env=test", "relay:nodeid=a")
	tokenB := createFleetToken(t, fr.harness, "relay:env=test", "relay:nodeid=b")
	policyPath := relaytest.WriteTempFile(t, "policy-*.toml", relaytest.FixturePolicy)
	startDaemonSubprocess(t, daemonBin, fr.addr, fr.caCertPath, tokenA, t.TempDir(), policyPath, "fleet-freeze-a")
	startDaemonSubprocess(t, daemonBin, fr.addr, fr.caCertPath, tokenB, t.TempDir(), policyPath, "fleet-freeze-b")
	waitForConnected(t, fr.harness, 2)

	// -------------------------------------------------------------------
	// (a) Freeze stops dispatch before any Task is sent.
	// -------------------------------------------------------------------
	if err := fr.cmd.Process.Signal(syscall.SIGUSR1); err != nil {
		t.Fatalf("send SIGUSR1 (engage Freeze) to relay: %v", err)
	}
	waitForFrozen(t, fr.harness, true)

	frozenResp := fr.harness.callRaw(t, map[string]any{
		"op":         "run_job",
		"selector":   "relay:env=test",
		"operation":  "file.read",
		"args":       map[string]string{"path": "/etc/hostname"},
		"risk_class": "read",
	})
	errMsg, _ := frozenResp["error"].(string)
	if errMsg == "" || !strings.Contains(errMsg, "Freeze") {
		t.Fatalf("run_job while frozen: error = %q, want a Freeze refusal", errMsg)
	}
	if results := toMapSlice(frozenResp["results"]); len(results) != 0 {
		t.Errorf("run_job while frozen: results = %v, want empty (no Task ever sent)", results)
	}

	auditResp := fr.harness.call(t, map[string]any{"op": "query_audit"})
	if !auditHasKind(auditResp, "freeze_engage") {
		t.Errorf("query_audit: no freeze_engage record found among %v", auditResp["audit"])
	}
	if !auditHasKind(auditResp, "refusal") {
		t.Errorf("query_audit: no refusal record found among %v", auditResp["audit"])
	}

	if err := fr.cmd.Process.Signal(syscall.SIGUSR2); err != nil {
		t.Fatalf("send SIGUSR2 (release Freeze) to relay: %v", err)
	}
	waitForFrozen(t, fr.harness, false)

	unfrozenResp := fr.harness.call(t, map[string]any{
		"op":         "run_job",
		"selector":   "relay:env=test",
		"operation":  "file.read",
		"args":       map[string]string{"path": "/etc/hostname"},
		"risk_class": "read",
	})
	if results := toMapSlice(unfrozenResp["results"]); len(results) != 2 {
		t.Fatalf("run_job after Freeze release: results = %v, want 2 entries", results)
	}

	// -------------------------------------------------------------------
	// (b) Cancel kills an in-flight Task and stops an undispatched one.
	// jobEngine dispatches Nodes sequentially (execution.go), so whichever
	// Node is dispatched first sits in-flight (running /bin/sleep 30) while
	// the other's Task is still Pending when cancel_job races in.
	// -------------------------------------------------------------------
	harness2 := dialHarness(t, fr.sockPath)
	type runOutcome struct {
		resp map[string]any
		err  error
	}
	runDone := make(chan runOutcome, 1)
	go func() {
		// send (not call/callRaw): this goroutine must never touch *testing.T
		// — the main goroutine reads the result off runDone instead.
		resp, err := harness2.send(map[string]any{
			"op":         "run_job",
			"selector":   "relay:env=test",
			"raw_exec":   []string{"/bin/sleep", "30"},
			"risk_class": "mutate",
		})
		runDone <- runOutcome{resp: resp, err: err}
	}()

	jobID := waitForInFlightJobID(t, fr.harness)

	fr.harness.call(t, map[string]any{"op": "cancel_job", "job_id": jobID})

	select {
	case out := <-runDone:
		if out.err != nil {
			t.Fatalf("run_job (cancel target): %v", out.err)
		}
		if errMsg, _ := out.resp["error"].(string); errMsg != "" {
			t.Fatalf("run_job (cancel target) failed: %s", errMsg)
		}
		results := toMapSlice(out.resp["results"])
		if len(results) != 2 {
			t.Fatalf("cancelled run_job results = %v, want 2 entries", results)
		}
		for _, r := range results {
			if r["outcome"] != "OUTCOME_CANCELLED" {
				t.Errorf("cancelled run_job result %v, want OUTCOME_CANCELLED", r)
			}
		}
	case <-time.After(20 * time.Second):
		t.Fatal("cancel_job did not unblock the in-flight run_job within 20s")
	}

	jobResp := fr.harness.call(t, map[string]any{"op": "query_job", "job_id": jobID})
	tasks := toMapSlice(jobResp["tasks"])
	if len(tasks) != 2 {
		t.Fatalf("query_job tasks = %v, want 2", tasks)
	}
	for _, tk := range tasks {
		if tk["outcome"] != "OUTCOME_CANCELLED" {
			t.Errorf("task %v outcome = %v, want OUTCOME_CANCELLED", tk["task_id"], tk["outcome"])
		}
	}
}

// TestFleetE2E_AuditAndRestartSurvival is acceptance criterion 4: every
// dispatch produces a queryable audit record, and Jobs/Tasks/audit survive a
// Relay restart.
func TestFleetE2E_AuditAndRestartSurvival(t *testing.T) {
	relayBin, daemonBin := skipUnlessFleetBins(t)

	fr := startFleetRelay(t, relayBin, nil)

	token := createFleetToken(t, fr.harness, "relay:env=test")
	policyPath := relaytest.WriteTempFile(t, "policy-*.toml", relaytest.FixturePolicy)
	startDaemonSubprocess(t, daemonBin, fr.addr, fr.caCertPath, token, t.TempDir(), policyPath, "fleet-restart-node")
	waitForConnected(t, fr.harness, 1)

	wantContent := "hello from fleet restart-survival e2e\n"
	contentPath := relaytest.WriteTempFile(t, "content-*.txt", wantContent)
	resp := fr.harness.call(t, map[string]any{
		"op":         "run_job",
		"selector":   "relay:env=test",
		"operation":  "file.read",
		"args":       map[string]string{"path": contentPath},
		"risk_class": "read",
	})
	jobID, _ := resp["job_id"].(string)
	if jobID == "" {
		t.Fatal("run_job: empty job_id in response")
	}
	results := toMapSlice(resp["results"])
	if len(results) != 1 || results[0]["outcome"] != "OUTCOME_SUCCESS" {
		t.Fatalf("run_job results = %v, want 1 entry with OUTCOME_SUCCESS", results)
	}

	auditResp := fr.harness.call(t, map[string]any{"op": "query_audit", "job_id": jobID})
	auditBefore := toMapSlice(auditResp["audit"])
	if len(auditBefore) == 0 {
		t.Fatal("query_audit(job_id): no records found for a just-dispatched Job")
	}
	for _, rec := range auditBefore {
		if rec["kind"] != "dispatch" {
			t.Errorf("audit record kind = %v, want dispatch", rec["kind"])
		}
	}

	// Restart the Relay against the SAME store/addr/CA dir.
	fr.restart(t, nil)

	jobResp := fr.harness.call(t, map[string]any{"op": "query_job", "job_id": jobID})
	tasks := toMapSlice(jobResp["tasks"])
	if len(tasks) != 1 || tasks[0]["state"] != "resolved" || tasks[0]["outcome"] != "OUTCOME_SUCCESS" {
		t.Errorf("query_job after restart: tasks = %v, want 1 resolved/OUTCOME_SUCCESS entry", tasks)
	}

	auditAfterResp := fr.harness.call(t, map[string]any{"op": "query_audit", "job_id": jobID})
	auditAfter := toMapSlice(auditAfterResp["audit"])
	if len(auditAfter) != len(auditBefore) {
		t.Errorf("query_audit after restart = %d record(s), want %d (same as before restart)", len(auditAfter), len(auditBefore))
	}
}

// TestFleetE2E_CrashMidJobNeverDoubleRuns is acceptance criterion 5 — the
// hardest one (ADR-0004): kill the Relay after a Task is durably Dispatched
// but before any Result lands, restart both the Relay and the daemon (the
// daemon has no reconnect loop of its own), and confirm the Task is not
// re-run: the daemon's own dedup marker (daemon/src/dedup.rs) makes the
// reconciled resend return the benign already-processed result, never a
// second real execution.
func TestFleetE2E_CrashMidJobNeverDoubleRuns(t *testing.T) {
	relayBin, daemonBin := skipUnlessFleetBins(t)

	fr := startFleetRelay(t, relayBin, nil)

	token := createFleetToken(t, fr.harness, "relay:env=test")
	policyPath := relaytest.WriteTempFile(t, "policy-*.toml", relaytest.FixturePolicy)
	stateDir := t.TempDir()
	daemon := startDaemonSubprocess(t, daemonBin, fr.addr, fr.caCertPath, token, stateDir, policyPath, "fleet-crash-node")
	waitForConnected(t, fr.harness, 1)

	harness2 := dialHarness(t, fr.sockPath)
	go func() {
		// Fire-and-forget: by the time this send would return, the Relay has
		// already been killed (or the Task has genuinely finished); the test
		// never reads this response. send (not call/callRaw) never touches
		// *testing.T, so it is safe to ignore from a background goroutine.
		_, _ = harness2.send(map[string]any{
			"op":         "run_job",
			"selector":   "relay:env=test",
			"raw_exec":   []string{"/bin/sleep", "30"},
			"risk_class": "mutate",
		})
	}()

	// Learn the Job's ID once its Task is in flight (Dispatched, no Result
	// yet — the daemon has recorded its dedup marker and started the sleep).
	jobID := waitForInFlightJobID(t, fr.harness)

	// MarkDispatched is durably committed at this point (list_inflight only
	// sees it once persisted); sleep further so there is no doubt the write
	// landed well before the crash, and the sleep is nowhere near done.
	time.Sleep(1500 * time.Millisecond)

	// Kill -9 the Relay: a real crash, not a graceful shutdown (no deferred
	// stop() runs, mirroring an actual power-loss/OOM-kill). The daemon's
	// stream drops when the Relay dies; it has no reconnect loop
	// (daemon/src/main.rs) so it exits on its own, but kill it explicitly too
	// so the test never depends on that timing. Reaping (the corresponding
	// receive on fr.exited) is left to restart() below: fr.exited only ever
	// delivers once, so it must have exactly one reader.
	if fr.cmd.Process != nil {
		fr.cmd.Process.Kill() //nolint:errcheck
	}
	daemon.Kill()

	// Restart the Relay on the SAME store/addr/CA dir: its persisted store
	// still has the Task Dispatched with no Result (TaskRepository.InFlight).
	fr.restart(t, nil)

	// Relaunch the daemon against the SAME stateDir: persisted identity and
	// persisted dedup marker survive. On reconnect, Router.onConnect ->
	// Reconciler.ReconcileNode resends the in-flight Task; the daemon's dedup
	// returns the benign already-processed result WITHOUT re-executing.
	daemon.Relaunch()

	// Poll query_job until the Task reaches Resolved.
	var task map[string]any
	deadline := time.Now().Add(30 * time.Second)
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
		time.Sleep(100 * time.Millisecond)
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
}
