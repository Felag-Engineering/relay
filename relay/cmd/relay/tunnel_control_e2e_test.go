//go:build integration

// Package main: tunnel_control_e2e_test.go proves the v0.0.4 acceptance
// criteria (milestone "Execution Control & Policy Tooling") end to
// end, over the real mTLS Tunnel with a real relay-daemon subprocess:
//
//  1. TestE2E_CancelInFlightAndRaceWindow — cancel kills the process group and
//     reports OUTCOME_CANCELLED; a Task that finished in the race window still
//     reports success, and cancelling a deregistered id is a no-op (ADR-0013).
//  2. TestE2E_MutateSerialReadParallel — mutate Tasks never overlap; read
//     Tasks are not serialized behind a held mutate slot (ADR-0004/0012).
//  3. TestE2E_PolicyQueryMatchesExecution — PolicyQuery verdicts match what
//     real execution then does, across allow / deny-by-default /
//     deny-beats-allow / Raw Exec allow / Raw Exec deny (ADR-0011).
//  4. TestE2E_PolicyCheckAgreesWithLiveEngine — the offline `policy check`
//     subcommand rejects a malformed Policy file and agrees with the live
//     wire dispatch outcome for the same actions on the same Policy file.
//  5. TestE2E_RegistryFingerprintAfterReconnect — the registry reports the
//     Node's Policy fingerprint after connect and again after a reconnect,
//     unchanged (ADR-0002/0006 drift visibility; report-only, no write-back).
//
// All five reuse the startDaemonNode harness in tunnel_dispatch_e2e_test.go.
// The Relay never evaluates Policy itself (ADR-0011): these tests only send
// PolicyQuery/TaskRequest and read back PolicyVerdict/TaskResult/registry
// state — no Go-side Policy evaluation is added anywhere in this file.
package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"testing"
	"time"

	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// ---------------------------------------------------------------------------
// AC1: cancel in-flight, honest race window
// ---------------------------------------------------------------------------

func TestE2E_CancelInFlightAndRaceWindow(t *testing.T) {
	node := startDaemonNode(t, relaytest.FixturePolicy)
	resultCh := node.resultCh()

	// (a) In-flight cancel: dispatch a long-running raw_exec, wait long enough
	// that the process is definitely spawned and running (30x margin over the
	// 300ms cancel timing exercised by executor.rs::cancel_kills_group_no_orphans),
	// then cancel it. Expect OUTCOME_CANCELLED, exit_code -1 (ADR-0013).
	sleepTask := &relayv1.RelayMessage{
		Body: &relayv1.RelayMessage_Task{
			Task: &relayv1.TaskRequest{
				TaskId:         "cancel-sleep",
				TimeoutSeconds: 60,
				Action: &relayv1.TaskRequest_RawExec{RawExec: &relayv1.RawExec{
					Argv: []string{"/bin/sleep", "30"},
				}},
			},
		},
	}
	if err := node.disp.Dispatch(node.nodeID, sleepTask); err != nil {
		t.Fatalf("Dispatch cancel-sleep: %v", err)
	}
	time.Sleep(time.Second)
	if err := node.disp.SendCancel(node.nodeID, "cancel-sleep"); err != nil {
		t.Fatalf("SendCancel cancel-sleep: %v", err)
	}
	select {
	case result := <-resultCh:
		if result.TaskId != "cancel-sleep" {
			t.Errorf("TaskId: got %q, want %q", result.TaskId, "cancel-sleep")
		}
		if result.Outcome != relayv1.Outcome_OUTCOME_CANCELLED {
			t.Errorf("outcome: got %v, want OUTCOME_CANCELLED", result.Outcome)
		}
		if result.ExitCode != -1 {
			t.Errorf("exit_code: got %d, want -1", result.ExitCode)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout: no TaskResult for cancel-sleep")
	}

	// (b) Honest race, made deterministic by ordering: await SUCCESS first,
	// THEN cancel the now-finished/deregistered id. A Task that completed
	// must never become a retroactive cancelled, and cancelling a
	// deregistered id must be a harmless no-op (ADR-0013).
	contentPath := relaytest.WriteTempFile(t, "content-*.txt", "race-fast content\n")
	fastTask := &relayv1.RelayMessage{
		Body: &relayv1.RelayMessage_Task{
			Task: &relayv1.TaskRequest{
				TaskId:         "race-fast",
				TimeoutSeconds: 10,
				Action: &relayv1.TaskRequest_Operation{Operation: &relayv1.Operation{
					Name: "file.read",
					Args: map[string]string{"path": contentPath},
				}},
			},
		},
	}
	if err := node.disp.Dispatch(node.nodeID, fastTask); err != nil {
		t.Fatalf("Dispatch race-fast: %v", err)
	}
	select {
	case result := <-resultCh:
		if result.TaskId != "race-fast" {
			t.Errorf("TaskId: got %q, want %q", result.TaskId, "race-fast")
		}
		if result.Outcome != relayv1.Outcome_OUTCOME_SUCCESS {
			t.Fatalf("outcome: got %v, want OUTCOME_SUCCESS", result.Outcome)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout: no TaskResult for race-fast")
	}
	if err := node.disp.SendCancel(node.nodeID, "race-fast"); err != nil {
		t.Fatalf("SendCancel race-fast: %v", err)
	}
	select {
	case result := <-resultCh:
		t.Fatalf("unexpected second TaskResult for race-fast after cancel: %+v", result)
	case <-time.After(time.Second):
		// Expected: cancel of an already-finished/deregistered id is a no-op.
	}
}

// ---------------------------------------------------------------------------
// AC2: mutate serial / read independent of mutate
// ---------------------------------------------------------------------------

func TestE2E_MutateSerialReadParallel(t *testing.T) {
	node := startDaemonNode(t, relaytest.FixturePolicy)
	resultCh := node.resultCh()

	// (a) Mutate serial: two raw_exec /bin/sleep 1 Tasks dispatched
	// back-to-back must never overlap (ADR-0012 mutate lane is Semaphore(1)).
	t0 := time.Now()
	for _, id := range []string{"mut-a", "mut-b"} {
		task := &relayv1.RelayMessage{
			Body: &relayv1.RelayMessage_Task{
				Task: &relayv1.TaskRequest{
					TaskId:         id,
					TimeoutSeconds: 10,
					Action: &relayv1.TaskRequest_RawExec{RawExec: &relayv1.RawExec{
						Argv: []string{"/bin/sleep", "1"},
					}},
				},
			},
		}
		if err := node.disp.Dispatch(node.nodeID, task); err != nil {
			t.Fatalf("Dispatch %s: %v", id, err)
		}
	}
	mutateResults := make(map[string]*relayv1.TaskResult, 2)
	mutateDeadline := time.After(15 * time.Second)
	for len(mutateResults) < 2 {
		select {
		case r := <-resultCh:
			mutateResults[r.TaskId] = r
		case <-mutateDeadline:
			t.Fatalf("timeout: only got %d/2 mutate results: %v", len(mutateResults), mutateResults)
		}
	}
	// Parallel execution would finish in ~1s; serial execution takes ~2s.
	// 1.8s is a generous one-sided threshold, never equality on wall time.
	if wallElapsed := time.Since(t0); wallElapsed < 1800*time.Millisecond {
		t.Errorf("mutate Tasks appear to have overlapped: wall elapsed %v, want >= 1.8s", wallElapsed)
	}
	mutA, okA := mutateResults["mut-a"]
	mutB, okB := mutateResults["mut-b"]
	if !okA || !okB {
		t.Fatalf("missing mutate results: got %v", mutateResults)
	}
	if mutA.Outcome != relayv1.Outcome_OUTCOME_SUCCESS {
		t.Errorf("mut-a outcome: got %v, want SUCCESS; stderr=%q", mutA.Outcome, mutA.Stderr)
	}
	if mutB.Outcome != relayv1.Outcome_OUTCOME_SUCCESS {
		t.Errorf("mut-b outcome: got %v, want SUCCESS; stderr=%q", mutB.Outcome, mutB.Stderr)
	}
	// duration_millis is measured by the executor from the moment a Task
	// actually starts running (executor.rs's own `started` clock) — it does
	// NOT include queue-wait time (that clock, `received_at`, only surfaces in
	// duration_millis on the queued-timeout/queued-cancel exit paths). So both
	// Tasks' own duration_millis are expected to be close to the 1s sleep
	// regardless of queue position; the wall-clock assertion above (elapsed
	// >= 1.8s across two back-to-back dispatches) is what proves the two
	// Tasks did not overlap. Sanity-check here only that each Task actually
	// ran its full ~1s sleep (not e.g. an instant no-op).
	for _, r := range []*relayv1.TaskResult{mutA, mutB} {
		if r.DurationMillis < 700 {
			t.Errorf("%s duration_millis = %d, want >= 700 (must have run the full /bin/sleep 1)",
				r.TaskId, r.DurationMillis)
		}
	}

	// (b) Reads are independent of / not blocked behind the mutate lane:
	// occupy the mutate lane with a 2s sleep, then dispatch 4 file.read Tasks.
	// All 4 must complete near-instantly in the independent read lane, not
	// behind the 2s mutate hold. (The read lane's own peak==4 bounded-parallel
	// semantics are proven deterministically by scheduler.rs unit tests
	// ac2_read_bounded_max_four / ac3_read_and_mutate_concurrent — there is no
	// slow-read Operation to gauge peak overlap over the wire.)
	contentPath := relaytest.WriteTempFile(t, "content-*.txt", "read parallel content\n")
	holdTask := &relayv1.RelayMessage{
		Body: &relayv1.RelayMessage_Task{
			Task: &relayv1.TaskRequest{
				TaskId:         "mut-hold",
				TimeoutSeconds: 10,
				Action: &relayv1.TaskRequest_RawExec{RawExec: &relayv1.RawExec{
					Argv: []string{"/bin/sleep", "2"},
				}},
			},
		},
	}
	if err := node.disp.Dispatch(node.nodeID, holdTask); err != nil {
		t.Fatalf("Dispatch mut-hold: %v", err)
	}
	// readsStart is a real wall-clock capture: duration_millis (asserted below)
	// excludes queue-wait, so it cannot by itself prove the reads weren't
	// serialized behind the 2s mutate hold. This wall-clock signal can.
	readsStart := time.Now()
	readIDs := []string{"rd-0", "rd-1", "rd-2", "rd-3"}
	for _, id := range readIDs {
		task := &relayv1.RelayMessage{
			Body: &relayv1.RelayMessage_Task{
				Task: &relayv1.TaskRequest{
					TaskId:         id,
					TimeoutSeconds: 10,
					Action: &relayv1.TaskRequest_Operation{Operation: &relayv1.Operation{
						Name: "file.read",
						Args: map[string]string{"path": contentPath},
					}},
				},
			},
		}
		if err := node.disp.Dispatch(node.nodeID, task); err != nil {
			t.Fatalf("Dispatch %s: %v", id, err)
		}
	}
	readResults := make(map[string]*relayv1.TaskResult, len(readIDs))
	readDeadline := time.After(5 * time.Second)
	for len(readResults) < len(readIDs) {
		select {
		case r := <-resultCh:
			if r.TaskId == "mut-hold" {
				t.Fatalf("mut-hold (2s sleep) completed before all 4 reads — reads were blocked behind mutate")
			}
			readResults[r.TaskId] = r
		case <-readDeadline:
			t.Fatalf("timeout: only got %d/%d read results: %v", len(readResults), len(readIDs), readResults)
		}
	}
	// Real wall-clock signal: duration_millis is measured by the executor
	// from Task start (after leaving the queue), so it EXCLUDES queue-wait —
	// a read wrongly stalled 2s behind the mutate lane would still report
	// near-zero duration_millis and pass a duration_millis-only check. This
	// wall-clock capture (from before the reads were even dispatched) is the
	// real signal: all 4 reads must return well under the 2s mutate hold,
	// proving they were not serialized behind it. The mut-hold-arrives-first
	// guard above (which fails if mut-hold's result appears before all 4
	// reads) remains the load-bearing ordering proof.
	if elapsed := time.Since(readsStart); elapsed >= 1500*time.Millisecond {
		t.Errorf("reads took %v (wall clock) to return, want < 1500ms (must not be blocked behind the 2s mut-hold)",
			elapsed)
	}
	for _, id := range readIDs {
		r, ok := readResults[id]
		if !ok {
			t.Errorf("missing read result for %s", id)
			continue
		}
		if r.Outcome != relayv1.Outcome_OUTCOME_SUCCESS {
			t.Errorf("%s outcome: got %v, want SUCCESS; stderr=%q", id, r.Outcome, r.Stderr)
		}
	}
}

// ---------------------------------------------------------------------------
// Shared Policy matrix (AC3, AC4): allow / deny-by-default / deny-beats-allow /
// Raw Exec allow / Raw Exec deny, evaluated against relaytest.FixturePolicy.
// ---------------------------------------------------------------------------

// policyMatrixCase pairs a PolicyQuery/TaskRequest builder with the CLI
// `--would-allow` spec for the identical action, and the expected verdict.
type policyMatrixCase struct {
	label      string
	wantAllow  bool
	cliSpec    []string // args following "--would-allow", exact operation_positional_args key spelling
	buildQuery func(queryID string) *relayv1.PolicyQuery
	buildTask  func(taskID string) *relayv1.TaskRequest
}

// policyMatrixCases returns the v0.0.4 acceptance matrix: allow, deny-by-default,
// deny-beats-allow, Raw Exec allow, Raw Exec deny — all against relaytest.FixturePolicy.
// contentPath must be a file.read-able temp file (allow case gives a clean
// SUCCESS unlike the systemctl allow case, which may FAIL on a box without
// systemd — assertions key on DENIED_BY_POLICY vs not, never on SUCCESS).
func policyMatrixCases(contentPath string) []policyMatrixCase {
	return []policyMatrixCase{
		{
			label:     "file.read allow",
			wantAllow: true,
			cliSpec:   []string{"operation", "file.read", "path=" + contentPath},
			buildQuery: func(queryID string) *relayv1.PolicyQuery {
				return &relayv1.PolicyQuery{
					QueryId: queryID,
					Action: &relayv1.PolicyQuery_Operation{Operation: &relayv1.Operation{
						Name: "file.read",
						Args: map[string]string{"path": contentPath},
					}},
				}
			},
			buildTask: func(taskID string) *relayv1.TaskRequest {
				return &relayv1.TaskRequest{
					TaskId:         taskID,
					TimeoutSeconds: 10,
					Action: &relayv1.TaskRequest_Operation{Operation: &relayv1.Operation{
						Name: "file.read",
						Args: map[string]string{"path": contentPath},
					}},
				}
			},
		},
		{
			label:     "service.restart deny-by-default",
			wantAllow: false,
			cliSpec:   []string{"operation", "service.restart", "unit=sshd"},
			buildQuery: func(queryID string) *relayv1.PolicyQuery {
				return &relayv1.PolicyQuery{
					QueryId: queryID,
					Action: &relayv1.PolicyQuery_Operation{Operation: &relayv1.Operation{
						Name: "service.restart",
						Args: map[string]string{"unit": "sshd"},
					}},
				}
			},
			buildTask: func(taskID string) *relayv1.TaskRequest {
				return &relayv1.TaskRequest{
					TaskId:         taskID,
					TimeoutSeconds: 10,
					Action: &relayv1.TaskRequest_Operation{Operation: &relayv1.Operation{
						Name: "service.restart",
						Args: map[string]string{"unit": "sshd"},
					}},
				}
			},
		},
		{
			label:     "file.read deny-beats-allow",
			wantAllow: false,
			cliSpec:   []string{"operation", "file.read", "path=/etc/shadow"},
			buildQuery: func(queryID string) *relayv1.PolicyQuery {
				return &relayv1.PolicyQuery{
					QueryId: queryID,
					Action: &relayv1.PolicyQuery_Operation{Operation: &relayv1.Operation{
						Name: "file.read",
						Args: map[string]string{"path": "/etc/shadow"},
					}},
				}
			},
			buildTask: func(taskID string) *relayv1.TaskRequest {
				return &relayv1.TaskRequest{
					TaskId:         taskID,
					TimeoutSeconds: 10,
					Action: &relayv1.TaskRequest_Operation{Operation: &relayv1.Operation{
						Name: "file.read",
						Args: map[string]string{"path": "/etc/shadow"},
					}},
				}
			},
		},
		{
			label:     "raw_exec systemctl allow",
			wantAllow: true,
			cliSpec:   []string{"raw-exec", "--", "/usr/bin/systemctl", "status", "nginx"},
			buildQuery: func(queryID string) *relayv1.PolicyQuery {
				return &relayv1.PolicyQuery{
					QueryId: queryID,
					Action: &relayv1.PolicyQuery_RawExec{RawExec: &relayv1.RawExec{
						Argv: []string{"/usr/bin/systemctl", "status", "nginx"},
					}},
				}
			},
			buildTask: func(taskID string) *relayv1.TaskRequest {
				return &relayv1.TaskRequest{
					TaskId:         taskID,
					TimeoutSeconds: 10,
					Action: &relayv1.TaskRequest_RawExec{RawExec: &relayv1.RawExec{
						Argv: []string{"/usr/bin/systemctl", "status", "nginx"},
					}},
				}
			},
		},
		{
			label:     "raw_exec rm deny",
			wantAllow: false,
			cliSpec:   []string{"raw-exec", "--", "/bin/rm", "-rf", "/tmp/relay-e2e-should-not-run"},
			buildQuery: func(queryID string) *relayv1.PolicyQuery {
				return &relayv1.PolicyQuery{
					QueryId: queryID,
					Action: &relayv1.PolicyQuery_RawExec{RawExec: &relayv1.RawExec{
						Argv: []string{"/bin/rm", "-rf", "/tmp/relay-e2e-should-not-run"},
					}},
				}
			},
			buildTask: func(taskID string) *relayv1.TaskRequest {
				return &relayv1.TaskRequest{
					TaskId:         taskID,
					TimeoutSeconds: 10,
					Action: &relayv1.TaskRequest_RawExec{RawExec: &relayv1.RawExec{
						Argv: []string{"/bin/rm", "-rf", "/tmp/relay-e2e-should-not-run"},
					}},
				}
			},
		},
	}
}

// ---------------------------------------------------------------------------
// AC3: PolicyQuery verdicts match subsequent real execution
// ---------------------------------------------------------------------------

func TestE2E_PolicyQueryMatchesExecution(t *testing.T) {
	node := startDaemonNode(t, relaytest.FixturePolicy)
	resultCh := node.resultCh()
	verdictCh := node.verdictCh()

	contentPath := relaytest.WriteTempFile(t, "content-*.txt", "policy query matches execution\n")
	cases := policyMatrixCases(contentPath)

	for i, c := range cases {
		queryID := fmt.Sprintf("pq-%d", i)
		taskID := fmt.Sprintf("pq-task-%d", i)

		if err := node.disp.SendPolicyQuery(node.nodeID, c.buildQuery(queryID)); err != nil {
			t.Fatalf("[%s] SendPolicyQuery: %v", c.label, err)
		}
		var verdict *relayv1.PolicyVerdict
		select {
		case v := <-verdictCh:
			verdict = v
		case <-time.After(10 * time.Second):
			t.Fatalf("[%s] timeout waiting for PolicyVerdict", c.label)
		}
		if verdict.QueryId != queryID {
			t.Errorf("[%s] verdict query_id: got %q, want %q", c.label, verdict.QueryId, queryID)
		}
		if verdict.Allowed != c.wantAllow {
			t.Errorf("[%s] verdict.Allowed: got %v, want %v", c.label, verdict.Allowed, c.wantAllow)
		}
		if !verdict.Allowed && verdict.DecidingRule == "" {
			t.Errorf("[%s] deny verdict must carry a non-empty deciding_rule", c.label)
		}

		task := &relayv1.RelayMessage{Body: &relayv1.RelayMessage_Task{Task: c.buildTask(taskID)}}
		if err := node.disp.Dispatch(node.nodeID, task); err != nil {
			t.Fatalf("[%s] Dispatch: %v", c.label, err)
		}
		var result *relayv1.TaskResult
		select {
		case r := <-resultCh:
			result = r
		case <-time.After(15 * time.Second):
			t.Fatalf("[%s] timeout waiting for TaskResult", c.label)
		}
		// Allow cases may execute to FAILURE on a box without systemd/rm; key
		// the assertion on DENIED_BY_POLICY vs not, exactly as the daemon's own
		// unit test does — never on SUCCESS for systemctl.
		execAllowed := result.Outcome != relayv1.Outcome_OUTCOME_DENIED_BY_POLICY
		if execAllowed != c.wantAllow {
			t.Errorf("[%s] execution outcome %v (denied=%v) does not match expected allow=%v",
				c.label, result.Outcome, !execAllowed, c.wantAllow)
		}
		if verdict.Allowed != execAllowed {
			t.Errorf("[%s] verdict.Allowed=%v does not match execution allow=%v",
				c.label, verdict.Allowed, execAllowed)
		}
	}
}

// ---------------------------------------------------------------------------
// AC4: `policy check` agrees with the live engine
// ---------------------------------------------------------------------------

func TestE2E_PolicyCheckAgreesWithLiveEngine(t *testing.T) {
	node := startDaemonNode(t, relaytest.FixturePolicy)
	resultCh := node.resultCh()

	// (a) Malformed variant: an invalid raw_exec regex must be rejected with
	// exit code 1 and a useful stderr message. No Tunnel needed for the CLI.
	malformedPath := relaytest.WriteTempFile(t, "malformed-*.toml", `
[raw_exec]
allow = ["[invalid"]
`)
	malformedCmd := exec.Command(node.daemonBin, "policy", "check", malformedPath)
	var malformedStderr bytes.Buffer
	malformedCmd.Stderr = &malformedStderr
	err := malformedCmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("policy check malformed: expected *exec.ExitError, got %v (stderr=%q)", err, malformedStderr.String())
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("policy check malformed: exit code got %d, want 1 (stderr=%q)", exitErr.ExitCode(), malformedStderr.String())
	}
	if malformedStderr.Len() == 0 {
		t.Error("policy check malformed: expected a non-empty stderr message")
	}

	// (b) --would-allow vs live dispatch parity, on the SAME on-disk Policy
	// file the daemon subprocess loaded (node.policyPath) — binding the
	// offline CLI to the live engine on an unchanged Policy (ADR-0011).
	contentPath := relaytest.WriteTempFile(t, "content-*.txt", "policy check parity\n")
	cases := policyMatrixCases(contentPath)

	for i, c := range cases {
		args := append([]string{"policy", "check", node.policyPath, "--would-allow"}, c.cliSpec...)
		cliCmd := exec.Command(node.daemonBin, args...)
		var cliStderr bytes.Buffer
		cliCmd.Stderr = &cliStderr
		var cliErr error
		if runErr := cliCmd.Run(); runErr != nil {
			ee, ok := runErr.(*exec.ExitError)
			if !ok {
				t.Fatalf("[%s] policy check --would-allow: %v (stderr=%q)", c.label, runErr, cliStderr.String())
			}
			cliErr = ee
		}
		// Exit 0 = allow, exit 2 = would-deny. Exit 1 (invalid) is never
		// expected here since relaytest.FixturePolicy is already known-valid — assert
		// that explicitly so a regression making a valid check exit 1 can't
		// be silently collapsed into "deny" and hidden behind a coincidental
		// wire DENIED_BY_POLICY (cliAllowed := cliErr == nil would score exit
		// 1 identically to exit 2).
		code := 0
		if cliErr != nil {
			code = cliErr.(*exec.ExitError).ExitCode()
		}
		if code != 0 && code != 2 {
			t.Fatalf("[%s] policy check --would-allow: exit code %d, want 0 (allow) or 2 (would-deny), never 1 (invalid) (stderr=%q)",
				c.label, code, cliStderr.String())
		}
		cliAllowed := code == 0

		taskID := fmt.Sprintf("pc-task-%d", i)
		task := &relayv1.RelayMessage{Body: &relayv1.RelayMessage_Task{Task: c.buildTask(taskID)}}
		if err := node.disp.Dispatch(node.nodeID, task); err != nil {
			t.Fatalf("[%s] Dispatch: %v", c.label, err)
		}
		var result *relayv1.TaskResult
		select {
		case r := <-resultCh:
			result = r
		case <-time.After(15 * time.Second):
			t.Fatalf("[%s] timeout waiting for TaskResult", c.label)
		}
		wireAllowed := result.Outcome != relayv1.Outcome_OUTCOME_DENIED_BY_POLICY
		if cliAllowed != wireAllowed {
			t.Errorf("[%s] policy check --would-allow allowed=%v, wire dispatch allowed=%v (outcome=%v)",
				c.label, cliAllowed, wireAllowed, result.Outcome)
		}
	}
}

// ---------------------------------------------------------------------------
// AC5: registry shows the Node's Policy fingerprint after (re)connect
// ---------------------------------------------------------------------------

func TestE2E_RegistryFingerprintAfterReconnect(t *testing.T) {
	node := startDaemonNode(t, relaytest.FixturePolicy)

	before, ok := node.deps.registry.Get(node.nodeID)
	if !ok {
		t.Fatal("node not found in registry after connect")
	}
	if before.PolicyFingerprint == "" {
		t.Fatal("PolicyFingerprint is empty after initial connect")
	}

	// Kill the daemon and relaunch it against the same stateDir/policyPath —
	// it reconnects as the same Node (identity persisted in stateDir).
	node.restart()

	after, ok := node.deps.registry.Get(node.nodeID)
	if !ok {
		t.Fatal("node not found in registry after reconnect")
	}
	if after.PolicyFingerprint == "" {
		t.Fatal("PolicyFingerprint is empty after reconnect")
	}
	if after.PolicyFingerprint != before.PolicyFingerprint {
		t.Errorf("PolicyFingerprint changed after reconnect on an unchanged Policy file: got %q, want %q",
			after.PolicyFingerprint, before.PolicyFingerprint)
	}
}
