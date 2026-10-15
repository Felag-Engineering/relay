// Package main: approval_release_once_e2e_test.go proves AP-77 ("an approval
// releases one execution", #713) through the REAL composition root, across
// surfaces: a single-Plan approval's release is claimed exactly once, and
// every later re-drive of the same plan — on the Control API or through MCP,
// by the original requester or a different Account — re-attaches to the Job
// it already released rather than dispatching a second one.
//
// The Console is not exercised here: it does not execute yet (invariant 10's
// gap table, #438), so it is covered by construction through Execution.Run and
// needs no screen test of its own.
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// decodeRunOutput decodes an MCP run_operation CallToolResult's text content
// into mcp.ExecutionOutput. ExecutionOutput's JobID/Results fields are the
// JSON-tag-compatible subset of run_operation's real RunOrPlanOutput shape
// (mirroring mcp_execution_e2e_test.go's own decode), which is all this test
// needs: whether a Job was produced, and which one.
func decodeRunOutput(t *testing.T, res *sdkmcp.CallToolResult) mcp.ExecutionOutput {
	t.Helper()
	if res.IsError {
		t.Fatalf("run_operation returned IsError=true; content = %+v", res.Content)
	}
	if len(res.Content) == 0 {
		t.Fatal("run_operation: CallToolResult.Content is empty")
	}
	tc, ok := res.Content[0].(*sdkmcp.TextContent)
	if !ok {
		t.Fatalf("run_operation: Content[0] = %T, want *sdkmcp.TextContent", res.Content[0])
	}
	var out mcp.ExecutionOutput
	if err := json.Unmarshal([]byte(tc.Text), &out); err != nil {
		t.Fatalf("json.Unmarshal(%q): %v", tc.Text, err)
	}
	return out
}

// countAuditKinds tallies records by Kind, and — for KindRead — by
// OperationName, so a test can assert on both without a second pass.
func countAuditKinds(records []audit.Record) (dispatch int, reattachReads []audit.Record) {
	for _, r := range records {
		switch r.Kind {
		case audit.KindDispatch:
			dispatch++
		case audit.KindRead:
			if r.OperationName == "approval_reattach" {
				reattachReads = append(reattachReads, r)
			}
		}
	}
	return dispatch, reattachReads
}

// TestApprovalRelease_ReDriveOnAnySurfaceReAttaches is AP-77's headline
// cross-surface proof: a released approval's Job is bound once, and every
// later re-drive — Control API or MCP, sequential — re-attaches to it rather
// than dispatching again.
func TestApprovalRelease_ReDriveOnAnySurfaceReAttaches(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates)

	requester := f.Credential
	approver := mintAccount(t, f, "ana", accounts.KindHuman, accounts.RoleOperator)

	// 1. Park via the Control API.
	parkResp := restartMutate(t, f, requester)
	defer parkResp.Body.Close()
	if parkResp.StatusCode != http.StatusAccepted {
		t.Fatalf("park status = %d, want 202", parkResp.StatusCode)
	}
	var parked parkedBody
	if err := json.NewDecoder(parkResp.Body).Decode(&parked); err != nil {
		t.Fatalf("decode park: %v", err)
	}

	// 2. The approver decides on the authenticated decision endpoint.
	decideResp := controlAPIRequest(t, f.ClientFor(approver), http.MethodPost,
		f.ControlBase+parked.DecisionPath, approver,
		map[string]any{"approve": true, "plan_hash": parked.PlanHash})
	defer decideResp.Body.Close()
	if decideResp.StatusCode != http.StatusOK {
		t.Fatalf("decision status = %d, want 200", decideResp.StatusCode)
	}

	// 3. The requester re-drives via the Control API: this is the ACTUAL
	//    dispatch, claiming the release and minting Job J.
	firstRun := restartMutate(t, f, requester)
	defer firstRun.Body.Close()
	if firstRun.StatusCode != http.StatusOK {
		t.Fatalf("first re-drive status = %d, want 200", firstRun.StatusCode)
	}
	var ran struct {
		JobID string `json:"job_id"`
	}
	if err := json.NewDecoder(firstRun.Body).Decode(&ran); err != nil {
		t.Fatalf("decode first re-drive: %v", err)
	}
	if ran.JobID == "" {
		t.Fatal("no job_id after approval; the approved Plan must actually dispatch")
	}
	jobJ := ran.JobID

	// 4a. A second re-drive via the Control API re-attaches to the SAME Job.
	secondRun := restartMutate(t, f, requester)
	defer secondRun.Body.Close()
	if secondRun.StatusCode != http.StatusOK {
		t.Fatalf("second re-drive status = %d, want 200", secondRun.StatusCode)
	}
	var ran2 struct {
		JobID string `json:"job_id"`
	}
	if err := json.NewDecoder(secondRun.Body).Decode(&ran2); err != nil {
		t.Fatalf("decode second re-drive: %v", err)
	}
	if ran2.JobID != jobJ {
		t.Fatalf("second re-drive job_id = %q, want the released %q", ran2.JobID, jobJ)
	}

	// 4b. A third re-drive over MCP run_operation, with the IDENTICAL
	//     operation/args/selector and no request state at all, re-attaches to
	//     the same Job too — this is the "plain re-drive" trigger the owner
	//     named as realistic (#713 comment 2026-09-25).
	session := relaytest.Connect(t, f.ControlBase, f.ClientFor(requester))
	mcpRes := relaytest.CallTool(t, session, "run_operation", map[string]any{
		"operation": "service.restart",
		"args":      map[string]string{"unit": "nginx"},
	})
	out := decodeRunOutput(t, mcpRes)
	if out.JobID != jobJ {
		t.Fatalf("MCP re-drive job_id = %q, want the released %q", out.JobID, jobJ)
	}

	// 5. Exactly one Job exists, exactly one KindDispatch record was written,
	//    and the two re-drives each left an audited approval_reattach read.
	if got := allJobs(t, f); len(got) != 1 {
		t.Fatalf("allJobs = %d, want exactly 1 — a released approval must never mint a second Job", len(got))
	}
	records, err := f.Deps.audit.List(context.Background())
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	dispatchCount, reattachReads := countAuditKinds(records)
	if dispatchCount != 1 {
		t.Errorf("KindDispatch records = %d, want 1", dispatchCount)
	}
	if len(reattachReads) != 2 {
		t.Fatalf("approval_reattach KindRead records = %d, want 2", len(reattachReads))
	}
	for _, r := range reattachReads {
		if r.JobID != jobJ {
			t.Errorf("reattach read JobID = %q, want %q", r.JobID, jobJ)
		}
	}
}

// TestApprovalRelease_DifferentAccountReAttachesAndRunsNothing proves AP-77's
// requester-agnostic re-attach: a different Account's identical re-drive
// re-attaches to the already-released Job, is audited under its OWN
// attribution, and dispatches nothing.
func TestApprovalRelease_DifferentAccountReAttachesAndRunsNothing(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates)

	requester := f.Credential
	approver := mintAccount(t, f, "ana", accounts.KindHuman, accounts.RoleOperator)
	bystander := mintAccount(t, f, "bo", accounts.KindHuman, accounts.RoleOperator)

	parkResp := restartMutate(t, f, requester)
	defer parkResp.Body.Close()
	if parkResp.StatusCode != http.StatusAccepted {
		t.Fatalf("park status = %d, want 202", parkResp.StatusCode)
	}
	var parked parkedBody
	if err := json.NewDecoder(parkResp.Body).Decode(&parked); err != nil {
		t.Fatalf("decode park: %v", err)
	}

	decideResp := controlAPIRequest(t, f.ClientFor(approver), http.MethodPost,
		f.ControlBase+parked.DecisionPath, approver,
		map[string]any{"approve": true, "plan_hash": parked.PlanHash})
	defer decideResp.Body.Close()
	if decideResp.StatusCode != http.StatusOK {
		t.Fatalf("decision status = %d, want 200", decideResp.StatusCode)
	}

	firstRun := restartMutate(t, f, requester)
	defer firstRun.Body.Close()
	if firstRun.StatusCode != http.StatusOK {
		t.Fatalf("first re-drive status = %d, want 200", firstRun.StatusCode)
	}
	var ran struct {
		JobID string `json:"job_id"`
	}
	if err := json.NewDecoder(firstRun.Body).Decode(&ran); err != nil {
		t.Fatalf("decode first re-drive: %v", err)
	}
	jobJ := ran.JobID
	if jobJ == "" {
		t.Fatal("no job_id after approval")
	}

	// A bystander Account, who never asked for anything, re-drives the
	// IDENTICAL plan and gets the released Job back rather than a fresh
	// dispatch.
	bystanderRun := restartMutate(t, f, bystander)
	defer bystanderRun.Body.Close()
	if bystanderRun.StatusCode != http.StatusOK {
		t.Fatalf("bystander re-drive status = %d, want 200", bystanderRun.StatusCode)
	}
	var ran2 struct {
		JobID string `json:"job_id"`
	}
	if err := json.NewDecoder(bystanderRun.Body).Decode(&ran2); err != nil {
		t.Fatalf("decode bystander re-drive: %v", err)
	}
	if ran2.JobID != jobJ {
		t.Fatalf("bystander re-drive job_id = %q, want the released %q", ran2.JobID, jobJ)
	}

	if got := allJobs(t, f); len(got) != 1 {
		t.Fatalf("allJobs = %d, want exactly 1 — the bystander's re-drive must not dispatch", len(got))
	}
	records, err := f.Deps.audit.List(context.Background())
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	_, reattachReads := countAuditKinds(records)
	if len(reattachReads) != 1 {
		t.Fatalf("approval_reattach KindRead records = %d, want 1", len(reattachReads))
	}
	if reattachReads[0].Attribution.Verified.AccountName != "bo" {
		t.Errorf("reattach read attributed to %q, want the bystander bo", reattachReads[0].Attribution.Verified.AccountName)
	}
}
