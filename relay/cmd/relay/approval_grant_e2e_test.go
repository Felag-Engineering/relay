// Package main: approval_grant_e2e_test.go drives batch/window approvals
// (#378, ADR-0027 decision 12) through the REAL composition root — real gate
// file, real store, real control-plane listener, real Account authentication,
// real SQLite claim transaction.
//
// It is the counterpart to approval_e2e_test.go, and exists because grants are
// the one part of the callout whose correctness is distributed across every
// layer at once: the domain decides coverage, the store enforces the use bound
// and the authorization link, the capability layer keeps the gate ahead of the
// claim, and the surfaces never see any of it. A unit test of any one of those
// can pass while the assembled thing quietly grants more than it should.
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
)

// grantBody mirrors the API's grant shape, decoded as an outside caller would
// rather than by importing package api's internal types.
type grantBody struct {
	GrantID   string `json:"grant_id"`
	RequestID string `json:"request_id"`
	Summary   string `json:"summary"`
	MaxUses   int    `json:"max_uses"`
	Uses      int    `json:"uses"`
	Remaining int    `json:"remaining"`
	Active    bool   `json:"active"`
	RevokedBy string `json:"revoked_by"`
}

type createGrantBody struct {
	Grant        grantBody    `json:"grant"`
	Approval     approvalBody `json:"approval"`
	DecisionPath string       `json:"decision_path"`
}

type grantListBody struct {
	Grants []grantBody `json:"grants"`
}

// requestGrant asks for a window covering service.restart mutates.
func requestGrant(t *testing.T, f *relayFixture, credential, account string, maxUses int) *http.Response {
	t.Helper()
	return controlAPIRequest(t, f.ClientFor(credential), http.MethodPost,
		f.ControlBase+"/api/v1/approval-grants", credential, map[string]any{
			"scope": map[string]any{
				"account":     account,
				"risk_class":  "mutate",
				"max_fan_out": 5,
				"operations":  []string{"service.restart"},
			},
			"expires_at": time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339),
			"max_uses":   maxUses,
		})
}

func decodeJSONBody[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return out
}

// TestApprovalGrant_RequestApproveReleaseExhaust is decision 12's whole
// lifecycle over the real surfaces: a window is asked for, a second person
// approves it, dispatches inside it stop parking, and the window closes itself
// when its use budget runs out.
//
// The exhaustion half is the point. A grant that released work indefinitely
// would be a standing authorization wearing a window's clothes, and the bound
// is the entire security argument for the mechanism.
func TestApprovalGrant_RequestApproveReleaseExhaust(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates)

	// The founding admin requests; ana approves. The gate sets
	// requester_allowed: false, and that carries over to a grant unchanged,
	// because a grant IS an approval request.
	requester := f.Credential
	requesterName := accounts.FoundingAdminName
	approver := mintAccount(t, f, "ana", accounts.KindHuman, accounts.RoleOperator)

	// 1. Asking for the window creates a PENDING request, not a usable grant.
	createResp := requestGrant(t, f, requester, requesterName, 2)
	defer createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want 201", createResp.StatusCode)
	}
	created := decodeJSONBody[createGrantBody](t, createResp)
	if created.Approval.State != "pending" {
		t.Fatalf("approval state = %q, want pending — asking for a window must never open it", created.Approval.State)
	}
	if created.Grant.GrantID == "" || created.Grant.MaxUses != 2 {
		t.Fatalf("grant = %+v, want a bounded grant", created.Grant)
	}

	// 2. Before it is approved, the gate still parks. This is the property that
	//    matters most: a grant row exists, and it authorizes nothing.
	preResp := restartMutate(t, f, requester)
	defer preResp.Body.Close()
	if preResp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 — an unapproved grant must release nothing", preResp.StatusCode)
	}

	// 3. The approver answers through the ORDINARY decision route. There is no
	//    grant-specific approval path, which is why quorum and the requester
	//    exclusion cannot drift between the two.
	decideResp := controlAPIRequest(t, f.ClientFor(approver), http.MethodPost,
		f.ControlBase+created.DecisionPath, approver,
		map[string]any{"approve": true, "plan_hash": created.Approval.PlanHash,
			"reason": "batch restart window, change OPS-104"})
	defer decideResp.Body.Close()
	if decideResp.StatusCode != http.StatusOK {
		t.Fatalf("decision status = %d, want 200", decideResp.StatusCode)
	}
	if decoded := decodeJSONBody[approvalBody](t, decideResp); decoded.State != "approved" {
		t.Fatalf("state = %q, want approved", decoded.State)
	}

	// 4. Now dispatches inside the window run without parking — the fatigue
	//    property. Two of them, which is exactly the grant's budget.
	jobIDs := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		resp := restartMutate(t, f, requester)
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("dispatch %d status = %d, want 200 under an approved grant", i+1, resp.StatusCode)
		}
		ran := decodeJSONBody[struct {
			JobID string `json:"job_id"`
		}](t, resp)
		resp.Body.Close()
		if ran.JobID == "" {
			t.Fatalf("dispatch %d produced no Job", i+1)
		}
		jobIDs = append(jobIDs, ran.JobID)
	}
	if jobIDs[0] == jobIDs[1] {
		t.Fatal("both dispatches returned the same Job; the grant released one execution, not two")
	}

	// 5. The third parks again. The window is spent, and a spent window is
	//    indistinguishable from no window at all.
	exhaustedResp := restartMutate(t, f, requester)
	defer exhaustedResp.Body.Close()
	if exhaustedResp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 once the grant is exhausted", exhaustedResp.StatusCode)
	}

	// 6. It has left the live list, and its own view says so.
	listResp := controlAPIRequest(t, f.Client(), http.MethodGet,
		f.ControlBase+"/api/v1/approval-grants", requester, nil)
	defer listResp.Body.Close()
	if live := decodeJSONBody[grantListBody](t, listResp); len(live.Grants) != 0 {
		t.Errorf("live grants = %+v, want none once exhausted", live.Grants)
	}

	getResp := controlAPIRequest(t, f.Client(), http.MethodGet,
		f.ControlBase+"/api/v1/approval-grants/"+created.Grant.GrantID, requester, nil)
	defer getResp.Body.Close()
	spent := decodeJSONBody[grantBody](t, getResp)
	if spent.Active || spent.Uses != 2 || spent.Remaining != 0 {
		t.Errorf("spent grant = %+v, want inactive with 2 of 2 used", spent)
	}

	// 7. docs/specs/approval.md acceptance: "every covered Job auditing to the same approval
	//    ID". One query over the grant's authorizing request returns the whole
	//    story — including both Jobs the window released.
	records, err := f.Deps.audit.ByApproval(context.Background(), created.Grant.RequestID)
	if err != nil {
		t.Fatalf("audit ByApproval: %v", err)
	}
	released := map[string]bool{}
	var sawDecision bool
	for _, r := range records {
		switch r.Kind {
		case audit.KindApprovalDecided:
			sawDecision = true
			if r.Attribution.Verified.AccountName != "ana" {
				t.Errorf("decision attributed to %q, want the approver", r.Attribution.Verified.AccountName)
			}
		case audit.KindDispatch:
			if r.GrantID != created.Grant.GrantID {
				t.Errorf("dispatch record %q has grant %q, want %q", r.ID, r.GrantID, created.Grant.GrantID)
			}
			released[r.JobID] = true
		}
	}
	if !sawDecision {
		t.Error("the grant's own approval is not in its audit story")
	}
	for _, id := range jobIDs {
		if !released[id] {
			t.Errorf("Job %s ran under the grant but is not reachable from its approval ID", id)
		}
	}
}

// TestApprovalGrant_RevokeClosesTheWindowImmediately: revocation is the lever
// that exists because reduced friction against a compromised requester is
// exactly when someone needs to shut a window without reaching for the
// fleet-wide Freeze.
func TestApprovalGrant_RevokeClosesTheWindowImmediately(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates)
	requester := f.Credential
	requesterName := accounts.FoundingAdminName
	approver := mintAccount(t, f, "ana", accounts.KindHuman, accounts.RoleOperator)

	createResp := requestGrant(t, f, requester, requesterName, 50)
	defer createResp.Body.Close()
	created := decodeJSONBody[createGrantBody](t, createResp)

	decideResp := controlAPIRequest(t, f.ClientFor(approver), http.MethodPost,
		f.ControlBase+created.DecisionPath, approver,
		map[string]any{"approve": true, "plan_hash": created.Approval.PlanHash})
	defer decideResp.Body.Close()
	if decideResp.StatusCode != http.StatusOK {
		t.Fatalf("decision status = %d, want 200", decideResp.StatusCode)
	}

	// It is live: one dispatch runs.
	runResp := restartMutate(t, f, requester)
	defer runResp.Body.Close()
	if runResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 under an approved grant", runResp.StatusCode)
	}

	revokeResp := controlAPIRequest(t, f.ClientFor(approver), http.MethodPost,
		f.ControlBase+"/api/v1/approval-grants/"+created.Grant.GrantID+"/revoke", approver,
		map[string]any{"reason": "requester credential rotated"})
	defer revokeResp.Body.Close()
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", revokeResp.StatusCode)
	}
	if revoked := decodeJSONBody[grantBody](t, revokeResp); revoked.Active || revoked.RevokedBy != "ana" {
		t.Errorf("revoked grant = %+v, want inactive and attributed to ana", revoked)
	}

	// The very next dispatch parks again, with 49 uses nominally left.
	afterResp := restartMutate(t, f, requester)
	defer afterResp.Body.Close()
	if afterResp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 immediately after revocation", afterResp.StatusCode)
	}

	// Revoking twice is a truthful 409, not a silent success.
	againResp := controlAPIRequest(t, f.ClientFor(approver), http.MethodPost,
		f.ControlBase+"/api/v1/approval-grants/"+created.Grant.GrantID+"/revoke", approver,
		map[string]any{"reason": "again"})
	defer againResp.Body.Close()
	if againResp.StatusCode != http.StatusConflict {
		t.Errorf("second revoke status = %d, want 409", againResp.StatusCode)
	}
}

// TestApprovalGrant_RequesterCannotApproveTheirOwnWindow: the rule that stops
// somebody approving their own dispatch stops them approving a window over a
// hundred of them, because it is the same code.
//
// This is the property that makes grants safe to have at all: if a grant were a
// separate approval path, it would be a cheaper one, and the cheaper path is
// always the one that gets used.
func TestApprovalGrant_RequesterCannotApproveTheirOwnWindow(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates)
	requester := f.Credential
	requesterName := accounts.FoundingAdminName

	createResp := requestGrant(t, f, requester, requesterName, 10)
	defer createResp.Body.Close()
	created := decodeJSONBody[createGrantBody](t, createResp)

	selfResp := controlAPIRequest(t, f.Client(), http.MethodPost,
		f.ControlBase+created.DecisionPath, requester,
		map[string]any{"approve": true, "plan_hash": created.Approval.PlanHash})
	defer selfResp.Body.Close()
	if selfResp.StatusCode != http.StatusConflict {
		t.Fatalf("self-approval status = %d, want 409 — requester_allowed: false applies to a window too", selfResp.StatusCode)
	}

	// And nothing was released: the dispatch still parks.
	runResp := restartMutate(t, f, requester)
	defer runResp.Body.Close()
	if runResp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", runResp.StatusCode)
	}
}

// TestApprovalGrant_RefusesAWindowOverUngatedWork: a grant covering only work
// that would never have parked authorizes nothing, so creating one would leave
// a live authorization in the table with real reach and no purpose — the sort
// of object that later gets widened by somebody who assumes it must have been
// there for a reason.
func TestApprovalGrant_RefusesAWindowOverUngatedWork(t *testing.T) {
	const rawExecOnly = `{
  "rules": [
    {
      "name": "raw-exec-needs-a-human",
      "match": { "raw_exec": true },
      "require": { "count": 1, "requester_allowed": false, "channel": "out-of-band", "ttl": "1h" }
    }
  ]
}`
	f := startGatedRelay(t, rawExecOnly)

	resp := requestGrant(t, f, f.Credential, accounts.FoundingAdminName, 10)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 for a grant over work nothing gates", resp.StatusCode)
	}
}
