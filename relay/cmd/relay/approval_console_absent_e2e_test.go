// Package main: approval_console_absent_e2e_test.go proves docs/specs/approval.md
// AP-80 against the REAL composition root with a live Console mounted beside
// the Control API: the Console renders no approval request and decides none,
// while a parked request is still decided end to end on the Control API, which
// alone reads the one Decision that ended it.
//
// The Console is opted in with WithConfig(func(c *Config) { c.ConsoleEnabled =
// true }); without it every /console/ request would 404 for the wrong reason.
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
)

// withConsole enables the Console listener on the fixture.
func withConsole() FixtureOption {
	return WithConfig(func(c *Config) { c.ConsoleEnabled = true })
}

// parkRestart parks restartMutate as requester and returns the park body.
func parkRestart(t *testing.T, f *relayFixture, requester string) parkedBody {
	t.Helper()
	resp := restartMutate(t, f, requester)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("park status = %d, want 202", resp.StatusCode)
	}
	var parked parkedBody
	if err := json.NewDecoder(resp.Body).Decode(&parked); err != nil {
		t.Fatalf("decode park: %v", err)
	}
	return parked
}

// getApproval reads one request on the Control API as credential.
func getApproval(t *testing.T, f *relayFixture, credential, requestID string) approvalBody {
	t.Helper()
	resp := controlAPIRequest(t, f.ClientFor(credential), http.MethodGet,
		f.ControlBase+"/api/v1/approvals/"+requestID, credential, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET approval status = %d, want 200", resp.StatusCode)
	}
	var got approvalBody
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode approval: %v", err)
	}
	return got
}

// decideOnAPI approves on the Control API's out-of-band endpoint as credential.
func decideOnAPI(t *testing.T, f *relayFixture, credential string, parked parkedBody) approvalBody {
	t.Helper()
	resp := controlAPIRequest(t, f.ClientFor(credential), http.MethodPost,
		f.ControlBase+parked.DecisionPath, credential,
		map[string]any{"approve": true, "plan_hash": parked.PlanHash})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("decision status = %d, want 200", resp.StatusCode)
	}
	var got approvalBody
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	return got
}

// assertRestartRuns re-drives the dispatch as requester and requires that it
// ran. The Node is registered but never connects, so `unreachable` is the
// truthful per-Node outcome; what matters is that dispatch happened.
func assertRestartRuns(t *testing.T, f *relayFixture, requester string) {
	t.Helper()
	resp := restartMutate(t, f, requester)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("re-drive status = %d, want 200 after approval", resp.StatusCode)
	}
	var ran struct {
		JobID   string `json:"job_id"`
		Results []struct {
			NodeID  string `json:"node_id"`
			Outcome string `json:"outcome"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ran); err != nil {
		t.Fatalf("decode run: %v", err)
	}
	if ran.JobID == "" {
		t.Fatal("no job_id after approval; the approved Plan must actually dispatch")
	}
	if len(ran.Results) != 1 || ran.Results[0].NodeID != "node-e2e-1" || ran.Results[0].Outcome != "unreachable" {
		t.Errorf("results = %+v, want one truthful unreachable result for node-e2e-1", ran.Results)
	}
}

// TestApprovalCallout_TheConsoleHasNoApprovalSurface: a signed-in Console
// session finds no approval request and no decision route (AP-80), takes no
// step-up and records no decision for a POST at the retired path — and the same
// parked request is then decided on the Control API and runs.
func TestApprovalCallout_TheConsoleHasNoApprovalSurface(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates, withConsole())

	requester := mintAccount(t, f, "gleipnir-prod", accounts.KindMachine, accounts.RoleAdmin)
	parked := parkRestart(t, f, requester)

	const password = "dana's console password"
	_, danaToken := mintConsoleHumanAccount(t, f, "dana", password, accounts.RoleAdmin)
	client := consoleClient(t, f)
	consoleSignIn(t, client, f, "dana", password)

	for _, path := range []string{"/console/approvals", "/console/approvals/" + parked.RequestID} {
		resp, err := client.Get(f.ControlBase + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = readAll(t, resp)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want the Console's ordinary 404", path, resp.StatusCode)
		}
	}

	homeResp, err := client.Get(f.ControlBase + "/console/")
	if err != nil {
		t.Fatalf("GET /console/: %v", err)
	}
	home := readAll(t, homeResp)
	if homeResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /console/ = %d, want 200", homeResp.StatusCode)
	}
	if strings.Contains(home, ">Approvals<") || strings.Contains(home, "/console/approvals") {
		t.Error("the Console's navigation still offers Approvals")
	}

	csrfToken := consoleHiddenField(t, home, "csrf_token")
	decideResp, err := client.PostForm(f.ControlBase+"/console/approvals/"+parked.RequestID+"/decision", url.Values{
		"csrf_token": {csrfToken},
		"plan_hash":  {parked.PlanHash},
		"answer":     {"approve"},
		"password":   {password},
	})
	if err != nil {
		t.Fatalf("POST decision: %v", err)
	}
	_ = readAll(t, decideResp)
	if decideResp.StatusCode != http.StatusNotFound {
		t.Errorf("POST the retired decision path = %d, want 404", decideResp.StatusCode)
	}

	if got := getApproval(t, f, danaToken, parked.RequestID); got.State != "pending" || len(got.Decisions) != 0 {
		t.Fatalf("after the Console POST the request is %q with %d decisions, want pending with none", got.State, len(got.Decisions))
	}
	records, err := f.Deps.audit.List(context.Background())
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	for _, r := range records {
		if r.Kind == audit.KindApprovalDecided || r.Kind == audit.KindStepUp {
			t.Errorf("the retired Console path left a %s record", r.Kind)
		}
	}

	decided := decideOnAPI(t, f, danaToken, parked)
	if decided.State != "approved" || len(decided.Decisions) != 1 {
		t.Fatalf("API decision = %q with %d decisions, want approved with one", decided.State, len(decided.Decisions))
	}
	if got := decided.Decisions[0]; got.Account != "dana" || got.Channel != "out-of-band" || !got.Human {
		t.Errorf("decision = %+v, want dana's human out-of-band answer", got)
	}
	assertRestartRuns(t, f, requester)
}

// TestApprovalCallout_OneDecisionEndsTheRequest: the first Decision ends a
// request, a second from another Account is refused as not pending, and the
// Control API's read shows exactly the one Decision, its channel, and none of
// the removed rule terms. The Console, with the first decider signed in, shows
// nothing of it (AP-80).
//
// Proves AP-82, AP-80.
func TestApprovalCallout_OneDecisionEndsTheRequest(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates, withConsole())

	requester := mintAccount(t, f, "gleipnir-prod", accounts.KindMachine, accounts.RoleAdmin)
	parked := parkRestart(t, f, requester)

	const password = "dana's console password"
	_, danaToken := mintConsoleHumanAccount(t, f, "dana", password, accounts.RoleAdmin)
	erinToken := mintAccount(t, f, "erin", accounts.KindHuman, accounts.RoleAdmin)

	if decided := decideOnAPI(t, f, danaToken, parked); decided.State != "approved" {
		t.Fatalf("after one answer: state %q, want approved", decided.State)
	}

	// A second Decision, from another Account, is refused as not pending.
	second := controlAPIRequest(t, f.ClientFor(erinToken), http.MethodPost,
		f.ControlBase+parked.DecisionPath, erinToken,
		map[string]any{"approve": false, "plan_hash": parked.PlanHash})
	defer second.Body.Close()
	if second.StatusCode != http.StatusConflict {
		t.Fatalf("second decision status = %d, want 409 not pending", second.StatusCode)
	}
	var problem struct {
		Title string `json:"title"`
	}
	if err := json.NewDecoder(second.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Title != "approval request is not pending" {
		t.Errorf("second decision problem = %q, want the not-pending title", problem.Title)
	}

	getResp := controlAPIRequest(t, f.ClientFor(danaToken), http.MethodGet,
		f.ControlBase+"/api/v1/approvals/"+parked.RequestID, danaToken, nil)
	defer getResp.Body.Close()
	var raw map[string]any
	if err := json.NewDecoder(getResp.Body).Decode(&raw); err != nil {
		t.Fatalf("decode approval: %v", err)
	}
	for _, key := range []string{"required_count", "progress", "audience", "requester_allowed", "channel"} {
		if _, present := raw[key]; present {
			t.Errorf("the approval JSON carries %q; a rule names no such term", key)
		}
	}
	got := getApproval(t, f, danaToken, parked.RequestID)
	if got.State != "approved" || len(got.Decisions) != 1 {
		t.Fatalf("request is %q with %d decisions, want approved with exactly one", got.State, len(got.Decisions))
	}
	if d := got.Decisions[0]; d.Account != "dana" || !d.Approve || !d.Human || d.Channel != "out-of-band" {
		t.Errorf("decision = %+v, want dana's human out-of-band approval", d)
	}

	client := consoleClient(t, f)
	consoleSignIn(t, client, f, "dana", password)
	consoleResp, err := client.Get(f.ControlBase + "/console/approvals/" + parked.RequestID)
	if err != nil {
		t.Fatalf("GET Console request screen: %v", err)
	}
	_ = readAll(t, consoleResp)
	if consoleResp.StatusCode != http.StatusNotFound {
		t.Errorf("the Console's request screen = %d, want 404: the Control API alone reads the request", consoleResp.StatusCode)
	}
	assertRestartRuns(t, f, requester)
}
