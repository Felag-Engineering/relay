package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

// tools_execution_retry_test.go is #727's proof: run_operation and raw_exec's
// answered-retry path (isAnsweredRetry, answerThenDispatch), driven at the
// mcp handler seam — real HTTP, real SDK client, real requeststate seal, real
// clientCanBeAsked gate — against a scripted Executor/ApprovalDecider. Package
// mcp (not mcp_test) because the tests reach unexported identifiers
// (answerRequestID and friends from tools_approval_test.go, isAnsweredRetry,
// answerThenDispatch's field names on the decoded RunOrPlanOutput).
//
// These tests exercise the handler seam directly, against a scripted
// Executor/ApprovalDecider, independent of whether the composition root
// wires mcp.WithApprovalElicitation() in. See
// cmd/relay/answered_retry_e2e_test.go for the same claims through the real
// composition root, where #730 turns this path on in production.

// -----------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------

// scriptedRetryExecutor's first Run call always parks askably as answerRequestID
// / answerPlanHash — the SAME identifiers tools_approval_test.go's fixtures
// use, so a scriptedDecider (also from that file) answering "apr-1" lines up
// with what this Executor parked. second is what every SUBSEQUENT call
// returns — the retry's own re-entry into dispatch().
type scriptedRetryExecutor struct {
	mu     sync.Mutex
	n      int
	second struct {
		results []capability.NodeResult
		err     error
	}
}

func (e *scriptedRetryExecutor) Start(context.Context, capability.Principal, capability.Selector, jobs.Action, capability.StartOptions) (capability.StartedJob, error) {
	e.mu.Lock()
	e.n++
	call := e.n
	e.mu.Unlock()
	if call == 1 {
		return capability.StartedJob{}, &capability.ParkedError{
			RequestID: answerRequestID,
			PlanHash:  answerPlanHash,
			Summary:   `service.restart(unit="nginx") [mutate] on 1 node(s): node-a`,
			Progress:  "0 of 1",
			Rules:     []string{"all-mutates-need-a-human"},
			ExpiresAt: fixedNow.Add(4 * time.Hour),
			Askable:   true,
		}
	}
	return startedJobOf(e.second.results, e.second.err)
}

func (e *scriptedRetryExecutor) CancelJob(context.Context, capability.Principal, string) error {
	return nil
}

func (e *scriptedRetryExecutor) Plan(context.Context, capability.Principal, capability.Selector, jobs.Action) (capability.PlanResult, error) {
	return capability.PlanResult{}, nil
}

func (e *scriptedRetryExecutor) runCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.n
}

// retryEvent is one event a scriptedReadAuditor or scriptedJobResultReader
// recorded, in a shared, ordered log — so a test can assert the read audit
// landed BEFORE the Job read-back (BLOCKING 1, plan review).
type retryEvent struct {
	kind  string // "read", "get_job", or "tasks_by_job"
	jobID string
	tool  string
}

type retryEventLog struct {
	mu     sync.Mutex
	events []retryEvent
}

func (l *retryEventLog) record(e retryEvent) {
	l.mu.Lock()
	l.events = append(l.events, e)
	l.mu.Unlock()
}

func (l *retryEventLog) all() []retryEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]retryEvent(nil), l.events...)
}

// scriptedReadAuditor is a ReadAuditor that appends to a shared retryEventLog
// and can be scripted to fail (BLOCKING 1's failing-auditor row).
type scriptedReadAuditor struct {
	log *retryEventLog
	err error
}

func (a *scriptedReadAuditor) RecordRead(_ context.Context, e ReadEvent) error {
	a.log.record(retryEvent{kind: "read", jobID: e.JobID, tool: e.Tool})
	return a.err
}

// scriptedJobResultReader is a JobResultReader that appends to the SAME
// shared retryEventLog and can be scripted to fail GetJob.
type scriptedJobResultReader struct {
	log       *retryEventLog
	getJobErr error

	mu              sync.Mutex
	getJobCalls     int
	tasksByJobCalls int
}

func (r *scriptedJobResultReader) GetJob(_ context.Context, id string) (jobs.Job, error) {
	r.mu.Lock()
	r.getJobCalls++
	r.mu.Unlock()
	r.log.record(retryEvent{kind: "get_job", jobID: id})
	if r.getJobErr != nil {
		return jobs.Job{}, r.getJobErr
	}
	return jobs.Job{ID: id, CreatedAt: fixedNow}, nil
}

func (r *scriptedJobResultReader) TasksByJob(_ context.Context, jobID string) ([]jobs.Task, error) {
	r.mu.Lock()
	r.tasksByJobCalls++
	r.mu.Unlock()
	r.log.record(retryEvent{kind: "tasks_by_job", jobID: jobID})
	return []jobs.Task{{
		ID: "task-1", JobID: jobID, NodeID: "node-a",
		Action:       jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate},
		State:        jobs.DispatchStateResolved,
		Outcome:      jobs.OutcomeUnreachable,
		CreatedAt:    fixedNow,
		DispatchedAt: fixedNow,
		ResolvedAt:   fixedNow.Add(time.Second),
	}}, nil
}

func (r *scriptedJobResultReader) counts() (getJob, tasksByJob int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.getJobCalls, r.tasksByJobCalls
}

// retryOperationArgs/retryRawExecArgs are the SAME typed call on both the
// initial (parking) request and the retry — the digest that binds an answer
// to the call it answers depends on it (issue #727 comment 1).
func retryOperationArgs() map[string]any {
	return map[string]any{"operation": "service.restart", "args": map[string]string{"unit": "nginx"}}
}

func retryRawExecArgs() map[string]any {
	return map[string]any{"argv": []string{"systemctl", "restart", "nginx"}}
}

// retryServer mounts the real handler with elicitation on, exactly like
// approveRequestServer but also wiring reads/results, so the answered-retry
// path is fully reachable.
func retryServer(t *testing.T, exec Executor, reads ReadAuditor, results JobResultReader, dec ApprovalDecider) *httptest.Server {
	t.Helper()
	handler := New(nil, stubOpsLister{}, exec, results, reads, nil,
		WithApprovalDecider(dec), WithApprovalElicitation(), WithClock(func() time.Time { return fixedNow }))
	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	srv := httptest.NewServer(controlplane.NewAuthenticator(answerTestVerifier{}).Middleware(mux))
	t.Cleanup(srv.Close)
	return srv
}

// retrySession connects a client that CAN be asked (advertises form
// elicitation) but answers nothing on its own — the MRTR happy path, driven
// by the test rather than the SDK's automatic middleware.
func retrySession(t *testing.T, srv *httptest.Server) *sdkmcp.ClientSession {
	t.Helper()
	return relaytest.ConnectWithOptions(t, srv.URL, answerClient(), relaytest.ConnectOptions{
		Client:     relaytest.ElicitingClientOptions(),
		ClientName: relaytest.GleipnirClientName,
	})
}

// askQuestion drives tool's first (parking) call and asserts it renders the
// question keyed by answerRequestID — scriptedRetryExecutor's fixed park.
func askQuestion(t *testing.T, session *sdkmcp.ClientSession, tool string, args map[string]any) *sdkmcp.CallToolResult {
	t.Helper()
	res := relaytest.CallToolWith(t, session, &sdkmcp.CallToolParams{Name: tool, Arguments: args})
	if !res.NeedsInput() {
		t.Fatalf("initial %s call: NeedsInput() = false, want true; IsError=%v Content=%+v", tool, res.IsError, res.Content)
	}
	if _, ok := res.InputRequests[answerRequestID]; !ok {
		t.Fatalf("InputRequests not keyed by %q: %+v", answerRequestID, res.InputRequests)
	}
	return res
}

// retryWith sends the MRTR retry, answering answerRequestID with action
// ("accept"/"decline") asserted as alice.
func retryWith(t *testing.T, session *sdkmcp.ClientSession, tool string, args map[string]any, requestState, action string) *sdkmcp.CallToolResult {
	t.Helper()
	responses := sdkmcp.InputResponseMap{answerRequestID: &sdkmcp.ElicitResult{Action: action, Meta: permissionResponder("alice")}}
	return relaytest.RetryTool(t, session, tool, args, requestState, responses)
}

// -----------------------------------------------------------------------
// AP-66: lapsed re-parks and asks afresh
// -----------------------------------------------------------------------

func TestAnsweredRetry_LapsedRequestReParks(t *testing.T) {
	exec := &scriptedRetryExecutor{}
	exec.second.err = &capability.ParkedError{
		RequestID: "apr-2",
		PlanHash:  "hash-2",
		Summary:   `service.restart(unit="nginx") [mutate] on 1 node(s): node-a`,
		Progress:  "0 of 1",
		Rules:     []string{"all-mutates-need-a-human"},
		ExpiresAt: fixedNow.Add(4 * time.Hour),
		Askable:   true,
	}
	log := &retryEventLog{}
	reads := &scriptedReadAuditor{log: log}
	results := &scriptedJobResultReader{log: log}
	dec := scriptedDecider{
		resp: approval.Request{ID: answerRequestID, State: approval.StateExpired, ExpiresAt: fixedNow.Add(-time.Hour)},
		err:  approval.ErrNotPending,
	}
	srv := retryServer(t, exec, reads, results, dec)
	session := retrySession(t, srv)

	q := askQuestion(t, session, toolRunOperation, retryOperationArgs())
	res := retryWith(t, session, toolRunOperation, retryOperationArgs(), q.RequestState, "accept")

	if !res.NeedsInput() {
		t.Fatalf("retry: NeedsInput() = false, want true (a lapsed answer re-parks and asks afresh); IsError=%v", res.IsError)
	}
	if _, ok := res.InputRequests["apr-2"]; !ok {
		t.Fatalf("InputRequests not keyed by the new request id apr-2: %+v", res.InputRequests)
	}
	if n := exec.runCount(); n != 2 {
		t.Errorf("Run called %d times, want 2 (the initial park plus one retry dispatch)", n)
	}
}

// -----------------------------------------------------------------------
// Domain refusals render as results, never as tool errors
// -----------------------------------------------------------------------

func TestAnsweredRetry_DomainRefusalsAreResultsNotErrors(t *testing.T) {
	wantMachineText := machineSelfDecisionErrorText(t)

	cases := []struct {
		name       string
		action     string
		meta       sdkmcp.Meta
		deciderErr error
	}{
		{name: "ErrRequesterExcluded", action: "accept", meta: permissionResponder("alice"), deciderErr: approval.ErrRequesterExcluded},
		{name: "ErrNotInAudience", action: "accept", meta: permissionResponder("alice"), deciderErr: approval.ErrNotInAudience},
		{name: "ErrWeakChannel", action: "accept", meta: permissionResponder("alice"), deciderErr: approval.ErrWeakChannel},
		{name: "ErrPlanChanged", action: "accept", meta: permissionResponder("alice"), deciderErr: approval.ErrPlanChanged},
		{name: "the decider itself returns ErrMachineSelfDecision", action: "accept", meta: permissionResponder("alice"), deciderErr: approval.ErrMachineSelfDecision},
		{name: "adapter: no responder at all", action: "accept", meta: nil},
		{name: `adapter: gate "information"`, action: "accept", meta: sdkmcp.Meta{responderMetaKey: map[string]any{"gate": "information", "username": "alice"}}},
		{name: `adapter: action "cancel"`, action: "cancel", meta: permissionResponder("alice")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exec := &scriptedRetryExecutor{}
			log := &retryEventLog{}
			reads := &scriptedReadAuditor{log: log}
			results := &scriptedJobResultReader{log: log}
			dec := scriptedDecider{err: tc.deciderErr}
			srv := retryServer(t, exec, reads, results, dec)
			session := retrySession(t, srv)

			q := askQuestion(t, session, toolRunOperation, retryOperationArgs())
			responses := sdkmcp.InputResponseMap{answerRequestID: &sdkmcp.ElicitResult{Action: tc.action, Meta: tc.meta}}
			res := relaytest.RetryTool(t, session, toolRunOperation, retryOperationArgs(), q.RequestState, responses)

			if res.IsError {
				t.Fatalf("IsError = true, want false (a refusal is a tool result): content=%+v", res.Content)
			}
			var out RunOrPlanOutput
			relaytest.DecodeToolJSON(t, res, &out)
			if out.AnswerRefused == nil {
				t.Fatalf("AnswerRefused is nil, want a refusal: %+v", out)
			}
			if out.JobID != "" {
				t.Errorf("JobID = %q, want empty", out.JobID)
			}

			wantReason := wantMachineText
			if tc.deciderErr != nil && tc.deciderErr != approval.ErrMachineSelfDecision {
				wantReason = renderApprovalError(tc.deciderErr).Error()
			}
			if out.AnswerRefused.Reason != wantReason {
				t.Errorf("Reason = %q, want %q", out.AnswerRefused.Reason, wantReason)
			}
			if strings.Contains(out.AnswerRefused.Reason, "Pass their identity in") {
				t.Errorf("Reason contains renderApprovalError's approve_request-only wording, an MRTR client cannot act on: %q", out.AnswerRefused.Reason)
			}
			if n := exec.runCount(); n != 1 {
				t.Errorf("Run called %d times, want 1 (only the initial park)", n)
			}
		})
	}
}

// -----------------------------------------------------------------------
// An audit-write failure after the decision was made durable must never be
// rendered as "nothing recorded" (issue #727 comment 2, point 2)
// -----------------------------------------------------------------------

func TestAnsweredRetry_AuditWriteFailureIsNotRenderedAsNothingRecorded(t *testing.T) {
	exec := &scriptedRetryExecutor{}
	log := &retryEventLog{}
	reads := &scriptedReadAuditor{log: log}
	results := &scriptedJobResultReader{log: log}
	dec := scriptedDecider{
		resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash},
		err:  errors.New("capability: record audit entry: disk full"),
	}
	srv := retryServer(t, exec, reads, results, dec)
	session := retrySession(t, srv)

	q := askQuestion(t, session, toolRunOperation, retryOperationArgs())
	res := retryWith(t, session, toolRunOperation, retryOperationArgs(), q.RequestState, "accept")

	if res.IsError {
		t.Fatalf("IsError = true, want false: content=%+v", res.Content)
	}
	var out RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.AnswerRefused == nil {
		t.Fatalf("AnswerRefused is nil: %+v", out)
	}
	if !strings.Contains(out.AnswerRefused.Reason, "may have been recorded") {
		t.Errorf("Reason = %q, want it to say the answer MAY have been recorded", out.AnswerRefused.Reason)
	}
	for _, forbidden := range []string{"was not recorded", "not recorded:", "ignored"} {
		if strings.Contains(out.AnswerRefused.Reason, forbidden) {
			t.Errorf("Reason = %q, must not claim the answer was not recorded or ignored", out.AnswerRefused.Reason)
		}
	}
	if !strings.Contains(out.AnswerRefused.Reason, "GET /api/v1/approvals/{id}") {
		t.Errorf("Reason = %q, want it to point at the Control API's approval-read route", out.AnswerRefused.Reason)
	}
	if strings.Contains(out.AnswerRefused.Reason, "Confirm the request's state with approve_request") {
		t.Errorf("Reason = %q, must not suggest approve_request as a way to confirm state — it records a decision, not a read", out.AnswerRefused.Reason)
	}
	if out.AnswerRefused.NextStep != answerRefusalNextStepMayAlreadyReflectAnswer {
		t.Errorf("NextStep = %q, want %q", out.AnswerRefused.NextStep, answerRefusalNextStepMayAlreadyReflectAnswer)
	}
	if n := exec.runCount(); n != 1 {
		t.Errorf("Run called %d times, want 1 (no extra dispatch)", n)
	}
}

// -----------------------------------------------------------------------
// #735 review / issue #727 comment 1: a refused decision renders only the
// state, the Job ID and the deadline — never another approver's detail
// -----------------------------------------------------------------------

func TestAnsweredRetry_RefusedDecisionRendersOnlyStateJobAndDeadline(t *testing.T) {
	expiresAt := fixedNow.Add(time.Hour)
	leaky := approval.Request{
		ID:          answerRequestID,
		PlanHash:    answerPlanHash,
		State:       approval.StateApproved,
		ExpiresAt:   expiresAt,
		RequestedBy: "dana",
		Summary:     "secret-summary",
		Decisions: []approval.Decision{
			{Account: "carol", OnBehalfOf: "Carol Private", Reason: "private note", Approve: true},
		},
	}
	exec := &scriptedRetryExecutor{}
	log := &retryEventLog{}
	reads := &scriptedReadAuditor{log: log}
	results := &scriptedJobResultReader{log: log}
	dec := scriptedDecider{resp: leaky, err: approval.ErrNotPending}
	srv := retryServer(t, exec, reads, results, dec)
	session := retrySession(t, srv)

	q := askQuestion(t, session, toolRunOperation, retryOperationArgs())
	res := retryWith(t, session, toolRunOperation, retryOperationArgs(), q.RequestState, "decline")

	if res.IsError {
		t.Fatalf("IsError = true, want false: content=%+v", res.Content)
	}

	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	for _, secret := range []string{"carol", "Carol Private", "private note", "dana", "secret-summary"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("result contains %q, which came from another approver's Decision — it must never leak: %s", secret, raw)
		}
	}

	var out RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.AnswerRefused == nil {
		t.Fatalf("AnswerRefused is nil: %+v", out)
	}
	if out.AnswerRefused.RequestID != answerRequestID {
		t.Errorf("RequestID = %q, want %q", out.AnswerRefused.RequestID, answerRequestID)
	}
	if out.AnswerRefused.State != approval.StateApproved.String() {
		t.Errorf("State = %q, want %q", out.AnswerRefused.State, approval.StateApproved.String())
	}
	if out.AnswerRefused.JobID != "" {
		t.Errorf("JobID = %q, want empty", out.AnswerRefused.JobID)
	}
	if out.AnswerRefused.ExpiresAt != expiresAt.UTC().Format(time.RFC3339) {
		t.Errorf("ExpiresAt = %q, want %q", out.AnswerRefused.ExpiresAt, expiresAt.UTC().Format(time.RFC3339))
	}
	if n := exec.runCount(); n != 1 {
		t.Errorf("Run called %d times, want 1 (a refusal never dispatches)", n)
	}
}

// -----------------------------------------------------------------------
// A tampered/unbound state is refused, fail closed, and the rescue still
// works: approve_request on the same server still reaches the decider.
// -----------------------------------------------------------------------

func TestAnsweredRetry_StateRefusedLeavesTheRequestUndecided(t *testing.T) {
	exec := &scriptedRetryExecutor{}
	log := &retryEventLog{}
	reads := &scriptedReadAuditor{log: log}
	results := &scriptedJobResultReader{log: log}
	dec := &recordingDecider{resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash}}
	srv := retryServer(t, exec, reads, results, dec)
	session := retrySession(t, srv)

	q := askQuestion(t, session, toolRunOperation, retryOperationArgs())
	tampered := flipMiddleChar(q.RequestState)
	res := retryWith(t, session, toolRunOperation, retryOperationArgs(), tampered, "accept")

	if res.IsError {
		t.Fatalf("IsError = true, want false: content=%+v", res.Content)
	}
	var out RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.AnswerRefused == nil {
		t.Fatalf("AnswerRefused is nil: %+v", out)
	}
	if !strings.Contains(out.AnswerRefused.Reason, errAnswerStateRefused.Error()) {
		t.Errorf("Reason = %q, want it to contain errAnswerStateRefused's text", out.AnswerRefused.Reason)
	}
	if calls := dec.calls(); len(calls) != 0 {
		t.Errorf("decider called %d times, want 0", len(calls))
	}
	if n := exec.runCount(); n != 1 {
		t.Errorf("Run called %d times, want 1 (no dispatch on a state-refused retry)", n)
	}

	// The rescue: approve_request on the same server still reaches the
	// decider — a refused state leaves the request pending and decidable.
	approveRes := relaytest.CallTool(t, session, "approve_request", map[string]any{
		"request_id": answerRequestID,
		"plan_hash":  answerPlanHash,
		"approve":    true,
		"approver":   "alice",
	})
	if approveRes.IsError {
		t.Fatalf("approve_request: IsError, content=%+v", approveRes.Content)
	}
	if calls := dec.calls(); len(calls) != 1 {
		t.Fatalf("decider called %d times after approve_request, want 1", len(calls))
	}
}

// -----------------------------------------------------------------------
// AP-63/AP-66: an approving retry with no Job bound calls Run exactly once
// and carries the decision alongside the results
// -----------------------------------------------------------------------

func TestAnsweredRetry_ApproveAtTheHandlerSeamRunsOnceAndCarriesTheDecision(t *testing.T) {
	exec := &scriptedRetryExecutor{}
	exec.second.results = []capability.NodeResult{{NodeID: "node-a", Outcome: jobs.OutcomeUnreachable, JobID: "job-1"}}
	log := &retryEventLog{}
	reads := &scriptedReadAuditor{log: log}
	results := &scriptedJobResultReader{log: log}
	dec := scriptedDecider{resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash}}
	srv := retryServer(t, exec, reads, results, dec)
	session := retrySession(t, srv)

	q := askQuestion(t, session, toolRunOperation, retryOperationArgs())
	res := retryWith(t, session, toolRunOperation, retryOperationArgs(), q.RequestState, "accept")

	if res.IsError {
		t.Fatalf("IsError = true, want false: content=%+v", res.Content)
	}
	var out RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.JobID != "job-1" {
		t.Errorf("JobID = %q, want job-1", out.JobID)
	}
	if out.Decision == nil {
		t.Fatalf("Decision is nil: %+v", out)
	}
	if out.Decision.State != approval.StateApproved.String() {
		t.Errorf("State = %q, want approved", out.Decision.State)
	}
	if out.Decision.Channel != approval.ChannelInBand.String() {
		t.Errorf("Channel = %q, want in-band", out.Decision.Channel)
	}
	if out.Decision.OnBehalfOf != "alice" {
		t.Errorf("OnBehalfOf = %q, want alice", out.Decision.OnBehalfOf)
	}
	wantNextStep := nextStepRanThePipeline + " " + nextStepAnswerRecorded
	if out.Decision.NextStep != wantNextStep {
		t.Errorf("NextStep = %q, want %q", out.Decision.NextStep, wantNextStep)
	}
	if n := exec.runCount(); n != 2 {
		t.Errorf("Run called %d times, want 2 (the initial park plus one retry dispatch)", n)
	}
}

// -----------------------------------------------------------------------
// Plan review suggestion 3: NextStep is chosen from Outcome AND what the
// dispatch actually returned, never from Outcome alone
// -----------------------------------------------------------------------

func TestAnsweredRetry_NextStepFollowsWhatTheDispatchReturned(t *testing.T) {
	cases := []struct {
		name           string
		dec            scriptedDecider
		second         func(*scriptedRetryExecutor)
		wantJobID      string
		wantPending    bool
		wantNextStep   string
		wantChannel    string
		wantOnBehalfOf string
	}{
		{
			name: "quorum completed concurrently: still pending, but the re-entered dispatch ran",
			dec: scriptedDecider{resp: approval.Request{
				ID: answerRequestID, State: approval.StatePending, PlanHash: answerPlanHash,
				Require: approval.Requirement{Count: 2}, Decisions: []approval.Decision{{Approve: true}},
			}},
			second: func(e *scriptedRetryExecutor) {
				e.second.results = []capability.NodeResult{{NodeID: "node-a", Outcome: jobs.OutcomeUnreachable, JobID: "job-1"}}
			},
			wantJobID:      "job-1",
			wantNextStep:   nextStepRanThePipeline + " " + nextStepAnswerRecorded,
			wantChannel:    approval.ChannelInBand.String(),
			wantOnBehalfOf: "alice",
		},
		{
			name: "the rule changed: approved and recorded, but the re-entered dispatch re-parks non-askable",
			dec:  scriptedDecider{resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash}},
			second: func(e *scriptedRetryExecutor) {
				e.second.err = &capability.ParkedError{
					RequestID: "apr-3", PlanHash: "hash-3", Summary: "a different rule now applies",
					ExpiresAt: fixedNow.Add(time.Hour), Askable: false,
				}
			},
			wantPending:    true,
			wantNextStep:   nextStepReParkedOnApproval + " " + nextStepAnswerRecorded,
			wantChannel:    approval.ChannelInBand.String(),
			wantOnBehalfOf: "alice",
		},
		{
			name: "already decided elsewhere: approved but NOT recorded, dispatch still ran",
			dec: scriptedDecider{
				resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash},
				err:  approval.ErrNotPending,
			},
			second: func(e *scriptedRetryExecutor) {
				e.second.results = []capability.NodeResult{{NodeID: "node-a", Outcome: jobs.OutcomeUnreachable, JobID: "job-1"}}
			},
			wantJobID:    "job-1",
			wantNextStep: nextStepRanThePipeline + " " + nextStepAnswerNotRecordedAlreadyDecided,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exec := &scriptedRetryExecutor{}
			tc.second(exec)
			log := &retryEventLog{}
			reads := &scriptedReadAuditor{log: log}
			results := &scriptedJobResultReader{log: log}
			srv := retryServer(t, exec, reads, results, tc.dec)
			session := retrySession(t, srv)

			q := askQuestion(t, session, toolRunOperation, retryOperationArgs())
			res := retryWith(t, session, toolRunOperation, retryOperationArgs(), q.RequestState, "accept")

			if res.NeedsInput() {
				t.Fatalf("NeedsInput() = true, want false: %+v", res)
			}
			if res.IsError {
				t.Fatalf("IsError = true, want false: content=%+v", res.Content)
			}
			var out RunOrPlanOutput
			relaytest.DecodeToolJSON(t, res, &out)
			if out.JobID != tc.wantJobID {
				t.Errorf("JobID = %q, want %q", out.JobID, tc.wantJobID)
			}
			if tc.wantPending && out.PendingApproval == nil {
				t.Fatalf("PendingApproval is nil, want set: %+v", out)
			}
			if out.Decision == nil {
				t.Fatalf("Decision is nil: %+v", out)
			}
			if out.Decision.NextStep != tc.wantNextStep {
				t.Errorf("NextStep = %q, want %q", out.Decision.NextStep, tc.wantNextStep)
			}
			if out.Decision.Channel != tc.wantChannel {
				t.Errorf("Channel = %q, want %q", out.Decision.Channel, tc.wantChannel)
			}
			if out.Decision.OnBehalfOf != tc.wantOnBehalfOf {
				t.Errorf("OnBehalfOf = %q, want %q", out.Decision.OnBehalfOf, tc.wantOnBehalfOf)
			}
		})
	}
}

// -----------------------------------------------------------------------
// BLOCKING 2 (plan review): a dispatch error after the answer was taken
// never claims nothing ran
// -----------------------------------------------------------------------

func TestAnsweredRetry_DispatchErrorAfterTheAnswerNeverClaimsNothingRan(t *testing.T) {
	cases := []struct {
		name   string
		second func(*scriptedRetryExecutor, *scriptedJobResultReader)
	}{
		{
			name: "Run returns results together with an audit-write error",
			second: func(e *scriptedRetryExecutor, _ *scriptedJobResultReader) {
				e.second.results = []capability.NodeResult{{NodeID: "node-a", Outcome: jobs.OutcomeUnreachable, JobID: "job-1"}}
				e.second.err = errors.New("capability: record dispatch audit: disk full")
			},
		},
		{
			name: "Run succeeds but the Job read-back fails",
			second: func(e *scriptedRetryExecutor, r *scriptedJobResultReader) {
				e.second.results = []capability.NodeResult{{NodeID: "node-a", Outcome: jobs.OutcomeUnreachable, JobID: "job-1"}}
				r.getJobErr = errors.New("store: get job: timeout")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exec := &scriptedRetryExecutor{}
			log := &retryEventLog{}
			reads := &scriptedReadAuditor{log: log}
			results := &scriptedJobResultReader{log: log}
			tc.second(exec, results)
			dec := scriptedDecider{resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash}}
			srv := retryServer(t, exec, reads, results, dec)
			session := retrySession(t, srv)

			q := askQuestion(t, session, toolRunOperation, retryOperationArgs())
			res := retryWith(t, session, toolRunOperation, retryOperationArgs(), q.RequestState, "accept")

			if !res.IsError {
				t.Fatalf("IsError = false, want true: %+v", res)
			}
			text := relaytest.ToolErrorText(t, res)
			if !strings.Contains(text, answerRequestID) {
				t.Errorf("text = %q, does not name the request id", text)
			}
			if !strings.Contains(text, "may have run") {
				t.Errorf("text = %q, want it to allow that the call may have run", text)
			}
			if !strings.Contains(text, "get_job") {
				t.Errorf("text = %q, want it to point at get_job", text)
			}
			for _, forbidden := range []string{"nothing ran", "nothing was dispatched", "was then refused"} {
				if strings.Contains(text, forbidden) {
					t.Errorf("text = %q, must not say %q", text, forbidden)
				}
			}
			if n := exec.runCount(); n != 2 {
				t.Errorf("Run called %d times, want 2 (the initial park plus the re-entered dispatch)", n)
			}
		})
	}
}

// -----------------------------------------------------------------------
// AP-67 / BLOCKING 1: a bound Job re-attaches as an audited read
// -----------------------------------------------------------------------

func TestAnsweredRetry_BoundJobReAttachesAtTheHandlerSeam(t *testing.T) {
	exec := &scriptedRetryExecutor{}
	log := &retryEventLog{}
	reads := &scriptedReadAuditor{log: log}
	results := &scriptedJobResultReader{log: log}
	dec := scriptedDecider{
		resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash, JobID: "job-1"},
		err:  approval.ErrNotPending,
	}
	srv := retryServer(t, exec, reads, results, dec)
	session := retrySession(t, srv)

	q := askQuestion(t, session, toolRunOperation, retryOperationArgs())
	res := retryWith(t, session, toolRunOperation, retryOperationArgs(), q.RequestState, "accept")

	if res.IsError {
		t.Fatalf("IsError = true, want false: content=%+v", res.Content)
	}
	var out RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.JobID != "job-1" {
		t.Errorf("JobID = %q, want job-1 (re-attached, never a second Job)", out.JobID)
	}
	if out.Decision == nil {
		t.Fatalf("Decision is nil: %+v", out)
	}
	if out.Decision.OnBehalfOf != "" || out.Decision.Channel != "" {
		t.Errorf("Decision = %+v, want empty OnBehalfOf/Channel (this answer was not recorded)", out.Decision)
	}
	if n := exec.runCount(); n != 1 {
		t.Errorf("Run called %d times, want 1 (re-attach never dispatches)", n)
	}

	events := log.all()
	if len(events) < 2 {
		t.Fatalf("event log = %+v, want at least a read audit then a Job read", events)
	}
	if events[0].kind != "read" || events[0].jobID != "job-1" || events[0].tool != toolRunOperation {
		t.Errorf("first event = %+v, want the read audit naming job-1/run_operation FIRST", events[0])
	}
	for _, e := range events[1:] {
		if e.kind == "read" {
			t.Errorf("event log = %+v, want exactly ONE read-audit record", events)
		}
	}
}

func TestAnsweredRetry_BoundJobReAttachFailsClosedWhenTheReadCannotBeAudited(t *testing.T) {
	exec := &scriptedRetryExecutor{}
	log := &retryEventLog{}
	reads := &scriptedReadAuditor{log: log, err: errors.New("audit store: disk full")}
	results := &scriptedJobResultReader{log: log}
	dec := scriptedDecider{
		resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash, JobID: "job-1"},
		err:  approval.ErrNotPending,
	}
	srv := retryServer(t, exec, reads, results, dec)
	session := retrySession(t, srv)

	q := askQuestion(t, session, toolRunOperation, retryOperationArgs())
	res := retryWith(t, session, toolRunOperation, retryOperationArgs(), q.RequestState, "accept")

	if !res.IsError {
		t.Fatalf("IsError = false, want true: %+v", res)
	}
	text := relaytest.ToolErrorText(t, res)
	if !strings.Contains(text, "job-1") {
		t.Errorf("text = %q, does not name the Job", text)
	}
	if !strings.Contains(text, "decision stands") {
		t.Errorf("text = %q, want it to say the decision stands", text)
	}
	if !strings.Contains(text, "get_job") {
		t.Errorf("text = %q, want it to point at get_job", text)
	}
	if res.StructuredContent != nil {
		t.Errorf("StructuredContent = %+v, want nil on a tool error", res.StructuredContent)
	}
	getJobCalls, tasksByJobCalls := results.counts()
	if getJobCalls != 0 || tasksByJobCalls != 0 {
		t.Errorf("JobResultReader called (getJob=%d tasksByJob=%d), want 0 — no job output appears anywhere", getJobCalls, tasksByJobCalls)
	}
	if n := exec.runCount(); n != 1 {
		t.Errorf("Run called %d times, want 1", n)
	}
}

// -----------------------------------------------------------------------
// raw_exec is wired too, not only run_operation
// -----------------------------------------------------------------------

func TestAnsweredRetry_RawExecIsWiredToo(t *testing.T) {
	t.Run("approve", func(t *testing.T) {
		exec := &scriptedRetryExecutor{}
		exec.second.results = []capability.NodeResult{{NodeID: "node-a", Outcome: jobs.OutcomeUnreachable, JobID: "job-1"}}
		log := &retryEventLog{}
		reads := &scriptedReadAuditor{log: log}
		results := &scriptedJobResultReader{log: log}
		dec := scriptedDecider{resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash}}
		srv := retryServer(t, exec, reads, results, dec)
		session := retrySession(t, srv)

		q := askQuestion(t, session, toolRawExec, retryRawExecArgs())
		res := retryWith(t, session, toolRawExec, retryRawExecArgs(), q.RequestState, "accept")
		if res.IsError {
			t.Fatalf("IsError = true, want false: content=%+v", res.Content)
		}
		var out RunOrPlanOutput
		relaytest.DecodeToolJSON(t, res, &out)
		if out.JobID != "job-1" || out.Decision == nil || out.Decision.State != approval.StateApproved.String() {
			t.Errorf("out = %+v, want an approved decision carrying job-1", out)
		}
		if n := exec.runCount(); n != 2 {
			t.Errorf("Run called %d times, want 2", n)
		}
	})

	t.Run("decline", func(t *testing.T) {
		exec := &scriptedRetryExecutor{}
		log := &retryEventLog{}
		reads := &scriptedReadAuditor{log: log}
		results := &scriptedJobResultReader{log: log}
		dec := scriptedDecider{resp: approval.Request{ID: answerRequestID, State: approval.StateDenied, PlanHash: answerPlanHash}}
		srv := retryServer(t, exec, reads, results, dec)
		session := retrySession(t, srv)

		q := askQuestion(t, session, toolRawExec, retryRawExecArgs())
		res := retryWith(t, session, toolRawExec, retryRawExecArgs(), q.RequestState, "decline")
		if res.IsError {
			t.Fatalf("IsError = true, want false: content=%+v", res.Content)
		}
		var out RunOrPlanOutput
		relaytest.DecodeToolJSON(t, res, &out)
		if out.JobID != "" || out.Decision == nil || out.Decision.State != approval.StateDenied.String() {
			t.Errorf("out = %+v, want a denied decision with no Job", out)
		}
		if n := exec.runCount(); n != 1 {
			t.Errorf("Run called %d times, want 1 (a denial never dispatches)", n)
		}
	})
}

// -----------------------------------------------------------------------
// AP-70: the option-off guard, at the handler seam
// -----------------------------------------------------------------------
//
// The composition root passes WithApprovalElicitation() in production since
// #730, but mcp.New itself still accepts a handler with the option off —
// this is that configuration's own proof, at the seam where it is still
// real, independent of what any composition root chooses to pass.

func TestAnsweredRetry_OptionOffIgnoresRetryFields(t *testing.T) {
	t.Run("option off: retry fields are ignored", func(t *testing.T) {
		exec := &scriptedRetryExecutor{}
		// Every call parks (never dispatches), so "a call without these
		// fields" and "a call carrying them" are directly comparable.
		exec.second.err = &capability.ParkedError{
			RequestID: answerRequestID, PlanHash: answerPlanHash, Summary: "s", ExpiresAt: fixedNow.Add(time.Hour), Askable: false,
		}
		log := &retryEventLog{}
		reads := &scriptedReadAuditor{log: log}
		results := &scriptedJobResultReader{log: log}
		dec := &recordingDecider{}
		handler := New(nil, stubOpsLister{}, exec, results, reads, nil, WithApprovalDecider(dec), WithClock(func() time.Time { return fixedNow }))
		mux := http.NewServeMux()
		mux.Handle("/mcp", handler)
		srv := httptest.NewServer(controlplane.NewAuthenticator(answerTestVerifier{}).Middleware(mux))
		t.Cleanup(srv.Close)

		session := relaytest.ConnectWithOptions(t, srv.URL, answerClient(), relaytest.ConnectOptions{
			Client:     relaytest.ElicitingClientOptions(),
			ClientName: relaytest.GleipnirClientName,
		})

		baseline := relaytest.CallTool(t, session, toolRunOperation, retryOperationArgs())
		var baselineOut RunOrPlanOutput
		relaytest.DecodeToolJSON(t, baseline, &baselineOut)
		if baselineOut.PendingApproval == nil {
			t.Fatalf("baseline did not park: %+v", baselineOut)
		}

		retried := relaytest.RetryTool(t, session, toolRunOperation, retryOperationArgs(), "garbage-request-state",
			sdkmcp.InputResponseMap{answerRequestID: &sdkmcp.ElicitResult{Action: "accept", Meta: permissionResponder("alice")}})
		var retriedOut RunOrPlanOutput
		relaytest.DecodeToolJSON(t, retried, &retriedOut)
		if retriedOut.PendingApproval == nil {
			t.Fatalf("retry carrying stray fields did not park: %+v", retriedOut)
		}
		if retriedOut.AnswerRefused != nil || retriedOut.Decision != nil {
			t.Errorf("retry rendered an answered-retry block with the option off: %+v", retriedOut)
		}
		if calls := dec.calls(); len(calls) != 0 {
			t.Errorf("decider called %d times, want 0", len(calls))
		}
		if n := exec.runCount(); n != 2 {
			t.Errorf("Run called %d times, want 2 (once per call)", n)
		}
	})

	t.Run("plan=true ignores retry fields even with the option on", func(t *testing.T) {
		exec := &scriptedRetryExecutor{}
		log := &retryEventLog{}
		reads := &scriptedReadAuditor{log: log}
		results := &scriptedJobResultReader{log: log}
		dec := &recordingDecider{}
		srv := retryServer(t, exec, reads, results, dec)
		session := retrySession(t, srv)

		args := retryOperationArgs()
		args["plan"] = true
		res := relaytest.RetryTool(t, session, toolRunOperation, args, "garbage-request-state",
			sdkmcp.InputResponseMap{answerRequestID: &sdkmcp.ElicitResult{Action: "accept", Meta: permissionResponder("alice")}})
		if res.IsError {
			t.Fatalf("IsError = true, want false: content=%+v", res.Content)
		}
		var out RunOrPlanOutput
		relaytest.DecodeToolJSON(t, res, &out)
		if out.Plan == nil {
			t.Fatalf("Plan is nil, want a plan result (a call that did not park is today's call): %+v", out)
		}
		if out.AnswerRefused != nil || out.Decision != nil {
			t.Errorf("plan=true rendered an answered-retry block: %+v", out)
		}
		if calls := dec.calls(); len(calls) != 0 {
			t.Errorf("decider called %d times, want 0", len(calls))
		}
	})

	t.Run("a client that cannot be asked has its retry fields ignored", func(t *testing.T) {
		exec := &scriptedRetryExecutor{}
		exec.second.err = &capability.ParkedError{
			RequestID: answerRequestID, PlanHash: answerPlanHash, Summary: "s", ExpiresAt: fixedNow.Add(time.Hour), Askable: false,
		}
		log := &retryEventLog{}
		reads := &scriptedReadAuditor{log: log}
		results := &scriptedJobResultReader{log: log}
		dec := &recordingDecider{}
		srv := retryServer(t, exec, reads, results, dec)
		// A PLAIN session — no ElicitingClientOptions — so clientCanBeAsked's
		// condition 3 (an elicitation capability) is never satisfied.
		session := relaytest.Connect(t, srv.URL, answerClient())

		baseline := relaytest.CallTool(t, session, toolRunOperation, retryOperationArgs())
		var baselineOut RunOrPlanOutput
		relaytest.DecodeToolJSON(t, baseline, &baselineOut)
		if baselineOut.PendingApproval == nil {
			t.Fatalf("baseline did not park: %+v", baselineOut)
		}

		retried := relaytest.RetryTool(t, session, toolRunOperation, retryOperationArgs(), "garbage-request-state",
			sdkmcp.InputResponseMap{answerRequestID: &sdkmcp.ElicitResult{Action: "accept", Meta: permissionResponder("alice")}})
		var retriedOut RunOrPlanOutput
		relaytest.DecodeToolJSON(t, retried, &retriedOut)
		if retriedOut.PendingApproval == nil {
			t.Fatalf("retry carrying stray fields did not park: %+v", retriedOut)
		}
		if retriedOut.AnswerRefused != nil || retriedOut.Decision != nil {
			t.Errorf("a client that cannot be asked still had its retry fields read: %+v", retriedOut)
		}
		if calls := dec.calls(); len(calls) != 0 {
			t.Errorf("decider called %d times, want 0", len(calls))
		}
		if n := exec.runCount(); n != 2 {
			t.Errorf("Run called %d times, want 2 (once per call)", n)
		}
	})
}
