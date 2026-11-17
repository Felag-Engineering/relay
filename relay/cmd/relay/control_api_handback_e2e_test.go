// Package main: control_api_handback_e2e_test.go proves, through the composed
// Control API, that a dispatch returns its Job once the Tasks are stored, with
// an optional bounded wait (EX-57), and that an Idempotency-Key makes a lost
// response safe to retry (EX-58).
//
// A Node is driven by hand over the fixture's bufconn Tunnel and holds its
// TaskResult until the test releases it, so "the Job is still running" is a
// state the test controls rather than a race it hopes to win.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
)

// heldNode is an enrolled Node on a live Tunnel that receives Tasks and answers
// them only when the test says so.
type heldNode struct {
	id      string
	stream  relayv1.Tunnel_OpenClient
	sendMu  sync.Mutex // a gRPC stream is not safe for concurrent Send
	tasks   chan *relayv1.TaskRequest
	cancels chan string
}

// startHeldNode enrolls a Node, opens its Tunnel and returns once the Relay's
// Router can reach it. Its cleanup is registered after startRelay's, so
// (last-in-first-out) it ends the stream before the fixture's Drain runs: a
// Task still held then resolves (EX-62) and Drain completes.
func startHeldNode(t *testing.T, f *relayFixture) *heldNode {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	nodeID, cert, pool := connAuditEnroll(ctx, t, f)
	conn := dialTLS(t, f.Bufconn, &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool})
	stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("Tunnel Open: %v", err)
	}
	n := &heldNode{
		id:      nodeID,
		stream:  stream,
		tasks:   make(chan *relayv1.TaskRequest, 16),
		cancels: make(chan string, 16),
	}
	n.send(t, &relayv1.DaemonMessage{Body: &relayv1.DaemonMessage_Hello{Hello: &relayv1.Hello{}}})
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv Ping: %v", err)
	}
	if msg.GetPing() == nil {
		t.Fatalf("expected Ping after Hello, got %T", msg.Body)
	}
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				return
			}
			switch {
			case m.GetTask() != nil:
				n.tasks <- m.GetTask()
			case m.GetTaskCancel() != nil:
				n.cancels <- m.GetTaskCancel().GetTaskId()
			}
		}
	}()

	// The Ping precedes the Router's registration of the stream, so a dispatch
	// racing it would resolve the Task unreachable. The Relay reads a message
	// only once it has registered, so a Heartbeat that advances LastSeen proves
	// the Node is reachable.
	before, ok := f.Deps.registry.Get(nodeID)
	if !ok {
		t.Fatalf("node %s not in the registry", nodeID)
	}
	n.send(t, &relayv1.DaemonMessage{Body: &relayv1.DaemonMessage_Heartbeat{
		Heartbeat: &relayv1.Heartbeat{UnixMillis: time.Now().UnixMilli()},
	}})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if cur, _ := f.Deps.registry.Get(nodeID); cur.LastSeen.After(before.LastSeen) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the Relay never processed the Node's Heartbeat")
		}
		time.Sleep(time.Millisecond)
	}
	return n
}

// selector names this Node and no other.
func (n *heldNode) selector() string { return "relay:node-id=" + n.id }

func (n *heldNode) send(t *testing.T, m *relayv1.DaemonMessage) {
	t.Helper()
	n.sendMu.Lock()
	defer n.sendMu.Unlock()
	if err := n.stream.Send(m); err != nil {
		t.Fatalf("send: %v", err)
	}
}

// nextTask waits for the Relay to send the Node a Task.
func (n *heldNode) nextTask(t *testing.T) *relayv1.TaskRequest {
	t.Helper()
	select {
	case tr := <-n.tasks:
		return tr
	case <-time.After(10 * time.Second):
		t.Fatal("the Node was sent no Task")
		return nil
	}
}

// noTask asserts the Relay sends the Node no Task within d.
func (n *heldNode) noTask(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case tr := <-n.tasks:
		t.Fatalf("the Node was sent an unexpected Task %s", tr.GetTaskId())
	case <-time.After(d):
	}
}

// noCancel asserts the Relay sends the Node no TaskCancel within d.
func (n *heldNode) noCancel(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case id := <-n.cancels:
		t.Fatalf("the Node was sent a TaskCancel for %s", id)
	case <-time.After(d):
	}
}

// answer sends the Task's result: outcome success with stdout.
func (n *heldNode) answer(t *testing.T, taskID, stdout string) {
	t.Helper()
	n.send(t, &relayv1.DaemonMessage{Body: &relayv1.DaemonMessage_TaskResult{TaskResult: &relayv1.TaskResult{
		TaskId:  taskID,
		Outcome: relayv1.Outcome_OUTCOME_SUCCESS,
		Stdout:  []byte(stdout),
	}}})
}

// dispatchBody is the Control API's dispatch response, decoded as an outside
// caller would.
type dispatchBody struct {
	JobID      string              `json:"job_id"`
	JobStatus  string              `json:"job_status"`
	Reattached bool                `json:"reattached"`
	Results    []mcp.PerNodeResult `json:"results"`
}

// problemBody is an RFC 9457 problem as the Control API renders it.
type problemBody struct {
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// doDispatch POSTs body to url with an optional Idempotency-Key, returning the
// error rather than failing the test, so a goroutine may call it.
func doDispatch(ctx context.Context, client *http.Client, url, token string, body any, key string) (*http.Response, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	return client.Do(req)
}

// postDispatch is doDispatch for the test goroutine.
func postDispatch(ctx context.Context, t *testing.T, client *http.Client, url, token string, body any, key string) *http.Response {
	t.Helper()
	resp, err := doDispatch(ctx, client, url, token, body, key)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

// decodeBody decodes resp's JSON body into out and closes it.
func decodeBody(t *testing.T, resp *http.Response, out any) {
	t.Helper()
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("decode %q: %v", raw, err)
	}
}

// requireDispatch decodes a 200 dispatch response.
func requireDispatch(t *testing.T, resp *http.Response) dispatchBody {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("status = %d, want 200; body %s", resp.StatusCode, raw)
	}
	var out dispatchBody
	decodeBody(t, resp, &out)
	return out
}

// requireProblem decodes a problem response with the wanted status.
func requireProblem(t *testing.T, resp *http.Response, status int) problemBody {
	t.Helper()
	if resp.StatusCode != status {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("status = %d, want %d; body %s", resp.StatusCode, status, raw)
	}
	var out problemBody
	decodeBody(t, resp, &out)
	return out
}

// pollJob reads GET /api/v1/jobs/{id} until job_status is complete.
func pollJob(t *testing.T, f *relayFixture, jobID string) dispatchBody {
	t.Helper()
	for range 100 {
		resp := controlAPIRequest(t, f.ClientFor(""), http.MethodGet, f.ControlBase+"/api/v1/jobs/"+jobID, f.Credential, nil)
		var out dispatchBody
		decodeBody(t, resp, &out)
		if out.JobStatus == "complete" {
			return out
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("Job %s never became complete", jobID)
	return dispatchBody{}
}

func operationsURL(f *relayFixture) string { return f.ControlBase + "/api/v1/operations" }

// restartBody is a gated service.restart dispatch to sel.
func restartBody(sel string, waitSeconds int) map[string]any {
	return map[string]any{
		"selector":     sel,
		"operation":    "service.restart",
		"args":         map[string]string{"unit": "nginx"},
		"wait_seconds": waitSeconds,
	}
}

// A dispatch with no wait returns its Job as soon as the Task is stored, while
// the Node has not answered, and the Jobs route then reads it to completion.
//
// Proves EX-57.
func TestControlAPI_ADispatchReturnsItsRunningJobBeforeTheNodeAnswers(t *testing.T) {
	f := startRelay(t, WithControlPlane())
	node := startHeldNode(t, f)

	resp := postDispatch(context.Background(), t, f.ClientFor(""), operationsURL(f), f.Credential,
		map[string]any{"selector": node.selector(), "operation": "system.facts"}, "")
	out := requireDispatch(t, resp)
	if out.JobID == "" || out.JobStatus != "running" || out.Reattached {
		t.Fatalf("dispatch = %+v, want a fresh running Job", out)
	}
	if len(out.Results) != 1 || out.Results[0].NodeID != node.id {
		t.Fatalf("results = %+v, want one row for the Node", out.Results)
	}

	tr := node.nextTask(t)
	node.answer(t, tr.GetTaskId(), "facts-out")

	job := pollJob(t, f, out.JobID)
	if len(job.Results) != 1 || job.Results[0].Outcome != "success" || job.Results[0].Stdout != "facts-out" {
		t.Fatalf("complete Job = %+v, want one success row with the Node's stdout", job)
	}
}

// With wait_seconds the call holds until the Node answers and then returns the
// full results.
//
// Proves EX-57.
func TestControlAPI_WaitSecondsReturnsFullResults(t *testing.T) {
	f := startRelay(t, WithControlPlane())
	node := startHeldNode(t, f)

	type reply struct {
		resp *http.Response
		err  error
	}
	done := make(chan reply, 1)
	go func() {
		resp, err := doDispatch(context.Background(), f.ClientFor(""), operationsURL(f), f.Credential,
			map[string]any{"selector": node.selector(), "operation": "system.facts", "wait_seconds": 30}, "")
		done <- reply{resp, err}
	}()

	tr := node.nextTask(t)
	select {
	case r := <-done:
		t.Fatalf("the response arrived before the Node answered: %+v", r)
	case <-time.After(300 * time.Millisecond):
	}
	node.answer(t, tr.GetTaskId(), "held-then-answered")

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("POST: %v", r.err)
		}
		out := requireDispatch(t, r.resp)
		if out.JobStatus != "complete" || len(out.Results) != 1 || out.Results[0].Outcome != "success" || out.Results[0].Stdout != "held-then-answered" {
			t.Fatalf("dispatch = %+v, want a complete Job with the success row", out)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the waiting dispatch never returned after the Node answered")
	}
}

// A wait that lapses returns the running Job and never cancels it: the Node is
// sent no TaskCancel and its later answer completes the Job.
//
// Proves EX-57.
func TestControlAPI_ALapsedWaitReturnsTheRunningJobAndNeverCancelsIt(t *testing.T) {
	f := startRelay(t, WithControlPlane())
	node := startHeldNode(t, f)

	resp := postDispatch(context.Background(), t, f.ClientFor(""), operationsURL(f), f.Credential,
		map[string]any{"selector": node.selector(), "operation": "system.facts", "wait_seconds": 1}, "")
	out := requireDispatch(t, resp)
	if out.JobStatus != "running" {
		t.Fatalf("job_status = %q after a lapsed wait, want running", out.JobStatus)
	}

	tr := node.nextTask(t)
	node.noCancel(t, 300*time.Millisecond)
	node.answer(t, tr.GetTaskId(), "late")

	job := pollJob(t, f, out.JobID)
	if len(job.Results) != 1 || job.Results[0].Outcome != "success" {
		t.Fatalf("Job after the lapse = %+v, want the Node's success", job)
	}
}

// After an approval, the first re-drive starts the Job and waits for it; a
// second re-drive meanwhile dispatches nothing and returns that same Job at
// once.
//
// Proves EX-57, AP-77.
func TestControlAPI_TheFirstReDriveAfterAnApprovalWaitsAndASecondReAttachesAtOnce(t *testing.T) {
	rules := gateRules(t, gateAllMutates)
	f := startRelay(t, WithControlPlane(), WithConfig(func(c *Config) { c.ApprovalRules = rules }))
	node := startHeldNode(t, f)
	approver := mintAccount(t, f, "ana", accounts.KindHuman, accounts.RoleOperator)

	park := postDispatch(context.Background(), t, f.ClientFor(""), operationsURL(f), f.Credential, restartBody(node.selector(), 0), "")
	if park.StatusCode != http.StatusAccepted {
		t.Fatalf("park status = %d, want 202", park.StatusCode)
	}
	var parked parkedBody
	decodeBody(t, park, &parked)

	decide := controlAPIRequest(t, f.ClientFor(approver), http.MethodPost, f.ControlBase+parked.DecisionPath, approver,
		map[string]any{"approve": true, "plan_hash": parked.PlanHash, "reason": "change ticket"})
	defer decide.Body.Close()
	if decide.StatusCode != http.StatusOK {
		t.Fatalf("decision status = %d, want 200", decide.StatusCode)
	}

	type reply struct {
		resp *http.Response
		err  error
	}
	first := make(chan reply, 1)
	go func() {
		resp, err := doDispatch(context.Background(), f.ClientFor(""), operationsURL(f), f.Credential, restartBody(node.selector(), 300), "")
		first <- reply{resp, err}
	}()

	tr := node.nextTask(t)
	second := requireDispatch(t, postDispatch(context.Background(), t, f.ClientFor(""), operationsURL(f), f.Credential, restartBody(node.selector(), 300), ""))
	if !second.Reattached || second.JobStatus != "running" || second.JobID == "" {
		t.Fatalf("second re-drive = %+v, want the running Job re-attached at once", second)
	}

	node.answer(t, tr.GetTaskId(), "restarted")
	select {
	case r := <-first:
		if r.err != nil {
			t.Fatalf("first re-drive: %v", r.err)
		}
		out := requireDispatch(t, r.resp)
		if out.JobStatus != "complete" || out.Reattached || out.JobID != second.JobID {
			t.Fatalf("first re-drive = %+v, want the complete Job %s, not re-attached", out, second.JobID)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the first re-drive never returned after the Node answered")
	}
	if n := len(allJobs(t, f)); n != 1 {
		t.Fatalf("Jobs = %d, want exactly 1", n)
	}
}

// A wait_seconds above 300 is refused as a 400 on both routes by the adapter:
// no Job and no refusal record, because the wait is not the capability layer's.
//
// Proves EX-57.
func TestControlAPI_WaitSecondsAbove300IsABadRequest(t *testing.T) {
	f := startRelay(t, WithControlPlane())

	for path, body := range map[string]map[string]any{
		"/api/v1/operations": {"selector": e2eFleetSelector, "operation": "system.facts", "wait_seconds": 301},
		"/api/v1/raw-exec":   {"selector": e2eFleetSelector, "argv": []string{"/bin/true"}, "wait_seconds": 301},
	} {
		resp := postDispatch(context.Background(), t, f.ClientFor(""), f.ControlBase+path, f.Credential, body, "")
		if p := requireProblem(t, resp, http.StatusBadRequest); p.Title != "invalid wait_seconds" {
			t.Errorf("%s: title = %q, want \"invalid wait_seconds\"", path, p.Title)
		}
	}
	if n := len(allJobs(t, f)); n != 0 {
		t.Errorf("Jobs = %d, want 0", n)
	}
	if refusals := recordsOfKind(auditList(t, f.Deps.audit), audit.KindRefusal); len(refusals) != 0 {
		t.Errorf("refusal records = %+v, want none: a request the adapter refuses leaves no audit record", refusals)
	}
}

// A caller that lost the response re-sends the same key and gets the same Job
// back, at once, without a second dispatch.
//
// Proves EX-58, EX-9.
func TestControlAPI_ALostResponseIsRetriedSafelyWithItsIdempotencyKey(t *testing.T) {
	f := startRelay(t, WithControlPlane())
	node := startHeldNode(t, f)
	body := map[string]any{"selector": node.selector(), "operation": "system.facts", "wait_seconds": 300}

	ctx, cancel := context.WithCancel(context.Background())
	lost := make(chan string, 1)
	go func() {
		resp, err := doDispatch(ctx, f.ClientFor(""), operationsURL(f), f.Credential, body, "k-lost")
		if err != nil {
			lost <- ""
			return
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		lost <- fmt.Sprintf("%d %s", resp.StatusCode, raw)
	}()
	tr := node.nextTask(t)
	cancel()
	if answer := <-lost; answer != "" {
		t.Fatalf("the cancelled request was answered: %s", answer)
	}
	node.noCancel(t, 300*time.Millisecond)

	again := requireDispatch(t, postDispatch(context.Background(), t, f.ClientFor(""), operationsURL(f), f.Credential, body, "k-lost"))
	if !again.Reattached || again.JobStatus != "running" || again.JobID == "" {
		t.Fatalf("re-issued call = %+v, want the running Job re-attached at once", again)
	}

	node.answer(t, tr.GetTaskId(), "once")
	if job := pollJob(t, f, again.JobID); len(job.Results) != 1 || job.Results[0].Outcome != "success" {
		t.Fatalf("Job after the lost response = %+v, want the Node's success", job)
	}

	records := auditByJob(t, f.Deps.audit, again.JobID)
	if n := len(recordsOfKind(records, audit.KindDispatchIntent)); n != 1 {
		t.Errorf("dispatch intent records = %d, want 1", n)
	}
	var reattaches int
	for _, r := range recordsOfKind(records, audit.KindRead) {
		if r.OperationName == "idempotent_reattach" {
			reattaches++
		}
	}
	if reattaches != 1 {
		t.Errorf("idempotent_reattach read records = %d, want 1", reattaches)
	}
	tasks, err := f.Deps.tasks.ByJob(context.Background(), again.JobID)
	if err != nil || len(tasks) != 1 {
		t.Errorf("Tasks = %d (err %v), want 1", len(tasks), err)
	}
	if n := len(allJobs(t, f)); n != 1 {
		t.Errorf("Jobs = %d, want 1", n)
	}
	node.noTask(t, 300*time.Millisecond)
}

// The same key from another Account is a separate request and a new Job.
//
// Proves EX-58.
func TestControlAPI_AnotherAccountsSameKeyIsANewJob(t *testing.T) {
	f := startRelay(t, WithControlPlane())
	if _, err := f.Deps.registry.Upsert(linuxNode("node-e2e-1")); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	operator := mintAccount(t, f, "ana", accounts.KindHuman, accounts.RoleOperator)
	body := map[string]any{"selector": e2eFleetSelector, "operation": "system.facts"}

	a := requireDispatch(t, postDispatch(context.Background(), t, f.ClientFor(""), operationsURL(f), f.Credential, body, "k-shared"))
	b := requireDispatch(t, postDispatch(context.Background(), t, f.ClientFor(""), operationsURL(f), operator, body, "k-shared"))
	if a.JobID == "" || b.JobID == "" || a.JobID == b.JobID || b.Reattached {
		t.Fatalf("Account A = %+v, Account B = %+v, want two distinct fresh Jobs", a, b)
	}
	if n := len(allJobs(t, f)); n != 2 {
		t.Fatalf("Jobs = %d, want 2", n)
	}
}

// A malformed key is a 400 carrying the capability layer's text, audited as a
// refusal by the layer, and dispatches nothing.
//
// Proves EX-58.
func TestControlAPI_AMalformedIdempotencyKeyIsABadRequest(t *testing.T) {
	f := startRelay(t, WithControlPlane())
	if _, err := f.Deps.registry.Upsert(linuxNode("node-e2e-1")); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	body := map[string]any{"selector": e2eFleetSelector, "operation": "system.facts"}

	cases := []struct{ key, reason string }{
		{strings.Repeat("k", capability.MaxIdempotencyKeyBytes+1), "too long"},
		{"has a space", "unprintable or space byte"},
	}
	for _, tc := range cases {
		key := tc.key
		resp := postDispatch(context.Background(), t, f.ClientFor(""), operationsURL(f), f.Credential, body, key)
		p := requireProblem(t, resp, http.StatusBadRequest)
		if p.Title != "invalid idempotency key" {
			t.Errorf("key %q: title = %q, want \"invalid idempotency key\"", key, p.Title)
		}
		if want := (&capability.IdempotencyKeyError{Reason: tc.reason}).Error(); p.Detail != want {
			t.Errorf("key %q: detail = %q, want the capability layer's text %q", key, p.Detail, want)
		}
	}
	if n := len(allJobs(t, f)); n != 0 {
		t.Errorf("Jobs = %d, want 0", n)
	}
	if refusals := recordsOfKind(auditList(t, f.Deps.audit), audit.KindRefusal); len(refusals) != 2 {
		t.Errorf("refusal records = %d, want 2 (one per malformed key)", len(refusals))
	}
}

// A preflight claims no key: plan with a key answers a plan, and the same key
// on a real dispatch afterwards still creates a fresh Job.
//
// Proves EX-58, PF-8.
func TestControlAPI_APreflightWithAKeyClaimsNothing(t *testing.T) {
	f := startRelay(t, WithControlPlane())
	if _, err := f.Deps.registry.Upsert(linuxNode("node-e2e-1")); err != nil {
		t.Fatalf("seed registry: %v", err)
	}

	plan := postDispatch(context.Background(), t, f.ClientFor(""), operationsURL(f), f.Credential,
		map[string]any{"selector": e2eFleetSelector, "operation": "system.facts", "plan": true}, "k-plan")
	if plan.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(plan.Body)
		t.Fatalf("plan status = %d, want 200; body %s", plan.StatusCode, raw)
	}
	var planOut struct {
		JobID    string            `json:"job_id"`
		Verdicts []json.RawMessage `json:"verdicts"`
	}
	decodeBody(t, plan, &planOut)
	if planOut.JobID != "" || len(planOut.Verdicts) != 1 {
		t.Fatalf("plan = %+v, want one verdict and no Job", planOut)
	}

	fresh := requireDispatch(t, postDispatch(context.Background(), t, f.ClientFor(""), operationsURL(f), f.Credential,
		map[string]any{"selector": e2eFleetSelector, "operation": "system.facts"}, "k-plan"))
	if fresh.JobID == "" || fresh.Reattached {
		t.Fatalf("real dispatch = %+v, want a fresh Job", fresh)
	}
	if n := len(allJobs(t, f)); n != 1 {
		t.Fatalf("Jobs = %d, want 1", n)
	}
}
