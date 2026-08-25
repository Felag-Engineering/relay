//go:build devharness

// Package main: devharness.go is the ENTIRE dev-harness dispatch/control
// surface for #112's cross-binary CI test, extended by #103 to drive the
// full capability pipeline (Selector -> authz -> blast-cap -> Job engine ->
// dispatch -> audit, ADR-0009/0010) for the v0.0.5 fleet-semantics e2e suite.
// It is a deliberate dev backdoor on an RCE control plane (it lets a local
// unix-socket client mint an Enrollment Token, wait for a Node to register,
// dispatch Tasks and Jobs, engage/inspect Freeze, and read registry/Job/audit
// state) and MUST NOT exist in production builds.
//
// Exclusion is structural, not a runtime flag:
//   - All logic lives in this file, gated by the `devharness` build tag.
//   - devharness_stub.go supplies the production no-op under `!devharness`.
//   - Even in a devharness-tagged build, installDevHarness is inert unless
//     RELAY_DEVHARNESS_SOCKET is explicitly set (defense in depth).
//   - scripts/devharness-absent-check.sh mechanically asserts the untagged
//     binary contains neither the serveDevHarnessSocket symbol nor the
//     RELAY_DEVHARNESS_SOCKET string literal.
//
// The control protocol is newline-delimited JSON over a unix domain socket
// (not proto-on-the-wire): this file is the sole place that translates
// to/from relayv1/jobs/capability, keeping the harness client trivial and
// this file self-auditing.
//
// Capability-layer wiring (#103): unlike the composition root (main.go),
// which defers WithExecution to v0.0.6's real Authorizer, this file supplies
// its own allow-all devHarnessAuthorizer — a type distinct from capability's
// own allowAllAuthorizer, so New's fail-open guard is satisfied — precisely
// what dispatch_wiring.go's doc comment reserves for "the #103 integration
// harness." Every op below is driven through capSvc (invariant 10): this is
// what makes the audit trail, blast-cap, and Freeze acceptance criteria real
// rather than faked at the harness. The daemon's live Policy engine remains
// the sole source of Policy verdicts (ADR-0002/0011) — nothing here
// evaluates or mutates Policy.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/dispatch"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// harnessState is threaded through every socket handler: deps for
// registry/tokens/Freeze/store access, router as the transport-level Conduit
// (raw "dispatch" op + list_connected/get_node's connected field), and capSvc
// as the sole entry point for anything that must go through the capability
// pipeline (run_job/cancel_job/get_freeze).
type harnessState struct {
	deps   *appDeps
	router *dispatch.Router
	capSvc *capability.Service
}

// devHarnessAuthorizer is the #103 integration harness's allow-all
// Authorizer. It is a DISTINCT type from capability's own unexported
// allowAllAuthorizer so capability.New's fail-open guard — "a real dispatcher
// must never ride the package's own allow-all default" — is satisfied by
// construction, not by convention. Real Grant-based authorization is
// v0.0.6+ scope; this harness only proves the pipeline wiring, never a real
// authz decision.
type devHarnessAuthorizer struct{}

func (devHarnessAuthorizer) Authorize(context.Context, capability.Principal, jobs.Action, capability.Selector) error {
	return nil
}

// AuthorizeControl completes capability.Authorizer's administrative half
// (#397). Allow-all like its sibling, for the same reason and under the same
// build tag: the harness's whole purpose is to drive the pipeline from a
// local socket with no Account model behind it.
func (devHarnessAuthorizer) AuthorizeControl(context.Context, capability.Principal, capability.ControlAction) error {
	return nil
}

// installDevHarness wires the dev-harness control socket into deps, iff
// RELAY_DEVHARNESS_SOCKET is set. If it is empty, this is a no-op — even a
// devharness-tagged binary is inert by default (defense in depth).
//
// It builds the real dispatch transport (newDispatchStack, dispatch_wiring.go)
// and sets deps.tunnel.sink to it BEFORE the socket starts serving, and
// strictly before main's srv.Serve is called (installDevHarness runs between
// newServer and Serve), so there is no concurrency with the tunnel handler at
// the moment the sink is assigned. It then constructs an execution-wired
// capability.Service (WithExecution) over the SAME Router, so run_job's
// dispatch and the "dispatch" op's raw send share one Conduit and one set of
// live connections.
func installDevHarness(cfg Config, deps *appDeps) (stop func(), err error) {
	sockPath := os.Getenv("RELAY_DEVHARNESS_SOCKET")
	if sockPath == "" {
		return func() {}, nil
	}

	// Mutual exclusion (RB2, plan review): the production execution flip
	// (#154) makes newServer itself set deps.tunnel.sink when
	// Config.ControlEnabled, wiring its own capability.Service around the
	// SAME dispatch.Router assembly this function builds below. Installing
	// the dev harness on top of that would silently orphan newServer's
	// production sink/capSvc (split-brain: two Routers, two Services, one
	// Tunnel) — never enable the control plane and the dev harness together.
	// This is a composition-root wiring bug, not a recoverable runtime
	// condition, so it panics rather than silently overwriting the sink.
	if deps.tunnel.sink != nil {
		panic("devharness: installDevHarness: deps.tunnel.sink is already set — " +
			"the control plane (Config.ControlEnabled) and the dev harness must never be enabled together")
	}

	router, reconciler, sink := newDispatchStack(deps.tasks)
	// reconciler is captured by router's onConnect closure (dispatch_wiring.go)
	// and fires on every Node registration, including reconnects — this is
	// what makes the crash-mid-Job test's restart reconciliation happen; it
	// is not called directly from here.
	_ = reconciler
	deps.tunnel.sink = sink

	capSvc := capability.New(deps.registry,
		capability.WithExecution(deps.jobs, deps.tasks, router),
		capability.WithAuthorizer(devHarnessAuthorizer{}),
		capability.WithCapChecker(capability.NewBlastCap(cfg.ReadBlastCap, cfg.MutateBlastCap)),
		capability.WithAuditSink(auditsink.New(deps.audit)),
		capability.WithFreeze(deps.store.Freeze()))

	st := &harnessState{deps: deps, router: router, capSvc: capSvc}

	if dir := filepath.Dir(sockPath); dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("devharness: create socket dir: %w", err)
		}
	}
	// Best-effort: remove a stale socket file from a previous unclean shutdown.
	os.Remove(sockPath)

	lis, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("devharness: listen on %q: %w", sockPath, err)
	}
	if err := os.Chmod(sockPath, 0600); err != nil {
		lis.Close()
		return nil, fmt.Errorf("devharness: chmod socket: %w", err)
	}

	slog.Warn("devharness control socket active — CI/dev-only backdoor, never run in production",
		"socket", sockPath)

	go serveDevHarnessSocket(lis, st)

	stop = func() {
		lis.Close()
		os.Remove(sockPath)
	}
	return stop, nil
}

// serveDevHarnessSocket accepts connections on lis and handles each with the
// newline-delimited JSON control protocol. It returns when lis is closed
// (installDevHarness's stop func).
//
// //go:noinline is load-bearing: this is the SOLE symbol
// scripts/devharness-absent-check.sh greps for via `go tool nm` to prove the
// gated surface is absent from production builds. Without it the compiler
// could inline this small function away, making the check vacuous.
//
//go:noinline
func serveDevHarnessSocket(lis net.Listener, st *harnessState) {
	for {
		conn, err := lis.Accept()
		if err != nil {
			// Expected on stop(): lis.Close() causes Accept to return an error.
			return
		}
		go handleDevHarnessConn(conn, st)
	}
}

// harnessRequest is one line of the newline-delimited JSON control protocol.
type harnessRequest struct {
	Op             string            `json:"op"`
	Labels         []string          `json:"labels,omitempty"`
	TTLSeconds     int64             `json:"ttl_seconds,omitempty"`
	TimeoutSeconds int64             `json:"timeout_seconds,omitempty"`
	NodeID         string            `json:"node_id,omitempty"`
	TaskID         string            `json:"task_id,omitempty"`
	Operation      string            `json:"operation,omitempty"`
	Args           map[string]string `json:"args,omitempty"`
	// Selector/RawExec/RiskClass drive run_job: Selector is parsed via
	// capability.ParseSelector; RawExec (if non-empty) builds an ActionRawExec
	// Action and always takes RiskClassMutate (ADR-0012), regardless of
	// RiskClass; otherwise Operation+Args build an ActionOperation Action
	// with RiskClass from RiskClass ("read" -> RiskClassRead, else Mutate).
	Selector  string   `json:"selector,omitempty"`
	RawExec   []string `json:"raw_exec,omitempty"`
	RiskClass string   `json:"risk_class,omitempty"`
	// JobID drives cancel_job and query_job (and, optionally, query_audit).
	JobID string `json:"job_id,omitempty"`
}

// harnessNodeResult is one Node's outcome from a run_job dispatch.
type harnessNodeResult struct {
	NodeID  string `json:"node_id"`
	Outcome string `json:"outcome"`
}

// harnessTaskInfo is one Task's queryable state (query_job, list_inflight).
// JobID is only populated by list_inflight — query_job's caller already
// knows job_id (it is the query key), so it is left empty there.
type harnessTaskInfo struct {
	TaskID  string `json:"task_id"`
	JobID   string `json:"job_id,omitempty"`
	NodeID  string `json:"node_id"`
	State   string `json:"state"`
	Outcome string `json:"outcome"`
	Stderr  string `json:"stderr"`
}

// harnessAuditInfo is one audit.Record's queryable fields (query_audit).
type harnessAuditInfo struct {
	Kind      string `json:"kind"`
	Principal string `json:"principal"`
	Selector  string `json:"selector"`
	NodeID    string `json:"node_id"`
	Outcome   string `json:"outcome"`
	Reason    string `json:"reason"`
}

// harnessResponse is one line of the newline-delimited JSON control protocol
// reply. Only the fields relevant to the request's op are populated.
type harnessResponse struct {
	Token             string `json:"token,omitempty"`
	NodeID            string `json:"node_id,omitempty"`
	TaskID            string `json:"task_id,omitempty"`
	Outcome           string `json:"outcome,omitempty"`
	Stdout            string `json:"stdout,omitempty"`
	Stderr            string `json:"stderr,omitempty"`
	PolicyFingerprint string `json:"policy_fingerprint,omitempty"`
	// TemplateSetFingerprint is get_node's Template Operation drift signal
	// (ADR-0021), reported beside policy_fingerprint. No `omitempty` reason to
	// differ from policy_fingerprint's: an empty value legitimately means "no
	// templates installed on that Node".
	TemplateSetFingerprint string `json:"template_set_fingerprint,omitempty"`
	// NodeLabels/RelayLabels intentionally have no `omitempty`: an empty-but-
	// present map (get_node on a Node with no labels) must still round-trip as
	// `{}`, not be silently dropped from the response.
	NodeLabels  map[string]string `json:"node_labels"`
	RelayLabels map[string]string `json:"relay_labels"`
	// Connected is get_node's live-Tunnel bit (Router.Connected), so tests can
	// poll for a Node going offline deterministically.
	Connected bool `json:"connected,omitempty"`
	// JobID/Results are run_job's success-path fields. Error, below, is
	// INTENTIONALLY the refusal channel for run_job too (a CapExceededError
	// or FrozenError populates Error with Results left empty) — refusal-
	// expecting callers must use the harness client's non-failing helper.
	JobID   string              `json:"job_id,omitempty"`
	Results []harnessNodeResult `json:"results,omitempty"`
	// Frozen is get_freeze's result.
	Frozen bool `json:"frozen,omitempty"`
	// NodeIDs is list_connected's result.
	NodeIDs []string `json:"node_ids,omitempty"`
	// Tasks is query_job's result.
	Tasks []harnessTaskInfo `json:"tasks,omitempty"`
	// Audit is query_audit's result.
	Audit []harnessAuditInfo `json:"audit,omitempty"`
	Error string             `json:"error,omitempty"`
}

// handleDevHarnessConn reads newline-delimited JSON requests off conn and
// writes newline-delimited JSON responses, one per request, until the client
// disconnects or a write fails.
func handleDevHarnessConn(conn net.Conn, st *harnessState) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	enc := json.NewEncoder(conn)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req harnessRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			enc.Encode(harnessResponse{Error: fmt.Sprintf("invalid request: %v", err)}) //nolint:errcheck
			continue
		}
		resp := dispatchHarnessRequest(context.Background(), st, req)
		if err := enc.Encode(resp); err != nil {
			slog.Warn("devharness: write response failed", "err", err)
			return
		}
	}
}

// dispatchHarnessRequest routes req to its op handler. Every op is read-only
// with respect to Policy: it never evaluates or mutates it (ADR-0002/0011) —
// Policy verdicts always come from the daemon's live engine over the real
// wire.
func dispatchHarnessRequest(ctx context.Context, st *harnessState, req harnessRequest) harnessResponse {
	switch req.Op {
	case "create_token":
		return harnessCreateToken(ctx, st.deps, req)
	case "wait_node":
		return harnessWaitNode(st, req)
	case "dispatch":
		return harnessDispatch(ctx, st, req)
	case "get_node":
		return harnessGetNode(st, req)
	case "run_job":
		return harnessRunJob(ctx, st, req)
	case "cancel_job":
		return harnessCancelJob(ctx, st, req)
	case "get_freeze":
		return harnessGetFreeze(ctx, st)
	case "list_connected":
		return harnessListConnected(st)
	case "query_job":
		return harnessQueryJob(ctx, st, req)
	case "query_audit":
		return harnessQueryAudit(ctx, st, req)
	case "list_inflight":
		return harnessListInFlight(ctx, st)
	default:
		return harnessResponse{Error: fmt.Sprintf("unknown op %q", req.Op)}
	}
}

// harnessCreateToken mints an Enrollment Token via the real enroll.Service
// (enroll/token.go:174) and returns its plaintext credential.
//
// SECURITY: the plaintext token is returned to the socket client but MUST
// NEVER be logged (CLAUDE.md: never log secrets).
func harnessCreateToken(ctx context.Context, deps *appDeps, req harnessRequest) harnessResponse {
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	_, plaintext, err := deps.tokens.Create(ctx, req.Labels, ttl)
	if err != nil {
		slog.Warn("devharness: create_token failed", "err", err)
		return harnessResponse{Error: err.Error()}
	}
	return harnessResponse{Token: plaintext}
}

// harnessWaitNode blocks (up to timeout_seconds, default 30s) until a Node
// completes Hello->Ping registration, mirroring the poll at
// tunnel_dispatch_e2e_test.go:224-235.
func harnessWaitNode(st *harnessState, req harnessRequest) harnessResponse {
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	nodeID, err := st.router.WaitForAny(timeout)
	if err != nil {
		return harnessResponse{Error: err.Error()}
	}
	return harnessResponse{NodeID: nodeID}
}

// harnessDispatch builds and sends a single-Operation Task to node_id and
// blocks (up to timeout_seconds, default 15s) for its Result, via
// st.router.Dispatch directly — the #112 raw-dispatch contract (explicit
// task_id, single Node, raw result), unchanged by #103's capability-layer
// rewiring. It never evaluates Policy itself — the outcome (including
// OUTCOME_DENIED_BY_POLICY) comes from the daemon's live engine over the real
// wire (ADR-0011).
func harnessDispatch(ctx context.Context, st *harnessState, req harnessRequest) harnessResponse {
	if req.NodeID == "" || req.TaskID == "" || req.Operation == "" {
		return harnessResponse{Error: "dispatch: node_id, task_id, and operation are required"}
	}
	timeoutSeconds := req.TimeoutSeconds
	if timeoutSeconds <= 0 {
		timeoutSeconds = 15
	}

	dctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	task := jobs.Task{
		ID:             req.TaskID,
		NodeID:         req.NodeID,
		TimeoutSeconds: int32(timeoutSeconds),
		Action: jobs.Action{
			Kind:          jobs.ActionOperation,
			OperationName: req.Operation,
			OperationArgs: req.Args,
		},
	}
	result, err := st.router.Dispatch(dctx, req.NodeID, task)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return harnessResponse{Error: fmt.Sprintf("dispatch: timeout waiting for TaskResult %q", req.TaskID)}
		}
		return harnessResponse{Error: err.Error()}
	}

	return harnessResponse{
		TaskID:  req.TaskID,
		Outcome: outcomeString(result.Outcome),
		Stdout:  string(result.Stdout),
		Stderr:  string(result.Stderr),
	}
}

// harnessGetNode reads the registry (registry.go:102) for node_id and
// returns its Policy fingerprint, labels, and live-Tunnel connectivity. No
// get_ca op exists (plan-review BLOCKING-1): the harness client reads the CA
// bundle directly from <ca-dir>/ca-cert.pem, which ca.Open writes to disk
// during newServer, strictly before installDevHarness opens this socket.
func harnessGetNode(st *harnessState, req harnessRequest) harnessResponse {
	if req.NodeID == "" {
		return harnessResponse{Error: "get_node: node_id is required"}
	}
	node, ok := st.deps.registry.Get(req.NodeID)
	if !ok {
		return harnessResponse{Error: fmt.Sprintf("get_node: node %q not found", req.NodeID)}
	}
	return harnessResponse{
		NodeID:                 node.NodeID,
		PolicyFingerprint:      node.PolicyFingerprint,
		TemplateSetFingerprint: node.TemplateSetFingerprint,
		NodeLabels:             node.NodeLabels,
		RelayLabels:            node.RelayLabels,
		Connected:              st.router.Connected(req.NodeID),
	}
}

// harnessRunJob drives a Selector-targeted dispatch through the full
// capability pipeline (Selector -> authz -> blast-cap -> Job engine ->
// dispatch -> audit, ADR-0009/0010): the single entry point every real
// surface (MCP, Control API) must also use (invariant 10). A refusal
// (CapExceededError from the blast-radius cap, or FrozenError from the
// Relay-wide Freeze) is reported on the response's Error field, not a
// transport error — callers that expect a refusal must use the harness
// client's non-failing helper.
func harnessRunJob(ctx context.Context, st *harnessState, req harnessRequest) harnessResponse {
	sel, err := capability.ParseSelector(req.Selector)
	if err != nil {
		return harnessResponse{Error: fmt.Sprintf("run_job: parse selector %q: %v", req.Selector, err)}
	}

	act, err := harnessRunJobAction(req)
	if err != nil {
		return harnessResponse{Error: fmt.Sprintf("run_job: %v", err)}
	}

	results, err := st.capSvc.Run(ctx, capability.Principal{Account: "devharness"}, sel, act)
	if err != nil {
		return harnessResponse{Error: err.Error()}
	}

	resp := harnessResponse{Results: make([]harnessNodeResult, 0, len(results))}
	for _, r := range results {
		if resp.JobID == "" {
			resp.JobID = r.JobID
		}
		resp.Results = append(resp.Results, harnessNodeResult{NodeID: r.NodeID, Outcome: outcomeString(r.Outcome)})
	}
	return resp
}

// harnessRunJobAction builds run_job's Action: Raw Exec (if raw_exec is
// non-empty) ALWAYS takes RiskClassMutate (ADR-0012, invariant 13) regardless
// of risk_class, enforced here rather than assumed; a structured Operation
// takes its RiskClass from risk_class ("read" -> RiskClassRead, else Mutate —
// there is no Relay-side operation->risk-class registry until the v0.0.6 MCP
// vocabulary).
func harnessRunJobAction(req harnessRequest) (jobs.Action, error) {
	if len(req.RawExec) > 0 {
		return jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: req.RawExec, RiskClass: jobs.RiskClassMutate}, nil
	}
	if req.Operation == "" {
		return jobs.Action{}, fmt.Errorf("operation or raw_exec is required")
	}
	class := jobs.RiskClassMutate
	if req.RiskClass == "read" {
		class = jobs.RiskClassRead
	}
	return jobs.Action{Kind: jobs.ActionOperation, OperationName: req.Operation, OperationArgs: req.Args, RiskClass: class}, nil
}

// harnessCancelJob stops job_id's Tasks (#101, ADR-0013) via the capability
// pipeline's CancelJob: undispatched Tasks are marked cancelled without ever
// being sent, in-flight Tasks are asked to cancel over their Tunnels. Uses
// the same devharness Principal as its sibling harnessRunJob (v0.0.6 [5/8],
// owner DECISION 2: CancelJob now records who asked).
func harnessCancelJob(ctx context.Context, st *harnessState, req harnessRequest) harnessResponse {
	if req.JobID == "" {
		return harnessResponse{Error: "cancel_job: job_id is required"}
	}
	if err := st.capSvc.CancelJob(ctx, capability.Principal{Account: "devharness"}, req.JobID); err != nil {
		return harnessResponse{Error: err.Error()}
	}
	return harnessResponse{}
}

// harnessGetFreeze reads whether the Relay-wide Freeze (ADR-0013) is
// currently engaged, directly off the same persisted FreezeStore the local
// SIGUSR1/SIGUSR2 lever (freeze_signal.go) and st.capSvc share.
func harnessGetFreeze(ctx context.Context, st *harnessState) harnessResponse {
	frozen, err := st.deps.store.Freeze().Frozen(ctx)
	if err != nil {
		return harnessResponse{Error: err.Error()}
	}
	return harnessResponse{Frozen: frozen}
}

// harnessListConnected enumerates the live fleet — every Node with a
// currently-registered Tunnel — via Router.ConnectedNodes.
func harnessListConnected(st *harnessState) harnessResponse {
	return harnessResponse{NodeIDs: st.router.ConnectedNodes()}
}

// harnessQueryJob returns job_id's Tasks with their dispatch state, outcome,
// and stderr — used to assert restart survival and crash-mid-Job
// reconciliation (the daemon's dedup stderr signal lands here).
func harnessQueryJob(ctx context.Context, st *harnessState, req harnessRequest) harnessResponse {
	if req.JobID == "" {
		return harnessResponse{Error: "query_job: job_id is required"}
	}
	if _, err := st.deps.jobs.GetJob(ctx, req.JobID); err != nil {
		return harnessResponse{Error: fmt.Sprintf("query_job: get job %q: %v", req.JobID, err)}
	}
	tasks, err := st.deps.tasks.ByJob(ctx, req.JobID)
	if err != nil {
		return harnessResponse{Error: fmt.Sprintf("query_job: list tasks for job %q: %v", req.JobID, err)}
	}
	resp := harnessResponse{Tasks: make([]harnessTaskInfo, 0, len(tasks))}
	for _, task := range tasks {
		resp.Tasks = append(resp.Tasks, harnessTaskInfo{
			TaskID:  task.ID,
			NodeID:  task.NodeID,
			State:   dispatchStateString(task.State),
			Outcome: outcomeString(task.Outcome),
			Stderr:  string(task.Stderr),
		})
	}
	return resp
}

// harnessListInFlight returns every Task currently Dispatched with no Result
// yet (TaskRepository.InFlight — the same set a Relay restart reconciles,
// ADR-0004), each carrying its JobID. Not in the original plan enumeration:
// added because Service.Run blocks until EVERY matched Node's Task reaches a
// terminal state, so a caller can never learn a Job's ID from run_job's own
// response while a long-running Task (e.g. a raw_exec sleep) is still
// in-flight on another connection. list_inflight is the test's only way to
// discover that Job's ID early enough to cancel it (or, after a Relay
// restart, to keep polling the SAME Job across the crash-mid-Job test).
func harnessListInFlight(ctx context.Context, st *harnessState) harnessResponse {
	tasks, err := st.deps.tasks.InFlight(ctx)
	if err != nil {
		return harnessResponse{Error: fmt.Sprintf("list_inflight: %v", err)}
	}
	resp := harnessResponse{Tasks: make([]harnessTaskInfo, 0, len(tasks))}
	for _, task := range tasks {
		resp.Tasks = append(resp.Tasks, harnessTaskInfo{
			TaskID:  task.ID,
			JobID:   task.JobID,
			NodeID:  task.NodeID,
			State:   dispatchStateString(task.State),
			Outcome: outcomeString(task.Outcome),
			Stderr:  string(task.Stderr),
		})
	}
	return resp
}

// harnessQueryAudit returns every audit.Record for job_id, or every Record if
// job_id is empty — used to assert every dispatch/refusal is queryable
// (ROADMAP acceptance for #102).
func harnessQueryAudit(ctx context.Context, st *harnessState, req harnessRequest) harnessResponse {
	var records []audit.Record
	var err error
	if req.JobID != "" {
		records, err = st.deps.audit.ByJob(ctx, req.JobID)
	} else {
		records, err = st.deps.audit.List(ctx)
	}
	if err != nil {
		return harnessResponse{Error: fmt.Sprintf("query_audit: %v", err)}
	}
	resp := harnessResponse{Audit: make([]harnessAuditInfo, 0, len(records))}
	for _, rec := range records {
		resp.Audit = append(resp.Audit, harnessAuditInfo{
			Kind:      rec.Kind,
			Principal: rec.Principal,
			Selector:  rec.Selector,
			NodeID:    rec.NodeID,
			Outcome:   outcomeString(rec.Outcome),
			Reason:    rec.Reason,
		})
	}
	return resp
}

// outcomeString renders a domain jobs.Outcome as the proto-style
// "OUTCOME_..." string the harness client (and the #112 test) asserts on.
func outcomeString(o jobs.Outcome) string {
	switch o {
	case jobs.OutcomeSuccess:
		return "OUTCOME_SUCCESS"
	case jobs.OutcomeFailure:
		return "OUTCOME_FAILURE"
	case jobs.OutcomeTimeout:
		return "OUTCOME_TIMEOUT"
	case jobs.OutcomeDeniedByPolicy:
		return "OUTCOME_DENIED_BY_POLICY"
	case jobs.OutcomeCancelled:
		return "OUTCOME_CANCELLED"
	case jobs.OutcomeUnreachable:
		return "OUTCOME_UNREACHABLE"
	case jobs.OutcomeVersionRefused:
		return "OUTCOME_VERSION_REFUSED"
	case jobs.OutcomeUnsupported:
		return "OUTCOME_UNSUPPORTED"
	default:
		return "OUTCOME_UNSPECIFIED"
	}
}

// dispatchStateString renders a Task's DispatchState, mirroring
// internal/store/tasks.go's own state-string convention (lowercase).
func dispatchStateString(s jobs.DispatchState) string {
	switch s {
	case jobs.DispatchStatePending:
		return "pending"
	case jobs.DispatchStateDispatched:
		return "dispatched"
	case jobs.DispatchStateResolved:
		return "resolved"
	default:
		return "unspecified"
	}
}
