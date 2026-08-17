package mcp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/mcptask"
)

// This is an EXEC file (no_dispatch_test.go's relaxed partition — see
// tools_execution.go's doc comment for the full rationale).

// tasks.go serves the MCP Tasks extension's read side (#374, SEP-2663,
// ADR-0028): `tasks/get` and `tasks/cancel`, registered as custom methods
// beside the SDK's own dispatch table.
//
// This half needs no shim. sdkmcp.AddReceivingCustomMethod merges handlers into
// the server's `receiveMethods` map alongside the standard ones, so these are
// first-class methods with no interception and no fork. Only the outbound
// CreateTaskResult rewrite ([4/6]) needs the transport-layer trick, because the
// SDK's Result interface is sealed against a type it does not know.
//
// # What is NOT here, and must not arrive by accident
//
// `tasks/update` — the method by which a client answers an `inputRequests`
// elicitation. That is an approval decision travelling over the AI's own
// session, and whether an in-band answer can ever count is the open rung-2
// question on #272. Relay emits no `inputRequests`, so no client has anything
// to answer, and no handler exists to receive it. ADR-0028 states this as a
// boundary rather than an omission precisely because the failure mode is
// somebody later "completing the extension"; no_decision_test.go guards this
// file like every other in the package.
//
// # Why cancelling a parked task cannot touch the approval
//
// The rule is enforced in the capability layer (capability/mcptask.go), not
// here, but it is worth stating at the surface that requests it: a
// `tasks/cancel` arrives over the MCP session. If it could withdraw or decide
// the pending approval, the requesting agent would hold a lever over the one
// decision ADR-0027 exists to keep off its channel — it could yank a request
// back the instant it sensed a denial coming, erasing the evidence a human was
// about to rule on. So cancelling ends the CLIENT'S interest: a running Job is
// cancelled through the ordinary CancelJob path, and a still-parked request is
// left pending, queued, and decidable.

// TaskResolver is the capability-layer view the task methods need. Declared
// locally, like Executor, so this package names the layer's methods and never
// its constructor.
//
// Note what is absent: nothing that decides, approves, or denies. The widest
// thing reachable through this seam is cancelling a Job the caller already
// owns a handle to.
type TaskResolver interface {
	ResolveTask(ctx context.Context, p capability.Principal, taskID string) (capability.TaskView, error)
	CancelTask(ctx context.Context, p capability.Principal, taskID string) (capability.TaskView, error)
}

// defaultPollIntervalMs is the cadence Relay asks a Tasks-capable client to
// poll at, and it is the one thing this extension buys that re-driving a
// dispatch never could: server-controlled timing.
//
// Five seconds, because the wait being timed is a HUMAN one. A parked dispatch
// clears when somebody reads a notification and answers on the Control API —
// seconds to minutes, never milliseconds. Polling faster spends requests on a
// state that cannot have changed; polling much slower adds visible dead time
// after the approval lands, which is the moment an operator is watching. Five
// seconds costs twelve requests a minute per outstanding dispatch, which is
// nothing next to what re-driving cost: every one of those was a full
// dispatch attempt through the gate (#379).
const defaultPollIntervalMs = 5000

// taskGetParams is `tasks/get`'s request shape. ParamsBase supplies the SDK's
// `_meta` handling and the unexported marker; the field is SEP-2663's.
type taskGetParams struct {
	sdkmcp.ParamsBase
	TaskID string `json:"taskId"`
}

// taskCancelParams is `tasks/cancel`'s request shape.
type taskCancelParams struct {
	sdkmcp.ParamsBase
	TaskID string `json:"taskId"`
}

// TaskResult is SEP-2663's task shape, returned by both methods.
//
// Result is populated only on a terminal `completed`, and carries the SAME
// rendering `get_job` returns for the same Job — the parity rule the Control
// API already follows. A Job that read one way through a task handle and
// another through get_job would be two accounts of one execution, and an
// operator comparing them would have no way to know which was the fleet's.
type TaskResult struct {
	sdkmcp.ResultBase

	TaskID string `json:"taskId"`

	// Status is one of working | input_required | completed | failed |
	// cancelled. Relay never produces input_required — see the file header.
	Status string `json:"status"`

	CreatedAt     string `json:"createdAt"`
	LastUpdatedAt string `json:"lastUpdatedAt"`

	// TTLMs is how much longer this handle is pollable, floored at zero.
	TTLMs int64 `json:"ttlMs"`

	// PollIntervalMs is how long the client should wait before asking again.
	PollIntervalMs int64 `json:"pollIntervalMs"`

	// StatusMessage is the Relay-authored description of what is waiting — the
	// same text the approver reads. Carried so the agent holding this handle
	// tells its operator what the human is being asked, verbatim, rather than
	// paraphrasing a plan it did not author.
	StatusMessage string `json:"statusMessage,omitempty"`

	// Result is the completed call's payload: the Job's per-Node results.
	Result *ExecutionOutput `json:"result,omitempty"`

	// Error explains a terminal failure — a denied approval, an expired
	// request, a lapsed handle. It is prose for a human, not a code to branch
	// on; Status is what a client branches on.
	Error string `json:"error,omitempty"`
}

// registerTaskMethods adds tasks/get and tasks/cancel to srv.
//
// A registration failure is a programming error (the SDK refuses only names
// that shadow a standard method), so it panics rather than returning: a Relay
// that silently came up without the methods it advertises would be worse than
// one that refused to start.
func registerTaskMethods(srv *sdkmcp.Server, tasks TaskResolver, results JobResultReader, reads ReadAuditor, now func() time.Time) {
	if tasks == nil {
		return
	}

	if err := sdkmcp.AddReceivingCustomMethod(srv, "tasks/get",
		func(ctx context.Context, _ *sdkmcp.ServerSession, params *taskGetParams) (*TaskResult, error) {
			return handleTaskGet(ctx, tasks, results, reads, params.TaskID, now)
		}); err != nil {
		panic(fmt.Sprintf("mcp: register tasks/get: %v", err))
	}

	if err := sdkmcp.AddReceivingCustomMethod(srv, "tasks/cancel",
		func(ctx context.Context, _ *sdkmcp.ServerSession, params *taskCancelParams) (*TaskResult, error) {
			return handleTaskCancel(ctx, tasks, results, reads, params.TaskID, now)
		}); err != nil {
		panic(fmt.Sprintf("mcp: register tasks/cancel: %v", err))
	}
}

// handleTaskGet resolves a handle and renders it.
func handleTaskGet(ctx context.Context, tasks TaskResolver, results JobResultReader, reads ReadAuditor, taskID string, now func() time.Time) (*TaskResult, error) {
	logPrincipal(ctx, "tasks/get")
	p, err := requirePrincipal(ctx)
	if err != nil {
		return nil, err
	}
	if taskID == "" {
		return nil, fmt.Errorf("mcp: tasks/get: taskId is required")
	}

	view, err := tasks.ResolveTask(ctx, p, taskID)
	if err != nil {
		return nil, renderTaskError("tasks/get", taskID, err)
	}
	return renderTask(ctx, view, results, reads, now())
}

// handleTaskCancel ends the client's interest in a handle.
func handleTaskCancel(ctx context.Context, tasks TaskResolver, results JobResultReader, reads ReadAuditor, taskID string, now func() time.Time) (*TaskResult, error) {
	logPrincipal(ctx, "tasks/cancel")
	p, err := requirePrincipal(ctx)
	if err != nil {
		return nil, err
	}
	if taskID == "" {
		return nil, fmt.Errorf("mcp: tasks/cancel: taskId is required")
	}

	view, err := tasks.CancelTask(ctx, p, taskID)
	if err != nil {
		return nil, renderTaskError("tasks/cancel", taskID, err)
	}
	return renderTask(ctx, view, results, reads, now())
}

// renderTask turns a resolved view into the wire shape, reading the Job's
// results when the task completed.
//
// The read audit fires exactly when captured output is about to be returned —
// the same footing get_job is on (ADR-0025). A task handle that returned a
// Job's stdout without a record would be an unaudited back door to material the
// audited tool guards, which is the sort of gap a second path to the same data
// exists to create.
func renderTask(ctx context.Context, view capability.TaskView, results JobResultReader, reads ReadAuditor, now time.Time) (*TaskResult, error) {
	out := &TaskResult{
		TaskID:         view.TaskID,
		Status:         view.Status.String(),
		CreatedAt:      rfc3339(view.CreatedAt),
		LastUpdatedAt:  rfc3339(view.LastUpdatedAt),
		TTLMs:          ttlMillis(view.ExpiresAt, now),
		PollIntervalMs: defaultPollIntervalMs,
		StatusMessage:  view.Summary,
	}

	switch view.Status {
	case mcptask.StatusCompleted:
		if view.JobID == "" {
			break
		}
		if err := auditRead(ctx, reads, "tasks/get", ReadEvent{JobID: view.JobID}); err != nil {
			return nil, err
		}
		job, err := renderJob(ctx, results, view.JobID)
		if err != nil {
			return nil, err
		}
		out.Result = &job
	case mcptask.StatusFailed:
		out.Error = "the approval this call was waiting on will not be granted: it was denied, or it expired. " +
			"Nothing ran. Re-request the dispatch if it is still wanted — a lapsed approval is never revived."
	case mcptask.StatusCancelled:
		out.Error = "this task handle was cancelled. Note that cancelling a handle ends only the client's " +
			"polling: if the dispatch was still awaiting approval, that request remains pending and a human may still decide it."
	}
	return out, nil
}

// renderTaskError translates a capability/domain error into the JSON-RPC error
// a client sees.
//
// An unknown, unowned, or expired handle must be legible rather than a panic or
// a bare 500 — a client that cannot tell "your handle lapsed" from "the server
// broke" will retry the wrong one. Note that unknown and unowned deliberately
// render identically: the store cannot tell them apart on purpose, so that a
// guessed id cannot be confirmed (mcptask.ErrNotFound).
// It returns a *jsonrpc.Error so the reply carries a real JSON-RPC error CODE.
// Returning a plain error yields code 0, which is not a valid JSON-RPC code —
// well-formed enough that a lenient client shrugs and a strict one rejects the
// whole reply, the worst combination for a surface whose conformance we are
// hand-rolling.
//
// # Why every one of these is CodeInternalError
//
// CodeInvalidParams is the semantically better fit for an unknown taskId, and
// it is deliberately NOT used. The SDK's streamable transport maps
// InvalidParams (and MethodNotFound) onto a non-200 HTTP status
// (streamable.go's status mapping), and its client treats a non-200 as fatal
// for the whole session.
//
// Polling a handle that has lapsed is NORMAL — handles expire by design, and a
// client that comes back after its TTL is doing the expected thing. Tearing
// down its MCP session for that would be a far worse defect than an imprecise
// error code, so the code is chosen to keep the connection alive. Every other
// code maps to 200 and leaves the session usable.
//
// Flagged for [6/6]: if a real Tasks-capable client wants a specific code here,
// this is the trade-off to revisit — and the fix would belong upstream, in how
// the SDK maps codes to statuses, rather than here.
func renderTaskError(method, taskID string, err error) error {
	switch {
	case errors.Is(err, mcptask.ErrNotFound):
		return &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: fmt.Sprintf("mcp: %s: no task handle %q is resolvable by this account (unknown, or not yours)", method, taskID),
		}
	case errors.Is(err, mcptask.ErrHandleExpired):
		return &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: fmt.Sprintf("mcp: %s: task handle %q has expired and is no longer pollable", method, taskID),
		}
	case errors.Is(err, capability.ErrTasksUnavailable):
		return &jsonrpc.Error{
			Code: jsonrpc.CodeInternalError,
			Message: fmt.Sprintf("mcp: %s: this Relay does not have MCP task handles enabled; "+
				"a parked dispatch returns a pending_approval result instead, and re-driving the same call re-attaches to it", method),
		}
	default:
		return &jsonrpc.Error{
			Code:    jsonrpc.CodeInternalError,
			Message: fmt.Sprintf("mcp: %s %q: %v", method, taskID, err),
		}
	}
}

// ttlMillis renders remaining lifetime, floored at zero so a lapsed handle
// never advertises a negative window a client would read as garbage.
func ttlMillis(expiresAt, now time.Time) int64 {
	remaining := expiresAt.Sub(now)
	if remaining <= 0 {
		return 0
	}
	return remaining.Milliseconds()
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
