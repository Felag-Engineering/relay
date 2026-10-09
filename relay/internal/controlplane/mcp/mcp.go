// Package mcp is the Relay's MCP surface (ADR-0003): three READ meta-tools —
// list_nodes, describe_node, list_operations — plus, since #118, the
// execution meta-tools — run_operation, raw_exec, cancel_job, get_job — all
// thin adapters over the same control-plane capability layer (invariant 10).
// Since #680 the read tools adapt ONE audited seam, ReadLane, and hold no
// registry or cache of their own — every registry, Policy-view and
// Template-vocabulary read goes through the capability read lane, which
// records it before returning content and fails closed (QRY-28). The
// execution tools adapt an injected Executor (Service.Start/CancelJob's exact
// shape) and JobResultReader (per-Job Task read-back for rendering per-Node
// results).
//
// This file (mcp.go) — along with tools_nodes.go, tools_operations.go,
// attribution.go, and toolevents.go (#416, the tool-call event publisher) —
// is a strict READ file: its non-test source names no capability. identifier
// outside capabilityReadAllowlist (e.g. capability.StateEval, needed for
// NodeListing/NodeDescription's Eval field), and never
// capability.Principal, capability.Service or capability.New. ReadLane below
// is a read-only, Principal-free interface — the Principal is resolved on
// the composition root's side of the seam (the ReadAuditor precedent,
// readaudit.go) — so a read tool structurally cannot reach the execution
// path. The execution tools (tools_execution.go, tools_jobs.go) are relaxed
// EXEC files: they may reference capability.Principal/Selector/NodeResult/
// FrozenError/CapExceededError (needed for Executor's signature and error
// rendering) but, like every file in this package, may never spell
// capability.Service/capability.New/newDispatch or type-assert to
// registry.Repository — those remain unconditionally forbidden.
// no_dispatch_test.go AST-guards this whole partition: every non-test .go
// file must be classified as a read file or an exec file (an unclassified
// new file fails the build), the unconditional rules fire on every file, and
// the relaxed non-allowlisted-capability-selector rule fires only on read
// files.
//
// Wiring note (RB1, plan review): New's Executor/JobResultReader parameters
// are narrowed via execAdapter/jobResultReaderAdapter below New, mirroring
// readLaneAdapter/operationListerAdapter for the read inputs. execAdapter
// itself is defined in tools_execution.go (an exec file, since its method
// bodies must spell capability.Principal/Selector/NodeResult) — New wires it
// here with an UNQUALIFIED composite literal (`execAdapter{r: exec}`) so
// this file never names capability.Principal, the allowlist exclusion that
// is still load-bearing for the Principal-free ReadLane.
//
// The narrow interfaces here are a compile-time guarantee, not a runtime one
// on their own: composition roots pass concrete values (e.g. a
// *capability.Service-backed adapter) whose dynamic type could be wider than
// the interface. Without more, a value read through ReadLane could still be
// type-asserted back to something wider. New immediately re-wraps every
// input in an unexported adapter (readLaneAdapter / operationListerAdapter /
// execAdapter / jobResultReaderAdapter) whose ONLY dynamic type exposes the
// narrow method set — so such a type assertion fails at runtime too, not
// just at the interface boundary.
package mcp

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/opvocab"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// NodeListing is list_nodes' result, as ReadLane returns it. Nodes may be a
// NIL slice when the Selector matched nothing (capability.Selector.Resolve
// returns nil) — the tool must build its response array with an explicit
// zero-length, pre-sized make rather than range straight into a var-declared
// slice, so a no-match result renders an empty JSON array, never null
// (#207/#253).
type NodeListing struct {
	Nodes []registry.Node
	Eval  capability.StateEval
}

// NodeDescription is describe_node's result, as ReadLane returns it: the
// Node plus its DISPLAY-ONLY Policy and Template views. PolicyReported/
// TemplatesReported=false is the ONLY "nothing captured yet" signal — never
// an empty Policy or vocabulary (QRY-7). Deliberately omits PolicyPeers/
// TemplatePeers: MCP does not report peer counts today (QRY-5, Future work),
// and this type must not make that claim untrue by carrying them anyway.
type NodeDescription struct {
	Node              registry.Node
	Eval              capability.StateEval
	Policy            policyview.Snapshot
	PolicyReported    bool
	Templates         nodevocab.Snapshot
	TemplatesReported bool
}

// NodeVocabulary is list_operations' Node-scoped result, as ReadLane
// returns it for a non-empty node_id.
type NodeVocabulary struct {
	Templates nodevocab.Snapshot
	Reported  bool
}

// ReadLane is the ONE audited seam the read tools call (#680, QRY-28): every
// registry, Policy-view and Template-vocabulary read goes through it, which
// records the read before returning content and fails closed. It is
// deliberately Principal-free — capability.Principal is not on
// capabilityReadAllowlist (no_dispatch_test.go), so this package can never
// name it even on its strict read files — and the composition root resolves
// the Principal on its side of the seam (mirrors ReadAuditor, readaudit.go).
type ReadLane interface {
	ListNodes(ctx context.Context, selector string) (NodeListing, error)
	DescribeNode(ctx context.Context, nodeID string) (NodeDescription, error)
	ListOperations(ctx context.Context, nodeID string) (NodeVocabulary, error)
}

// OperationLister is the read-only view over the FLEET-WIDE Native Operation
// vocabulary (opvocab, invariant 8). Since ADR-0021 the full vocabulary is
// per-Node — natives are frozen and uniform, Template Operations are local to
// each Node — so a per-Node view needs this plus ReadLane's
// ListOperations. It reads no registry and no cache and discloses nothing
// about this fleet, so it stays a plain seam rather than going through
// ReadLane: the frozen, compile-time table (ADR-0015/ADR-0021) has nothing
// for an audited lane to record.
type OperationLister interface {
	Operations() []opvocab.Descriptor
}

// JobResultReader is the read-only view over a Job's persisted Tasks the
// execution tools use to render per-Node results (exit code, output,
// duration) — both run_operation/raw_exec's own result rendering and
// get_job's polling re-read go through it (tools_execution.go's renderJob).
// It is satisfied by a tiny jobs.JobRepository+TaskRepository adapter the
// composition root builds (cmd/relay/main.go). jobs.* identifiers are not
// gated by no_dispatch_test.go's capability/registry guard, so this
// interface (and its adapter below) live here alongside the read-only
// interfaces even though JobResultReader backs the execution tools.
type JobResultReader interface {
	GetJob(ctx context.Context, id string) (jobs.Job, error)
	TasksByJob(ctx context.Context, jobID string) ([]jobs.Task, error)
}

// readLaneAdapter narrows an arbitrary ReadLane down to a value whose dynamic
// type is readLaneAdapter itself, exposing only ListNodes/DescribeNode/
// ListOperations. See the package doc comment: this is what makes a type
// assertion on the value New() was given fail at runtime, not just at the
// static-interface boundary.
type readLaneAdapter struct {
	r ReadLane
}

func (a readLaneAdapter) ListNodes(ctx context.Context, selector string) (NodeListing, error) {
	return a.r.ListNodes(ctx, selector)
}

func (a readLaneAdapter) DescribeNode(ctx context.Context, nodeID string) (NodeDescription, error) {
	return a.r.DescribeNode(ctx, nodeID)
}

func (a readLaneAdapter) ListOperations(ctx context.Context, nodeID string) (NodeVocabulary, error) {
	return a.r.ListOperations(ctx, nodeID)
}

// operationListerAdapter is readLaneAdapter's sibling for OperationLister.
// Today's only caller (opvocabLister) is already this narrow, but New
// re-wraps unconditionally so the guarantee doesn't depend on callers
// remembering to.
type operationListerAdapter struct {
	r OperationLister
}

func (a operationListerAdapter) Operations() []opvocab.Descriptor { return a.r.Operations() }

// jobResultReaderAdapter is readLaneAdapter's sibling for JobResultReader:
// it strips whatever concrete JobRepository/TaskRepository-backed value the
// composition root passed down to GetJob/TasksByJob only.
type jobResultReaderAdapter struct {
	r JobResultReader
}

func (a jobResultReaderAdapter) GetJob(ctx context.Context, id string) (jobs.Job, error) {
	return a.r.GetJob(ctx, id)
}

func (a jobResultReaderAdapter) TasksByJob(ctx context.Context, jobID string) ([]jobs.Task, error) {
	return a.r.TasksByJob(ctx, jobID)
}

// serverVersion is the MCP server's advertised Implementation.Version. It is
// intentionally decoupled from the Relay's own release versioning — nothing
// downstream parses it — and is bumped only if the tool surface itself needs
// to signal a breaking change to clients.
const serverVersion = "0.1.0"

// New builds the Relay's MCP server, registers the read tools against
// lane/ops and the execution tools against exec/results, and
// returns it as a plain http.Handler (the SDK's StreamableHTTPHandler) —
// mountable directly on controlplane.Server.Mux() behind the existing
// Authenticator.Middleware (invariant 10: one control path, auth inherited
// from the mux, not reimplemented here).
//
// exec is typically a *capability.Service (which satisfies Executor
// structurally); results is typically a tiny jobs.JobRepository+
// TaskRepository adapter built by the composition root. See #118's DECISION
// 1: passing a *capability.Service here wires the tools but does NOT itself
// turn on production dispatch — that depends on whether exec's own
// dispatcher was configured with capability.WithExecution, which is the
// composition root's call, isolated to #154.
//
// A nil lane is legal only for a server whose read tools (list_nodes,
// describe_node, list_operations) are never called — e.g. a golden-file
// fixture exercising only the execution tools; a stray read-tool call
// through a nil lane panics rather than failing legibly, mirroring the
// pre-existing nil ReadAuditor.
// Option configures a server built by New — WithClock overrides the Tasks
// surface's clock, WithApprovalDecider wires the in-band approval tool,
// WithApprovalElicitation turns on the in-band MRTR question path, and
// WithToolCallObserver attaches the tool-call event publisher.
type Option func(*serverOptions)

type serverOptions struct {
	now       func() time.Time
	approvals ApprovalDecider
	toolCalls ToolCallObserver
	// elicitApprovals is WithApprovalElicitation's flag (elicit.go). It has
	// effect only when approvals is also wired: Relay never asks a question
	// it cannot accept an answer to.
	elicitApprovals bool
	// log is where this surface's operational notes go; nil means
	// slog.Default().
	log *slog.Logger
}

// WithLogger sets the logger the MCP surface reports operational notes to.
// Observational only; without it the surface logs through slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(cfg *serverOptions) { cfg.log = l }
}

// WithClock overrides the clock the Tasks surface renders timestamps from
// (production default: time.Now().UTC()). Since #727 cfg.now is also the
// clock an answered retry opens its sealed request state against (seal
// expiry) and passes to acceptElicitedAnswer for its PastDeadline judgement —
// still a test seam, never configuration (invariant 11).
func WithClock(now func() time.Time) Option {
	return func(o *serverOptions) { o.now = now }
}

// WithToolCallObserver attaches a ToolCallObserver (#416, toolevents.go)
// that is called once per tools/call invocation, before the tool's handler
// runs. A nil observer (the default) installs no middleware at all — see
// New, where AddReceivingMiddleware has no nil-tolerant form, so the guard
// is an explicit `if cfg.toolCalls != nil` around the call, not a
// register*-style function that itself no-ops on a nil collaborator.
func WithToolCallObserver(o ToolCallObserver) Option {
	return func(cfg *serverOptions) { cfg.toolCalls = o }
}

func New(lane ReadLane, ops OperationLister, exec Executor, results JobResultReader, reads ReadAuditor, tasks TaskResolver, opts ...Option) http.Handler {
	cfg := serverOptions{now: func() time.Time { return time.Now().UTC() }}
	for _, o := range opts {
		o(&cfg)
	}

	// Re-wrap every input immediately: from this point on, nothing in this
	// package ever holds a value whose dynamic type is wider than what
	// ReadLane/OperationLister/Executor/JobResultReader expose (see the
	// package doc comment and the adapter types above).
	lane = readLaneAdapter{r: lane}
	ops = operationListerAdapter{r: ops}
	exec = execAdapter{r: exec}
	results = jobResultReaderAdapter{r: results}

	srv := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "relay", Version: serverVersion}, nil)

	// The tool-call event publisher (#416, toolevents.go). Installed before
	// any tool is registered so it is in place for every one of them from
	// the first request; AddReceivingMiddleware has no nil-tolerant form,
	// so a nil observer installs no middleware at all rather than a
	// disabled branch inside one.
	if cfg.toolCalls != nil {
		srv.AddReceivingMiddleware(toolCallMiddleware(cfg.toolCalls))
	}

	// ask is the in-band MRTR question path (elicit.go, S2b), and — since
	// #727 — the same nil check that gates emission also gates the
	// answered-retry path (isAnsweredRetry, tools_execution.go): a nil ask
	// means no question was ever asked, so no retry could ever be answering
	// one either. It is wired only when the caller both turned the option on
	// AND wired a decider — an unwired decider leaves ask nil, so the
	// emission path is absent rather than a disabled branch, and no question
	// could ever be answered anyway. The seal key it mints (requeststate.Mint,
	// crypto/rand) is process-lifetime and never configuration (invariant 11
	// by construction) — minted here, once per New, once per process in
	// production; the restart/replica cost that follows is recorded as
	// threat-model R27 and docs/specs/approval-assurance.md.
	var ask *questioner
	if cfg.elicitApprovals && cfg.approvals != nil {
		ask = newQuestioner(cfg.log)
	}

	registerNodeTools(srv, lane)
	registerOperationTools(srv, ops, lane)
	registerExecutionTools(srv, exec, results, ops, ask, reads, cfg.approvals, cfg.now)
	registerJobTools(srv, exec, results, reads)
	// tasks/get and tasks/cancel (#374, SEP-2663). A nil resolver registers
	// nothing, which is a Relay without the Tasks extension: parked dispatches
	// still return the universal pending_approval result (#371), so the
	// extension's absence costs a client its poll handle and nothing else.
	registerTaskMethods(srv, tasks, results, reads, cfg.now)
	// approve_request (#391, ADR-0029). A nil decider registers nothing, so
	// the in-band rung is opt-in at the composition root: without it, parked
	// dispatches are answerable only on the authenticated /api/v1 endpoint,
	// exactly as before.
	registerApprovalTools(srv, cfg.approvals)

	// Stateless + JSON responses (MCP spec 2026-07-28; #267): the SDK accepts
	// the 2026-07-28 protocol only in stateless mode, and every tool here is
	// already stateless request/response over shared backing stores — a Job ID
	// is the durable handle, never an Mcp-Session-Id. Also removes the
	// per-instance session map that would break behind a round-robin LB (#139).
	var handler http.Handler = sdkmcp.NewStreamableHTTPHandler(func(*http.Request) *sdkmcp.Server {
		return srv
	}, &sdkmcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})

	// The SEP-2663 task-result shim (#375, ADR-0028) wraps the SDK handler,
	// because the SDK cannot express a CreateTaskResult (its resultType is
	// unexported and its Result interface is sealed). It is mounted ONLY when
	// Tasks are wired, so a Relay without the extension has none of this code
	// on its request path at all — not a disabled branch, an absent one. See
	// taskshim.go's header for the preconditions this depends on.
	if tasks != nil {
		handler = withTaskShim(handler, cfg.now, cfg.log)
	}
	return handler
}
