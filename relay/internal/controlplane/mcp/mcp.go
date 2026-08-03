// Package mcp is the Relay's MCP surface (ADR-0003): three READ meta-tools —
// list_nodes, describe_node, list_operations — plus, since #118, the
// execution meta-tools — run_operation, raw_exec, cancel_job, get_job — all
// thin adapters over the same control-plane capability layer (invariant 10).
// The read tools adapt the registry, the display-only effective-Policy
// cache, and the Operation vocabulary; the execution tools adapt an injected
// Executor (Service.Run/CancelJob's exact shape) and JobResultReader
// (per-Job Task read-back for rendering per-Node results).
//
// This file (mcp.go) — along with tools_nodes.go, tools_operations.go, and
// attribution.go — is a strict READ file: its non-test source never spells a
// capability. token at all (not even capability.Principal), never imports
// *capability.Service, and never calls capability.New. NodeReader,
// PolicyReader, and OperationLister below are read-only interfaces —
// Get/List/Operations, no Run — so a read tool structurally cannot reach the
// execution path. The execution tools (tools_execution.go, tools_jobs.go)
// are relaxed EXEC files: they may reference capability.Principal/Selector/
// NodeResult/FrozenError/CapExceededError (needed for Executor's signature
// and error rendering) but, like every file in this package, may never
// spell capability.Service/capability.New/newDispatch or type-assert to
// registry.Repository — those remain unconditionally forbidden.
// no_dispatch_test.go AST-guards this whole partition: every non-test .go
// file must be classified as a read file or an exec file (an unclassified
// new file fails the build), the unconditional rules fire on every file, and
// the relaxed non-allowlisted-capability-selector rule fires only on read
// files.
//
// Wiring note (RB1, plan review): New's Executor/JobResultReader parameters
// are narrowed via execAdapter/jobResultReaderAdapter below New, mirroring
// nodeReaderAdapter/policyReaderAdapter/operationListerAdapter for the read
// inputs. execAdapter itself is defined in tools_execution.go (an exec
// file, since its method bodies must spell capability.Principal/Selector/
// NodeResult) — New wires it here with an UNQUALIFIED composite literal
// (`execAdapter{r: exec}`) so this file's own source still names no
// capability. token.
//
// The narrow interfaces here are a compile-time guarantee, not a runtime one
// on their own: composition roots pass concrete values (e.g.
// registry.Repository, *policyview.Cache, *capability.Service) whose dynamic
// type is wider than the interface. Without more, a value read through
// NodeReader could still be type-asserted back to registry.Repository to
// recover Upsert/SetRelayLabels/Delete (and, for Executor, back to
// *capability.Service to recover EngageFreeze/ReleaseFreeze). New
// immediately re-wraps every input in an unexported adapter
// (nodeReaderAdapter / policyReaderAdapter / operationListerAdapter /
// execAdapter / jobResultReaderAdapter) whose ONLY dynamic type exposes the
// narrow method set — so such a type assertion fails at runtime too, not
// just at the interface boundary.
package mcp

import (
	"context"
	"net/http"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/opvocab"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// NodeReader is the read-only registry view the mcp package needs. It is
// deliberately narrower than registry.Repository (Get/List only, no
// Upsert/SetRelayLabels/SetRevoked/...) so this package's write surface to
// the registry is structurally nil — it is satisfied by registry.Repository
// as passed from the composition root, but callers here can never reach a
// write method through it.
type NodeReader interface {
	Get(nodeID string) (registry.Node, bool)
	List() []registry.Node
}

// PolicyReader is the read-only view over the display-only effective-Policy
// cache (policyview.Cache). Display-only: the Relay never evaluates or sets
// Policy through this or any other path (ADR-0002, invariant 12).
type PolicyReader interface {
	Get(nodeID string) (policyview.Snapshot, bool)
}

// OperationLister is the read-only view over the Operation vocabulary
// (opvocab, invariant 8).
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

// nodeReaderAdapter narrows an arbitrary NodeReader down to a value whose
// dynamic type is nodeReaderAdapter itself, exposing only Get/List. See the
// package doc comment: this is what makes a `.(registry.Repository)` type
// assertion on the value New() was given fail at runtime, not just at the
// static-interface boundary.
type nodeReaderAdapter struct {
	r NodeReader
}

func (a nodeReaderAdapter) Get(nodeID string) (registry.Node, bool) { return a.r.Get(nodeID) }
func (a nodeReaderAdapter) List() []registry.Node                   { return a.r.List() }

// policyReaderAdapter is nodeReaderAdapter's sibling for PolicyReader: it
// strips a *policyview.Cache (which also exposes Set) down to Get only.
type policyReaderAdapter struct {
	r PolicyReader
}

func (a policyReaderAdapter) Get(nodeID string) (policyview.Snapshot, bool) { return a.r.Get(nodeID) }

// operationListerAdapter is nodeReaderAdapter's sibling for OperationLister.
// Today's only caller (opvocabLister) is already this narrow, but New
// re-wraps unconditionally so the guarantee doesn't depend on callers
// remembering to.
type operationListerAdapter struct {
	r OperationLister
}

func (a operationListerAdapter) Operations() []opvocab.Descriptor { return a.r.Operations() }

// jobResultReaderAdapter is nodeReaderAdapter's sibling for JobResultReader:
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
// nodes/policy/ops and the execution tools against exec/results, and
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
func New(nodes NodeReader, policy PolicyReader, ops OperationLister, exec Executor, results JobResultReader) http.Handler {
	// Re-wrap every input immediately: from this point on, nothing in this
	// package ever holds a value whose dynamic type is wider than what
	// NodeReader/PolicyReader/OperationLister/Executor/JobResultReader
	// expose (see the package doc comment and the adapter types above).
	nodes = nodeReaderAdapter{r: nodes}
	policy = policyReaderAdapter{r: policy}
	ops = operationListerAdapter{r: ops}
	exec = execAdapter{r: exec}
	results = jobResultReaderAdapter{r: results}

	srv := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "relay", Version: serverVersion}, nil)

	registerNodeTools(srv, nodes, policy)
	registerOperationTools(srv, ops)
	registerExecutionTools(srv, exec, results, ops)
	registerJobTools(srv, exec, results)

	// Stateless + JSON responses (MCP spec 2026-07-28; #267): the SDK accepts
	// the 2026-07-28 protocol only in stateless mode, and every tool here is
	// already stateless request/response over shared backing stores — a Job ID
	// is the durable handle, never an Mcp-Session-Id. Also removes the
	// per-instance session map that would break behind a round-robin LB (#139).
	return sdkmcp.NewStreamableHTTPHandler(func(*http.Request) *sdkmcp.Server {
		return srv
	}, &sdkmcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
}
