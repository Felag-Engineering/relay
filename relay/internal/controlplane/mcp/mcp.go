// Package mcp is the Relay's MCP surface (ADR-0003): a thin adapter that
// exposes exactly three READ meta-tools — list_nodes, describe_node,
// list_operations — over the registry, the display-only effective-Policy
// cache, and the Operation vocabulary. It is one of the three thin surfaces
// over the same control-plane capability layer (invariant 10); execution
// tools (Operation dispatch, Raw Exec) are a separate, later issue (#118).
//
// No dispatch: this package never imports *capability.Service and never
// calls its dispatch constructor. NodeReader, PolicyReader, and
// OperationLister below are read-only interfaces — Get/List/Operations, no
// Run — so a read tool structurally cannot reach the execution path.
// no_dispatch_test.go AST-guards this by failing the build if this
// package's non-test source ever references capability.Service,
// capability.New, any other non-allow-listed capability selector, or
// type-asserts to registry.Repository. (It MAY, and does, import the
// capability package itself for the pure Selector/ParseSelector helpers used
// to filter list_nodes.)
//
// The narrow interfaces above are a compile-time guarantee, not a runtime
// one on their own: composition roots pass concrete values (e.g.
// registry.Repository, *policyview.Cache) whose dynamic type is wider than
// the interface. Without more, a value read through NodeReader could still
// be type-asserted back to registry.Repository to recover Upsert/
// SetRelayLabels/Delete. New immediately re-wraps every input in an
// unexported adapter (nodeReaderAdapter / policyReaderAdapter /
// operationListerAdapter below) whose ONLY dynamic type exposes the narrow
// method set — so such a type assertion fails at runtime too, not just at
// the interface boundary.
package mcp

import (
	"net/http"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

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

// serverVersion is the MCP server's advertised Implementation.Version. It is
// intentionally decoupled from the Relay's own release versioning — nothing
// downstream parses it — and is bumped only if the tool surface itself needs
// to signal a breaking change to clients.
const serverVersion = "0.1.0"

// New builds the Relay's MCP server, registers the three read tools against
// nodes/policy/ops, and returns it as a plain http.Handler (the SDK's
// StreamableHTTPHandler) — mountable directly on controlplane.Server.Mux()
// behind the existing Authenticator.Middleware (invariant 10: one control
// path, auth inherited from the mux, not reimplemented here).
func New(nodes NodeReader, policy PolicyReader, ops OperationLister) http.Handler {
	// Re-wrap every input immediately: from this point on, nothing in this
	// package ever holds a value whose dynamic type is wider than what
	// NodeReader/PolicyReader/OperationLister expose (see the package doc
	// comment and the adapter types above).
	nodes = nodeReaderAdapter{r: nodes}
	policy = policyReaderAdapter{r: policy}
	ops = operationListerAdapter{r: ops}

	srv := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "relay", Version: serverVersion}, nil)

	registerNodeTools(srv, nodes, policy)
	registerOperationTools(srv, ops)

	return sdkmcp.NewStreamableHTTPHandler(func(*http.Request) *sdkmcp.Server {
		return srv
	}, nil)
}
