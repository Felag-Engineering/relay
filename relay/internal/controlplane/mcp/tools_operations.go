package mcp

import (
	"context"
	"sort"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// riskClassString renders a jobs.RiskClass as the "read"/"mutate" string
// list_operations emits. jobs.RiskClass has no String()/JSON helper of its
// own today (jobs.go); this is the small, local read/mutate mapping helper
// rather than an ad hoc improvisation elsewhere. RiskClassUnspecified maps to
// "unspecified" — it should never appear in practice (opvocab_test.go pins
// every vocabulary entry to Read or Mutate), but a rendering exists rather
// than panicking if it ever does.
func riskClassString(r jobs.RiskClass) string {
	switch r {
	case jobs.RiskClassRead:
		return "read"
	case jobs.RiskClassMutate:
		return "mutate"
	default:
		return "unspecified"
	}
}

// registerOperationTools registers list_operations on srv.
func registerOperationTools(srv *sdkmcp.Server, ops OperationLister) {
	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "list_operations",
		Description: "List the Operation vocabulary: for each Operation, its purpose, risk class, argument " +
			"names/types/constraints, and a concrete usage example. Consult this before run_operation so you " +
			"pick the typed Operation — and build its args correctly — without trial-and-error; run_operation " +
			"is the default execution path (ADR-0001) and list_operations is how you learn its vocabulary. " +
			"Raw Exec is a separate tool (#118), not an Operation, and is always mutate.",
	}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, _ any) (*sdkmcp.CallToolResult, ListOperationsOutput, error) {
		logPrincipal(ctx, "list_operations")

		descs := ops.Operations()
		items := make([]OperationItem, 0, len(descs))
		for _, d := range descs {
			items = append(items, OperationItem{
				Name:           d.Name,
				RiskClass:      riskClassString(d.Risk),
				Purpose:        d.Purpose,
				ArgConstraints: d.ArgConstraints,
				Example:        d.Example,
			})
		}
		sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })

		return nil, ListOperationsOutput{Operations: items}, nil
	})
}
