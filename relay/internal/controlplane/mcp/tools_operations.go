package mcp

import (
	"context"
	"sort"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// operationItem is one Operation's vocabulary entry, rendered by
// list_operations. Raw Exec is deliberately absent from this list: it is not
// an Operation (ADR-0003, CONTEXT.md) and has no OperationDescriptor on the
// wire; it surfaces through its own tool (#118) and is always risk class
// mutate.
type operationItem struct {
	Name           string            `json:"name"`
	RiskClass      string            `json:"risk_class"`
	ArgConstraints map[string]string `json:"arg_constraints"`
}

type listOperationsOutput struct {
	Operations []operationItem `json:"operations"`
}

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
		Description: "List the Operation vocabulary with risk class and argument constraints " +
			"per Operation. Raw Exec is a separate tool (#118), not an Operation, and is always mutate.",
	}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, _ any) (*sdkmcp.CallToolResult, listOperationsOutput, error) {
		logPrincipal(ctx, "list_operations")

		descs := ops.Operations()
		items := make([]operationItem, 0, len(descs))
		for _, d := range descs {
			items = append(items, operationItem{
				Name:           d.Name,
				RiskClass:      riskClassString(d.Risk),
				ArgConstraints: d.ArgConstraints,
			})
		}
		sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })

		return nil, listOperationsOutput{Operations: items}, nil
	})
}
