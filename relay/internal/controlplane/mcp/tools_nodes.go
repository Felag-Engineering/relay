package mcp

import (
	"context"
	"fmt"
	"sort"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

func nodeItemFromNode(n registry.Node) NodeItem {
	item := NodeItem{
		NodeID:      n.NodeID,
		NodeLabels:  n.NodeLabels,
		RelayLabels: n.RelayLabels,
		Facts: FactsOutput{
			Hostname:    n.Facts.Hostname,
			OS:          n.Facts.OS,
			Kernel:      n.Facts.Kernel,
			Arch:        n.Facts.Arch,
			IPAddresses: n.Facts.IPAddresses,
		},
		PolicyFingerprint: n.PolicyFingerprint,
		Revoked:           !n.RevokedAt.IsZero(),
	}
	if !n.LastSeen.IsZero() {
		item.LastSeen = n.LastSeen.UTC().Format(time.RFC3339)
	}
	if !n.RevokedAt.IsZero() {
		item.RevokedAt = n.RevokedAt.UTC().Format(time.RFC3339)
	}
	return item
}

// listNodesInput is list_nodes' argument: an optional Selector filter,
// parsed via capability.ParseSelector — the single source of truth for the
// "node:key=value"/"relay:key=value" grammar every Selector-consuming
// surface shares. Fail-closed: a term with no node:/relay: prefix is a parse
// error, not a guess.
type listNodesInput struct {
	Selector string `json:"selector,omitempty" jsonschema:"Selector filter, e.g. 'node:role=web, relay:quarantine=on'. Every term must carry a node: or relay: prefix. Empty or omitted matches every Node."`
}

// describeNodeInput is describe_node's argument: the exact Node ID.
type describeNodeInput struct {
	NodeID string `json:"node_id" jsonschema:"exact Node ID to describe"`
}

// registerNodeTools registers list_nodes and describe_node on srv.
func registerNodeTools(srv *sdkmcp.Server, nodes NodeReader, policy PolicyReader) {
	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "list_nodes",
		Description: "List Nodes in the fleet registry, optionally filtered by a Selector " +
			"(node:/relay: label predicates). node: and relay: labels are returned as separate " +
			"maps, never merged.",
	}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, in listNodesInput) (*sdkmcp.CallToolResult, ListNodesOutput, error) {
		logPrincipal(ctx, "list_nodes")

		sel, err := capability.ParseSelector(in.Selector)
		if err != nil {
			return nil, ListNodesOutput{}, fmt.Errorf("invalid selector: %w", err)
		}

		items := make([]NodeItem, 0)
		// This loop reimplements capability.Selector.Resolve's match-and-collect
		// logic (selector.go) against the narrower NodeReader (Get/List only)
		// rather than calling Resolve directly, which requires a full
		// registry.Repository. Deliberate narrowing to keep this package's
		// registry dependency minimal (see NodeReader's doc comment) — Matches
		// itself (the only non-trivial part) is still reused, not reimplemented.
		for _, n := range nodes.List() {
			if sel.Matches(n) {
				items = append(items, nodeItemFromNode(n))
			}
		}
		sort.Slice(items, func(i, j int) bool { return items[i].NodeID < items[j].NodeID })

		return nil, ListNodesOutput{Nodes: items}, nil
	})

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "describe_node",
		Description: "Describe one Node in full, including its effective Policy as last " +
			"reported by the daemon. Display-only: the Relay never evaluates Policy itself " +
			"(ADR-0002/0011).",
	}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, in describeNodeInput) (*sdkmcp.CallToolResult, DescribeNodeOutput, error) {
		logPrincipal(ctx, "describe_node")

		n, ok := nodes.Get(in.NodeID)
		if !ok {
			return nil, DescribeNodeOutput{}, fmt.Errorf("node %q not found", in.NodeID)
		}

		out := DescribeNodeOutput{NodeItem: nodeItemFromNode(n)}
		if snap, ok := policy.Get(in.NodeID); ok {
			out.EffectivePolicy = EffectivePolicyOutput{
				RawExecEnabled:    snap.RawExecEnabled,
				RawAllowPatterns:  snap.RawAllowPatterns,
				RawDenyPatterns:   snap.RawDenyPatterns,
				AllowedOperations: snap.AllowedOperations,
				PolicyFingerprint: snap.PolicyFingerprint,
				Reported:          true,
			}
		} else {
			// No snapshot captured yet: still surface the registry's Policy
			// fingerprint (the Hello-reported drift signal) but mark
			// reported=false so a caller never mistakes "nothing captured
			// yet" for "no restrictions".
			out.EffectivePolicy = EffectivePolicyOutput{
				PolicyFingerprint: n.PolicyFingerprint,
				Reported:          false,
			}
		}

		return nil, out, nil
	})
}
