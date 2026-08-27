package mcp

import (
	"context"
	"fmt"
	"sort"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
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
		PolicyFingerprint:      n.PolicyFingerprint,
		TemplateSetFingerprint: n.TemplateSetFingerprint,
		Revoked:                !n.RevokedAt.IsZero(),
		Outdated:               n.Outdated,
		Connected:              n.Connected,
	}
	if !n.LastSeen.IsZero() {
		item.LastSeen = n.LastSeen.UTC().Format(time.RFC3339)
	}
	if !n.RevokedAt.IsZero() {
		item.RevokedAt = n.RevokedAt.UTC().Format(time.RFC3339)
	}
	return item
}

// certificateFromNode renders the Node's identity provenance (#440).
//
// Recorded gates every other field. A Node that enrolled before provenance was
// stored has a zero NotAfter, and emitting that as an RFC3339 timestamp would
// hand a caller an expiry in 1970 — a Node that reads as catastrophically
// overdue rather than one the Relay simply has nothing to say about.
func certificateFromNode(n registry.Node) CertificateOutput {
	out := CertificateOutput{
		Recorded:     n.CertProvenanceKnown(),
		Fingerprint:  n.CertFingerprint,
		RenewalCount: n.RenewalCount,
	}
	if !out.Recorded {
		return out
	}
	out.NotAfter = n.CertNotAfter.UTC().Format(time.RFC3339)
	if !n.EnrolledAt.IsZero() {
		out.EnrolledAt = n.EnrolledAt.UTC().Format(time.RFC3339)
	}
	if !n.LastRenewedAt.IsZero() {
		out.LastRenewedAt = n.LastRenewedAt.UTC().Format(time.RFC3339)
	}
	return out
}

// normalizeArgSets maps a nil positional arg-set list to an empty one, so a
// rule's allowed_args/args always render as a JSON array, never null
// (#207/#253): a policyview rule whose sets arrived as nil (proto empty
// repeated field) means exactly the same zero-argument set an explicit []
// does, and null carried no distinct semantics — it only forced consumers to
// branch on two spellings. Non-nil sets pass through verbatim (display-only,
// ADR-0002).
func normalizeArgSets(sets [][]string) [][]string {
	if sets == nil {
		return [][]string{}
	}
	return sets
}

// operationRuleOutputsFromSnapshot renders the display-only, verbatim
// [[operation]] allow-rule mirror (ADR-0002) for describe_node. It never
// evaluates, dedups, or resolves wildcards — see policyview.OperationRule.
// Always returns a non-nil slice with non-nil AllowedArgs, so
// operation_rules and every allowed_args render as JSON arrays, never null
// (#207/#253 — see normalizeArgSets and OperationRuleOutput).
func operationRuleOutputsFromSnapshot(rules []policyview.OperationRule) []OperationRuleOutput {
	out := make([]OperationRuleOutput, 0, len(rules))
	for _, r := range rules {
		out = append(out, OperationRuleOutput{Name: r.Name, AllowedArgs: normalizeArgSets(r.AllowedArgs)})
	}
	return out
}

// denyRuleOutputsFromSnapshot renders the display-only, verbatim [[deny]]
// rule mirror (ADR-0002) for describe_node. See policyview.DenyRule. Always
// returns a non-nil slice with non-nil Args (#207/#253, mirroring
// operationRuleOutputsFromSnapshot).
func denyRuleOutputsFromSnapshot(rules []policyview.DenyRule) []DenyRuleOutput {
	out := make([]DenyRuleOutput, 0, len(rules))
	for _, r := range rules {
		out = append(out, DenyRuleOutput{Name: r.Name, Args: normalizeArgSets(r.Args)})
	}
	return out
}

// templateVocabularyOutput renders a Node's reported Template Operation
// vocabulary for describe_node (nodevocab.Snapshot; ADR-0021). Display-only:
// it never validates a slot or decides anything (invariant 12). Templates and
// every Slots/EnumValues are ALWAYS arrays, never null (#207/#253 discipline) —
// `reported` is the sole "no data captured yet" signal.
func templateVocabularyOutput(snap nodevocab.Snapshot, reported bool) TemplateVocabularyOutput {
	templates := make([]TemplateOperationOutput, 0, len(snap.Templates))
	for _, t := range snap.Templates {
		slots := make([]TemplateSlotOutput, 0, len(t.Slots))
		for _, sl := range t.Slots {
			values := sl.EnumValues
			if values == nil {
				values = []string{}
			}
			slots = append(slots, TemplateSlotOutput{Name: sl.Name, Type: sl.Type, EnumValues: values})
		}
		templates = append(templates, TemplateOperationOutput{
			Name:      t.Name,
			RiskClass: riskClassString(jobs.RiskClass(t.RiskClass)),
			Slots:     slots,
		})
	}
	return TemplateVocabularyOutput{
		Fingerprint: snap.Fingerprint,
		Reported:    reported,
		Templates:   templates,
	}
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
func registerNodeTools(srv *sdkmcp.Server, nodes NodeReader, policy PolicyReader, vocab VocabReader, reads ReadAuditor) {
	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "list_nodes",
		Description: "List Nodes in the fleet registry, optionally filtered by a Selector " +
			"(node:/relay: label predicates). node: and relay: labels are returned as separate " +
			"maps, never merged. `outdated` flags Nodes below the Relay's configured " +
			"minimum daemon version (ADR-0014); always false when no minimum is set.",
	}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, in listNodesInput) (*sdkmcp.CallToolResult, ListNodesOutput, error) {
		if err := auditRead(ctx, reads, "list_nodes", ReadEvent{Selector: in.Selector}); err != nil {
			return nil, ListNodesOutput{}, err
		}

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
			"(ADR-0002/0011). `outdated` flags a Node below the Relay's configured minimum " +
			"daemon version (ADR-0014); always false when no minimum is set. In " +
			"effective_policy, operation_rules[].allowed_args and deny_rules[].args are " +
			"always arrays, never null: an empty allowed_args means the Operation is allowed " +
			"with zero arguments only ('*' is the explicit per-position any-value wildcard), " +
			"and an empty deny args denies the Operation regardless of arguments. " +
			"reported=false — never a null — is the only 'no Policy data captured yet' signal. " +
			"template_vocabulary lists the Template Operations THIS Node has loaded from its local " +
			"root-owned template files (ADR-0021) — vocabulary is per-Node: dispatching a template a " +
			"Node has not loaded reports the `unsupported` outcome, which is neither a failure nor a " +
			"Policy denial.",
	}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, in describeNodeInput) (*sdkmcp.CallToolResult, DescribeNodeOutput, error) {
		if err := auditRead(ctx, reads, "describe_node", ReadEvent{NodeID: in.NodeID}); err != nil {
			return nil, DescribeNodeOutput{}, err
		}

		n, ok := nodes.Get(in.NodeID)
		if !ok {
			return nil, DescribeNodeOutput{}, fmt.Errorf("node %q not found", in.NodeID)
		}

		out := DescribeNodeOutput{
			NodeItem:    nodeItemFromNode(n),
			Certificate: certificateFromNode(n),
		}
		vsnap, vok := vocab.Get(in.NodeID)
		out.TemplateVocabulary = templateVocabularyOutput(vsnap, vok)
		if snap, ok := policy.Get(in.NodeID); ok {
			out.EffectivePolicy = EffectivePolicyOutput{
				RawExecEnabled:    snap.RawExecEnabled,
				RawAllowPatterns:  snap.RawAllowPatterns,
				RawDenyPatterns:   snap.RawDenyPatterns,
				AllowedOperations: snap.AllowedOperations,
				PolicyFingerprint: snap.PolicyFingerprint,
				Reported:          true,
				OperationRules:    operationRuleOutputsFromSnapshot(snap.OperationRules),
				DenyRules:         denyRuleOutputsFromSnapshot(snap.DenyRules),
			}
		} else {
			// No snapshot captured yet: still surface the registry's Policy
			// fingerprint (the Hello-reported drift signal) but mark
			// reported=false so a caller never mistakes "nothing captured
			// yet" for "no restrictions". OperationRules/DenyRules stay
			// empty arrays, never null (#207/#253) — reported=false is the
			// only "no data yet" signal.
			out.EffectivePolicy = EffectivePolicyOutput{
				PolicyFingerprint: n.PolicyFingerprint,
				Reported:          false,
				OperationRules:    []OperationRuleOutput{},
				DenyRules:         []DenyRuleOutput{},
			}
		}

		return nil, out, nil
	})
}
