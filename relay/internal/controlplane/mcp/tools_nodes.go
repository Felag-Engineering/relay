package mcp

import (
	"context"
	"errors"
	"fmt"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodestate"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// nodeItemFromNode renders n as list_nodes/describe_node's shared base shape.
// ev is the SAME StateEval the caller resolved its Selector against — one
// instant, one cert-expiring window per response — so a Node's rendered
// state_labels can never disagree with whether it matched the request's own
// filter.
func nodeItemFromNode(n registry.Node, ev capability.StateEval) NodeItem {
	states := nodestate.Labels(nodestate.Input{Node: n, Now: ev.Now, CertExpiringWithin: ev.CertExpiringWithin})
	stateLabels := make([]string, 0, len(states))
	for _, l := range states {
		stateLabels = append(stateLabels, l.String())
	}

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
		StateLabels:            stateLabels,
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
			RiskClass: jobs.RiskClassName(jobs.RiskClass(t.RiskClass)),
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
// "node:key=value"/"relay:key=value"/"state:key[=value]" grammar every
// Selector-consuming surface shares. Fail-closed: a term with no
// node:/relay:/state: prefix is a parse error, not a guess.
//
// tag: parses as an error too, and the schema below says so (#560). It used
// to be advertised without a caveat while resolving to nothing, which handed
// an agent HTTP 200 and an empty list for a namespace that is simply not
// implemented — a false negative given to the caller least able to notice it.
type listNodesInput struct {
	Selector string `json:"selector,omitempty" jsonschema:"Selector filter, e.g. 'node:role=web, relay:quarantine=on, state:offline'. Every term must carry a node:, relay:, or state: prefix. tag: is a valid namespace in the model but is NOT resolvable yet — it has no storage until label management lands (#430) — so a tag: term is refused outright rather than matching nothing; do not filter on it. state: is a closed, Relay-derived vocabulary (ADR-0034): the boolean markers state:offline, state:outdated, state:template-unloadable, state:cert-expiring, and the facts state:daemon-version=, state:policy-fingerprint=, state:template-fingerprint=. Empty or omitted matches every Node."`
}

// describeNodeInput is describe_node's argument: the exact Node ID.
type describeNodeInput struct {
	NodeID string `json:"node_id" jsonschema:"exact Node ID to describe"`
}

// registerNodeTools registers list_nodes and describe_node on srv, both
// backed by lane — the capability read lane (#680, QRY-28): the record and
// the read are the same call, so neither tool can reach the registry without
// it.
func registerNodeTools(srv *sdkmcp.Server, lane ReadLane) {
	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "list_nodes",
		Description: "List Nodes in the fleet registry, optionally filtered by a Selector " +
			"(node:/relay:/state: label predicates; tag: is refused until #430). node: and relay: labels are returned as " +
			"separate maps, never merged; state: labels are Relay-derived and returned as " +
			"state_labels, in Selector syntax with the state: prefix. `outdated` flags Nodes below " +
			"the Relay's configured minimum daemon version (ADR-0014); always false when no " +
			"minimum is set.",
	}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, in listNodesInput) (*sdkmcp.CallToolResult, ListNodesOutput, error) {
		listing, err := lane.ListNodes(ctx, in.Selector)
		if err != nil {
			if errors.Is(err, capability.ErrInvalidFilter) {
				// The lane's own error renders "capability: invalid query
				// filter: capability: selector …", doubling the internal
				// package prefix. Re-parse to recover ParseSelector's own
				// text and wrap it the way run_operation/raw_exec already do
				// (tools_execution.go's "invalid selector: %w").
				if _, perr := capability.ParseSelector(in.Selector); perr != nil {
					return nil, ListNodesOutput{}, fmt.Errorf("invalid selector: %w", perr)
				}
			}
			return nil, ListNodesOutput{}, err
		}

		// listing.Nodes may be a NIL slice when the Selector matched nothing
		// (capability.Selector.Resolve never returns an empty non-nil slice) —
		// an explicit zero-length, pre-sized make keeps the response an empty
		// JSON array rather than null (#207/#253).
		items := make([]NodeItem, 0, len(listing.Nodes))
		for _, n := range listing.Nodes {
			items = append(items, nodeItemFromNode(n, listing.Eval))
		}

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
			"Policy denial. state_labels are Relay-derived state: labels (ADR-0034): the boolean " +
			"markers state:offline, state:outdated, state:template-unloadable, state:cert-expiring, " +
			"and the facts state:daemon-version=, state:policy-fingerprint=, state:template-fingerprint= " +
			"— set by nobody, targetable verbatim in a list_nodes/run_operation/raw_exec selector. " +
			"A missing or oversized node_id is refused before anything is read or recorded.",
	}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, in describeNodeInput) (*sdkmcp.CallToolResult, DescribeNodeOutput, error) {
		desc, err := lane.DescribeNode(ctx, in.NodeID)
		if err != nil {
			switch {
			case errors.Is(err, capability.ErrNodeNotFound):
				// The lane's own error renders "capability: node not found:
				// <id>", which would leak an internal package prefix into a
				// model-facing tool — map it to the tool's own wording
				// instead.
				return nil, DescribeNodeOutput{}, fmt.Errorf("node %q not found", in.NodeID)
			case errors.Is(err, capability.ErrInvalidFilter):
				// The lane's before-any-record bound on a missing/oversized
				// id (QRY-27) renders "capability: invalid query filter: …",
				// the same internal-prefix leak — mapped the same way
				// (security review, cycle 2, LOW 5).
				return nil, DescribeNodeOutput{}, errors.New("invalid node_id: must be 1-256 bytes")
			}
			return nil, DescribeNodeOutput{}, err
		}

		out := DescribeNodeOutput{
			NodeItem:    nodeItemFromNode(desc.Node, desc.Eval),
			Certificate: certificateFromNode(desc.Node),
		}
		out.TemplateVocabulary = templateVocabularyOutput(desc.Templates, desc.TemplatesReported)
		if desc.PolicyReported {
			out.EffectivePolicy = EffectivePolicyOutput{
				RawExecEnabled:    desc.Policy.RawExecEnabled,
				RawAllowPatterns:  desc.Policy.RawAllowPatterns,
				RawDenyPatterns:   desc.Policy.RawDenyPatterns,
				AllowedOperations: desc.Policy.AllowedOperations,
				PolicyFingerprint: desc.Policy.PolicyFingerprint,
				Reported:          true,
				OperationRules:    operationRuleOutputsFromSnapshot(desc.Policy.OperationRules),
				DenyRules:         denyRuleOutputsFromSnapshot(desc.Policy.DenyRules),
			}
		} else {
			// No snapshot captured yet: still surface the registry's Policy
			// fingerprint (the Hello-reported drift signal) but mark
			// reported=false so a caller never mistakes "nothing captured
			// yet" for "no restrictions". OperationRules/DenyRules stay
			// empty arrays, never null (#207/#253) — reported=false is the
			// only "no data yet" signal.
			out.EffectivePolicy = EffectivePolicyOutput{
				PolicyFingerprint: desc.Node.PolicyFingerprint,
				Reported:          false,
				OperationRules:    []OperationRuleOutput{},
				DenyRules:         []DenyRuleOutput{},
			}
		}

		return nil, out, nil
	})
}
