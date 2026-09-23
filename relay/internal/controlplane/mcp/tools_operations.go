package mcp

import (
	"context"
	"errors"
	"fmt"
	"sort"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"
)

// riskClassString renders a jobs.RiskClass as the "read"/"mutate" string
// list_operations emits. jobs.RiskClass has no String()/JSON helper of its
// own today (jobs.go); this is the small, local read/mutate mapping helper
// rather than an ad hoc improvisation elsewhere. RiskClassUnspecified maps to
// "unspecified" — it should never appear in practice (opvocab_test.go pins
// every vocabulary entry to Read or Mutate, and a template without a valid
// risk class fails to load daemon-side, ADR-0012), but a rendering exists
// rather than panicking if it ever does.
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

// sourceNative and sourceTemplate are OperationItem.Source's two values: the
// frozen Native Operation vocabulary every Node has, and the Template
// Operations one specific Node loaded from its local root-owned files
// (ADR-0021).
const (
	sourceNative   = "native"
	sourceTemplate = "template"
)

// listOperationsInput is list_operations' argument: an optional Node ID.
//
// Since ADR-0021 the Operation vocabulary is per-Node — natives are frozen and
// present everywhere, Template Operations are local to whichever Nodes have
// the pack installed — so "the vocabulary" is only fully answerable about a
// named Node. Omitting node_id answers the fleet-wide native part.
type listOperationsInput struct {
	NodeID string `json:"node_id,omitempty" jsonschema:"Optional exact Node ID. Given one, the response also lists that Node's Template Operations (source=template) with their typed parameter slots. Omitted, only the frozen native vocabulary (present on every Node) is returned."`
}

// templateOperationItems renders a Node's reported Template Operations as
// list_operations entries, with the same model-facing legibility fields the
// native entries carry: a Purpose derived from what the Relay actually knows
// (the name, class, and slot types — the Relay never sees a template body),
// ArgConstraints built from each slot's declared type, and a concrete Example.
// Advisory prose, exactly like opvocab's: the daemon's own typed validation is
// the real gate (ADR-0002, invariant 2).
func templateOperationItems(snap nodevocab.Snapshot) []OperationItem {
	items := make([]OperationItem, 0, len(snap.Templates))
	for _, t := range snap.Templates {
		constraints := make(map[string]string, len(t.Slots))
		example := "run_operation operation=" + t.Name
		args := ""
		for _, sl := range t.Slots {
			constraints[sl.Name] = slotConstraintProse(sl)
			if args != "" {
				args += ","
			}
			args += `"` + sl.Name + `":"<` + sl.Type + `>"`
		}
		if args != "" {
			example += ` args={` + args + `}`
		} else {
			example += " (no args)"
		}
		items = append(items, OperationItem{
			Name:           t.Name,
			RiskClass:      riskClassString(jobs.RiskClass(t.RiskClass)),
			Purpose:        templatePurpose(t),
			ArgConstraints: constraints,
			Example:        example,
			Source:         sourceTemplate,
		})
	}
	return items
}

// templatePurpose states what the Relay can honestly say about a Template
// Operation: it is operator-authored and local to this Node, so its command
// is fixed by whoever installed it and only its parameters vary.
func templatePurpose(t nodevocab.Template) string {
	return "Template Operation loaded on this Node from a local root-owned template file (ADR-0021). " +
		"The command structure is fixed by the operator who installed it; only the typed parameter " +
		"slots below vary, and the daemon validates and quotes each one before it runs. Governed by " +
		"the Node's Policy exactly like a Native Operation. Not present on Nodes without this " +
		"template — dispatching it there reports `unsupported`."
}

// slotConstraintProse renders one slot's declared type as the same
// "type, required/optional. constraint prose." shape opvocab uses for native
// arguments, so a model reads both kinds of entry the same way. Every slot is
// required (the daemon's engine has no optional slots today) and the charsets
// mirror daemon/src/operations/template.rs's SlotType::validate.
func slotConstraintProse(sl nodevocab.Slot) string {
	switch sl.Type {
	case "identifier":
		return "string, required. Charset [A-Za-z0-9_.@+-], must start alphanumeric (no leading '-'), " +
			"max 256 bytes. Validated daemon-side before substitution."
	case "integer":
		return "string, required. Unsigned decimal digits only ([0-9]+, max 19 digits) — no sign, " +
			"so it can never be read as an option. Validated daemon-side before substitution."
	case "path":
		return "string, required. Absolute canonical path (starts '/', no '.', '..', empty or trailing " +
			"segment), max 4096 bytes, no control characters. Which paths are reachable is decided by " +
			"the Node's Policy, not this argument."
	case "enum":
		values := ""
		for i, v := range sl.EnumValues {
			if i > 0 {
				values += ", "
			}
			values += v
		}
		return "string, required. Must be exactly one of: " + values + ". Validated daemon-side."
	default:
		return "string, required. Validated daemon-side against its declared slot type (" + sl.Type + ")."
	}
}

// registerOperationTools registers list_operations on srv. The Native half
// always comes from ops.Operations() — a frozen, fleet-wide, compile-time
// table (ADR-0015/ADR-0021) that discloses nothing about this fleet and
// reads no registry or cache, so it never touches the audited lane. The
// per-Node Template half comes from lane.ListOperations, called
// UNCONDITIONALLY — including for a fleet-wide call with no node_id — so the
// lane records the whole call under one name and fails closed for both
// shapes (#680, QRY-28).
func registerOperationTools(srv *sdkmcp.Server, ops OperationLister, lane ReadLane) {
	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "list_operations",
		Description: "List the Operation vocabulary: for each Operation, its purpose, risk class, argument " +
			"names/types/constraints, and a concrete usage example. Consult this before run_operation so you " +
			"pick the typed Operation — and build its args correctly — without trial-and-error; run_operation " +
			"is the default execution path (ADR-0001) and list_operations is how you learn its vocabulary. " +
			"Vocabulary is PER-NODE (ADR-0021): the four native Operations (source=native) exist on every " +
			"Node, while Template Operations (source=template) are loaded from local root-owned files on " +
			"individual Nodes. Pass node_id to see one Node's full vocabulary; without it you get the native " +
			"part only. An unknown node_id is refused, not answered with an empty template set. " +
			"Dispatching an Operation to a Node that does not have it reports the `unsupported` " +
			"outcome — nothing runs and Policy is never consulted, so it is neither a failure nor a denial. " +
			"Raw Exec is a separate tool (#118), not an Operation, and is always mutate.",
	}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, in listOperationsInput) (*sdkmcp.CallToolResult, ListOperationsOutput, error) {
		vocab, err := lane.ListOperations(ctx, in.NodeID)
		if err != nil {
			switch {
			case errors.Is(err, capability.ErrNodeNotFound):
				return nil, ListOperationsOutput{}, fmt.Errorf("node %q not found", in.NodeID)
			case errors.Is(err, capability.ErrInvalidFilter):
				// The lane's before-any-record bound on an oversized node_id
				// renders "capability: invalid query filter: …", the same
				// internal-prefix leak fixed for describe_node — mapped the
				// same way (security review, cycle 2, LOW 5).
				return nil, ListOperationsOutput{}, errors.New("invalid node_id: must be 1-256 bytes")
			}
			return nil, ListOperationsOutput{}, err
		}

		descs := ops.Operations()
		items := make([]OperationItem, 0, len(descs))
		for _, d := range descs {
			items = append(items, OperationItem{
				Name:           d.Name,
				RiskClass:      riskClassString(d.Risk),
				Purpose:        d.Purpose,
				ArgConstraints: d.ArgConstraints,
				Example:        d.Example,
				Source:         sourceNative,
			})
		}

		out := ListOperationsOutput{}
		if in.NodeID != "" {
			// Per-Node view: add whatever Template Operations that Node last
			// reported. A Node with no captured snapshot yields no template
			// entries and templates_reported=false — never a claim that it has
			// none (nodevocab.Cache.Get).
			out.NodeID = in.NodeID
			out.TemplatesReported = vocab.Reported
			out.TemplateSetFingerprint = vocab.Templates.Fingerprint
			items = append(items, templateOperationItems(vocab.Templates)...)
		}

		sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
		out.Operations = items

		return nil, out, nil
	})
}
