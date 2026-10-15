package dispatch

import (
	"regexp"
	"testing"

	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest/protowalk"
)

// nestedPreviewFieldNameRegex is the sibling MCP/Control-API/proto files'
// shared preflightDetectorRegex PLUS the bare "plan" token (security/code
// review, cycle 2, SR7/CR1) — deliberately DIFFERENT from theirs, and the
// difference is the point. Those files drop the token because a TOOL or
// ROUTE name legitimately carries it after ADR-0038 (propose_plan,
// GET /api/v1/plans, …), so a bare-token match would false-positive the
// moment plan.md ships. Neither hazard applies to a proto FIELD name
// reached from inside Operation/RawExec: proto/relay/v1 has no field named
// anything like "plan" today, and the Plan capability's own wire vocabulary
// (docs/specs/plan.md) is HTTP routes and MCP tool names, never a Task
// message field — so the token costs nothing at THIS seam, and carrying it
// closes a real gap the sibling files' regex-only walks would otherwise
// leave: without it, a preview bit named literally "plan" inside Operation
// or RawExec would evade this walk.
var nestedPreviewFieldNameRegex = regexp.MustCompile(`(?i)preflight|preview|dry.?run|simulate|what.?if|plan`)

// TestTaskRequest_CarriesNoPreviewFlag proves PF-9's second half
// (docs/specs/policy-preflight.md): "the Task message carries no preview
// flag. A flag means one dropped or defaulted bit turns a preview into real
// execution; a separate message type has no execution code path at all."
//
// TaskRequest's exact field set is asserted in THREE places in this tree —
// this test, internal/dispatch/convert_test.go's TestWireCarriesNoCallerIdentity,
// and relay/cmd/relay/policy_immutability_test.go's copy of the same name —
// so a proto change to TaskRequest must update all three.
func TestTaskRequest_CarriesNoPreviewFlag(t *testing.T) {
	md := (&relayv1.TaskRequest{}).ProtoReflect().Descriptor()

	protowalk.AssertExactTopLevelFieldSet(t, md, map[string]bool{
		"task_id": true, "operation": true, "raw_exec": true, "timeout_seconds": true, "risk_class": true,
	})

	// Below the top level: a preview bit smuggled inside Operation or
	// RawExec, rather than added as a new top-level field, would evade the
	// assertion above but not this walk. This is a NARROWER guarantee than
	// it might look, corrected on review (SR7):
	// protowalk.WalkReachableMessageFields does not traverse enums at all,
	// so a preview expressed as a new enum
	// value (e.g. a RiskClass-shaped RISK_CLASS_PREVIEW) or as an overloaded
	// sentinel on an existing scalar (e.g. timeout_seconds < 0 meaning
	// "preview") is outside every guard in this file — that residual is
	// recorded here, not tested, because there is no field-name seam to
	// assert against. What this walk DOES close, alongside
	// convert_test.go's TestWireCarriesNoCallerIdentity (which separately
	// pins Operation's and RawExec's own exact field sets, so a same-named
	// but differently-typed field addition is caught there too), is a new
	// FIELD anywhere in the reachable message graph.
	protowalk.WalkReachableMessageFields(md, func(fieldName string) {
		if nestedPreviewFieldNameRegex.MatchString(fieldName) {
			t.Errorf("TaskRequest reaches a field named %q, which looks like a preview flag — "+
				"the executing message must never carry one (PF-9): a preview is a separate message, "+
				"never a flag on the one that runs", fieldName)
		}
	})
}

// TestPolicyVerdict_CannotExpressUnknown proves PF-22's second half: "unknown
// is never a wire value: the daemon only ever answers allow, deny or
// unsupported." allowed plus unsupported spans exactly three answers, and
// unknown is the Relay's own conclusion about its inability to ask — a Node
// can never claim it.
//
// Same residual as TestTaskRequest_CarriesNoPreviewFlag above (SR7):
// protowalk.WalkReachableMessageFields does not traverse enums, so an unknown
// expressed as a new enum value rather than a new field name would be
// outside this walk too — worth stating, not worth a test against a wire
// shape that does not exist today.
func TestPolicyVerdict_CannotExpressUnknown(t *testing.T) {
	md := (&relayv1.PolicyVerdict{}).ProtoReflect().Descriptor()

	protowalk.AssertExactTopLevelFieldSet(t, md, map[string]bool{
		"query_id": true, "allowed": true, "deciding_rule": true, "unsupported": true,
	})

	unknownFieldName := regexp.MustCompile(`(?i)unknown|offline|unreachable`)
	protowalk.WalkReachableMessageFields(md, func(fieldName string) {
		if unknownFieldName.MatchString(fieldName) {
			t.Errorf("PolicyVerdict reaches a field named %q — a Node must never be able to assert "+
				"\"I do not know\" on the wire; unknown is the Relay's own conclusion about its inability "+
				"to ask (PF-22), never a Policy answer", fieldName)
		}
	})
}
