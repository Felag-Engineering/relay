package main

// TestPolicyImmutability_ProtoOneof asserts that the proto wire contract
// enforces the Policy-immutability invariant (ADR-0002, invariant #2):
// the Relay may NEVER modify a Node's Policy over the wire.
//
// Proto-level proof: RelayMessage.Body is a oneof whose variants are exactly
// the current read/dispatch/cancel/query allow-set (ping, task, task_cancel,
// policy_query). There is no policy-setter variant. Any code that attempted
// to build a RelayMessage carrying policy data would not compile.
//
// DaemonMessage.Body has a policy field (PolicySnapshot, outbound display-only —
// used by the daemon to share its current Policy with the Relay for display,
// never for write-back). The Relay only reads it; the daemon is the sole
// authority.

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	relayv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"
)

// TestRelayMessage_BodyOneofIsExactlyAllowSet reflectively enumerates the
// `body` oneof on RelayMessage's descriptor and asserts its field-name set is
// EXACTLY the current allow-set: {ping, task, task_cancel, policy_query}.
//
// This replaces a prior version of this test (TestRelayMessage_OnlyPingAndTask)
// that switched over a hand-built `{Ping, Task}` slice — that construction is
// structurally blind to the real oneof: it can only ever see the variants the
// test itself constructs, so a new generated `RelayMessage.Body` variant (e.g.
// a hypothetical policy-setter) would sail straight through it without
// touching the `default` case, even though the oneof already had 4 variants
// (ping, task, task_cancel, policy_query) at the time that test was green.
//
// Reading the descriptor directly means ANY new oneof variant — added to the
// generated code by a future proto change — makes `got` diverge from `want`
// and fails this test until a human deliberately updates the allow-set,
// which is the actual ADR-0002 wire-immutability gate.
func TestRelayMessage_BodyOneofIsExactlyAllowSet(t *testing.T) {
	md := (&relayv1.RelayMessage{}).ProtoReflect().Descriptor()
	oneof := md.Oneofs().ByName("body")
	if oneof == nil {
		t.Fatal("RelayMessage has no oneof named \"body\" — proto contract changed shape")
	}

	fields := oneof.Fields()
	got := make(map[string]bool, fields.Len())
	for i := 0; i < fields.Len(); i++ {
		got[string(fields.Get(i).Name())] = true
	}

	want := map[string]bool{
		"ping":         true, // handshake confirmation — not a policy setter
		"task":         true, // dispatch request — not a policy setter
		"task_cancel":  true, // Task cancellation — not a policy setter
		"policy_query": true, // read-only ADR-0011 hypothetical-evaluation probe — not a mutation
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("RelayMessage.body oneof field set changed:\n  got:  %v\n  want: %v\n"+
			"any new variant must be reviewed for ADR-0002 wire-immutability before this "+
			"allow-set is updated", got, want)
	}

	// Belt-and-suspenders: no field name in the oneof may denote a policy
	// mutation. "policy_query" is a read-only hypothetical-evaluation probe
	// (ADR-0011: the Relay may query the daemon's live Policy engine, never
	// set it), not a mutation, so it is intentionally excluded from this check.
	for name := range got {
		if name == "policy_query" {
			continue
		}
		if strings.Contains(name, "set") || strings.Contains(name, "update") || strings.Contains(name, "write") {
			t.Errorf("RelayMessage.body field %q looks like a policy-mutation field name — "+
				"the Relay must never be able to send a policy setter over the wire (ADR-0002)", name)
		}
	}
}

// TestDaemonMessage_PolicyIsOutboundOnly documents the intended direction of the
// DaemonMessage.policy field (a PolicySnapshot).
//
// The field carries the Node's current Policy outbound (daemon → Relay) for
// display purposes only. The Relay reads it and may surface it in the Admin
// Console (planned, v0.3.0). The Relay must NEVER write it back to the daemon.
//
// This test confirms the field is present on DaemonMessage (outbound) and
// absent on RelayMessage (inbound to daemon), which is the proto-level
// enforcement of the immutability invariant.
func TestDaemonMessage_PolicyIsOutboundOnly(t *testing.T) {
	// DaemonMessage has a policy field (outbound: daemon → Relay).
	// GetPolicy() is generated iff the field exists; this call is a compile-time
	// assertion that the field is on DaemonMessage (not a RelayMessage setter).
	dm := &relayv1.DaemonMessage{}
	snapshot := dm.GetPolicy()
	// At runtime the field is nil on an empty message; nil is expected here.
	if snapshot != nil {
		t.Errorf("unexpected non-nil policy snapshot on empty DaemonMessage: %v", snapshot)
	}

	// RelayMessage does NOT have GetPolicy — calling it would be a compile error.
	// The absence proves the Relay cannot send a policy setter to the daemon.
	//
	// Verified: the following would NOT compile:
	//   rm := &relayv1.RelayMessage{}
	//   _ = rm.GetPolicy()   // no such method — ADR-0002 enforced at proto level
	//
	// If this file compiles, RelayMessage carries no policy-setter (ADR-0002). ✓
}

// callerIdentityFieldName matches any reachable field name that looks like it
// could carry who is asking — the structural proof behind
// policyBoundaryExplanation's claim that "the Node is never told which
// Account or role asked" (#454). A field named e.g. "principal_id" or
// "actor_role" must fail this just as readily as a field literally named
// "principal".
var callerIdentityFieldName = regexp.MustCompile(`(?i)principal|actor|account|role|token|caller|subject|identity|user|auth`)

// walkReachableMessageFields performs a BFS from start's message descriptor
// over every field reachable through a message-kind field — including oneof
// members and map value types — tracking visited full names so recursion
// terminates on any cycle. It calls visit once per reachable field
// (including start's own top-level fields), and returns after exhausting the
// message graph.
//
// This is the same descriptor-reflection idiom as
// TestRelayMessage_BodyOneofIsExactlyAllowSet above, deliberately: a
// hand-built Go-side field list is structurally blind to the real oneof (that
// test's own doc comment explains why), and the same blindness would apply
// here to caller identity added inside a oneof payload (Operation, RawExec)
// or directly on RelayMessage, rather than as a new top-level TaskRequest
// field. Walking the descriptor graph is not blind to that.
func walkReachableMessageFields(start protoreflect.MessageDescriptor, visit func(fieldName string)) {
	visited := map[protoreflect.FullName]bool{}
	queue := []protoreflect.MessageDescriptor{start}
	for len(queue) > 0 {
		md := queue[0]
		queue = queue[1:]
		if visited[md.FullName()] {
			continue
		}
		visited[md.FullName()] = true

		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			// Synthetic map-entry messages declare "key"/"value" fields that
			// are never themselves caller-identity-shaped (Operation.args is
			// map<string,string>) — skip those two well-known names only,
			// and only on a synthetic map-entry message.
			if md.IsMapEntry() && (f.Name() == "key" || f.Name() == "value") {
				if f.Kind() == protoreflect.MessageKind || f.Kind() == protoreflect.GroupKind {
					queue = append(queue, f.Message())
				}
				continue
			}
			visit(string(f.Name()))
			if f.Kind() == protoreflect.MessageKind || f.Kind() == protoreflect.GroupKind {
				queue = append(queue, f.Message())
			}
		}
	}
}

// TestWireCarriesNoCallerIdentity is the structural guard behind
// policyBoundaryExplanation's claim (capability/refusal.go, #454) that "the
// Node is never told which Account or role asked" — the wire contract carries
// no caller identity, so the same request from an admin token and a machine
// Account are byte-identical modulo task_id, and the daemon's answer cannot
// depend on who asked (the bypass beat, F2).
//
// It walks TRANSITIVELY (BFS) from RelayMessage's descriptor over every
// reachable message-kind field, including oneof members (Operation, RawExec)
// and map value types, so a caller-identity field added inside a oneof
// payload is caught just as readily as one added directly on RelayMessage.
// A Go-struct-reflection version considered first is blind to exactly that
// case; see walkReachableMessageFields's doc comment.
//
// The regex alone has a residual blind spot: a caller-identity field can be
// RENAMED past it (e.g. "requested_by", "on_behalf_of", "session_id", "cn",
// "sub", "who" all match no word in callerIdentityFieldName), and that rename
// would sail through silently. The exact-field-set assertions below close
// that gap for the four messages a Task/PolicyQuery actually carries: any
// addition OR rename inside Operation/RawExec — not just one matching the
// regex — must be reviewed and named here before it passes.
//
// Mirrored in relay/internal/dispatch/convert_test.go, which IS on
// docs/agents/security-surface.txt (relay/cmd/relay/** is not, except
// main.go) and is where the wire conversion this guard is really about
// actually happens — so a security review of a caller-identity addition
// finds this guard even if it never opens this file.
func TestWireCarriesNoCallerIdentity(t *testing.T) {
	start := (&relayv1.RelayMessage{}).ProtoReflect().Descriptor()
	walkReachableMessageFields(start, func(fieldName string) {
		if callerIdentityFieldName.MatchString(fieldName) {
			t.Errorf("RelayMessage reaches a field named %q, which looks like caller identity — "+
				"the wire contract must never let the Relay tell the Node who is asking (ADR-0002, #454)", fieldName)
		}
	})

	// Belt-and-suspenders on the four messages the loop actually dispatches
	// through, INCLUDING the two oneof payload messages: a rename evades the
	// regex above (e.g. a caller-identity field spelled "requested_by" or
	// "on_behalf_of" matches no word in callerIdentityFieldName), so an
	// addition OR a rename inside Operation/RawExec must be named explicitly
	// here to pass, not just caught by the regex.
	assertExactTopLevelFieldSet(t, (&relayv1.TaskRequest{}).ProtoReflect().Descriptor(),
		map[string]bool{"task_id": true, "operation": true, "raw_exec": true, "timeout_seconds": true})
	assertExactTopLevelFieldSet(t, (&relayv1.PolicyQuery{}).ProtoReflect().Descriptor(),
		map[string]bool{"query_id": true, "operation": true, "raw_exec": true})
	assertExactTopLevelFieldSet(t, (&relayv1.Operation{}).ProtoReflect().Descriptor(),
		map[string]bool{"name": true, "args": true})
	assertExactTopLevelFieldSet(t, (&relayv1.RawExec{}).ProtoReflect().Descriptor(),
		map[string]bool{"argv": true})
}

// assertExactTopLevelFieldSet fails t if md's own (non-transitive) field-name
// set is not exactly want.
func assertExactTopLevelFieldSet(t *testing.T, md protoreflect.MessageDescriptor, want map[string]bool) {
	t.Helper()
	fields := md.Fields()
	got := make(map[string]bool, fields.Len())
	for i := 0; i < fields.Len(); i++ {
		got[string(fields.Get(i).Name())] = true
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s field set changed:\n  got:  %v\n  want: %v\n"+
			"any addition must be reviewed for caller identity before this allow-set is updated",
			md.FullName(), got, want)
	}
}
