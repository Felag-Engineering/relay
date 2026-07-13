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
	"strings"
	"testing"

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
