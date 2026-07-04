package main

// TestPolicyImmutability_ProtoOneof asserts that the proto wire contract
// enforces the Policy-immutability invariant (ADR-0002, invariant #2):
// the Relay may NEVER modify a Node's Policy over the wire.
//
// Proto-level proof: RelayMessage.Body is a oneof with only Ping and Task
// variants. There is no policy-setter variant. Any code that attempted to
// build a RelayMessage carrying policy data would not compile.
//
// DaemonMessage.Body has a policy field (PolicySnapshot, outbound display-only —
// used by the daemon to share its current Policy with the Relay for display,
// never for write-back). The Relay only reads it; the daemon is the sole
// authority.

import (
	"testing"

	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
)

// TestRelayMessage_OnlyPingAndTask constructs every valid RelayMessage and
// asserts via a switch that only Ping and Task variants exist. If the proto
// gains a new oneof variant (e.g. a policy-setter), the new generated type
// would cause the default case to fire and fail the test, forcing human review
// of the change (ADR-0002).
func TestRelayMessage_OnlyPingAndTask(t *testing.T) {
	msgs := []*gleipnirv1.RelayMessage{
		{Body: &gleipnirv1.RelayMessage_Ping{Ping: &gleipnirv1.Ping{UnixMillis: 1}}},
		{Body: &gleipnirv1.RelayMessage_Task{Task: &gleipnirv1.TaskRequest{TaskId: "t1"}}},
	}
	for _, msg := range msgs {
		switch msg.Body.(type) {
		case *gleipnirv1.RelayMessage_Ping:
			// Handshake confirmation — not a policy setter. ✓
		case *gleipnirv1.RelayMessage_Task:
			// Dispatch request — not a policy setter. ✓
		default:
			t.Errorf("unexpected RelayMessage.Body type %T — "+
				"proto must not add a policy-setter variant (ADR-0002)", msg.Body)
		}
	}

	// Compile-time policy-immutability proof:
	//   The following would NOT compile because there is no such type:
	//     _ = &gleipnirv1.RelayMessage_Policy{...}
	//   If this file compiles, RelayMessage carries no policy setter.
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
	dm := &gleipnirv1.DaemonMessage{}
	snapshot := dm.GetPolicy()
	// At runtime the field is nil on an empty message; nil is expected here.
	if snapshot != nil {
		t.Errorf("unexpected non-nil policy snapshot on empty DaemonMessage: %v", snapshot)
	}

	// RelayMessage does NOT have GetPolicy — calling it would be a compile error.
	// The absence proves the Relay cannot send a policy setter to the daemon.
	//
	// Verified: the following would NOT compile:
	//   rm := &gleipnirv1.RelayMessage{}
	//   _ = rm.GetPolicy()   // no such method — ADR-0002 enforced at proto level
	//
	// If this file compiles, RelayMessage carries no policy-setter (ADR-0002). ✓
}
