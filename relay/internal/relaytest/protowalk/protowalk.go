// Package protowalk holds the descriptor-reflection helpers behind
// TestWireCarriesNoCallerIdentity, the structural guard that the wire
// contract carries no caller identity: the Node is never told which Account
// or role asked, so the daemon's answer cannot depend on who asked
// (ADR-0002).
//
// That test is kept in two places deliberately — internal/dispatch, where the
// wire conversion happens and which is on the security surface, and
// cmd/relay, beside its sibling wire-immutability test — and each copy keeps
// its own regex and exact-field-set allow-sets so a reviewer reads the whole
// rule in either file. Only the walking and set-comparison machinery, which
// was byte-identical in both, is shared here. internal/dispatch's
// preflight_wire_test.go uses the same two helpers to prove the executing
// message carries no preview flag and PolicyVerdict cannot express
// "unknown" (PF-9, PF-22).
//
// Like its parent relaytest, protowalk links into no production binary: only
// _test.go files import it.
package protowalk

import (
	"reflect"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// WalkReachableMessageFields performs a BFS from start's message descriptor
// over every field reachable through a message-kind field — including oneof
// members and map value types — tracking visited full names so recursion
// terminates on any cycle. It calls visit once per reachable field
// (including start's own top-level fields), and returns after exhausting the
// message graph.
//
// Walking the descriptor graph is deliberate: a hand-built Go-side field list
// is structurally blind to the real oneof, and that blindness would apply to
// caller identity added inside a oneof payload (Operation, RawExec) or
// directly on RelayMessage, rather than as a new top-level TaskRequest field.
// The descriptor graph is not blind to that.
//
// It reports field NAMES only and does not traverse enums (SR7): a new enum
// value, or an overloaded sentinel on an existing scalar, is invisible to it.
// A caller that needs that shape covered must pin it some other way.
func WalkReachableMessageFields(start protoreflect.MessageDescriptor, visit func(fieldName string)) {
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

// AssertExactTopLevelFieldSet fails t if md's own (non-transitive) field-name
// set is not exactly want. It closes the regex's rename blind spot: a
// caller-identity field spelled e.g. "requested_by" matches no identity word,
// but it still changes the field set, so any addition or rename must be
// reviewed and named in want before it passes.
func AssertExactTopLevelFieldSet(t *testing.T, md protoreflect.MessageDescriptor, want map[string]bool) {
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
