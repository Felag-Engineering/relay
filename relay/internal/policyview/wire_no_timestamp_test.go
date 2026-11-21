package policyview

import (
	"strings"
	"testing"

	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	_ "google.golang.org/protobuf/types/known/timestamppb"
)

// timeNameHints are the substrings that mark a field name as carrying a time.
var timeNameHints = []string{"time", "_at", "timestamp", "date", "received", "reported"}

// timeFieldsOf walks desc and every message type reachable from it, returning
// the full name of each field that is a time-typed message or whose name reads
// as a time, and the number of fields visited. A message type is visited once,
// so a cycle in the message graph terminates.
func timeFieldsOf(desc protoreflect.MessageDescriptor) (flagged []string, visited int) {
	seen := map[protoreflect.FullName]bool{}
	var walk func(protoreflect.MessageDescriptor)
	walk = func(md protoreflect.MessageDescriptor) {
		if seen[md.FullName()] {
			return
		}
		seen[md.FullName()] = true
		fields := md.Fields()
		for i := range fields.Len() {
			f := fields.Get(i)
			visited++
			if reason := timeFieldReason(f); reason != "" {
				flagged = append(flagged, string(f.FullName())+": "+reason)
			}
			if f.Message() != nil {
				walk(f.Message())
			}
		}
	}
	walk(desc)
	return flagged, visited
}

func timeFieldReason(f protoreflect.FieldDescriptor) string {
	if m := f.Message(); m != nil {
		switch m.FullName() {
		case "google.protobuf.Timestamp", "google.protobuf.Duration":
			return "typed " + string(m.FullName())
		}
	}
	name := strings.ToLower(string(f.Name()))
	for _, hint := range timeNameHints {
		if strings.Contains(name, hint) {
			return "named like a time (" + hint + ")"
		}
	}
	return ""
}

// timeControl builds a message that refers to itself and carries one
// Timestamp-typed field, so the walk's detection and its cycle guard are both
// exercised on a type known to be bad.
func timeControl(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	ts, err := protoregistry.GlobalFiles.FindDescriptorByName("google.protobuf.Timestamp")
	if err != nil {
		t.Fatalf("find Timestamp: %v", err)
	}
	fd, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:       proto.String("control.proto"),
		Package:    proto.String("control"),
		Syntax:     proto.String("proto3"),
		Dependency: []string{ts.ParentFile().Path()},
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Loop"),
			Field: []*descriptorpb.FieldDescriptorProto{
				{
					Name:     proto.String("next"),
					Number:   proto.Int32(1),
					Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
					TypeName: proto.String(".control.Loop"),
				},
				{
					Name:     proto.String("when"),
					Number:   proto.Int32(2),
					Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
					TypeName: proto.String(".google.protobuf.Timestamp"),
				},
			},
		}},
	}, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("build control descriptor: %v", err)
	}
	return fd.Messages().ByName("Loop")
}

// TestWire_PolicySnapshotCarriesNoTimestamp pins that the Policy snapshot the
// daemon sends is the bare PolicySnapshot message, and that neither it nor
// anything nested in it carries a time-typed or time-named field. A snapshot's
// receipt time is therefore stamped by the Relay and can never come from the
// Node.
//
// The walk is armed: it must visit the nested rule messages, and it must flag
// a self-referential control message that carries a Timestamp, so a walker
// that fails to descend, to recognise a time or to stop on a cycle cannot pass.
//
// Residual: a time carried inside an existing string field is not a time-typed
// field and is not detected here.
//
// Proves QRY-8.
func TestWire_PolicySnapshotCarriesNoTimestamp(t *testing.T) {
	snapshot := (&relayv1.PolicySnapshot{}).ProtoReflect().Descriptor()

	t.Run("the daemon's Policy report is the bare PolicySnapshot", func(t *testing.T) {
		f := (&relayv1.DaemonMessage{}).ProtoReflect().Descriptor().Fields().ByName("policy")
		if f == nil || f.Message() == nil || f.Message().FullName() != snapshot.FullName() {
			t.Fatalf("DaemonMessage.policy is not a %s: a wrapper could carry a timestamp this test does not walk", snapshot.FullName())
		}
	})

	t.Run("the walker flags a time and survives a cycle", func(t *testing.T) {
		flagged, visited := timeFieldsOf(timeControl(t))
		if len(flagged) != 1 || visited != 4 {
			t.Fatalf("control walk flagged %v over %d field(s), want exactly the Timestamp field over 4 (two of Loop, two inside Timestamp)", flagged, visited)
		}
	})

	flagged, visited := timeFieldsOf(snapshot)
	if visited < 8 {
		t.Fatalf("walked %d field(s) of %s; the walk did not descend into the nested rules", visited, snapshot.FullName())
	}
	for _, reason := range flagged {
		t.Errorf("the wire Policy snapshot carries a time field: %s", reason)
	}
}
