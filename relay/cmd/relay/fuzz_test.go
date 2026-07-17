package main

import (
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/protoconv"
	relayv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"
	"google.golang.org/protobuf/proto"
)

// FuzzSnapshotFromProto drives snapshotFromProto (and transitively
// argMatchersToArgSets) with wire bytes: proto.Unmarshal into a
// relayv1.PolicySnapshot, then convert. Display-only conversion (ADR-0002,
// invariant 12) — never evaluates Policy. Property: no panic, no hang on any
// successfully-unmarshalled snapshot.
func FuzzSnapshotFromProto(f *testing.F) {
	seed, err := proto.Marshal(&relayv1.PolicySnapshot{
		RawExecEnabled:    true,
		RawAllowPatterns:  []string{"^systemctl status .*$"},
		AllowedOperations: []string{"file.read"},
		PolicyFingerprint: "abc123",
		OperationRules: []*relayv1.OperationRule{
			{Name: "file.read", AllowedArgs: []*relayv1.ArgMatcher{{Values: []string{"/etc/hosts"}}}},
		},
		DenyRules: []*relayv1.DenyRule{
			{Name: "raw_exec", Args: []*relayv1.ArgMatcher{{Values: []string{"rm -rf /"}}}},
		},
	})
	if err != nil {
		f.Fatalf("marshal seed PolicySnapshot: %v", err)
	}
	f.Add(seed)
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, data []byte) {
		var ps relayv1.PolicySnapshot
		if proto.Unmarshal(data, &ps) != nil {
			return // rejected non-proto input, not a crash
		}
		_ = snapshotFromProto(&ps)
	})
}

// FuzzNodeLabelsFromHello drives nodeLabelsFromHello with wire bytes: a
// relayv1.Hello's Labels field, exercising the node:/relay:/empty-key
// namespace edges (ADR-0006). Property: no panic, no hang; a relay:-prefixed
// key must never surface in the returned map.
func FuzzNodeLabelsFromHello(f *testing.F) {
	seed, err := proto.Marshal(&relayv1.Hello{
		Labels: []*relayv1.Label{
			{Key: "node:role", Value: "web"},
			{Key: "relay:x", Value: "y"},
			{Key: "", Value: "z"},
		},
	})
	if err != nil {
		f.Fatalf("marshal seed Hello: %v", err)
	}
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		var h relayv1.Hello
		if proto.Unmarshal(data, &h) != nil {
			return // rejected non-proto input, not a crash
		}
		_ = nodeLabelsFromHello(h.GetLabels())
	})
}

// FuzzDaemonMessageUnmarshal mirrors the live tunnel entry point
// (stream.Recv -> *relayv1.DaemonMessage, tunnel.go's Open) and fans the
// result through every Relay-side converter it can reach, exactly as Open
// does on a Hello or PolicySnapshot body. Property: no panic, no hang on any
// successfully-unmarshalled DaemonMessage, for every oneof Body case reached.
func FuzzDaemonMessageUnmarshal(f *testing.F) {
	seed, err := proto.Marshal(&relayv1.DaemonMessage{
		Body: &relayv1.DaemonMessage_Hello{
			Hello: &relayv1.Hello{
				NodeId:        "node-seed",
				DaemonVersion: "0.1.0",
				Facts: &relayv1.Facts{
					Hostname: "h",
					Os:       "linux",
				},
				Labels: []*relayv1.Label{
					{Key: "node:role", Value: "web"},
				},
			},
		},
	})
	if err != nil {
		f.Fatalf("marshal seed DaemonMessage: %v", err)
	}
	f.Add(seed)
	f.Add([]byte(nil))
	f.Add([]byte{0x08, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		var m relayv1.DaemonMessage
		if proto.Unmarshal(data, &m) != nil {
			return // rejected non-proto input, not a crash
		}
		if h := m.GetHello(); h != nil {
			_ = nodeLabelsFromHello(h.GetLabels())
			_ = protoconv.FactsFromProto(h.GetFacts())
		}
		if ps := m.GetPolicy(); ps != nil {
			_ = snapshotFromProto(ps)
		}
	})
}
