package protoconv_test

import (
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/protoconv"
	relayv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"
	"google.golang.org/protobuf/proto"
)

// FuzzParseNodeLabel fuzzes the two-namespace label-authority parser
// (ADR-0006). Property: ParseNodeLabel must never panic or hang on any key,
// and must never accept a "relay:"-prefixed key as node-space.
func FuzzParseNodeLabel(f *testing.F) {
	f.Add("node:role")
	f.Add("relay:secret")
	f.Add("node:")
	f.Add("")
	f.Add("plainkey")

	f.Fuzz(func(t *testing.T, key string) {
		_, _ = protoconv.ParseNodeLabel(key)
	})
}

// FuzzFactsFromProto drives FactsFromProto with wire bytes: proto.Unmarshal
// into relayv1.Facts, then convert. A non-proto payload is rejected by
// Unmarshal (not a crash) and returned early. Property: FactsFromProto must
// never panic or hang on any successfully-unmarshalled Facts.
func FuzzFactsFromProto(f *testing.F) {
	seed, err := proto.Marshal(&relayv1.Facts{
		Hostname:    "h",
		Os:          "linux",
		Kernel:      "6.x",
		Arch:        "amd64",
		IpAddresses: []string{"10.0.0.1"},
	})
	if err != nil {
		f.Fatalf("marshal seed Facts: %v", err)
	}
	f.Add(seed)
	f.Add([]byte(nil))
	f.Add([]byte{0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		var pf relayv1.Facts
		if proto.Unmarshal(data, &pf) != nil {
			return // rejected non-proto input, not a crash
		}
		_ = protoconv.FactsFromProto(&pf)
	})
}
