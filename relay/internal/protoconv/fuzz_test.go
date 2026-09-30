package protoconv_test

import (
	"fmt"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/protoconv"
	relayv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"
	"google.golang.org/protobuf/proto"
)

// FuzzParseNodeLabel fuzzes the two-namespace label-authority parser
// (ADR-0006) AND the well-formedness gate (#504). Properties:
//   - ParseNodeLabel must never panic or hang on any (key, value);
//   - it must never accept a "relay:"-prefixed key as node-space;
//   - whenever it accepts, capability.ParseSelector("node:"+bare+"="+value)
//     must parse to EXACTLY ONE Predicate, in NamespaceNode, with the same
//     Key and Value — the property that closes the issue's whole class: an
//     accepted label can never render as more (or fewer, or differently
//     namespaced) than the one Selector term it came from. This is a
//     property assertion, not just a no-panic check, so any future widening
//     of the allowlist that reopens a term-splitting or split-shifting byte
//     is caught here without a new hand-written case.
func FuzzParseNodeLabel(f *testing.F) {
	f.Add("node:role", "web")
	f.Add("relay:secret", "x")
	f.Add("node:", "x")
	f.Add("", "")
	f.Add("plainkey", "x")
	// The measured payload (#504's evidence): before the fix this rendered as
	// two Selector predicates, the second spelled relay:.
	f.Add("node:role", "web, relay:quarantine=on")

	f.Fuzz(func(t *testing.T, key, value string) {
		bare, ok := protoconv.ParseNodeLabel(key, value)
		if !ok {
			return
		}
		sel, err := capability.ParseSelector(fmt.Sprintf("node:%s=%s", bare, value))
		if err != nil {
			t.Fatalf("ParseNodeLabel(%q, %q) accepted (bare=%q), but the rendered term %q failed to parse: %v",
				key, value, bare, fmt.Sprintf("node:%s=%s", bare, value), err)
		}
		if len(sel.Predicates) != 1 {
			t.Fatalf("ParseNodeLabel(%q, %q) accepted (bare=%q), but rendered to %d Selector predicates, want exactly 1",
				key, value, bare, len(sel.Predicates))
		}
		p := sel.Predicates[0]
		if p.Namespace != capability.NamespaceNode || p.Key != bare || p.Value != value {
			t.Fatalf("ParseNodeLabel(%q, %q) accepted (bare=%q), but rendered predicate = %+v, want {NamespaceNode %q %q}",
				key, value, bare, p, bare, value)
		}
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
