// Package protoconv is the single proto-aware seam that translates relayv1
// wire types into registry domain types. It lives outside registry because
// registry intentionally carries no proto dependency (registry.go:25-26).
package protoconv

import (
	"strings"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	relayv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"
)

// FactsFromProto converts a proto Facts message to registry.Facts.
// Nil-safe: returns a zero-value registry.Facts when pf is nil.
// IPAddresses is copied into a fresh slice (never aliases the proto slice).
func FactsFromProto(pf *relayv1.Facts) registry.Facts {
	if pf == nil {
		return registry.Facts{}
	}
	return registry.Facts{
		Hostname:    pf.GetHostname(),
		OS:          pf.GetOs(),
		Kernel:      pf.GetKernel(),
		Arch:        pf.GetArch(),
		IPAddresses: append([]string(nil), pf.GetIpAddresses()...),
	}
}

// ParseNodeLabel applies the two-namespace label-authority rule (ADR-0006)
// AND the well-formedness gate (#504, registry.WellFormedNodeLabel): a label
// is a node-space label iff its key has a "node:" prefix, the bare key is
// non-empty, and (bare key, value) is well-formed. On success it returns the
// bare key (prefix stripped) and true. Otherwise it returns "" and false. It
// does NOT decide what to do on failure — callers keep their own
// drop-vs-reject policy (Hello omits the label, Enroll rejects the request).
//
// TAKING THE VALUE IS THE POINT: a caller can no longer check the key and
// forget the value, because doing so no longer compiles. Before #504 this
// only validated the key; the measured payload — a `node:role` value of
// "web, relay:quarantine=on" — passed straight through and rendered as two
// Selector predicates, the second spelled relay:.
func ParseNodeLabel(key, value string) (bare string, ok bool) {
	if !strings.HasPrefix(key, "node:") {
		return "", false
	}
	bare = strings.TrimPrefix(key, "node:")
	if !registry.WellFormedNodeLabel(bare, value) {
		return "", false
	}
	return bare, true
}
