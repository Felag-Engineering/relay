// Package protoconv is the single proto-aware seam that translates relayv1
// wire types into registry domain types. It lives outside registry because
// registry intentionally carries no proto dependency.
package protoconv

import (
	"strings"

	"github.com/Felag-Engineering/relay/relay/internal/registry"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
)

// The names of the Hello and Facts fields the Relay can refuse, as the proto
// names them: registry's closed vocabulary, shared with the read-back that
// declines a stored value. A refusal names the field and never carries the
// wire value.
const (
	FieldPolicyFingerprint      = registry.FieldPolicyFingerprint
	FieldTemplateSetFingerprint = registry.FieldTemplateSetFingerprint
	FieldDaemonVersion          = registry.FieldDaemonVersion
	FieldHostname               = registry.FieldHostname
	FieldOS                     = registry.FieldOS
	FieldKernel                 = registry.FieldKernel
	FieldArch                   = registry.FieldArch
	FieldIPAddresses            = registry.FieldIPAddresses
)

// FactsFromProto converts a proto Facts message to registry.Facts, bounding
// every field the way a well-behaved relay-daemon reports it. Hello and Enroll
// share it, so one rule holds at both ingresses. A text field that fails
// registry.WellFormedSelfReportedText is omitted (""), and an address that is
// not a plain IP is dropped; nothing is rewritten.
// Nil-safe: returns a zero-value registry.Facts when pf is nil.
// IPAddresses is a fresh slice (never aliases the proto slice), nil when there
// is no address to keep.
func FactsFromProto(pf *relayv1.Facts) registry.Facts {
	f, _ := FactsFromProtoWithRefusals(pf)
	return f
}

// FactsFromProtoWithRefusals is FactsFromProto that also returns the names of
// the fields it refused, from the Field* closed set and never a wire value, so
// an ingress can log what it declined to record.
func FactsFromProtoWithRefusals(pf *relayv1.Facts) (registry.Facts, []string) {
	if pf == nil {
		return registry.Facts{}, nil
	}
	r, refused := registry.DeclineMalformedSelfReport(registry.SelfReport{Facts: factsFromProto(pf)})
	return r.Facts, refused
}

// factsFromProto copies pf with no bound applied. The IP list is a fresh
// slice, nil when pf carries none.
func factsFromProto(pf *relayv1.Facts) registry.Facts {
	return registry.Facts{
		Hostname:    pf.GetHostname(),
		OS:          pf.GetOs(),
		Kernel:      pf.GetKernel(),
		Arch:        pf.GetArch(),
		IPAddresses: append([]string(nil), pf.GetIpAddresses()...),
	}
}

// HelloReport is the part of a Hello the Relay records about the Node, after
// the ingress bounds. Labels are deliberately absent: they stay with the
// tunnel's pinned node: label writer.
type HelloReport = registry.SelfReport

// HelloReportFromProto accepts each self-reported field of h only in the shape
// a well-behaved relay-daemon sends (registry.DeclineMalformedSelfReport), and
// returns the names of the fields it refused (a closed set, never a wire
// value). A non-empty value that fails is returned as "": that is an outcome
// the Node could choose by reporting nothing, so the Relay never manufactures
// a value (ADR-0017). Nil-safe.
func HelloReportFromProto(h *relayv1.Hello) (HelloReport, []string) {
	if h == nil {
		return HelloReport{}, nil
	}
	return registry.DeclineMalformedSelfReport(registry.SelfReport{
		Facts:                  factsFromProto(h.GetFacts()),
		PolicyFingerprint:      h.GetPolicyFingerprint(),
		TemplateSetFingerprint: h.GetTemplateSetFingerprint(),
		DaemonVersion:          h.GetDaemonVersion(),
	})
}

// ParseNodeLabel applies the two-namespace label-authority rule (ADR-0006)
// AND the well-formedness gate (registry.WellFormedLabel): a label
// is a node-space label iff its key has a "node:" prefix, the bare key is
// non-empty, and (bare key, value) is well-formed. On success it returns the
// bare key (prefix stripped) and true. Otherwise it returns "" and false. It
// does NOT decide what to do on failure — callers keep their own
// drop-vs-reject policy (Hello omits the label, Enroll rejects the request).
//
// Taking the value is the point: a caller cannot check the key and forget the
// value. Validating only the key would let a `node:role` value of
// "web, relay:quarantine=on" render as two Selector predicates, the second
// spelled relay:.
//
// A self-reported key and value are also bounded in length, by the
// selectors-and-labels Limits shared with tag: (registry.WellFormedNodeLabel).
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
