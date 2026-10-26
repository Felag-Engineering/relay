// Package protoconv is the single proto-aware seam that translates relayv1
// wire types into registry domain types. It lives outside registry because
// registry intentionally carries no proto dependency.
package protoconv

import (
	"net/netip"
	"strings"

	"github.com/Felag-Engineering/relay/relay/internal/nodestate"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
)

// The names of the Hello and Facts fields the Relay can refuse, as the proto
// names them. They are the closed vocabulary a refusal is logged under: a
// refusal names the field and never carries the wire value.
const (
	FieldPolicyFingerprint      = "policy_fingerprint"
	FieldTemplateSetFingerprint = "template_set_fingerprint"
	FieldDaemonVersion          = "daemon_version"
	FieldHostname               = "facts.hostname"
	FieldOS                     = "facts.os"
	FieldKernel                 = "facts.kernel"
	FieldArch                   = "facts.arch"
	FieldIPAddresses            = "facts.ip_addresses"
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
	var refused []string
	text := func(field, v string) string {
		if registry.WellFormedSelfReportedText(v) {
			return v
		}
		refused = append(refused, field)
		return ""
	}
	f := registry.Facts{
		Hostname: text(FieldHostname, pf.GetHostname()),
		OS:       text(FieldOS, pf.GetOs()),
		Kernel:   text(FieldKernel, pf.GetKernel()),
		Arch:     text(FieldArch, pf.GetArch()),
	}
	// Starting from nil keeps the store's nil-versus-empty distinction: no
	// input and all-dropped input both stay nil.
	dropped := false
	for _, s := range pf.GetIpAddresses() {
		addr, err := netip.ParseAddr(s)
		if err != nil || addr.Zone() != "" {
			dropped = true
			continue
		}
		f.IPAddresses = append(f.IPAddresses, s)
	}
	if dropped {
		refused = append(refused, FieldIPAddresses)
	}
	return f, refused
}

// HelloReport is the part of a Hello the Relay records about the Node, after
// the ingress bounds. Labels are deliberately absent: they stay with the
// tunnel's pinned node: label writer.
type HelloReport struct {
	Facts                  registry.Facts
	PolicyFingerprint      string
	TemplateSetFingerprint string
	DaemonVersion          string
}

// HelloReportFromProto accepts each self-reported field of h only in the shape
// a well-behaved relay-daemon sends, and returns the names of the fields it
// refused (a closed set, never a wire value). A non-empty value that fails is
// returned as "": that is an outcome the Node could choose by reporting nothing,
// so the Relay never manufactures a value (ADR-0017). Nil-safe.
//
// One field differs: for template_set_fingerprint "" means "no templates
// loaded", not "not reported". A malformed template fingerprint is therefore
// recorded as the Node claiming no templates, a claim the Node could make for
// itself and one that gains it no Template reach.
func HelloReportFromProto(h *relayv1.Hello) (HelloReport, []string) {
	if h == nil {
		return HelloReport{}, nil
	}
	facts, refused := FactsFromProtoWithRefusals(h.GetFacts())
	r := HelloReport{Facts: facts}

	if fp := h.GetPolicyFingerprint(); fp == "" || registry.WellFormedFingerprint(fp) {
		r.PolicyFingerprint = fp
	} else {
		refused = append(refused, FieldPolicyFingerprint)
	}

	if fp := h.GetTemplateSetFingerprint(); fp == "" || fp == nodestate.TemplateUnloadable || registry.WellFormedFingerprint(fp) {
		r.TemplateSetFingerprint = fp
	} else {
		refused = append(refused, FieldTemplateSetFingerprint)
	}

	if v := h.GetDaemonVersion(); v == "" || (registry.ValidVersion(v) && len(v) <= registry.MaxSelfReportedTextBytes) {
		r.DaemonVersion = v
	} else {
		refused = append(refused, FieldDaemonVersion)
	}
	return r, refused
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
// selectors-and-labels Limits shared with tag: (registry.MaxLabelKeyLen and
// registry.MaxLabelValueLen).
func ParseNodeLabel(key, value string) (bare string, ok bool) {
	if !strings.HasPrefix(key, "node:") {
		return "", false
	}
	bare = strings.TrimPrefix(key, "node:")
	if !registry.WellFormedLabel(bare, value) ||
		len(bare) > registry.MaxLabelKeyLen || len(value) > registry.MaxLabelValueLen {
		return "", false
	}
	return bare, true
}
