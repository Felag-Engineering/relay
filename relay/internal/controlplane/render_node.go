package controlplane

import (
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/nodestate"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// The renderers below turn a registry.Node into the values both read surfaces
// (the Control API's node view and MCP's list_nodes/describe_node) put on the
// wire. Like render.go they are pure presentation and decide nothing
// (invariant 10), and the Rendered* types follow the same rule: no tags, and
// the same fields in the same order as each surface's tagged struct, so a
// surface converts with a plain Go struct conversion.

// RenderedFacts is a Node's self-reported facts, before a surface tags them.
type RenderedFacts struct {
	Hostname    string
	OS          string
	Kernel      string
	Arch        string
	IPAddresses []string
}

// RenderFacts renders n's self-reported facts verbatim.
func RenderFacts(n registry.Node) RenderedFacts {
	return RenderedFacts{
		Hostname:    n.Facts.Hostname,
		OS:          n.Facts.OS,
		Kernel:      n.Facts.Kernel,
		Arch:        n.Facts.Arch,
		IPAddresses: n.Facts.IPAddresses,
	}
}

// RenderedCertificate is a Node's identity provenance, before a
// surface tags it.
type RenderedCertificate struct {
	Recorded      bool
	Fingerprint   string
	NotAfter      string
	EnrolledAt    string
	RenewalCount  int
	LastRenewedAt string
}

// RenderCertificate renders n's identity provenance.
//
// Recorded gates every timestamp. A Node that enrolled before provenance was
// stored has a zero NotAfter, and emitting that as an RFC3339 timestamp would
// hand a caller an expiry in 1970 — a Node that reads as catastrophically
// overdue rather than one the Relay simply has nothing to say about.
func RenderCertificate(n registry.Node) RenderedCertificate {
	out := RenderedCertificate{
		Recorded:     n.CertProvenanceKnown(),
		Fingerprint:  n.CertFingerprint,
		RenewalCount: n.RenewalCount,
	}
	if !out.Recorded {
		return out
	}
	out.NotAfter = n.CertNotAfter.UTC().Format(time.RFC3339)
	out.EnrolledAt = RFC3339(n.EnrolledAt)
	out.LastRenewedAt = RFC3339(n.LastRenewedAt)
	return out
}

// RenderedClockSkew is the clock skew the Relay measured for a Node, before a
// surface tags it.
type RenderedClockSkew struct {
	Measured   bool
	SkewMs     *int64
	MeasuredAt string
}

// RenderClockSkew renders n's measured clock skew, signed as the registry
// records it: the Node's time minus the Relay's receive time, positive when the
// Node is ahead (NC-37).
//
// Measured gates the value. A Node the Relay has not measured renders no
// SkewMs at all, so "not measured" is never a zero skew, and a measured zero
// stays visible as 0. The skew is information, never a warning (QRY-43).
func RenderClockSkew(n registry.Node) RenderedClockSkew {
	if !n.ClockSkewKnown() {
		return RenderedClockSkew{}
	}
	ms := n.ClockSkew.Milliseconds()
	return RenderedClockSkew{Measured: true, SkewMs: &ms, MeasuredAt: RFC3339(n.ClockSkewMeasuredAt)}
}

// RenderedFirstConnect is when a Node first connected, before a surface tags
// it.
type RenderedFirstConnect struct {
	EverConnected bool
	At            string
}

// RenderFirstConnect renders when n first connected. EverConnected gates At,
// so a Node that has never connected carries no time rather than a 1970 one.
func RenderFirstConnect(n registry.Node) RenderedFirstConnect {
	return RenderedFirstConnect{
		EverConnected: !n.FirstConnectedAt.IsZero(),
		At:            RFC3339(n.FirstConnectedAt),
	}
}

// StateLabels renders n's Relay-derived state: labels (nodestate.Labels) as
// strings, never nil. ev must be the SAME StateEval the caller resolved its
// Selector against — one instant, one cert-expiring window per response — so
// a Node's rendered state can never disagree with whether it matched.
func StateLabels(n registry.Node, ev capability.StateEval) []string {
	states := nodestate.Labels(nodestate.Input{Node: n, Now: ev.Now, CertExpiringWithin: ev.CertExpiringWithin})
	return MapSlice(states, nodestate.Label.String)
}
