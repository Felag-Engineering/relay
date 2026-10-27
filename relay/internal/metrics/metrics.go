// Package metrics is the real capability.MetricsSink and enroll.
// EnrollmentObserver: a minimal, hand-rolled Prometheus text exposition for
// the Relay's control plane (v0.0.7).
//
// It lives in its own package, not package capability, because capability's
// non-test files are locked to a small import allowlist
// (.golangci.yml's capability-imports rule) that bars a metrics package
// import — mirroring internal/auditsink's own rationale. capability never
// imports metrics; metrics imports capability (for RefusalKind) and jobs
// (for Outcome) only, one-directional.
//
// Every exposed metric is aggregate-only: fixed, small-cardinality labels
// (outcome/reason enums) and Relay-wide gauges. No metric here ever carries a
// node_id, token, account, selector, or human-readable reason string — that
// would be an unbounded-cardinality label and a secrets-in-metrics risk
// (AGENTS.md). This package has no execution capability: it only reads
// gauge-source closures and formats counters (invariant 10).
//
// relay_build_info is the one metric with free-form label values. It is
// still bounded: its labels are this process's own build stamp, fixed for the
// process's lifetime, so the series cardinality is exactly one per running
// Relay — the standard Prometheus build-info idiom. The values are injected by
// the composition root (main.go passes internal/version's linker-set
// variables), which is why this package still imports nothing but capability
// and jobs.
package metrics

import (
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"sync/atomic"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// nOutcomes is the number of jobs.Outcome values
// (Unspecified..Unsupported). dispatches is sized to it; an out-of-range
// Outcome falls back to the OutcomeUnspecified bucket rather than panicking or
// growing unbounded. Every value in range has a series in outcomeOrder below —
// a counted outcome that nothing renders would be silently dropped at scrape
// time.
const nOutcomes = 9

// nRefusalKinds sizes the refusals counter array to cover every
// capability.RefusalKind value, including the ones IncRefusal folds into
// RefusalInternal's slot (see IncRefusal) rather than rendering their own
// series.
const nRefusalKinds = int(capability.RefusalMalformed) + 1

// nViolationRules is the number of relay_protocol_violations_total
// series. Unlike dispatches and refusals, THE SLOT IS NOT THE
// jobs.ViolationRule VALUE: there is no such thing as a violation whose
// rule is ViolationNone, so slot 0 would be a series that can never
// advance, and folding an unrecognised rule into it would label a real
// violation "none" — the one lie this whole change is about.
// violationSlot maps the vocabulary onto these three slots and is TOTAL;
// anything it does not name, including a rule added to internal/jobs
// later, lands in "other".
const nViolationRules = 3

const (
	violationSlotRelayOnly  = 0
	violationSlotUnresolved = 1
	violationSlotOther      = 2
)

// ServerCertListener names a listener that presents the Relay's server
// certificate. It is a closed two-value enum rather than a string so the label
// it renders is bounded by construction, like every other label in this package.
type ServerCertListener int

const (
	// ListenerNodePlane is the mTLS gRPC listener the fleet dials.
	ListenerNodePlane ServerCertListener = iota
	// ListenerControlPlane is the HTTPS listener operators and AI-agents dial.
	ListenerControlPlane
)

// nServerCertListeners is the number of ServerCertListener values.
const nServerCertListeners = 2

// GaugeSources supplies the live values behind each gauge. Any field left nil
// is skipped at scrape time (its metric is omitted entirely), which keeps
// unit tests that only care about counters simple.
type GaugeSources struct {
	// Connected returns the number of Nodes with at least one live Tunnel
	// stream (revocation.Connections.Count).
	Connected func() int
	// Nodes returns the total number of enrolled Nodes and the subset
	// currently revoked (registry.Repository.Count).
	Nodes func() (total, revoked int, err error)
	// Frozen reports whether the Relay-wide Freeze (ADR-0013) is engaged
	// (capability's FreezeStore.Frozen). Takes no context: the composition
	// root's closure supplies its own (main.go), keeping this seam as simple
	// as Connected/Nodes.
	Frozen func() (bool, error)
	// Build is this Relay's build stamp, rendered as the constant
	// relay_build_info gauge. A value, not a closure: unlike the gauges above
	// it never changes while the process runs. A zero Build (empty Version)
	// omits the metric entirely, matching the nil-closure behaviour above.
	Build BuildInfo
	// LabelsDeclined returns the SQLite read-back label filter's live
	// counters (internal/store's Store.LabelsDeclined): how many stored
	// pairs have been declined so far this process, by namespace. A closure
	// rather than an IncX method on Metrics, because the atomics it reads
	// live in internal/store at the filter itself, not here — and plain
	// int64s rather than a namespace type, so neither package needs to import
	// the other's enum, exactly as Nodes above reads registry.Count without
	// internal/registry importing this package. nil omits both series.
	LabelsDeclined func() (node, relay int64)
}

// BuildInfo is the Relay binary's build identity as exposed on /metrics. The
// composition root fills it from internal/version; this package deliberately
// does not import that package, so metrics stays a leaf of the control plane.
type BuildInfo struct {
	Version   string
	Commit    string
	BuildDate string
}

// outcomeOrder is the rendering order of the relay_dispatches_total series —
// unspecified last, since it is the fallback bucket rather than a real
// resolution.
var outcomeOrder = []jobs.Outcome{
	jobs.OutcomeSuccess,
	jobs.OutcomeFailure,
	jobs.OutcomeTimeout,
	jobs.OutcomeDeniedByPolicy,
	jobs.OutcomeCancelled,
	jobs.OutcomeUnreachable,
	jobs.OutcomeVersionRefused,
	jobs.OutcomeUnsupported,
	jobs.OutcomeUnspecified,
}

// refusalLabel maps k to its Prometheus label value. Any unrecognized kind
// (defensive only — capability.RefusalKind is a closed, small enum) falls
// back to "internal".
func refusalLabel(k capability.RefusalKind) string {
	switch k {
	case capability.RefusalFrozen:
		return "frozen"
	case capability.RefusalUnauthorized:
		return "unauthorized"
	case capability.RefusalBlastCap:
		return "blast_cap"
	case capability.RefusalNoNodesMatched:
		return "no_nodes_matched"
	case capability.RefusalUnknownOperation:
		return "unknown_operation"
	case capability.RefusalMalformed:
		return "malformed"
	default:
		return "internal"
	}
}

// violationSlot maps r onto one of the three relay_protocol_violations_total
// slots (see nViolationRules). An unrecognised rule — including a future one
// added to internal/jobs without a case here — falls back to
// violationSlotOther rather than to slot 0, which is what keeps a real
// violation from ever being counted under a label meaning "no violation".
func violationSlot(r jobs.ViolationRule) int {
	switch r {
	case jobs.ViolationRelayOnlyOutcome:
		return violationSlotRelayOnly
	case jobs.ViolationUnresolvedOutcome:
		return violationSlotUnresolved
	default:
		return violationSlotOther
	}
}

// violationSlotLabel maps a violationSlot* constant to its Prometheus label
// value. It must NOT call jobs.ViolationRule.String() — that returns
// "unknown_violation_rule(N)" for an unrecognised value, which is an
// unbounded label this package's doc comment forbids.
func violationSlotLabel(slot int) string {
	switch slot {
	case violationSlotRelayOnly:
		return "relay_only_outcome"
	case violationSlotUnresolved:
		return "unresolved_outcome"
	default:
		return "other"
	}
}

// listenerLabel maps l to its Prometheus label value. Any unrecognized value
// (defensive only — the enum is closed) falls back to the node plane, the
// listener whose certificate expiring is the fleet-wide failure.
func listenerLabel(l ServerCertListener) string {
	if l == ListenerControlPlane {
		return "control_plane"
	}
	return "node_plane"
}

// listenerOrder is the rendering order of the
// relay_server_cert_rotations_total series.
var listenerOrder = []ServerCertListener{
	ListenerNodePlane,
	ListenerControlPlane,
}

// refusalOrder is the rendering order of the relay_refusals_total series.
var refusalOrder = []capability.RefusalKind{
	capability.RefusalFrozen,
	capability.RefusalUnauthorized,
	capability.RefusalBlastCap,
	capability.RefusalInternal,
	capability.RefusalNoNodesMatched,
	capability.RefusalUnknownOperation,
	capability.RefusalMalformed,
}

// violationSlotOrder is the rendering order of the
// relay_protocol_violations_total series — the fallback bucket ("other")
// last and still RENDERED, exactly like outcomeOrder's "unspecified" (a
// counted value nothing renders is silently dropped at scrape time).
var violationSlotOrder = []int{violationSlotRelayOnly, violationSlotUnresolved, violationSlotOther}

// Metrics is the real capability.MetricsSink and enroll.EnrollmentObserver,
// backed by lock-free atomic counters and the caller-supplied GaugeSources.
type Metrics struct {
	src GaugeSources

	dispatches           [nOutcomes]atomic.Int64
	refusals             [nRefusalKinds]atomic.Int64
	enrollments          atomic.Int64
	certRotation         [nServerCertListeners]atomic.Int64
	violations           [nViolationRules]atomic.Int64
	violationsUnrecorded atomic.Int64
}

var _ capability.MetricsSink = (*Metrics)(nil)

// New returns a Metrics backed by src.
func New(src GaugeSources) *Metrics {
	return &Metrics{src: src}
}

// IncDispatch records one Task's outcome (capability.MetricsSink).
func (m *Metrics) IncDispatch(o jobs.Outcome) {
	idx := int(o)
	if idx < 0 || idx >= nOutcomes {
		idx = int(jobs.OutcomeUnspecified)
	}
	m.dispatches[idx].Add(1)
}

// IncRefusal records one dispatch refusal by kind (capability.MetricsSink).
// Only kinds with their own series in refusalOrder get their own slot;
// everything else — RefusalPendingApproval included, since a park is not a
// refusal and is counted here only for today's accounting — folds into
// RefusalInternal's slot. This keeps today's accounting for parks unchanged;
// giving parks their own series is out of scope here.
func (m *Metrics) IncRefusal(k capability.RefusalKind) {
	idx := int(capability.RefusalInternal)
	if slices.Contains(refusalOrder, k) {
		idx = int(k)
	}
	m.refusals[idx].Add(1)
}

// IncEnrollment records one successful Node enrollment (enroll.EnrollmentObserver).
func (m *Metrics) IncEnrollment() {
	m.enrollments.Add(1)
}

// IncServerCertRotation records that the certificate a listener presents was
// re-issued in-process (ADR-0031 §5). One certificate serves both listeners
// (ADR-0031 §1), so the composition root moves every presenting listener's
// series on one re-issue; a sum() across listeners counts each re-issue once
// per listener and is not the number of re-issues. A counter that stops
// advancing is how an operator sees rotation stop; the certificate's remaining
// lifetime after that is their warning window.
func (m *Metrics) IncServerCertRotation(l ServerCertListener) {
	idx := int(l)
	if idx < 0 || idx >= nServerCertListeners {
		idx = int(ListenerNodePlane)
	}
	m.certRotation[idx].Add(1)
}

// IncProtocolViolation records one relay-daemon report refused at the wire
// boundary as a protocol violation, by rule. It is not on
// capability.MetricsSink — the increment happens at the composition root
// (cmd/relay's violationRecorder), the same place enroll.EnrollmentObserver's
// methods live on this type without being on the capability port.
func (m *Metrics) IncProtocolViolation(r jobs.ViolationRule) {
	m.violations[violationSlot(r)].Add(1)
}

// IncProtocolViolationUnrecorded records one protocol violation the audit
// lane could not durably record. The wire boundary is fail-open by design
// (internal/dispatch's recordViolation), so an unwritable store means the
// trail is MISSING a violation it should contain. This counter is the only
// aggregate that says so; an operator alerts on a non-zero increase, not on
// grep.
func (m *Metrics) IncProtocolViolationUnrecorded() {
	m.violationsUnrecorded.Add(1)
}

// Handler returns the http.Handler that serves the Prometheus text
// exposition. It is reached only through the control-plane mux's existing
// bearer-auth middleware (relay/cmd/relay/control_surfaces.go); this package
// mounts nothing of its own.
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(m.serveMetrics)
}

func (m *Metrics) serveMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	var buf []byte
	buf = m.appendGauges(buf)
	buf = appendDispatches(buf, &m.dispatches)
	buf = appendRefusals(buf, &m.refusals)
	buf = appendCounter(buf, "relay_enrollments_total", "Total successful Node enrollments.", m.enrollments.Load())
	buf = appendCertRotations(buf, &m.certRotation)
	buf = appendProtocolViolations(buf, &m.violations)
	buf = appendCounter(buf, "relay_protocol_violations_unrecorded_total",
		"Total protocol violations the Relay refused but could not durably record in the audit trail.",
		m.violationsUnrecorded.Load())
	if m.src.LabelsDeclined != nil {
		node, relay := m.src.LabelsDeclined()
		buf = appendLabelsDeclined(buf, node, relay)
	}

	_, _ = w.Write(buf)
}

// appendGauges appends the connected/enrolled/revoked/freeze gauge series,
// skipping any whose GaugeSources field is nil, and — on a sampler error —
// logging at debug and omitting that gauge line rather than emitting a false
// value.
func (m *Metrics) appendGauges(buf []byte) []byte {
	if m.src.Build.Version != "" {
		buf = appendBuildInfo(buf, m.src.Build)
	}

	if m.src.Connected != nil {
		buf = appendGauge(buf, "relay_nodes_connected",
			"Number of Nodes with at least one live Tunnel stream.", int64(m.src.Connected()))
	}

	if m.src.Nodes != nil {
		total, revoked, err := m.src.Nodes()
		if err != nil {
			slog.Debug("metrics: read node counts failed", "err", err)
		} else {
			buf = appendGauge(buf, "relay_nodes_enrolled",
				"Total Nodes ever enrolled (including revoked).", int64(total))
			buf = appendGauge(buf, "relay_nodes_revoked",
				"Nodes currently revoked.", int64(revoked))
		}
	}

	if m.src.Frozen != nil {
		frozen, err := m.src.Frozen()
		if err != nil {
			slog.Debug("metrics: read freeze state failed", "err", err)
		} else {
			buf = appendGauge(buf, "relay_freeze_engaged",
				"Whether the Relay-wide Freeze (ADR-0013) is currently engaged (1) or not (0).", boolToInt64(frozen))
		}
	}

	return buf
}

func appendDispatches(buf []byte, dispatches *[nOutcomes]atomic.Int64) []byte {
	samples := make([]labelledValue, 0, len(outcomeOrder))
	for _, o := range outcomeOrder {
		samples = append(samples, labelledValue{jobs.OutcomeName(o), dispatches[int(o)].Load()})
	}
	return appendLabelledCounter(buf, "relay_dispatches_total",
		"Total Task dispatch outcomes, by outcome.", "outcome", samples)
}

func appendRefusals(buf []byte, refusals *[nRefusalKinds]atomic.Int64) []byte {
	samples := make([]labelledValue, 0, len(refusalOrder))
	for _, k := range refusalOrder {
		samples = append(samples, labelledValue{refusalLabel(k), refusals[int(k)].Load()})
	}
	return appendLabelledCounter(buf, "relay_refusals_total",
		"Total dispatch refusals before any Task was sent, by reason.", "reason", samples)
}

func appendCertRotations(buf []byte, rotations *[nServerCertListeners]atomic.Int64) []byte {
	samples := make([]labelledValue, 0, len(listenerOrder))
	for _, l := range listenerOrder {
		samples = append(samples, labelledValue{listenerLabel(l), rotations[int(l)].Load()})
	}
	return appendLabelledCounter(buf, "relay_server_cert_rotations_total",
		"Total in-process re-issuances of the Relay's own TLS server certificate, by listener.", "listener", samples)
}

func appendProtocolViolations(buf []byte, violations *[nViolationRules]atomic.Int64) []byte {
	samples := make([]labelledValue, 0, len(violationSlotOrder))
	for _, slot := range violationSlotOrder {
		samples = append(samples, labelledValue{violationSlotLabel(slot), violations[slot].Load()})
	}
	return appendLabelledCounter(buf, "relay_protocol_violations_total",
		"Total relay-daemon reports refused at the wire boundary as protocol violations, by rule.", "rule", samples)
}

// appendLabelsDeclined renders relay_labels_declined_total, one series per
// namespace, node before relay (matching every other two-value enum's
// render order in this file). Namespace label values are literals here
// rather than a type this package owns — a closed two-value set, mirroring
// listenerLabel — because internal/store's labelNamespace must not leak into
// this package's API surface any more than its atomics do.
//
// HELP says "events, not distinct Labels" deliberately: this counter
// advances once per DECLINED READ, not once per distinct stored Label, so an
// operator reading a large number here has NOT necessarily found that many
// broken Labels — a Node read or listed repeatedly re-advances the same
// series. It is also traffic-driven: a flat counter can mean "clean" or
// "nobody has read this Node since the fix", and only the one-shot startup
// scan (internal/store's ScanDeclinedLabels) distinguishes the two. Still
// monotonic despite being sourced from a closure rather than an internal
// atomic.Int64: the underlying counters are add-only.
func appendLabelsDeclined(buf []byte, node, relay int64) []byte {
	return appendLabelledCounter(buf, "relay_labels_declined_total",
		"Total stored Label pairs declined at read-back as not well-formed (threat model R13), by namespace. Counts read-back events, not distinct Labels.",
		"namespace", []labelledValue{{"node", node}, {"relay", relay}})
}

// appendBuildInfo renders the constant relay_build_info series: always the
// value 1, carrying this process's build stamp as labels (the standard
// Prometheus build-info idiom — the labels are the payload). Label values go
// through %q, the same escaping every other labelled series here uses.
func appendBuildInfo(buf []byte, b BuildInfo) []byte {
	buf = appendFamilyHeader(buf, "relay_build_info",
		"Relay build identity; always 1, the build stamp is in the labels.", "gauge")
	return fmt.Appendf(buf, "relay_build_info{version=%q,commit=%q,build_date=%q} 1\n",
		b.Version, b.Commit, b.BuildDate)
}

func appendGauge(buf []byte, name, help string, value int64) []byte {
	return appendSample(appendFamilyHeader(buf, name, help, "gauge"), name, value)
}

func appendCounter(buf []byte, name, help string, value int64) []byte {
	return appendSample(appendFamilyHeader(buf, name, help, "counter"), name, value)
}

// appendFamilyHeader appends a metric family's # HELP and # TYPE lines.
func appendFamilyHeader(buf []byte, name, help, typ string) []byte {
	buf = fmt.Appendf(buf, "# HELP %s %s\n", name, help)
	return fmt.Appendf(buf, "# TYPE %s %s\n", name, typ)
}

// appendSample appends one unlabelled sample line.
func appendSample(buf []byte, name string, value int64) []byte {
	buf = append(buf, name...)
	buf = append(buf, ' ')
	buf = strconv.AppendInt(buf, value, 10)
	return append(buf, '\n')
}

// labelledValue is one sample of a single-label counter family.
type labelledValue struct {
	label string
	value int64
}

// appendLabelledCounter appends a counter family with one label: the header,
// then one sample per entry in samples, in order. Label values go through %q,
// the escaping every labelled series here uses.
func appendLabelledCounter(buf []byte, name, help, label string, samples []labelledValue) []byte {
	buf = appendFamilyHeader(buf, name, help, "counter")
	for _, s := range samples {
		buf = fmt.Appendf(buf, "%s{%s=%q} %d\n", name, label, s.label, s.value)
	}
	return buf
}

func boolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
