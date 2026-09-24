package metrics

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// scrape drives m.Handler() through httptest and returns the response's
// Content-Type header and body.
func scrape(t *testing.T, m *Metrics) (string, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)
	return rec.Header().Get("Content-Type"), rec.Body.String()
}

func TestHandler_ContentType(t *testing.T) {
	m := New(GaugeSources{})
	contentType, _ := scrape(t, m)
	if want := "text/plain; version=0.0.4; charset=utf-8"; contentType != want {
		t.Errorf("Content-Type = %q, want %q", contentType, want)
	}
}

func TestHandler_GaugesFromSources(t *testing.T) {
	m := New(GaugeSources{
		Connected: func() int { return 3 },
		Nodes:     func() (int, int, error) { return 10, 2, nil },
		Frozen:    func() (bool, error) { return true, nil },
	})
	_, body := scrape(t, m)

	wantLines := []string{
		"# TYPE relay_nodes_connected gauge",
		"relay_nodes_connected 3",
		"# TYPE relay_nodes_enrolled gauge",
		"relay_nodes_enrolled 10",
		"# TYPE relay_nodes_revoked gauge",
		"relay_nodes_revoked 2",
		"# TYPE relay_freeze_engaged gauge",
		"relay_freeze_engaged 1",
	}
	for _, want := range wantLines {
		if !strings.Contains(body, want) {
			t.Errorf("body missing line %q; body = %s", want, body)
		}
	}
}

func TestHandler_FreezeNotEngaged(t *testing.T) {
	m := New(GaugeSources{Frozen: func() (bool, error) { return false, nil }})
	_, body := scrape(t, m)
	if !strings.Contains(body, "relay_freeze_engaged 0") {
		t.Errorf("body missing relay_freeze_engaged 0; body = %s", body)
	}
}

// TestHandler_NilSamplerOmitsGaugeLine is the DoD-adjacent case: a nil
// GaugeSources field must not appear in the exposition at all (no HELP/TYPE/
// value for that metric), rather than a fabricated zero.
func TestHandler_NilSamplerOmitsGaugeLine(t *testing.T) {
	m := New(GaugeSources{})
	_, body := scrape(t, m)

	for _, name := range []string{
		"relay_nodes_connected",
		"relay_nodes_enrolled",
		"relay_nodes_revoked",
		"relay_freeze_engaged",
	} {
		if strings.Contains(body, name) {
			t.Errorf("body contains %q with all samplers nil; want it omitted. body = %s", name, body)
		}
	}
}

// TestHandler_SamplerErrorOmitsGaugeLine: a sampler error omits that gauge's
// line rather than emitting a false value.
func TestHandler_SamplerErrorOmitsGaugeLine(t *testing.T) {
	m := New(GaugeSources{
		Nodes:  func() (int, int, error) { return 0, 0, errors.New("store unavailable") },
		Frozen: func() (bool, error) { return false, errors.New("store unavailable") },
	})
	_, body := scrape(t, m)

	for _, name := range []string{"relay_nodes_enrolled", "relay_nodes_revoked", "relay_freeze_engaged"} {
		if strings.Contains(body, name) {
			t.Errorf("body contains %q despite a sampler error; want it omitted. body = %s", name, body)
		}
	}
}

// TestHandler_LabelsDeclinedSeries asserts both relay_labels_declined_total
// series render with unequal values (so a swapped namespace cannot pass) and
// the counter TYPE, not a gauge.
func TestHandler_LabelsDeclinedSeries(t *testing.T) {
	m := New(GaugeSources{
		LabelsDeclined: func() (node, relay int64) { return 3, 5 },
	})
	_, body := scrape(t, m)

	if !strings.Contains(body, "# TYPE relay_labels_declined_total counter") {
		t.Errorf("body missing counter TYPE line; body = %s", body)
	}
	for _, want := range []string{
		`relay_labels_declined_total{namespace="node"} 3`,
		`relay_labels_declined_total{namespace="relay"} 5`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q; body = %s", want, body)
		}
	}
}

// TestHandler_NilLabelsDeclinedOmitsSeries mirrors
// TestHandler_NilSamplerOmitsGaugeLine: a nil LabelsDeclined must omit both
// series entirely, not fabricate zeros.
func TestHandler_NilLabelsDeclinedOmitsSeries(t *testing.T) {
	m := New(GaugeSources{})
	_, body := scrape(t, m)

	if strings.Contains(body, "relay_labels_declined_total") {
		t.Errorf("body contains relay_labels_declined_total with LabelsDeclined nil; want it omitted. body = %s", body)
	}
}

// TestIncDispatch_EveryOutcome drives IncDispatch across every jobs.Outcome
// and asserts each lands in its own relay_dispatches_total{outcome=...} bucket.
func TestIncDispatch_EveryOutcome(t *testing.T) {
	m := New(GaugeSources{})

	outcomes := []struct {
		outcome jobs.Outcome
		label   string
	}{
		{jobs.OutcomeSuccess, "success"},
		{jobs.OutcomeFailure, "failure"},
		{jobs.OutcomeTimeout, "timeout"},
		{jobs.OutcomeDeniedByPolicy, "denied_by_policy"},
		{jobs.OutcomeCancelled, "cancelled"},
		{jobs.OutcomeUnreachable, "unreachable"},
	}
	for _, o := range outcomes {
		m.IncDispatch(o.outcome)
	}

	_, body := scrape(t, m)
	if !strings.Contains(body, `# TYPE relay_dispatches_total counter`) {
		t.Errorf("body missing relay_dispatches_total TYPE line; body = %s", body)
	}
	for _, o := range outcomes {
		want := `relay_dispatches_total{outcome="` + o.label + `"} 1`
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q; body = %s", want, body)
		}
	}
}

// TestIncDispatch_OutOfRangeFallsBackToUnspecified proves an out-of-range
// Outcome value (a hypothetical future/malformed value) lands in the
// "unspecified" bucket rather than panicking or being silently dropped.
func TestIncDispatch_OutOfRangeFallsBackToUnspecified(t *testing.T) {
	m := New(GaugeSources{})
	m.IncDispatch(jobs.Outcome(999))
	m.IncDispatch(jobs.OutcomeUnspecified)

	_, body := scrape(t, m)
	if !strings.Contains(body, `relay_dispatches_total{outcome="unspecified"} 2`) {
		t.Errorf(`body missing relay_dispatches_total{outcome="unspecified"} 2; body = %s`, body)
	}
}

// TestIncRefusal_EveryKind drives IncRefusal across every capability.RefusalKind.
func TestIncRefusal_EveryKind(t *testing.T) {
	m := New(GaugeSources{})

	kinds := []struct {
		kind  capability.RefusalKind
		label string
	}{
		{capability.RefusalFrozen, "frozen"},
		{capability.RefusalUnauthorized, "unauthorized"},
		{capability.RefusalBlastCap, "blast_cap"},
		{capability.RefusalInternal, "internal"},
		{capability.RefusalNoNodesMatched, "no_nodes_matched"},
	}
	for _, k := range kinds {
		m.IncRefusal(k.kind)
	}

	_, body := scrape(t, m)
	if !strings.Contains(body, `# TYPE relay_refusals_total counter`) {
		t.Errorf("body missing relay_refusals_total TYPE line; body = %s", body)
	}
	for _, k := range kinds {
		want := `relay_refusals_total{reason="` + k.label + `"} 1`
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q; body = %s", want, body)
		}
	}
}

// TestIncRefusal_PendingApprovalStillCountsAsInternal pins IncRefusal's
// normalisation: RefusalPendingApproval is not a refusal (a park, not a
// denial) and rides the counter only for today's accounting, so it lands in
// RefusalInternal's slot rather than a series of its own.
func TestIncRefusal_PendingApprovalStillCountsAsInternal(t *testing.T) {
	m := New(GaugeSources{})
	m.IncRefusal(capability.RefusalPendingApproval)

	_, body := scrape(t, m)
	want := `relay_refusals_total{reason="internal"} 1`
	if !strings.Contains(body, want) {
		t.Errorf("body missing %q; body = %s", want, body)
	}
}

// TestMetrics_ProtocolViolationSeries drives IncProtocolViolation across
// every named rule plus an out-of-range jobs.ViolationRule, and asserts the
// out-of-range value is counted in the rendered "other" bucket rather than
// dropped or mislabelled "none" — the #638 correction on the plain
// enum-indexed idiom IncDispatch/IncRefusal use.
func TestMetrics_ProtocolViolationSeries(t *testing.T) {
	m := New(GaugeSources{})

	m.IncProtocolViolation(jobs.ViolationRelayOnlyOutcome)
	m.IncProtocolViolation(jobs.ViolationUnresolvedOutcome)
	m.IncProtocolViolation(jobs.ViolationUnresolvedOutcome)
	m.IncProtocolViolation(jobs.ViolationRule(999))

	_, body := scrape(t, m)
	if !strings.Contains(body, `# TYPE relay_protocol_violations_total counter`) {
		t.Errorf("body missing relay_protocol_violations_total TYPE line; body = %s", body)
	}
	for _, want := range []string{
		`relay_protocol_violations_total{rule="relay_only_outcome"} 1`,
		`relay_protocol_violations_total{rule="unresolved_outcome"} 2`,
		`relay_protocol_violations_total{rule="other"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q; body = %s", want, body)
		}
	}
	if strings.Contains(body, `rule="none"`) {
		t.Errorf("body renders a rule=\"none\" series — a real violation must never be countable under a label meaning \"no violation\"; body = %s", body)
	}
}

// TestMetrics_ProtocolViolationUnrecordedSeries pins that the unlabelled
// counter renders at 0 before any increment and at N after, so the "the
// trail is missing violations" signal is never silently absent from the
// scrape.
func TestMetrics_ProtocolViolationUnrecordedSeries(t *testing.T) {
	m := New(GaugeSources{})

	_, body := scrape(t, m)
	if !strings.Contains(body, "relay_protocol_violations_unrecorded_total 0") {
		t.Errorf("body missing relay_protocol_violations_unrecorded_total 0 before any increment; body = %s", body)
	}

	m.IncProtocolViolationUnrecorded()
	m.IncProtocolViolationUnrecorded()

	_, body = scrape(t, m)
	if !strings.Contains(body, "relay_protocol_violations_unrecorded_total 2") {
		t.Errorf("body missing relay_protocol_violations_unrecorded_total 2; body = %s", body)
	}
}

func TestIncEnrollment(t *testing.T) {
	m := New(GaugeSources{})
	m.IncEnrollment()
	m.IncEnrollment()
	m.IncEnrollment()

	_, body := scrape(t, m)
	if !strings.Contains(body, "# TYPE relay_enrollments_total counter") {
		t.Errorf("body missing relay_enrollments_total TYPE line; body = %s", body)
	}
	if !strings.Contains(body, "relay_enrollments_total 3") {
		t.Errorf("body missing relay_enrollments_total 3; body = %s", body)
	}
}

// TestIncServerCertRotation_EveryListener drives the server-certificate
// rotation counter (#403) across both listeners and asserts each renders its
// own series. A counter that stops advancing is how an operator sees rotation
// stop, so both series must be present even at zero.
func TestIncServerCertRotation_EveryListener(t *testing.T) {
	m := New(GaugeSources{})
	m.IncServerCertRotation(ListenerNodePlane)
	m.IncServerCertRotation(ListenerNodePlane)
	m.IncServerCertRotation(ListenerControlPlane)

	_, body := scrape(t, m)
	if !strings.Contains(body, "# TYPE relay_server_cert_rotations_total counter") {
		t.Errorf("body missing relay_server_cert_rotations_total TYPE line; body = %s", body)
	}
	for _, want := range []string{
		`relay_server_cert_rotations_total{listener="node_plane"} 2`,
		`relay_server_cert_rotations_total{listener="control_plane"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %s; body = %s", want, body)
		}
	}

	// Never incremented: both series still render, at zero.
	_, fresh := scrape(t, New(GaugeSources{}))
	for _, want := range []string{
		`relay_server_cert_rotations_total{listener="node_plane"} 0`,
		`relay_server_cert_rotations_total{listener="control_plane"} 0`,
	} {
		if !strings.Contains(fresh, want) {
			t.Errorf("fresh body missing %s; body = %s", want, fresh)
		}
	}
}

func TestIncServerCertRotation_OutOfRangeFallsBackToNodePlane(t *testing.T) {
	m := New(GaugeSources{})
	m.IncServerCertRotation(ServerCertListener(99))

	_, body := scrape(t, m)
	if !strings.Contains(body, `relay_server_cert_rotations_total{listener="node_plane"} 1`) {
		t.Errorf("out-of-range listener did not fall back to node_plane; body = %s", body)
	}
}

// --------------------------------------------------------------------------
// relay_build_info (#249)
// --------------------------------------------------------------------------

func TestHandler_BuildInfo(t *testing.T) {
	m := New(GaugeSources{
		Build: BuildInfo{Version: "0.0.9-0.dev+g0a0f22f03dcf", Commit: "0a0f22f03dcf", BuildDate: "2026-07-24"},
	})
	_, body := scrape(t, m)

	wantLines := []string{
		"# TYPE relay_build_info gauge",
		`relay_build_info{version="0.0.9-0.dev+g0a0f22f03dcf",commit="0a0f22f03dcf",build_date="2026-07-24"} 1`,
	}
	for _, want := range wantLines {
		if !strings.Contains(body, want) {
			t.Errorf("body missing line %q; body = %s", want, body)
		}
	}
	// Exactly one series: build info is per-process, not per-anything-else.
	if got := strings.Count(body, "relay_build_info{"); got != 1 {
		t.Errorf("relay_build_info series count = %d, want 1; body = %s", got, body)
	}
}

// An unset Build omits the metric entirely rather than exporting an empty
// stamp — the same skip-when-absent rule the gauge closures follow.
func TestHandler_BuildInfoOmittedWhenUnset(t *testing.T) {
	_, body := scrape(t, New(GaugeSources{}))
	if strings.Contains(body, "relay_build_info") {
		t.Errorf("body must omit relay_build_info when Build is unset; body = %s", body)
	}
}
