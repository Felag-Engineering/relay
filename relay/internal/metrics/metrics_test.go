package metrics

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
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
		"relay_approvals_waiting",
		"relay_certificate_remaining_seconds",
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
		{capability.RefusalUnknownOperation, "unknown_operation"},
		{capability.RefusalMalformed, "malformed"},
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

// TestHandler_FullExposition pins the complete scrape body byte for byte, so a
// change to how series are rendered cannot alter ordering, HELP/TYPE text or
// label escaping unnoticed.
func TestHandler_FullExposition(t *testing.T) {
	m := New(GaugeSources{
		Connected:      func() int { return 3 },
		Nodes:          func() (int, int, error) { return 10, 2, nil },
		Frozen:         func() (bool, error) { return true, nil },
		Build:          BuildInfo{Version: "1.2.3", Commit: "abc", BuildDate: "2026-01-02"},
		LabelsDeclined: func() (int64, int64) { return 4, 5 },

		ApprovalsWaiting: func() (int, error) { return 2, nil },
		CertificateRemaining: func(c Certificate) (time.Duration, bool) {
			if c == CertificateServer {
				return 90*time.Minute + 500*time.Millisecond, true
			}
			return 3650 * 24 * time.Hour, true
		},
	})
	m.IncDispatch(jobs.OutcomeSuccess)
	m.IncRefusal(capability.RefusalBlastCap)
	m.IncEnrollment()
	m.IncAuthRefusal(AuthSurfaceMCP, true)
	m.IncConsoleAuthFailure(ConsoleStepUpFailed)
	m.IncServerCertRotation(ListenerControlPlane)
	m.IncProtocolViolation(jobs.ViolationRelayOnlyOutcome)
	m.IncProtocolViolationUnrecorded()

	_, body := scrape(t, m)
	if body != wantFullExposition {
		t.Errorf("exposition changed.\ngot:\n%s\nwant:\n%s", body, wantFullExposition)
	}
}

const wantFullExposition = `# HELP relay_build_info Relay build identity; always 1, the build stamp is in the labels.
# TYPE relay_build_info gauge
relay_build_info{version="1.2.3",commit="abc",build_date="2026-01-02"} 1
# HELP relay_nodes_connected Number of Nodes with at least one live Tunnel stream.
# TYPE relay_nodes_connected gauge
relay_nodes_connected 3
# HELP relay_nodes_enrolled Total Nodes ever enrolled (including revoked).
# TYPE relay_nodes_enrolled gauge
relay_nodes_enrolled 10
# HELP relay_nodes_revoked Nodes currently revoked.
# TYPE relay_nodes_revoked gauge
relay_nodes_revoked 2
# HELP relay_freeze_engaged Whether the Relay-wide Freeze (ADR-0013) is currently engaged (1) or not (0).
# TYPE relay_freeze_engaged gauge
relay_freeze_engaged 1
# HELP relay_approvals_waiting Approval Requests waiting for an answer: pending and not past their deadline.
# TYPE relay_approvals_waiting gauge
relay_approvals_waiting 2
# HELP relay_certificate_remaining_seconds Seconds until a certificate the Relay holds expires, by certificate; negative once expired.
# TYPE relay_certificate_remaining_seconds gauge
relay_certificate_remaining_seconds{certificate="relay_ca"} 315360000
relay_certificate_remaining_seconds{certificate="server"} 5400
# HELP relay_dispatches_total Total Task dispatch outcomes, by outcome.
# TYPE relay_dispatches_total counter
relay_dispatches_total{outcome="success"} 1
relay_dispatches_total{outcome="failure"} 0
relay_dispatches_total{outcome="timeout"} 0
relay_dispatches_total{outcome="denied_by_policy"} 0
relay_dispatches_total{outcome="cancelled"} 0
relay_dispatches_total{outcome="unreachable"} 0
relay_dispatches_total{outcome="version_refused"} 0
relay_dispatches_total{outcome="unsupported"} 0
relay_dispatches_total{outcome="unspecified"} 0
# HELP relay_refusals_total Total dispatch refusals before any Task was sent, by reason.
# TYPE relay_refusals_total counter
relay_refusals_total{reason="frozen"} 0
relay_refusals_total{reason="unauthorized"} 0
relay_refusals_total{reason="blast_cap"} 1
relay_refusals_total{reason="internal"} 0
relay_refusals_total{reason="no_nodes_matched"} 0
relay_refusals_total{reason="unknown_operation"} 0
relay_refusals_total{reason="malformed"} 0
# HELP relay_enrollments_total Total successful Node enrollments.
# TYPE relay_enrollments_total counter
relay_enrollments_total 1
# HELP relay_server_cert_rotations_total Total in-process re-issuances of the Relay's own TLS server certificate, by listener.
# TYPE relay_server_cert_rotations_total counter
relay_server_cert_rotations_total{listener="node_plane"} 0
relay_server_cert_rotations_total{listener="control_plane"} 1
# HELP relay_auth_failures_total Total refused authentications on the control-plane listener, by surface and reason.
# TYPE relay_auth_failures_total counter
relay_auth_failures_total{surface="control_api",reason="no_credential"} 0
relay_auth_failures_total{surface="control_api",reason="rejected"} 0
relay_auth_failures_total{surface="mcp",reason="no_credential"} 0
relay_auth_failures_total{surface="mcp",reason="rejected"} 1
relay_auth_failures_total{surface="console",reason="no_credential"} 0
relay_auth_failures_total{surface="console",reason="rejected"} 0
relay_auth_failures_total{surface="console",reason="sign_in_failed"} 0
relay_auth_failures_total{surface="console",reason="sign_in_throttled"} 0
relay_auth_failures_total{surface="console",reason="step_up_failed"} 1
relay_auth_failures_total{surface="console",reason="step_up_throttled"} 0
relay_auth_failures_total{surface="other",reason="no_credential"} 0
relay_auth_failures_total{surface="other",reason="rejected"} 0
# HELP relay_protocol_violations_total Total relay-daemon reports refused at the wire boundary as protocol violations, by rule.
# TYPE relay_protocol_violations_total counter
relay_protocol_violations_total{rule="relay_only_outcome"} 1
relay_protocol_violations_total{rule="unresolved_outcome"} 0
relay_protocol_violations_total{rule="other"} 0
# HELP relay_protocol_violations_unrecorded_total Total protocol violations the Relay refused but could not durably record in the audit trail.
# TYPE relay_protocol_violations_unrecorded_total counter
relay_protocol_violations_unrecorded_total 1
# HELP relay_labels_declined_total Total stored Label pairs declined at read-back as not well-formed (threat model R13), by namespace. Counts read-back events, not distinct Labels.
# TYPE relay_labels_declined_total counter
relay_labels_declined_total{namespace="node"} 4
relay_labels_declined_total{namespace="relay"} 5
`

func TestHandler_ApprovalsWaiting(t *testing.T) {
	m := New(GaugeSources{ApprovalsWaiting: func() (int, error) { return 2, nil }})
	_, body := scrape(t, m)
	for _, want := range []string{"# TYPE relay_approvals_waiting gauge", "relay_approvals_waiting 2"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q; body = %s", want, body)
		}
	}
}

func TestHandler_ApprovalsWaitingErrorOmitsGauge(t *testing.T) {
	m := New(GaugeSources{ApprovalsWaiting: func() (int, error) { return 0, errors.New("store unavailable") }})
	_, body := scrape(t, m)
	if strings.Contains(body, "relay_approvals_waiting") {
		t.Errorf("body contains relay_approvals_waiting despite a source error; body = %s", body)
	}
}

func TestHandler_CertificateRemaining(t *testing.T) {
	remaining := map[Certificate]time.Duration{
		CertificateRelayCA: 3650 * 24 * time.Hour,
		CertificateServer:  90*time.Minute + 500*time.Millisecond,
	}
	m := New(GaugeSources{CertificateRemaining: func(c Certificate) (time.Duration, bool) { return remaining[c], true }})
	_, body := scrape(t, m)
	for _, want := range []string{
		"# TYPE relay_certificate_remaining_seconds gauge",
		`relay_certificate_remaining_seconds{certificate="relay_ca"} 315360000`,
		`relay_certificate_remaining_seconds{certificate="server"} 5400`, // truncated, not rounded
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q; body = %s", want, body)
		}
	}

	remaining[CertificateServer] = -30 * time.Second
	_, body = scrape(t, m)
	if want := `relay_certificate_remaining_seconds{certificate="server"} -30`; !strings.Contains(body, want) {
		t.Errorf("an expired certificate must render negative; missing %q in %s", want, body)
	}
}

func TestHandler_CertificateRemainingOmitsUnreadable(t *testing.T) {
	onlyCA := New(GaugeSources{CertificateRemaining: func(c Certificate) (time.Duration, bool) {
		return time.Hour, c == CertificateRelayCA
	}})
	_, body := scrape(t, onlyCA)
	if !strings.Contains(body, `certificate="relay_ca"`) {
		t.Errorf("body missing the relay_ca series; body = %s", body)
	}
	if strings.Contains(body, `certificate="server"`) {
		t.Errorf("body carries a server series the source could not read; body = %s", body)
	}

	neither := New(GaugeSources{CertificateRemaining: func(Certificate) (time.Duration, bool) { return 0, false }})
	_, body = scrape(t, neither)
	if strings.Contains(body, "relay_certificate_remaining_seconds") {
		t.Errorf("body carries the family with no readable certificate; body = %s", body)
	}
}

func TestIncAuthRefusal_EverySurface(t *testing.T) {
	m := New(GaugeSources{})
	surfaces := map[string]AuthSurface{
		"control_api": AuthSurfaceControlAPI,
		"mcp":         AuthSurfaceMCP,
		"console":     AuthSurfaceConsole,
		"other":       AuthSurfaceOther,
	}
	for _, s := range surfaces {
		m.IncAuthRefusal(s, false)
		m.IncAuthRefusal(s, true)
		m.IncAuthRefusal(s, true)
	}
	m.IncAuthRefusal(AuthSurface(99), false) // out of range lands on other
	_, body := scrape(t, m)

	for name := range surfaces {
		wantNo, wantRej := "1", "2"
		if name == "other" {
			wantNo = "2"
		}
		for reason, want := range map[string]string{"no_credential": wantNo, "rejected": wantRej} {
			line := `relay_auth_failures_total{surface="` + name + `",reason="` + reason + `"} ` + want + "\n"
			if !strings.Contains(body, line) {
				t.Errorf("body missing %q; body = %s", line, body)
			}
		}
	}
}

func TestIncConsoleAuthFailure_EveryKind(t *testing.T) {
	fresh := New(GaugeSources{})
	_, body := scrape(t, fresh)
	if n := strings.Count(body, "relay_auth_failures_total{"); n != 12 {
		t.Errorf("a fresh Metrics renders %d auth series, want 12", n)
	}
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "relay_auth_failures_total{") && !strings.HasSuffix(line, " 0") {
			t.Errorf("a fresh Metrics renders %q, want every auth series at 0", line)
		}
	}

	m := New(GaugeSources{})
	kinds := map[string]ConsoleAuthFailure{
		"sign_in_failed":    ConsoleSignInFailed,
		"sign_in_throttled": ConsoleSignInThrottled,
		"step_up_failed":    ConsoleStepUpFailed,
		"step_up_throttled": ConsoleStepUpThrottled,
	}
	for _, k := range kinds {
		m.IncConsoleAuthFailure(k)
	}
	m.IncConsoleAuthFailure(ConsoleAuthFailure(99)) // out of range lands on sign_in_failed
	_, body = scrape(t, m)
	for name := range kinds {
		want := "1"
		if name == "sign_in_failed" {
			want = "2"
		}
		line := `relay_auth_failures_total{surface="console",reason="` + name + `"} ` + want + "\n"
		if !strings.Contains(body, line) {
			t.Errorf("body missing %q; body = %s", line, body)
		}
	}
}

var (
	seriesLabelPair = regexp.MustCompile(`([a-z_]+)="([^"]*)"`)
	closedLabelName = map[string]bool{
		"outcome": true, "reason": true, "listener": true, "rule": true, "namespace": true,
		"surface": true, "certificate": true, "version": true, "commit": true, "build_date": true,
	}
	closedLabelValue = regexp.MustCompile(`^[a-z_]+$`)
)

// seriesIdentities returns each sample line's identity: the text before the
// last space, which is the metric name and its labels without the value.
func seriesIdentities(body string) map[string]bool {
	ids := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ids[line[:strings.LastIndex(line, " ")]] = true
	}
	return ids
}

// TestHandler_SeriesAreAFixedSet pins the cardinality rule: the series set does
// not depend on what has happened, and every label is a closed enum, so no Node
// ID, Account, Selector, argument or free text can appear as a label.
func TestHandler_SeriesAreAFixedSet(t *testing.T) {
	build := func(approvals int, remaining time.Duration) *Metrics {
		return New(GaugeSources{
			Connected:            func() int { return approvals },
			Nodes:                func() (int, int, error) { return approvals, approvals, nil },
			Frozen:               func() (bool, error) { return approvals > 0, nil },
			Build:                BuildInfo{Version: "1.2.3", Commit: "abc", BuildDate: "2026-01-02"},
			LabelsDeclined:       func() (int64, int64) { return int64(approvals), int64(approvals) },
			ApprovalsWaiting:     func() (int, error) { return approvals, nil },
			CertificateRemaining: func(Certificate) (time.Duration, bool) { return remaining, true },
		})
	}
	quiet := build(1, time.Hour)
	busy := build(100000, 3650*24*time.Hour)
	for i := 0; i < 500; i++ {
		busy.IncDispatch(jobs.Outcome(i % 20))
		busy.IncRefusal(capability.RefusalKind(i % 20))
		busy.IncEnrollment()
		busy.IncServerCertRotation(ServerCertListener(i % 5))
		busy.IncProtocolViolation(jobs.ViolationRule(i % 9))
		busy.IncProtocolViolationUnrecorded()
		busy.IncAuthRefusal(AuthSurface(i%7), i%2 == 0)
		busy.IncConsoleAuthFailure(ConsoleAuthFailure(i % 9))
	}

	_, quietBody := scrape(t, quiet)
	_, busyBody := scrape(t, busy)

	quietIDs, busyIDs := seriesIdentities(quietBody), seriesIdentities(busyBody)
	if len(quietIDs) != len(busyIDs) {
		t.Fatalf("series count depends on activity: %d vs %d", len(quietIDs), len(busyIDs))
	}
	for id := range quietIDs {
		if !busyIDs[id] {
			t.Errorf("series %q exists only in the quiet scrape", id)
		}
	}

	for id := range busyIDs {
		for _, pair := range seriesLabelPair.FindAllStringSubmatch(id, -1) {
			name, value := pair[1], pair[2]
			if !closedLabelName[name] {
				t.Errorf("series %q carries label %q outside the closed set", id, name)
			}
			if strings.HasPrefix(id, "relay_build_info") {
				continue
			}
			if !closedLabelValue.MatchString(value) {
				t.Errorf("series %q carries label value %q that is not a closed-enum token", id, value)
			}
		}
	}
}
