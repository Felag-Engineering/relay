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
