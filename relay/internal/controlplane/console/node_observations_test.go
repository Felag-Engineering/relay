package console

// node_observations_test.go carries the Console halves of QRY-43 and QRY-44,
// on a real *capability.ReadLane (see node_query_claims_test.go for why).

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// panelFrom returns the section of body that opens at open, up to its closing
// </section>, or "" when open is absent.
func panelFrom(body, open string) string {
	i := strings.Index(body, open)
	if i < 0 {
		return ""
	}
	rest := body[i:]
	if j := strings.Index(rest, "</section>"); j >= 0 {
		return rest[:j]
	}
	return rest
}

func clockPanelOf(body string) string { return panelFrom(body, "<h3>Clock ") }

// observedNodePage seeds one Node and returns its rendered detail page.
func observedNodePage(t *testing.T, id string, skew registry.ClockSkewReading, firstConnectedAt time.Time, enrolled bool) string {
	t.Helper()
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: id, Facts: registry.Facts{Hostname: "web-1"}}); err != nil {
		t.Fatalf("Upsert %s: %v", id, err)
	}
	if err := reg.RecordHeartbeat(id, testNow.Add(-time.Minute), skew); err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}
	if !firstConnectedAt.IsZero() {
		if err := reg.MarkConnected(id, firstConnectedAt); err != nil {
			t.Fatalf("MarkConnected: %v", err)
		}
	}
	if enrolled {
		cert := registry.Certificate{Fingerprint: "ab12", NotAfter: testNow.Add(24 * time.Hour)}
		if err := reg.RecordEnrollment(id, cert, testNow.Add(-48*time.Hour)); err != nil {
			t.Fatalf("RecordEnrollment: %v", err)
		}
	}
	d, _ := lanePanelDeps(t, reg, nil)
	rec := get(t, newTestHandler(d, accounts.RoleViewer), "/console/nodes/"+id)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /console/nodes/%s = %d, want 200", id, rec.Code)
	}
	return rec.Body.String()
}

// Proves QRY-43.
func TestNode_DetailShowsTheMeasuredClockSkewOutsideTheFactsPanel(t *testing.T) {
	measuredAt := testNow.Add(-time.Minute)
	cases := []struct {
		name    string
		skew    registry.ClockSkewReading
		want    []string
		notWant []string
	}{
		{"ahead", registry.MeasuredClockSkew(1234 * time.Millisecond),
			[]string{"&#43;1234 ms", "measured " + utcStamp(measuredAt)}, []string{"not measured"}},
		{"behind", registry.MeasuredClockSkew(-2500 * time.Millisecond),
			[]string{"-2500 ms", "measured " + utcStamp(measuredAt)}, []string{"not measured"}},
		{"zero", registry.MeasuredClockSkew(0),
			[]string{"<dd>0 ms "}, []string{"not measured", "&#43;0 ms"}},
		{"not measured", registry.ClockSkewReading{},
			[]string{"not measured"}, []string{" ms"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := observedNodePage(t, "node-skew", tc.skew, testNow.Add(-time.Hour), true)

			clock := clockPanelOf(body)
			if clock == "" {
				t.Fatal("the page has no Clock panel")
			}
			for _, w := range tc.want {
				if !strings.Contains(clock, w) {
					t.Errorf("Clock panel lacks %q:\n%s", w, clock)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(clock, w) {
					t.Errorf("Clock panel contains %q:\n%s", w, clock)
				}
			}
			// Information, never a warning.
			for _, banned := range []string{`class="chip`, "data-risk", "data-outcome", `class="gap"`, "state:"} {
				if strings.Contains(clock, banned) {
					t.Errorf("Clock panel contains %q, want no warning styling or state: term", banned)
				}
			}

			facts := panelFrom(body, "<h3>Facts ")
			if !strings.Contains(facts, "web-1") {
				t.Fatalf("the Facts panel is empty, so the absence below proves nothing:\n%s", facts)
			}
			for _, banned := range []string{"&#43;1234 ms", "-2500 ms", "0 ms", " ms</dd>", "skew"} {
				if strings.Contains(facts, banned) {
					t.Errorf("Facts panel contains %q, want the skew outside it", banned)
				}
			}
		})
	}
}

// Proves QRY-44.
func TestNode_DetailShowsTheFirstConnectBesideTheCertificateProvenance(t *testing.T) {
	const identity = "<h3>Identity &amp; enrollment"
	firstAt := testNow.Add(-3 * time.Hour)

	for _, enrolled := range []bool{true, false} {
		name := "provenance unrecorded"
		if enrolled {
			name = "provenance recorded"
		}
		t.Run(name+" connected", func(t *testing.T) {
			panel := panelFrom(observedNodePage(t, "node-conn", registry.ClockSkewReading{}, firstAt, enrolled), identity)
			if !strings.Contains(panel, "<dt>first connected</dt>") || !strings.Contains(panel, utcStamp(firstAt)) {
				t.Errorf("Identity panel lacks the first-connect time %q:\n%s", utcStamp(firstAt), panel)
			}
			if strings.Contains(panel, "never connected") {
				t.Errorf("a connected Node reads as never connected:\n%s", panel)
			}
		})
		t.Run(name+" never connected", func(t *testing.T) {
			panel := panelFrom(observedNodePage(t, "node-new", registry.ClockSkewReading{}, time.Time{}, enrolled), identity)
			if !strings.Contains(panel, "<dt>first connected</dt>") || !strings.Contains(panel, "never connected") {
				t.Errorf("Identity panel does not say the Node never connected:\n%s", panel)
			}
		})
	}
}
