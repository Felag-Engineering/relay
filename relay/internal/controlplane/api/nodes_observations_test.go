package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// observationFixture seeds Nodes covering each clock-skew state and both
// first-connect states, and returns the Control API handler over a real read
// lane, the registry, and the times the Nodes were stamped with.
func observationFixture(t *testing.T) (h http.Handler, measuredAt, firstAt time.Time) {
	t.Helper()
	measuredAt = fixedNow().Add(-time.Minute)
	firstAt = fixedNow().Add(-3 * time.Hour)

	reg := registry.NewInMemory()
	seed := func(id string, skew registry.ClockSkewReading, connected bool) {
		t.Helper()
		if _, err := reg.Upsert(registry.Report{NodeID: id, Facts: registry.Facts{Hostname: "web-1"}}); err != nil {
			t.Fatalf("Upsert %s: %v", id, err)
		}
		if err := reg.RecordHeartbeat(id, measuredAt, skew); err != nil {
			t.Fatalf("RecordHeartbeat %s: %v", id, err)
		}
		if connected {
			if err := reg.MarkConnected(id, firstAt); err != nil {
				t.Fatalf("MarkConnected %s: %v", id, err)
			}
		}
	}
	seed("node-ahead", registry.MeasuredClockSkew(1234*time.Millisecond), true)
	seed("node-behind", registry.MeasuredClockSkew(-2500*time.Millisecond), true)
	seed("node-zero", registry.MeasuredClockSkew(0), false)
	seed("node-never", registry.ClockSkewReading{}, false)

	lane := newNodeReaderLane(t, reg, &fakeCapabilityAuditSink{}, fixedNow, 0)
	return newTestHandler(Deps{NodeReader: lane}), measuredAt, firstAt
}

// getNodeBody reads one Node and returns the raw body and its top-level keys.
func getNodeBody(t *testing.T, h http.Handler, id string) (string, map[string]json.RawMessage) {
	t.Helper()
	rec := do(t, h, http.MethodGet, "/api/v1/nodes/"+id, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200; body = %s", id, rec.Code, rec.Body.String())
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &top); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	return rec.Body.String(), top
}

// Proves QRY-43.
func TestHandleGetNode_ShowsTheMeasuredClockSkewApartFromTheFacts(t *testing.T) {
	h, measuredAt, _ := observationFixture(t)
	stamp := measuredAt.UTC().Format(time.RFC3339)

	cases := []struct {
		id       string
		wantSkew string // the exact clock_skew object
	}{
		{"node-ahead", `{"measured":true,"skew_ms":1234,"measured_at":"` + stamp + `"}`},
		{"node-behind", `{"measured":true,"skew_ms":-2500,"measured_at":"` + stamp + `"}`},
		{"node-zero", `{"measured":true,"skew_ms":0,"measured_at":"` + stamp + `"}`},
		{"node-never", `{"measured":false}`},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			body, top := getNodeBody(t, h, tc.id)

			if got := string(top["clock_skew"]); got != tc.wantSkew {
				t.Errorf("clock_skew = %s, want %s", got, tc.wantSkew)
			}
			if tc.id == "node-never" && (strings.Contains(body, `"skew_ms"`) || strings.Contains(body, `"measured_at"`)) {
				t.Errorf("a Node that was never measured carries a skew value; body = %s", body)
			}

			// Apart from the Facts, and never a state: term.
			if facts := strings.ToLower(string(top["facts"])); strings.Contains(facts, "skew") || strings.Contains(facts, "clock") {
				t.Errorf("facts = %s, want no clock skew inside it", facts)
			}
			if labels := strings.ToLower(string(top["state_labels"])); strings.Contains(labels, "skew") || strings.Contains(labels, "clock") {
				t.Errorf("state_labels = %s, want no clock skew term", labels)
			}
		})
	}
}

// Proves QRY-44.
func TestHandleGetNode_ShowsTheFirstConnectOrThatTheNodeNeverConnected(t *testing.T) {
	h, _, firstAt := observationFixture(t)

	t.Run("connected", func(t *testing.T) {
		body, top := getNodeBody(t, h, "node-ahead")
		want := `{"ever_connected":true,"at":"` + firstAt.UTC().Format(time.RFC3339) + `"}`
		if got := string(top["first_connect"]); got != want {
			t.Errorf("first_connect = %s, want %s", got, want)
		}
		fc, cert := strings.Index(body, `"first_connect"`), strings.Index(body, `"certificate"`)
		if fc < 0 || cert < 0 || fc < cert {
			t.Errorf("first_connect precedes certificate, want it beside the provenance after it; body = %s", body)
		}
	})

	t.Run("never connected", func(t *testing.T) {
		_, top := getNodeBody(t, h, "node-never")
		if got := string(top["first_connect"]); got != `{"ever_connected":false}` {
			t.Errorf("first_connect = %s, want only ever_connected=false", got)
		}
	})
}
