package mcp_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

var (
	observedMeasuredAt = time.Date(2026, 7, 10, 11, 59, 0, 0, time.UTC)
	observedFirstAt    = time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
)

// seedObservations adds one Node per clock-skew state to ts's registry.
func seedObservations(t *testing.T, ts testServer) {
	t.Helper()
	seed := func(id string, skew registry.ClockSkewReading, connected bool) {
		t.Helper()
		if _, err := ts.reg.Upsert(registry.Report{NodeID: id, Facts: registry.Facts{Hostname: "web-1"}}); err != nil {
			t.Fatalf("Upsert %s: %v", id, err)
		}
		if err := ts.reg.RecordHeartbeat(id, observedMeasuredAt, skew); err != nil {
			t.Fatalf("RecordHeartbeat %s: %v", id, err)
		}
		if connected {
			if err := ts.reg.MarkConnected(id, observedFirstAt); err != nil {
				t.Fatalf("MarkConnected %s: %v", id, err)
			}
		}
	}
	seed("node-ahead", registry.MeasuredClockSkew(1234*time.Millisecond), true)
	seed("node-behind", registry.MeasuredClockSkew(-2500*time.Millisecond), true)
	seed("node-zero", registry.MeasuredClockSkew(0), false)
	seed("node-never", registry.ClockSkewReading{}, false)
}

// describeRaw calls describe_node and returns the raw JSON object's keys.
func describeRaw(t *testing.T, ts testServer, id string) (string, map[string]json.RawMessage) {
	t.Helper()
	session := ts.connect(t)
	res := callTool(t, session, "describe_node", map[string]any{"node_id": id})
	text := resultText(t, res)
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &top); err != nil {
		t.Fatalf("json.Unmarshal(%q): %v", text, err)
	}
	return text, top
}

// sameJSON reports whether got and want hold the same JSON value: the tool
// result's keys are not emitted in struct order, so the bytes are not compared.
func sameJSON(t *testing.T, got json.RawMessage, want string) bool {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("json.Unmarshal(%s): %v", got, err)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("json.Unmarshal(%s): %v", want, err)
	}
	return reflect.DeepEqual(g, w)
}

// Proves QRY-43.
func TestMCP_DescribeNode_ShowsTheMeasuredClockSkewApartFromTheFacts(t *testing.T) {
	ts := newTestServer(t)
	seedObservations(t, ts)
	stamp := observedMeasuredAt.Format(time.RFC3339)

	cases := []struct {
		id       string
		wantSkew string
	}{
		{"node-ahead", `{"measured":true,"skew_ms":1234,"measured_at":"` + stamp + `"}`},
		{"node-behind", `{"measured":true,"skew_ms":-2500,"measured_at":"` + stamp + `"}`},
		{"node-zero", `{"measured":true,"skew_ms":0,"measured_at":"` + stamp + `"}`},
		{"node-never", `{"measured":false}`},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			text, top := describeRaw(t, ts, tc.id)

			if !sameJSON(t, top["clock_skew"], tc.wantSkew) {
				t.Errorf("clock_skew = %s, want %s", top["clock_skew"], tc.wantSkew)
			}
			if tc.id == "node-never" && (strings.Contains(text, `"skew_ms"`) || strings.Contains(text, `"measured_at"`)) {
				t.Errorf("a Node that was never measured carries a skew value; result = %s", text)
			}
			if facts := strings.ToLower(string(top["facts"])); strings.Contains(facts, "skew") || strings.Contains(facts, "clock") {
				t.Errorf("facts = %s, want no clock skew inside it", facts)
			}
			if labels := strings.ToLower(string(top["state_labels"])); strings.Contains(labels, "skew") || strings.Contains(labels, "clock") {
				t.Errorf("state_labels = %s, want no clock skew term", labels)
			}
		})
	}

	// The typed decode keeps a measured zero distinct from a missing value.
	session := ts.connect(t)
	var out mcp.DescribeNodeOutput
	decodeResult(t, callTool(t, session, "describe_node", map[string]any{"node_id": "node-zero"}), &out)
	if out.ClockSkew.SkewMs == nil || *out.ClockSkew.SkewMs != 0 {
		t.Errorf("measured-zero skew_ms = %v, want a present 0", out.ClockSkew.SkewMs)
	}
}

// Proves QRY-44.
func TestMCP_DescribeNode_ShowsTheFirstConnectOrThatTheNodeNeverConnected(t *testing.T) {
	ts := newTestServer(t)
	seedObservations(t, ts)

	t.Run("connected", func(t *testing.T) {
		_, top := describeRaw(t, ts, "node-ahead")
		want := `{"ever_connected":true,"at":"` + observedFirstAt.Format(time.RFC3339) + `"}`
		if !sameJSON(t, top["first_connect"], want) {
			t.Errorf("first_connect = %s, want %s", top["first_connect"], want)
		}
	})

	t.Run("never connected", func(t *testing.T) {
		_, top := describeRaw(t, ts, "node-never")
		if got := string(top["first_connect"]); got != `{"ever_connected":false}` {
			t.Errorf("first_connect = %s, want only ever_connected=false", got)
		}
	})
}
