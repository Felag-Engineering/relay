package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/metrics"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

// scrapeMetrics drives m.Handler() through httptest and returns the
// response's Content-Type header and body, mirroring internal/metrics'
// own (unexported) scrape helper — duplicated here rather than exported,
// since this is the only place outside that package that needs it.
func scrapeMetrics(t *testing.T, m *metrics.Metrics) (string, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)
	return rec.Header().Get("Content-Type"), rec.Body.String()
}

// TestNewServer_RunsDeclinedLabelScanAtStartup is the composition-root half
// of #565: labelscan_test.go exercises store.ScanDeclinedLabels directly,
// but only newServer proves the Relay actually CALLS it on every boot,
// before the listener exists. A test asserting only that newServer succeeds
// would pass even if the ScanDeclinedLabels call — or the whole feature —
// were deleted from main.go; it must observe the log line the scan itself
// produces.
func TestNewServer_RunsDeclinedLabelScanAtStartup(t *testing.T) {
	cfg := baseTestConfig(t)

	// Pre-populate the store with a forged relay_labels row — exactly as a
	// pre-#555 enrollment would have stored it — then close it, so newServer
	// below opens the SAME on-disk database fresh, the way a real restart
	// would. SetRelayLabels itself performs no well-formedness check (that
	// validation lives in enroll.validateScope, the caller — see label.go
	// and registry.go's own doc), so it is a legitimate way to plant a
	// pre-gate row without reaching into store's unexported SQL.
	preSt, err := store.Open(cfg.StorePath)
	if err != nil {
		t.Fatalf("pre-create store.Open: %v", err)
	}
	const nodeID = "node-startup-scan"
	reg := preSt.Registry()
	if _, err := reg.Upsert(registry.Report{NodeID: nodeID}); err != nil {
		t.Fatalf("Upsert %s: %v", nodeID, err)
	}
	if err := reg.SetRelayLabels(nodeID, map[string]string{"env": "prod, relay:quarantine=on"}); err != nil {
		t.Fatalf("SetRelayLabels %s: %v", nodeID, err)
	}
	if err := preSt.Close(); err != nil {
		t.Fatalf("close pre-created store: %v", err)
	}

	var logBuf bytes.Buffer
	prevDefault := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logBuf, nil)))
	t.Cleanup(func() { slog.SetDefault(prevDefault) })

	srv, deps, err := newServer(cfg, testStartupFiles(t, cfg))
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	t.Cleanup(func() { deps.store.Close() })
	t.Cleanup(srv.Stop)

	var sawFinding bool
	for _, line := range strings.Split(strings.TrimRight(logBuf.String(), "\n"), "\n") {
		var entry struct {
			Msg    string `json:"msg"`
			NodeID string `json:"node_id"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if entry.Msg == "stored label declined on read-back" && entry.NodeID == nodeID {
			sawFinding = true
		}
	}
	if !sawFinding {
		t.Errorf("no startup-scan finding line naming node_id=%q — the ScanDeclinedLabels call was not made (or moved after something that can fail first); log:\n%s", nodeID, logBuf.String())
	}
}

// TestNewServer_WiresLabelsDeclinedMetric asserts newServer actually sets
// GaugeSources.LabelsDeclined to the live Store, not merely that the field
// exists on the struct — a field added to GaugeSources but never assigned in
// main.go would leave this series permanently absent from /metrics with no
// compile error anywhere.
func TestNewServer_WiresLabelsDeclinedMetric(t *testing.T) {
	cfg := baseTestConfig(t)

	srv, deps, err := newServer(cfg, testStartupFiles(t, cfg))
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	t.Cleanup(func() { deps.store.Close() })
	t.Cleanup(srv.Stop)

	if deps.metrics == nil {
		t.Fatal("deps.metrics is nil")
	}
	_, body := scrapeMetrics(t, deps.metrics)
	for _, want := range []string{
		`relay_labels_declined_total{namespace="node"} 0`,
		`relay_labels_declined_total{namespace="relay"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q; want the counter wired to a live (zero) Store.LabelsDeclined, not omitted. body = %s", want, body)
		}
	}
}
