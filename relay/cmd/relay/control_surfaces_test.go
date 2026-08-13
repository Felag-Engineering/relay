package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
)

// TestDefaultControlSurfaces_MountWithoutCollision mounts every surface
// defaultControlSurfaces() returns onto a bare *http.ServeMux — no
// controlplane.Server, no Authenticator, no listener — and verifies:
//  1. Mount never panics (mux.Handle itself panics on a duplicate pattern,
//     so a clean run already proves no two surfaces collide), and
//  2. every route callers depend on ("/mcp" and the five /api/v1/* routes)
//     actually resolves to a registered handler afterward.
func TestDefaultControlSurfaces_MountWithoutCollision(t *testing.T) {
	mux := http.NewServeMux()
	sd := surfaceDeps{
		ops: opvocabLister{},
		now: func() time.Time { return time.Time{} },
	}

	for _, s := range defaultControlSurfaces() {
		s.Mount(mux, sd)
	}

	wantRoutes := []struct {
		method, path string
	}{
		{http.MethodPost, "/mcp"},
		{http.MethodPost, "/api/v1/enrollment-tokens"},
		{http.MethodDelete, "/api/v1/enrollment-tokens/some-id"},
		{http.MethodPost, "/api/v1/nodes/some-node/revoke"},
		{http.MethodPost, "/api/v1/freeze/engage"},
		{http.MethodPost, "/api/v1/freeze/release"},
		{http.MethodGet, "/metrics"},
	}
	for _, want := range wantRoutes {
		req := httptest.NewRequest(want.method, want.path, nil)
		if h, pattern := mux.Handler(req); h == nil || pattern == "" {
			t.Errorf("mux.Handler(%s %s): no handler registered (pattern=%q)", want.method, want.path, pattern)
		}
	}
}

// TestDefaultControlSurfaces_Order pins defaultControlSurfaces() to exactly
// mcpSurface, apiSurface, and metricsSurface: a change here should be a
// deliberate one-line edit to the explicit slice, not an accidental drop.
func TestDefaultControlSurfaces_Order(t *testing.T) {
	surfaces := defaultControlSurfaces()
	if len(surfaces) != 3 {
		t.Fatalf("len(defaultControlSurfaces()) = %d, want 3", len(surfaces))
	}
	if _, ok := surfaces[0].(mcpSurface); !ok {
		t.Errorf("surfaces[0] = %T, want mcpSurface", surfaces[0])
	}
	if _, ok := surfaces[1].(apiSurface); !ok {
		t.Errorf("surfaces[1] = %T, want apiSurface", surfaces[1])
	}
	if _, ok := surfaces[2].(metricsSurface); !ok {
		t.Errorf("surfaces[2] = %T, want metricsSurface", surfaces[2])
	}
}

// TestSurfaceDeps_AuditSinkIsWired is a regression guard for a defect found
// while building #357: newServer assembled surfaceDeps WITHOUT setting
// auditSink, so it was nil, and mcp's readAuditor answered its defensive
// `sink == nil` check by skipping silently. Read-access auditing (#288,
// ADR-0025) was therefore dead in production from the day it shipped — the
// trail was empty and nothing anywhere said so.
//
// A nil sink fails silently by design (that skip is deliberate, so an unwired
// surface still works), which is exactly why it needs a test rather than a
// runtime check: the only way to notice is to assert the wiring.
func TestSurfaceDeps_AuditSinkIsWired(t *testing.T) {
	f := startRelay(t, WithControlPlane())

	// Drive a read through the surface and assert the trail actually grew.
	jobID := seedJob(t, f.Deps)
	resp := controlAPIRequest(t, f.ClientFor(""), http.MethodGet,
		f.ControlBase+"/api/v1/jobs/"+jobID, f.Credential, nil)
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read status = %d, want 200", resp.StatusCode)
	}

	records, err := f.Deps.audit.ByJob(context.Background(), jobID)
	if err != nil {
		t.Fatalf("audit.ByJob: %v", err)
	}
	for _, rec := range records {
		if rec.Kind == audit.KindRead {
			return // the sink is wired and writing
		}
	}
	t.Fatal("no KindRead record after a Job read — surfaceDeps.auditSink is not wired, so read auditing is silently disabled (ADR-0025)")
}
