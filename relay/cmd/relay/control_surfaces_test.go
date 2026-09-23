package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/events"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
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

// TestConsoleSurface_MountsTheLiveReadRouteAndTheFingerprints is the wiring
// half of #427, in the shape TestSurfaceDeps_AuditSinkIsWired established: a
// seam the Console degrades gracefully without is a seam whose absence is
// invisible, so the only way to notice it was never wired is to assert it.
//
// Day one renders "not wired" for missing fingerprints and drops its live watch
// for a missing event seam. Both are correct behaviour and both look exactly
// like a composition-root bug.
func TestConsoleSurface_MountsTheLiveReadRouteAndTheFingerprints(t *testing.T) {
	mux := http.NewServeMux()
	consoleSurface{}.Mount(mux, surfaceDeps{
		now:    func() time.Time { return time.Time{} },
		events: events.NewBus(),
		trust:  consoleTrustReader{caFingerprint: "abc123"},
	})

	req := httptest.NewRequest(http.MethodGet, "/console/events?kinds=enrollment", nil)
	if h, pattern := mux.Handler(req); h == nil || pattern == "" {
		t.Errorf("GET /console/events is not mounted (pattern=%q) — the Console has no live path", pattern)
	}
}

// TestConsoleSurface_UnwiredSeamsCrossTheBoundaryAsNil is Go's typed-nil trap,
// which this file already names for the audit sink: assigning a nil
// *events.Bus straight into an interface field produces a NON-nil interface
// holding a nil pointer, so every `d.Events == nil` guard in package console
// passes it through and the first call panics.
//
// The Console's contract is that an unwired seam makes the screens that need
// it degrade — day one drops its live watch, the stream answers 503. That is
// three written promises, and all three are false if the interface is never
// nil. Not reachable in production (newServer always builds a bus), which is
// exactly why it needs a test rather than a runtime check.
func TestConsoleSurface_UnwiredSeamsCrossTheBoundaryAsNil(t *testing.T) {
	if got := consoleEventsOrNil(nil); got != nil {
		t.Errorf("consoleEventsOrNil(nil) = %#v, want an untyped nil — a typed nil makes every "+
			"`d.Events == nil` guard in the Console false and the first call a panic", got)
	}

	// The whole surface, mounted with nothing wired, behind a real
	// authenticator — because the route's nil check comes BEFORE it resolves
	// a principal, and a request without one is refused earlier and never
	// reaches the seam at all. With the typed nil, this panics inside
	// Subscribe on a nil *events.Bus.
	mux := http.NewServeMux()
	consoleSurface{}.Mount(mux, surfaceDeps{now: func() time.Time { return time.Time{} }})
	authn := controlplane.NewAuthenticator(stubVerifier{})
	handler := authn.Middleware(mux)

	req := httptest.NewRequest(http.MethodGet, "/console/events?kinds=enrollment", nil)
	req.Header.Set("Authorization", "Bearer "+stubCredential)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req) // a panic here fails the test, which is the point

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /console/events with no event seam wired = %d, want 503 — an unwired seam "+
			"must reach the Console as an untyped nil so the route can say so", rec.Code)
	}
}

// stubVerifier authenticates one credential, so a test can drive a mounted
// surface through the REAL authentication boundary without standing up an
// Account store.
type stubVerifier struct{}

const stubCredential = accounts.TokenPrefix + "0123456789abcdef.stub" //nolint:gosec // test fixture

func (stubVerifier) Verify(_ context.Context, credential string) (accounts.Account, accounts.APIToken, error) {
	if credential != stubCredential {
		return accounts.Account{}, accounts.APIToken{}, accounts.ErrTokenInvalid
	}
	return accounts.Account{
		Name: "stub-admin", Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true,
	}, accounts.APIToken{ID: "tok-stub"}, nil
}

// TestSurfaceDeps_NoSurfaceIsHandedTheRegistryOrACache is the composition-root
// half of the structural guard (#680): the three adapter packages'
// no_dispatch_test.go guards (mcp, api, console) stop a SURFACE from
// DECLARING a seam that hands back a registry.Node or a display-only
// snapshot without a context; this test stops the ROOT from WIRING one.
// After this issue no surface is handed the registry or a display-only
// cache directly — every registry, Policy-view and Template-vocabulary
// read goes through d.capability, the capability read lane.
func TestSurfaceDeps_NoSurfaceIsHandedTheRegistryOrACache(t *testing.T) {
	// Keyed by PkgPath, not a type-name substring: a substring match would
	// pass a field concretely typed *registry.InMemory (it never spells
	// "registry.Repository"), which is exactly the regression this guard
	// exists to catch. Any type from these three packages is banned, not
	// just their headline Repository/Cache types.
	bannedPkgs := map[string]bool{
		reflect.TypeOf((*registry.Repository)(nil)).Elem().PkgPath(): true,
		reflect.TypeOf(policyview.Cache{}).PkgPath():                 true,
		reflect.TypeOf(nodevocab.Cache{}).PkgPath():                  true,
	}

	typ := reflect.TypeOf(surfaceDeps{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		elem := f.Type
		for elem.Kind() == reflect.Pointer || elem.Kind() == reflect.Slice {
			elem = elem.Elem()
		}
		if bannedPkgs[elem.PkgPath()] {
			t.Errorf("surfaceDeps.%s has type %s, whose element %s is from a banned package — no "+
				"surface may be handed the registry or a display-only cache directly; read through "+
				"d.capability (invariant 10, QRY-28)",
				f.Name, f.Type, elem)
		}
	}
}

// TestConsoleTrustReader_ReportsNothingRatherThanGuessing: the server leaf is
// held live because it rotates, and a Relay assembled without one must produce
// an empty string — which day one renders as "not wired" rather than as a
// fingerprint an operator might compare against.
func TestConsoleTrustReader_ReportsNothingRatherThanGuessing(t *testing.T) {
	r := consoleTrustReader{caFingerprint: "ca-digest"}

	if got := r.CAFingerprint(); got != "ca-digest" {
		t.Errorf("CAFingerprint() = %q, want the CA's digest", got)
	}
	if got := r.ServerFingerprint(); got != "" {
		t.Errorf("ServerFingerprint() with no certificate = %q, want empty", got)
	}
}
