package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc/test/bufconn"

	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// relayfixture_test.go is the one way this package starts a Relay in-process.
//
// It exists because there were nine: startRealServer, startTCPServer,
// startControlAPIServer, startSurfaceHarness, startAccountFleet, and the
// inline setup in mcp_execution_e2e_test.go each spun up the composition root
// slightly differently — different Config construction, different listener
// kind, different cleanup, different client wiring. The cost was not
// aesthetic. Retiring the shared control-plane credential (#298) touched seven
// test files, and most of that diff was harness plumbing rather than the
// change under test; the same was true of every auth change before it.
//
// The consolidation is a **builder, not a god-harness**. Each caller composes
// the pieces it needs and gets back only what it asked for. Fixtures that
// drive real *subprocesses* (crossbinary_e2e_test.go, fleet_e2e_test.go) are
// deliberately left alone: they exercise a genuinely different thing — the
// shipped binaries over real sockets — and folding them in here would produce
// one function with two unrelated jobs.

// nodePlane selects how the node-plane gRPC listener is bound.
type nodePlane int

const (
	// The zero value is an in-memory bufconn listener: fastest, and enough
	// whenever the test drives the node plane through a Go client. It is the
	// default precisely because it is the cheaper choice — a test should have
	// to ask for a real socket.
	//
	// nodePlaneTCP binds a real loopback socket, required whenever a
	// relay-daemon subprocess has to dial in.
	nodePlaneTCP nodePlane = iota + 1
)

type fixtureSpec struct {
	plane        nodePlane
	controlPlane bool
	configure    []func(*Config)
	mcpOptions   []mcp.Option

	revokedDialClock func() time.Time
}

// FixtureOption customizes a relay fixture.
type FixtureOption func(*fixtureSpec)

// WithTCPNodePlane binds a real loopback listener instead of a bufconn, for
// tests that run a relay-daemon subprocess.
func WithTCPNodePlane() FixtureOption {
	return func(s *fixtureSpec) { s.plane = nodePlaneTCP }
}

// WithControlPlane enables the control-plane listener (MCP + /api/v1), serves
// it, and mints the founding admin's bootstrap credential.
//
// Enabling it is also what flips execution on in the composition root (the
// #154 flip), so any fixture that dispatches needs this.
func WithControlPlane() FixtureOption {
	return func(s *fixtureSpec) { s.controlPlane = true }
}

// WithConfig applies a mutation to the Config before newServer sees it, for
// the handful of knobs a single test cares about (rate limits, blast caps, a
// minimum daemon version).
func WithConfig(f func(*Config)) FixtureOption {
	return func(s *fixtureSpec) { s.configure = append(s.configure, f) }
}

// WithMCPServerOptions appends opts to the mcp.New options of the real MCP
// surface when the control plane is mounted, via serverHooks (#721). It is
// test-only: this is the one hook production code never populates (see
// TestControlSurfaces_TestOnlyMCPOptionHookIsEmptyInProduction), for options
// the composition root does not itself pass. It has no effect without
// WithControlPlane, and repeated uses accumulate.
//
// opts land AFTER mcpSurface.Mount's own production options (in the order
// this option is applied), and mcp.New applies options in order — so an opt
// that sets the same field as a production option (for example a second
// mcp.WithToolCallObserver) wins for that test. This is deliberate: it is
// what lets a test observe or replace a production collaborator without a
// second wiring path, but it means a test relying on this override should say
// so, since it is exercising a different option list than production ships.
func WithMCPServerOptions(opts ...mcp.Option) FixtureOption {
	return func(s *fixtureSpec) { s.mcpOptions = append(s.mcpOptions, opts...) }
}

// WithRevokedDialClock replaces the clock of the revoked-dial recorder via
// serverHooks, so a test can cross the hourly throttle window. Test-only:
// production never populates the hook (see
// TestControlSurfaces_TestOnlyRevokedDialClockIsNilInProduction).
func WithRevokedDialClock(now func() time.Time) FixtureOption {
	return func(s *fixtureSpec) { s.revokedDialClock = now }
}

// relayFixture is a running Relay plus the handles tests reach for.
//
// Fields are populated only when the corresponding option was requested:
// Bufconn xor NodeAddr, and the control-plane group only under
// WithControlPlane. Reaching for one that was not requested is a programming
// error in the test, and reads as an obvious nil rather than as a subtle
// misbehaviour.
type relayFixture struct {
	Deps *appDeps

	// Bufconn is set unless WithTCPNodePlane.
	Bufconn *bufconn.Listener
	// NodeAddr is set under WithTCPNodePlane.
	NodeAddr string

	// ControlBase, CertPool, and Credential are set under WithControlPlane.
	ControlBase string
	CertPool    *x509.CertPool
	Credential  string
}

// startRelay boots the real composition root and returns the handles the
// requested options produced. Every listener and the store are registered for
// cleanup, so a caller never has to remember to close anything.
func startRelay(t *testing.T, opts ...FixtureOption) *relayFixture {
	t.Helper()

	var spec fixtureSpec
	for _, o := range opts {
		o(&spec)
	}

	cfg := baseTestConfig(t)
	if spec.controlPlane {
		cfg.ControlEnabled = true
		cfg.ControlAddr = "127.0.0.1:0"
	}
	// The TCP node plane is bound before newServer so the join strings the
	// Minter issues name a port a daemon can actually dial: the advertised
	// address defaults to the certificate hostname plus this listener's port.
	// WithConfig hooks run after this default and may override it.
	var tcpLis net.Listener
	if spec.plane == nodePlaneTCP {
		cfg.Addr = "127.0.0.1:0"
		var err error
		tcpLis, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Listen (node plane): %v", err)
		}
		_, port, _ := net.SplitHostPort(tcpLis.Addr().String())
		cfg.AdvertisedAddress = net.JoinHostPort(cfg.Hostname, port)
	}
	for _, f := range spec.configure {
		f(&cfg)
	}

	srv, deps, err := newServerWithHooks(cfg, testStartupFiles(t, cfg), serverHooks{testMCPOptions: spec.mcpOptions, testRevokedDialClock: spec.revokedDialClock})
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	t.Cleanup(func() { deps.store.Close() })
	// A background Job (Execution.Start, #895) must finish before the store
	// closes. Registered right after the store's cleanup, so (last-in-first-out)
	// it runs after the node plane and the control plane have stopped serving
	// and before the store closes.
	t.Cleanup(func() {
		// A control-disabled fixture has no Execution, so no background Jobs.
		if deps.execution == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := deps.execution.Drain(ctx); err != nil {
			t.Errorf("background Jobs did not drain before the store closed: %v", err)
		}
	})

	f := &relayFixture{Deps: deps}

	switch spec.plane {
	case nodePlaneTCP:
		f.NodeAddr = tcpLis.Addr().String()
		go srv.Serve(tcpLis)
		t.Cleanup(srv.GracefulStop)
	default:
		lis := bufconn.Listen(1 << 20)
		f.Bufconn = lis
		go srv.Serve(lis)
		t.Cleanup(srv.Stop)
	}

	if spec.controlPlane {
		f.ControlBase, f.CertPool = serveControlPlane(t, deps)
		f.Credential = bootstrapCredential(t, deps)
	}

	return f
}

// TLSConfig returns a client TLS config trusting the Relay's CA.
//
// ServerName stays "localhost" because it is the certificate hostname from
// baseTestConfig and the name a daemon is given; dialling 127.0.0.1 would also
// verify, through the loopback IP SAN.
func (f *relayFixture) TLSConfig() *tls.Config {
	return &tls.Config{RootCAs: f.CertPool, ServerName: "localhost"}
}

// Client returns an HTTP client trusting the Relay's CA and presenting the
// fixture's bootstrap credential on every request.
func (f *relayFixture) Client() *http.Client {
	return f.ClientFor(f.Credential)
}

// ClientFor returns a client presenting an explicit credential — for tests
// that authenticate as a specific Account, or deliberately as nobody (pass "").
func (f *relayFixture) ClientFor(credential string) *http.Client {
	transport := &http.Transport{TLSClientConfig: f.TLSConfig()}
	if credential == "" {
		return &http.Client{Transport: transport}
	}
	return &http.Client{Transport: relaytest.BearerRoundTripper{Base: transport, Token: credential}}
}
