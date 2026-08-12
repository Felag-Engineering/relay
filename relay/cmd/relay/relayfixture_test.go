package main

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"testing"

	"google.golang.org/grpc/test/bufconn"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
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
	if spec.plane == nodePlaneTCP {
		cfg.Addr = "127.0.0.1:0"
	}
	for _, f := range spec.configure {
		f(&cfg)
	}

	srv, deps, err := newServer(cfg)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	t.Cleanup(func() { deps.store.Close() }) //nolint:errcheck

	f := &relayFixture{Deps: deps}

	switch spec.plane {
	case nodePlaneTCP:
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Listen (node plane): %v", err)
		}
		f.NodeAddr = lis.Addr().String()
		go srv.Serve(lis) //nolint:errcheck
		t.Cleanup(srv.GracefulStop)
	default:
		lis := bufconn.Listen(1 << 20)
		f.Bufconn = lis
		go srv.Serve(lis) //nolint:errcheck
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
// ServerName is pinned to "localhost" because that is the SAN the composition
// root issues the control-plane certificate for (baseTestConfig's Hostname),
// even though tests dial 127.0.0.1.
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
