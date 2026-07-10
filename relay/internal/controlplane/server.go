package controlplane

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
)

// Config holds the parameters needed to construct a control-plane Server.
type Config struct {
	// Addr is the address the control-plane listener binds, distinct from the
	// node-plane gRPC listener (separate exposure posture: node-plane faces
	// the fleet, control-plane faces operators/AI — ADR-0009).
	Addr string
	// TLSCert is the server certificate presented on the control-plane
	// listener. Issued independently of the node-plane's gRPC server
	// certificate by the composition root.
	TLSCert tls.Certificate
}

// Server is the Relay's control-plane HTTP surface. Every route registered on
// its Mux is wrapped by a single Authenticator.Middleware, so #116 (Control
// API) and #117 (MCP) inherit auth simply by mounting handlers on Mux() — the
// one control path (invariant 10, ADR-0009/0010).
type Server struct {
	mux  *http.ServeMux
	http *http.Server
}

// New constructs a Server. It mounts one authenticated placeholder route so
// that the auth wiring is provable ahead of #116 landing the real Control
// API routes:
//   - GET /api/v1/ping  => 200 {"status":"ok"}  (Control API stand-in, #116)
//
// The real MCP server (#117) is mounted on Mux() by the composition root
// (relay/cmd/relay/main.go) at "/mcp", so this package keeps no MCP
// dependency; it is reached only through the Authenticator.Middleware
// wrapping installed below, exactly like every other route on Mux().
func New(cfg Config, authn *Authenticator) *Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/ping", handlePing)

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cfg.TLSCert},
		MinVersion:   tls.VersionTLS13,
		// One-way TLS: the control plane authenticates callers via the bearer
		// credential (Authenticator.Middleware), not a client certificate.
		ClientAuth: tls.NoClientCert,
	}

	return &Server{
		mux: mux,
		http: &http.Server{
			Addr:      cfg.Addr,
			Handler:   authn.Middleware(mux),
			TLSConfig: tlsCfg,
		},
	}
}

// Mux returns the underlying ServeMux so #116/#117 can register their real
// routes. Every route registered here — past, present, and future — is
// reached only through the Authenticator.Middleware wrapping installed by New.
func (s *Server) Mux() *http.ServeMux {
	return s.mux
}

// Serve runs the control-plane HTTPS server on lis until Shutdown is called,
// terminating and closing lis. It returns http.ErrServerClosed on a clean
// Shutdown.
func (s *Server) Serve(lis net.Listener) error {
	return s.http.ServeTLS(lis, "", "")
}

// ListenAndServe binds s.http.Addr and runs the control-plane HTTPS server
// until Shutdown is called. It returns http.ErrServerClosed on a clean
// Shutdown.
func (s *Server) ListenAndServe() error {
	return s.http.ListenAndServeTLS("", "")
}

// Shutdown gracefully stops the server, independent of any other listener the
// Relay runs (node-plane gRPC in particular): shutting down a Server here
// never affects the node plane, and vice versa.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

// handlePing is the Control API placeholder (#116): proves a REST route is
// reachable only through Authenticator.Middleware.
func handlePing(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
