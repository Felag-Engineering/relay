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
	// GetCertificate supplies the server certificate presented on the
	// control-plane listener, asked once per handshake. Issued independently
	// of the node-plane's gRPC server certificate by the composition root,
	// which also re-issues it before it expires (ca.ServerCertificate,
	// ADR-0031 §5).
	//
	// A callback rather than a tls.Certificate value: a certificate handed
	// over once expires while the process still runs, which is how a Relay up
	// longer than its leaf's lifetime came to serve a dead certificate (#403).
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
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

	// The ONE unauthenticated route on this listener: RFC 9728
	// protected-resource metadata (#299, ADR-0024).
	//
	// It has to be reachable without a credential, because it is what tells a
	// harness *how to get one* — a metadata document behind the auth it
	// describes is a locked door with the key inside. This is the same shape
	// as the daemon plane's single `certless` exemption for Enroll
	// (internal/transport), and it is deliberately expressed the same way:
	// one exact path, registered in one place, wrapped around the
	// authenticated mux rather than punched through it.
	//
	// It discloses an issuer URL and a resource identifier, both public by
	// definition, and 404s when no IdP is configured. Everything else on this
	// listener — every "/" — goes through Middleware.
	public := http.NewServeMux()
	public.Handle(ProtectedResourceMetadataPath, authn.MetadataHandler())
	public.Handle("/", authn.Middleware(mux))

	tlsCfg := &tls.Config{
		GetCertificate: cfg.GetCertificate,
		MinVersion:     tls.VersionTLS13,
		// One-way TLS: the control plane authenticates callers via the bearer
		// credential (Authenticator.Middleware), not a client certificate.
		ClientAuth: tls.NoClientCert,
	}

	return &Server{
		mux: mux,
		http: &http.Server{ //nolint:gosec // G112: pre-existing, no ReadHeaderTimeout; flagged for a follow-up fix, not changed in the CI-hardening PR
			Addr:      cfg.Addr,
			Handler:   public,
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
