package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/logctx"
)

// withRequestID gives every request a Relay-minted id for log correlation. It
// never reads an inbound header (a caller-chosen id would be log injection)
// and never writes a response header, so nothing changes on the wire. If the
// entropy source fails the request is served without an id rather than failed.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			next.ServeHTTP(w, r)
			return
		}
		ctx := logctx.WithRequestID(r.Context(), hex.EncodeToString(b[:]))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Connection bounds for the control-plane listener. It faces operators and AI-agent
// harnesses over the network, and every connection is accepted before anyone has
// authenticated, so without a bound a client that opens connections and sends nothing
// holds a goroutine and a file descriptor each, forever — and the descriptors it
// exhausts are the whole Relay's, node-plane gRPC included.
const (
	// DefaultReadHeaderTimeout bounds the TLS handshake and the request headers
	// together: net/http derives its handshake deadline from it.
	DefaultReadHeaderTimeout = 10 * time.Second
	// DefaultIdleTimeout closes a keep-alive connection that has gone quiet between
	// requests.
	DefaultIdleTimeout = 2 * time.Minute
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
	// longer than its leaf's lifetime came to serve a dead certificate.
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)

	// readHeaderTimeout and idleTimeout override the Default* bounds above; zero means
	// the default. Unexported on purpose: they exist so this package's tests can
	// shorten them, not as configuration — a listener bound is part of the security
	// floor (invariant 11), and nothing outside the host's code may change it.
	readHeaderTimeout time.Duration
	idleTimeout       time.Duration
}

// Server is the Relay's control-plane HTTP surface. Every route registered on
// its Mux is wrapped by a single Authenticator.Middleware, so the Control API
// and MCP inherit auth simply by mounting handlers on Mux() — the one control
// path (invariant 10, ADR-0009/0010).
type Server struct {
	mux  *http.ServeMux
	http *http.Server
}

// New constructs a Server. It mounts one authenticated placeholder route so
// that the auth wiring is provable independently of the Control API routes:
//   - GET /api/v1/ping  => 200 {"status":"ok"}  (Control API stand-in)
//
// The real MCP server is mounted on Mux() by the composition root
// (relay/cmd/relay/main.go) at "/mcp", so this package keeps no MCP
// dependency; it is reached only through the Authenticator.Middleware
// wrapping installed below, exactly like every other route on Mux().
func New(cfg Config, authn *Authenticator) *Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/ping", handlePing)

	// The ONE unauthenticated route on this listener: RFC 9728
	// protected-resource metadata (ADR-0024).
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

	readHeaderTimeout := cfg.readHeaderTimeout
	if readHeaderTimeout <= 0 {
		readHeaderTimeout = DefaultReadHeaderTimeout
	}
	idleTimeout := cfg.idleTimeout
	if idleTimeout <= 0 {
		idleTimeout = DefaultIdleTimeout
	}

	return &Server{
		mux: mux,
		http: &http.Server{
			Addr:      cfg.Addr,
			Handler:   withRequestID(public),
			TLSConfig: tlsCfg,
			// No server-wide ReadTimeout or WriteTimeout. On HTTP/1.1 a read deadline
			// that expires while a handler is still running cancels the request's
			// context, cutting a long tool call short; a write deadline cuts a long
			// response. What a client can hold open before it has authenticated is
			// bounded here (the handshake and headers, and the gap between requests)
			// and, for the one route that reads a body unauthenticated — the Console's
			// sign-in POST — by that handler itself. Every other route refuses an
			// unauthenticated request before reading its body.
			ReadHeaderTimeout: readHeaderTimeout,
			IdleTimeout:       idleTimeout,
		},
	}
}

// Mux returns the underlying ServeMux so the Control API and MCP can
// register their routes. Every route registered here — past, present, and future — is
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

// handlePing is the Control API placeholder: proves a REST route is
// reachable only through Authenticator.Middleware.
func handlePing(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
