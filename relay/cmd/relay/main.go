package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/ca"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll"
	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/ratelimit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/revocation"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/transport"
	"google.golang.org/grpc"
)

// Config holds all Relay startup parameters resolved from flags and environment.
type Config struct {
	Addr                string
	CADir               string
	Hostname            string
	EnrollIPRate        int
	EnrollIPBurst       int
	EnrollGlobalRate    int
	EnrollGlobalBurst   int
	EnrollMaxTrackedIPs int
	MaxNodes            int
}

// appDeps holds the constructed collaborators that tests and lifecycle hooks need
// to reach without starting a listener.
type appDeps struct {
	ca         *ca.CA
	registry   registry.Repository
	tokens     *enroll.Service
	denylist   *revocation.Denylist
	conns      *revocation.Connections
	revocation *revocation.Service
	limiter    *ratelimit.Limiter
	// tunnel is the registered tunnelServer. Exposed so integration tests can
	// inject a taskSink (tests only — never set in production).
	tunnel *tunnelServer
}

// envOr returns the value of environment variable key if it is non-empty, or
// fallback otherwise.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// parseConfig resolves all Relay startup parameters from CLI flags and
// environment. RELAY_-prefixed env vars override the corresponding CLI flags
// for string fields. For integer fields, non-integer env values are silently
// ignored and the flag default is kept.
func parseConfig() Config {
	addr := flag.String("addr", ":7654", "gRPC listen address")
	caDir := flag.String("ca-dir", "./ca-data", "directory for CA key and certificate")
	hostname := flag.String("hostname", "localhost", "hostname for the server certificate SAN")

	// Rate-limit and registry-cap flags. Env overrides follow the RELAY_ prefix
	// convention; non-integer env values are silently ignored (flag default kept).
	enrollIPRate := flag.Int("enroll-ip-rate", 5, "per-IP Enrollment rate (tokens/min)")
	enrollIPBurst := flag.Int("enroll-ip-burst", 3, "per-IP Enrollment burst capacity")
	enrollGlobalRate := flag.Int("enroll-global-rate", 50, "global Enrollment rate (tokens/min)")
	enrollGlobalBurst := flag.Int("enroll-global-burst", 10, "global Enrollment burst capacity")
	enrollMaxTrackedIPs := flag.Int("enroll-max-tracked-ips", 100000, "cap on per-IP rate-limit bucket map")
	maxNodes := flag.Int("max-nodes", 110000, "registry insert cap (0 = unlimited)")

	flag.Parse()

	var cfg Config
	cfg.Addr = envOr("RELAY_ADDR", *addr)
	cfg.CADir = envOr("RELAY_CA_DIR", *caDir)
	cfg.Hostname = envOr("RELAY_HOSTNAME", *hostname)

	cfg.EnrollIPRate = *enrollIPRate
	if env := os.Getenv("RELAY_ENROLL_IP_RATE"); env != "" {
		if v, err := strconv.Atoi(env); err == nil {
			cfg.EnrollIPRate = v
		} else {
			slog.Warn("ignoring invalid RELAY_ENROLL_IP_RATE", "value", env)
		}
	}
	cfg.EnrollIPBurst = *enrollIPBurst
	if env := os.Getenv("RELAY_ENROLL_IP_BURST"); env != "" {
		if v, err := strconv.Atoi(env); err == nil {
			cfg.EnrollIPBurst = v
		} else {
			slog.Warn("ignoring invalid RELAY_ENROLL_IP_BURST", "value", env)
		}
	}
	cfg.EnrollGlobalRate = *enrollGlobalRate
	if env := os.Getenv("RELAY_ENROLL_GLOBAL_RATE"); env != "" {
		if v, err := strconv.Atoi(env); err == nil {
			cfg.EnrollGlobalRate = v
		} else {
			slog.Warn("ignoring invalid RELAY_ENROLL_GLOBAL_RATE", "value", env)
		}
	}
	cfg.EnrollGlobalBurst = *enrollGlobalBurst
	if env := os.Getenv("RELAY_ENROLL_GLOBAL_BURST"); env != "" {
		if v, err := strconv.Atoi(env); err == nil {
			cfg.EnrollGlobalBurst = v
		} else {
			slog.Warn("ignoring invalid RELAY_ENROLL_GLOBAL_BURST", "value", env)
		}
	}
	cfg.EnrollMaxTrackedIPs = *enrollMaxTrackedIPs
	if env := os.Getenv("RELAY_ENROLL_MAX_TRACKED_IPS"); env != "" {
		if v, err := strconv.Atoi(env); err == nil {
			cfg.EnrollMaxTrackedIPs = v
		} else {
			slog.Warn("ignoring invalid RELAY_ENROLL_MAX_TRACKED_IPS", "value", env)
		}
	}
	cfg.MaxNodes = *maxNodes
	if env := os.Getenv("RELAY_MAX_NODES"); env != "" {
		if v, err := strconv.Atoi(env); err == nil {
			cfg.MaxNodes = v
		} else {
			slog.Warn("ignoring invalid RELAY_MAX_NODES", "value", env)
		}
	}

	return cfg
}

// newServer constructs and wires the gRPC server and all its dependencies from
// cfg. It does not create a listener or call Serve — those belong to main so
// that tests can construct the server without binding a port.
func newServer(cfg Config) (*grpc.Server, *appDeps, error) {
	relayCA, err := ca.Open(cfg.CADir)
	if err != nil {
		return nil, nil, fmt.Errorf("open CA: %w", err)
	}

	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(relayCA.Bundle()) {
		return nil, nil, fmt.Errorf("parse CA bundle into cert pool")
	}

	serverCert, err := relayCA.IssueServerCertificate([]string{cfg.Hostname}, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("issue server certificate: %w", err)
	}

	// denylist and conns implement immediate Node revocation (ADR-0006).
	// denylist.Add is now reachable at runtime via the post-enroll revocation
	// recheck: if a token is revoked mid-enrollment the handler calls
	// revocationSvc.RevokeNode, which calls denylist.Add. An admin-trigger RPC
	// to revoke nodes on demand still requires a proto change (future milestone).
	denylist := revocation.NewDenylist()
	conns := revocation.NewConnections()

	creds := transport.ServerCredentials(serverCert, clientCAs, denylist)

	// Enrollment_Enroll is the only certless RPC: daemons call it before they have
	// a client certificate. All other RPCs (including Tunnel and Enrollment_Renew)
	// remain mTLS-required. Renew is intentionally absent here: it is authenticated
	// by the caller's existing mTLS client cert, not a token.
	certless := map[string]struct{}{
		gleipnirv1.Enrollment_Enroll_FullMethodName: {},
	}

	limiter := ratelimit.New(ratelimit.Config{
		PerIPRatePerMin:  float64(cfg.EnrollIPRate),
		PerIPBurst:       float64(cfg.EnrollIPBurst),
		GlobalRatePerMin: float64(cfg.EnrollGlobalRate),
		GlobalBurst:      float64(cfg.EnrollGlobalBurst),
		MaxTrackedIPs:    cfg.EnrollMaxTrackedIPs,
	})
	reg := registry.NewInMemory(registry.WithMaxNodes(cfg.MaxNodes))
	tokenSvc := enroll.NewService(enroll.NewMemoryRepository())
	revocationSvc := revocation.NewService(denylist, conns, reg, tokenSvc)
	enrollSrv := enroll.NewServer(tokenSvc, relayCA, reg,
		enroll.WithPostEnrollRevocationCheck(tokenSvc, revocationSvc),
		enroll.WithRateLimiter(limiter))

	ts := &tunnelServer{conns: conns, reg: reg}
	// ts.sink is intentionally left nil — the production Relay never sets it.
	// Only integration tests inject a taskSink after calling newServer.

	srv := grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainStreamInterceptor(transport.StreamServerInterceptor(certless, denylist)),
		grpc.ChainUnaryInterceptor(transport.UnaryServerInterceptor(certless, denylist)),
	)
	gleipnirv1.RegisterTunnelServer(srv, ts)
	gleipnirv1.RegisterEnrollmentServer(srv, enrollSrv)

	deps := &appDeps{
		ca:         relayCA,
		registry:   reg,
		tokens:     tokenSvc,
		denylist:   denylist,
		conns:      conns,
		revocation: revocationSvc,
		limiter:    limiter,
		tunnel:     ts,
	}
	return srv, deps, nil
}

func main() {
	cfg := parseConfig()
	srv, _, err := newServer(cfg)
	if err != nil {
		slog.Error("build server failed", "err", err)
		os.Exit(1)
	}
	lis, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		slog.Error("listen failed", "addr", cfg.Addr, "err", err)
		os.Exit(1)
	}
	slog.Info("relay listening",
		"addr", cfg.Addr,
		"mtls", true,
		"ca_dir", cfg.CADir,
		"enroll_ip_rate_per_min", cfg.EnrollIPRate,
		"enroll_ip_burst", cfg.EnrollIPBurst,
		"enroll_global_rate_per_min", cfg.EnrollGlobalRate,
		"enroll_global_burst", cfg.EnrollGlobalBurst,
		"enroll_max_tracked_ips", cfg.EnrollMaxTrackedIPs,
		"max_nodes", cfg.MaxNodes,
	)
	if err := srv.Serve(lis); err != nil {
		slog.Error("serve failed", "err", err)
		os.Exit(1)
	}
}
