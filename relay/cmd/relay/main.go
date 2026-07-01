package main

import (
	"crypto/x509"
	"flag"
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

func main() {
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

	if env := os.Getenv("RELAY_ADDR"); env != "" {
		*addr = env
	}
	if env := os.Getenv("RELAY_CA_DIR"); env != "" {
		*caDir = env
	}
	if env := os.Getenv("RELAY_HOSTNAME"); env != "" {
		*hostname = env
	}
	if env := os.Getenv("RELAY_ENROLL_IP_RATE"); env != "" {
		if v, err := strconv.Atoi(env); err == nil {
			*enrollIPRate = v
		} else {
			slog.Warn("ignoring invalid RELAY_ENROLL_IP_RATE", "value", env)
		}
	}
	if env := os.Getenv("RELAY_ENROLL_IP_BURST"); env != "" {
		if v, err := strconv.Atoi(env); err == nil {
			*enrollIPBurst = v
		} else {
			slog.Warn("ignoring invalid RELAY_ENROLL_IP_BURST", "value", env)
		}
	}
	if env := os.Getenv("RELAY_ENROLL_GLOBAL_RATE"); env != "" {
		if v, err := strconv.Atoi(env); err == nil {
			*enrollGlobalRate = v
		} else {
			slog.Warn("ignoring invalid RELAY_ENROLL_GLOBAL_RATE", "value", env)
		}
	}
	if env := os.Getenv("RELAY_ENROLL_GLOBAL_BURST"); env != "" {
		if v, err := strconv.Atoi(env); err == nil {
			*enrollGlobalBurst = v
		} else {
			slog.Warn("ignoring invalid RELAY_ENROLL_GLOBAL_BURST", "value", env)
		}
	}
	if env := os.Getenv("RELAY_ENROLL_MAX_TRACKED_IPS"); env != "" {
		if v, err := strconv.Atoi(env); err == nil {
			*enrollMaxTrackedIPs = v
		} else {
			slog.Warn("ignoring invalid RELAY_ENROLL_MAX_TRACKED_IPS", "value", env)
		}
	}
	if env := os.Getenv("RELAY_MAX_NODES"); env != "" {
		if v, err := strconv.Atoi(env); err == nil {
			*maxNodes = v
		} else {
			slog.Warn("ignoring invalid RELAY_MAX_NODES", "value", env)
		}
	}

	relayCA, err := ca.Open(*caDir)
	if err != nil {
		slog.Error("open CA failed", "ca_dir", *caDir, "err", err)
		os.Exit(1)
	}

	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(relayCA.Bundle()) {
		slog.Error("failed to parse CA bundle into cert pool")
		os.Exit(1)
	}

	serverCert, err := relayCA.IssueServerCertificate([]string{*hostname}, nil)
	if err != nil {
		slog.Error("issue server certificate failed", "err", err)
		os.Exit(1)
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
		PerIPRatePerMin:  float64(*enrollIPRate),
		PerIPBurst:       float64(*enrollIPBurst),
		GlobalRatePerMin: float64(*enrollGlobalRate),
		GlobalBurst:      float64(*enrollGlobalBurst),
		MaxTrackedIPs:    *enrollMaxTrackedIPs,
	})
	reg := registry.NewInMemory(registry.WithMaxNodes(*maxNodes))
	tokenSvc := enroll.NewService(enroll.NewMemoryRepository())
	revocationSvc := revocation.NewService(denylist, conns, reg, tokenSvc)
	enrollSrv := enroll.NewServer(tokenSvc, relayCA, reg,
		enroll.WithPostEnrollRevocationCheck(tokenSvc, revocationSvc),
		enroll.WithRateLimiter(limiter))

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		slog.Error("listen failed", "addr", *addr, "err", err)
		os.Exit(1)
	}

	srv := grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainStreamInterceptor(transport.StreamServerInterceptor(certless, denylist)),
		grpc.ChainUnaryInterceptor(transport.UnaryServerInterceptor(certless, denylist)),
	)
	gleipnirv1.RegisterTunnelServer(srv, &tunnelServer{conns: conns, reg: reg})
	gleipnirv1.RegisterEnrollmentServer(srv, enrollSrv)

	slog.Info("relay listening",
		"addr", *addr,
		"mtls", true,
		"ca_dir", *caDir,
		"enroll_ip_rate_per_min", *enrollIPRate,
		"enroll_ip_burst", *enrollIPBurst,
		"enroll_global_rate_per_min", *enrollGlobalRate,
		"enroll_global_burst", *enrollGlobalBurst,
		"enroll_max_tracked_ips", *enrollMaxTrackedIPs,
		"max_nodes", *maxNodes,
	)
	if err := srv.Serve(lis); err != nil {
		slog.Error("serve failed", "err", err)
		os.Exit(1)
	}
}
