package main

import (
	"crypto/x509"
	"flag"
	"log/slog"
	"net"
	"os"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/ca"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll"
	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/revocation"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/transport"
	"google.golang.org/grpc"
)

func main() {
	addr := flag.String("addr", ":7654", "gRPC listen address")
	caDir := flag.String("ca-dir", "./ca-data", "directory for CA key and certificate")
	hostname := flag.String("hostname", "localhost", "hostname for the server certificate SAN")
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
	// denylist.Add is never called at runtime in this binary until the admin
	// trigger RPC is wired — that requires a proto change and is out of scope
	// for this milestone. The plumbing is live; revocation.Service is exercised
	// by tests.
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

	reg := registry.NewInMemory()
	tokenSvc := enroll.NewService(enroll.NewMemoryRepository())
	enrollSrv := enroll.NewServer(tokenSvc, relayCA, reg)

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

	slog.Info("relay listening", "addr", *addr, "mtls", true, "ca_dir", *caDir)
	if err := srv.Serve(lis); err != nil {
		slog.Error("serve failed", "err", err)
		os.Exit(1)
	}
}
