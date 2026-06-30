package main

import (
	"crypto/x509"
	"flag"
	"log/slog"
	"net"
	"os"

	ca "github.com/Felag-Engineering/gleipnir-relay/relay/internal/ca"
	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
	transport "github.com/Felag-Engineering/gleipnir-relay/relay/internal/transport"
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

	creds := transport.ServerCredentials(serverCert, clientCAs)

	// certless is the set of RPC FullMethod strings reachable without a client
	// certificate. It is intentionally empty today. When the Enrollment handler
	// lands (issue #25), register it here AND add
	// gleipnirv1.Enrollment_Enroll_FullMethodName
	// ("/gleipnir.v1.Enrollment/Enroll") to this set so Enrollment is reachable
	// certless. Do NOT register the Enrollment handler without updating this set.
	certless := map[string]struct{}{}

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		slog.Error("listen failed", "addr", *addr, "err", err)
		os.Exit(1)
	}

	srv := grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainStreamInterceptor(transport.StreamServerInterceptor(certless)),
		grpc.ChainUnaryInterceptor(transport.UnaryServerInterceptor(certless)),
	)
	gleipnirv1.RegisterTunnelServer(srv, &tunnelServer{})

	slog.Info("relay listening", "addr", *addr, "mtls", true, "ca_dir", *caDir)
	if err := srv.Serve(lis); err != nil {
		slog.Error("serve failed", "err", err)
		os.Exit(1)
	}
}
