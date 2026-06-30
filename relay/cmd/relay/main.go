package main

import (
	"flag"
	"log/slog"
	"net"
	"os"

	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
	"google.golang.org/grpc"
)

func main() {
	addr := flag.String("addr", ":7654", "gRPC listen address")
	flag.Parse()

	if env := os.Getenv("RELAY_ADDR"); env != "" {
		*addr = env
	}

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		slog.Error("listen failed", "addr", *addr, "err", err)
		os.Exit(1)
	}

	srv := grpc.NewServer()
	gleipnirv1.RegisterTunnelServer(srv, &tunnelServer{})

	slog.Info("relay listening", "addr", *addr)
	if err := srv.Serve(lis); err != nil {
		slog.Error("serve failed", "err", err)
		os.Exit(1)
	}
}
