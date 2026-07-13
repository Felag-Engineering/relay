package main

import (
	"context"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

// serveControlPlane starts deps.control's HTTPS listener on a real TCP
// 127.0.0.1:0 address (the control plane needs a real net.Listener; bufconn
// only wraps gRPC's dialer) and registers its Shutdown as a t.Cleanup. It
// returns the control-plane base URL and a cert pool trusting deps.ca — the
// verbatim listener+pool setup every appDeps-bound control-plane e2e starter
// needs (startControlAPIServer, startSurfaceHarness, mcp_execution's harness).
func serveControlPlane(t *testing.T, deps *appDeps) (base string, pool *x509.CertPool) {
	t.Helper()

	controlLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen (control-plane): %v", err)
	}
	go func() { _ = deps.control.Serve(controlLis) }()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = deps.control.Shutdown(shutdownCtx)
	})

	pool = relaytest.CertPool(t, deps.ca.Bundle())
	return "https://" + controlLis.Addr().String(), pool
}
