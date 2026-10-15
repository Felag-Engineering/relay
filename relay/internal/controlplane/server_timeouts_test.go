package controlplane

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// newBoundedTestServer starts a Server whose connection bounds are shortened to
// readHeader and idle, and returns its address.
func newBoundedTestServer(t *testing.T, readHeader, idle time.Duration) string {
	t.Helper()

	cert := relaytest.SelfSignedServerCert(t, "controlplane-timeouts-test")
	srv := New(Config{
		Addr:              "127.0.0.1:0",
		GetCertificate:    staticCert(cert),
		readHeaderTimeout: readHeader,
		idleTimeout:       idle,
	}, testAuthenticator())

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return lis.Addr().String()
}

// assertServerCloses fails unless the server closes conn within limit. A read that hits
// the test's own deadline means the server was still holding the connection open.
func assertServerCloses(t *testing.T, conn net.Conn, limit time.Duration) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(limit)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_, err := io.ReadAll(conn)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the server still held the connection open after %v", limit)
	}
}

// A client that connects and sends nothing — not even a TLS ClientHello — is the
// cheapest way to hold a goroutine and a file descriptor on a listener that accepts
// before authenticating. The server must close it.
func TestServer_SilentConnectionIsClosed(t *testing.T) {
	addr := newBoundedTestServer(t, 200*time.Millisecond, time.Minute)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	assertServerCloses(t, conn, 5*time.Second)
}

// Slowloris proper: complete the handshake, then send the request headers too slowly
// to ever finish them.
func TestServer_StalledHeadersAreCut(t *testing.T) {
	// One second, not the 200ms the silent test uses: this bound covers the TLS
	// handshake too, and this test must complete one first, under -race on a loaded
	// runner.
	addr := newBoundedTestServer(t, time.Second, time.Minute)

	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) // a self-signed test leaf; the handshake is not what is under test
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("GET /api/v1/ping HTTP/1.1\r\nHost: relay\r\n")); err != nil {
		t.Fatalf("write partial headers: %v", err)
	}
	assertServerCloses(t, conn, 5*time.Second)
}

// The bounds production gets, and the two it deliberately does not: a ReadTimeout or
// WriteTimeout would cut a long-lived MCP response mid-stream.
func TestServer_DefaultConnectionBounds(t *testing.T) {
	cert := relaytest.SelfSignedServerCert(t, "controlplane-defaults-test")
	srv := New(Config{Addr: "127.0.0.1:0", GetCertificate: staticCert(cert)}, testAuthenticator())

	if got := srv.http.ReadHeaderTimeout; got != DefaultReadHeaderTimeout {
		t.Errorf("ReadHeaderTimeout = %v, want %v", got, DefaultReadHeaderTimeout)
	}
	if got := srv.http.IdleTimeout; got != DefaultIdleTimeout {
		t.Errorf("IdleTimeout = %v, want %v", got, DefaultIdleTimeout)
	}
	if srv.http.ReadTimeout != 0 || srv.http.WriteTimeout != 0 {
		t.Errorf("ReadTimeout = %v, WriteTimeout = %v; want both 0 so streamed responses are not cut",
			srv.http.ReadTimeout, srv.http.WriteTimeout)
	}
}
