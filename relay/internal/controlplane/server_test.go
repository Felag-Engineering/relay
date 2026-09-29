package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

// staticCert presents a fixed certificate through Config.GetCertificate.
// Production hands that field *ca.ServerCertificate's method, which re-issues
// the leaf before it expires (#403); a fixed one is all these tests need.
func staticCert(cert tls.Certificate) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }
}

// newTestServer starts a Server on an OS-assigned port and returns it, its
// base URL, and a client trusting its self-signed leaf.
func newTestServer(t *testing.T) (*Server, string, *http.Client) {
	t.Helper()

	cert := relaytest.SelfSignedServerCert(t, "controlplane-test")
	srv := New(Config{Addr: "127.0.0.1:0", GetCertificate: staticCert(cert)}, testAuthenticator())

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	go func() {
		_ = srv.Serve(lis)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}

	return srv, "https://" + lis.Addr().String(), client
}

func doRequest(t *testing.T, client *http.Client, method, url, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do %s %s: %v", method, url, err)
	}
	return resp
}

func TestServer_Ping_RequiresCredential(t *testing.T) {
	_, base, client := newTestServer(t)

	resp := doRequest(t, client, http.MethodGet, base+"/api/v1/ping", "")
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without credential: status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	respWrong := doRequest(t, client, http.MethodGet, base+"/api/v1/ping", "wrong-"+testToken)
	defer respWrong.Body.Close() //nolint:errcheck
	if respWrong.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong credential: status = %d, want %d", respWrong.StatusCode, http.StatusUnauthorized)
	}

	respOK := doRequest(t, client, http.MethodGet, base+"/api/v1/ping", testToken)
	defer respOK.Body.Close() //nolint:errcheck
	if respOK.StatusCode != http.StatusOK {
		t.Fatalf("with credential: status = %d, want %d", respOK.StatusCode, http.StatusOK)
	}
	body, _ := io.ReadAll(respOK.Body)
	if string(body) != `{"status":"ok"}`+"\n" {
		t.Errorf("body = %q, want ping ok payload", body)
	}
}

// TestServer_CertificateIsFetchedEveryHandshake is the control plane's half of
// the #403 guard: the Console and Control API listener must ask for its
// certificate per handshake, not hold one captured at startup. It rides the
// same Relay CA as the node plane, so a captured certificate here expires on
// the same timer and locks every operator out of the browser.
func TestServer_CertificateIsFetchedEveryHandshake(t *testing.T) {
	first, rotated := relaytest.SelfSignedServerCert(t, "controlplane-test"), relaytest.SelfSignedServerCert(t, "controlplane-test")

	var calls atomic.Int64
	srv := New(Config{
		Addr: "127.0.0.1:0",
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			if calls.Add(1) == 1 {
				return &first, nil
			}
			return &rotated, nil
		},
	}, testAuthenticator())

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() {
		_ = srv.Serve(lis)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	// Trust both leaves, so the assertion is about WHICH was served rather
	// than about verification succeeding.
	pool := x509.NewCertPool()
	for _, c := range []tls.Certificate{first, rotated} {
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			t.Fatalf("ParseCertificate: %v", err)
		}
		pool.AddCert(leaf)
	}

	// A fresh connection per request: a reused one never handshakes again.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
			DisableKeepAlives: true,
		},
	}
	base := "https://" + lis.Addr().String()

	served := make([][]byte, 0, 2)
	for range 2 {
		resp := doRequest(t, client, http.MethodGet, base+"/api/v1/ping", testToken)
		if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
			t.Fatal("response carried no peer certificate")
		}
		served = append(served, resp.TLS.PeerCertificates[0].Raw)
		resp.Body.Close() //nolint:errcheck
	}

	if n := calls.Load(); n != 2 {
		t.Fatalf("certificate fetched %d times over 2 handshakes, want 2 (a static certificate was captured)", n)
	}
	if bytes.Equal(served[0], served[1]) {
		t.Fatal("second handshake served the first certificate; the rotated leaf never reached the wire")
	}
	if !bytes.Equal(served[1], rotated.Certificate[0]) {
		t.Error("second handshake did not serve the rotated leaf")
	}
}

// TestServer_IndependentShutdown proves two Servers are independently lived:
// shutting one down leaves the other serving. This mirrors the real Relay's
// separate node-plane/control-plane listeners.
func TestServer_IndependentShutdown(t *testing.T) {
	srvA, baseA, clientA := newTestServer(t)
	_, baseB, clientB := newTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srvA.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown srvA: %v", err)
	}

	// srvA is down: requests must fail (connection refused/reset), not succeed.
	req, _ := http.NewRequest(http.MethodGet, baseA+"/api/v1/ping", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	if _, err := clientA.Do(req); err == nil {
		t.Fatal("expected request to shut-down server A to fail")
	}

	// srvB is untouched by srvA's shutdown.
	respB := doRequest(t, clientB, http.MethodGet, baseB+"/api/v1/ping", testToken)
	defer respB.Body.Close() //nolint:errcheck
	if respB.StatusCode != http.StatusOK {
		t.Fatalf("server B after server A shutdown: status = %d, want %d", respB.StatusCode, http.StatusOK)
	}
}
