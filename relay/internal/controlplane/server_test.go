package controlplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

// selfSignedCert mints a throwaway, self-signed TLS certificate for tests.
// Production wires a real Relay-CA-issued certificate (relay/cmd/relay/main.go).
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "controlplane-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return cert
}

// newTestServer starts a Server on an OS-assigned port and returns it, its
// base URL, and a client trusting its self-signed leaf.
func newTestServer(t *testing.T) (*Server, string, *http.Client) {
	t.Helper()

	cert := selfSignedCert(t)
	sum := sha256.Sum256([]byte(testToken))
	srv := New(Config{Addr: "127.0.0.1:0", TLSCert: cert}, NewAuthenticator(sum[:]))

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
