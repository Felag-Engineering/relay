package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/Felag-Engineering/relay/relay/internal/ca"
	"github.com/Felag-Engineering/relay/relay/internal/metrics"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// fakeInterfaces returns an interfaceAddrs func reporting addrs, each either
// CIDR notation (an *net.IPNet carrying a 16-byte IP, as the OS reports) or a
// bare address (an *net.IPAddr).
func fakeInterfaces(t *testing.T, addrs ...string) func() ([]net.Addr, error) {
	t.Helper()
	var out []net.Addr
	for _, a := range addrs {
		if strings.Contains(a, "/") {
			ip, ipNet, err := net.ParseCIDR(a)
			if err != nil {
				t.Fatalf("parse %q: %v", a, err)
			}
			out = append(out, &net.IPNet{IP: ip, Mask: ipNet.Mask})
			continue
		}
		ip := net.ParseIP(a)
		if ip == nil {
			t.Fatalf("parse %q", a)
		}
		out = append(out, &net.IPAddr{IP: ip})
	}
	return func() ([]net.Addr, error) { return out, nil }
}

// detectedIPv4s is every IPv4 address this host reports that the certificate is
// expected to name. IPv4 only: IPv6 privacy addresses can change between two
// reads of the interfaces, IPv4 addresses do not.
func detectedIPv4s(t *testing.T) []net.IP {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Logf("list interface addresses: %v", err)
		return nil
	}
	var out []net.IP
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP.To4() == nil || !usableDetectedAddress(ipNet.IP) {
			continue
		}
		out = append(out, ipNet.IP.To4())
	}
	return out
}

func TestServerCertificateNames(t *testing.T) {
	loopback := []string{"127.0.0.1", "::1"}

	manyV4 := make([]string, 0, 70)
	for i := 0; i < 70; i++ {
		manyV4 = append(manyV4, fmt.Sprintf("10.0.%d.%d/24", i/200, i%200+1))
	}
	// IPv6 first in the input: the cap must still drop IPv6 before IPv4.
	capInput := append([]string{"2001:db8::1/64", "2001:db8::2/64", "2001:db8::3/64"}, manyV4...)

	tests := []struct {
		name       string
		hostname   string
		interfaces []string
		wantDNS    []string
		wantIPs    []string
		omitted    int
	}{
		{
			name:     "a DNS hostname is a DNS name",
			hostname: "relay.example.internal",
			wantDNS:  []string{"relay.example.internal"},
			wantIPs:  loopback,
		},
		{
			name:       "an IPv4 hostname is an IP address, once",
			hostname:   "10.0.0.5",
			interfaces: []string{"10.0.0.5/24"},
			wantIPs:    append([]string{"10.0.0.5"}, loopback...),
		},
		{
			name:     "an IPv6 hostname is an IP address",
			hostname: "2001:db8::5",
			wantIPs:  append([]string{"2001:db8::5"}, loopback...),
		},
		{
			name:     "only usable unicast addresses are detected, IPv4 first",
			hostname: "relay.example.internal",
			interfaces: []string{
				"127.0.0.1/8", "127.0.0.2/8", "::1/128", "fe80::1/64", "169.254.3.4/16",
				"0.0.0.0", "224.0.0.1", "2001:db8::10/64", "192.0.2.10/24",
			},
			wantDNS: []string{"relay.example.internal"},
			wantIPs: append(slices.Clone(loopback), "192.0.2.10", "2001:db8::10"),
		},
		{
			name:       "past the cap the IPv6 addresses go first and the count is reported",
			hostname:   "relay.example.internal",
			interfaces: capInput,
			wantDNS:    []string{"relay.example.internal"},
			omitted:    73 - maxDetectedAddresses,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := serverCertificateNames(tt.hostname, fakeInterfaces(t, tt.interfaces...))
			if err != nil {
				t.Fatalf("serverCertificateNames: %v", err)
			}
			if !slices.Equal(got.DNSNames, tt.wantDNS) {
				t.Errorf("DNSNames = %v, want %v", got.DNSNames, tt.wantDNS)
			}
			if got.Omitted != tt.omitted {
				t.Errorf("Omitted = %d, want %d", got.Omitted, tt.omitted)
			}
			if tt.wantIPs == nil {
				return
			}
			if gotIPs := ipStrings(got.IPAddresses); !slices.Equal(gotIPs, tt.wantIPs) {
				t.Errorf("IPAddresses = %v, want %v", gotIPs, tt.wantIPs)
			}
		})
	}

	t.Run("the cap keeps the hostname, loopback and 64 detected IPv4 addresses", func(t *testing.T) {
		got, err := serverCertificateNames("relay.example.internal", fakeInterfaces(t, capInput...))
		if err != nil {
			t.Fatalf("serverCertificateNames: %v", err)
		}
		const loopbackNames = 2
		if len(got.IPAddresses) != loopbackNames+maxDetectedAddresses {
			t.Fatalf("%d IP addresses, want %d: %v", len(got.IPAddresses), loopbackNames+maxDetectedAddresses, ipStrings(got.IPAddresses))
		}
		if !got.IPAddresses[0].Equal(net.IPv4(127, 0, 0, 1)) || !got.IPAddresses[1].Equal(net.IPv6loopback) {
			t.Errorf("loopback is not first: %v", ipStrings(got.IPAddresses))
		}
		for _, ip := range got.IPAddresses[loopbackNames:] {
			if ip.To4() == nil {
				t.Errorf("detected %v is not IPv4; the cap must drop IPv6 first", ip)
			}
		}
	})

	t.Run("a failed listing still names the hostname and loopback", func(t *testing.T) {
		boom := errors.New("netlink refused")
		got, err := serverCertificateNames("relay.example.internal", func() ([]net.Addr, error) { return nil, boom })
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want it to wrap %v", err, boom)
		}
		if !slices.Equal(got.DNSNames, []string{"relay.example.internal"}) {
			t.Errorf("DNSNames = %v", got.DNSNames)
		}
		if gotIPs := ipStrings(got.IPAddresses); !slices.Equal(gotIPs, loopback) {
			t.Errorf("IPAddresses = %v, want %v", gotIPs, loopback)
		}
	})
}

// handshakeProbe is what one TLS handshake against a listener showed.
type handshakeProbe struct {
	// clientCertAsked is whether the server sent a CertificateRequest.
	clientCertAsked bool
	acceptableCAs   int
	leafDER         []byte
}

// probeHandshake completes a TLS handshake with addr, offering no client
// certificate, and reports whether the server asked for one.
func probeHandshake(t *testing.T, addr string, roots *x509.CertPool, serverName string, nextProtos ...string) handshakeProbe {
	t.Helper()
	var probe handshakeProbe
	cfg := &tls.Config{
		RootCAs:    roots,
		ServerName: serverName,
		NextProtos: nextProtos,
		MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			probe.clientCertAsked = true
			probe.acceptableCAs = len(info.AcceptableCAs)
			return &tls.Certificate{}, nil
		},
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		t.Fatalf("TLS handshake with %s: %v", addr, err)
	}
	defer conn.Close()
	probe.leafDER = conn.ConnectionState().PeerCertificates[0].Raw
	return probe
}

// Proves EN-9. Sharing the certificate between listeners (ADR-0031 §1) must
// never share ClientAuth: that is the failure this change newly makes possible.
func TestServerCertificate_OneLeafOnBothListenersOnlyTheNodePlaneAsksForAClientCert(t *testing.T) {
	f := startRelay(t, WithTCPNodePlane(), WithControlPlane())

	node := probeHandshake(t, f.NodeAddr, f.CertPool, "localhost", "h2")
	if !node.clientCertAsked {
		t.Error("the node plane did not ask for a client certificate")
	}
	if node.acceptableCAs == 0 {
		t.Error("the node plane's certificate request names no acceptable CA")
	}

	control := probeHandshake(t, strings.TrimPrefix(f.ControlBase, "https://"), f.CertPool, "localhost", "http/1.1")
	if control.clientCertAsked {
		t.Error("the control plane asked for a client certificate")
	}

	if !bytes.Equal(node.leafDER, control.leafDER) {
		t.Error("the two listeners present different certificates")
	}
	current, err := f.Deps.serverCert.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if !bytes.Equal(node.leafDER, current.Certificate[0]) {
		t.Error("the listeners do not present the held server certificate")
	}

	// A certless client still reaches only the certless Enroll: every other
	// node-plane RPC refuses it.
	cc, err := grpc.NewClient(f.NodeAddr, grpc.WithTransportCredentials(
		credentials.NewTLS(&tls.Config{RootCAs: f.CertPool, ServerName: "localhost"})))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { cc.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = relayv1.NewEnrollmentClient(cc).Renew(ctx, &relayv1.RenewRequest{})
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Errorf("certless Renew: code %v (%v), want Unauthenticated", code, err)
	}

	stream, err := relayv1.NewTunnelClient(cc).Open(ctx)
	if err == nil {
		_, err = stream.Recv()
	}
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Errorf("certless Tunnel.Open: code %v (%v), want Unauthenticated", code, err)
	}

	_, err = relayv1.NewEnrollmentClient(cc).Enroll(ctx, &relayv1.EnrollRequest{})
	if code := status.Code(err); code != codes.InvalidArgument {
		t.Errorf("certless Enroll: code %v (%v), want InvalidArgument from its handler", code, err)
	}
}

func TestServerCertificate_VerifiesByIPAddressWithNoName(t *testing.T) {
	t.Run("a DNS tls.hostname that does not resolve", func(t *testing.T) {
		f := startRelay(t, WithTCPNodePlane(), WithConfig(func(c *Config) { c.Hostname = "relay.invalid" }))
		roots := relaytest.CertPool(t, f.Deps.ca.Bundle())

		// No ServerName: Go verifies against the IP it dialled.
		conn, err := tls.Dial("tcp", f.NodeAddr, &tls.Config{RootCAs: roots, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS13})
		if err != nil {
			t.Fatalf("dial %s by address: %v", f.NodeAddr, err)
		}
		defer conn.Close()
		leaf := conn.ConnectionState().PeerCertificates[0]

		if !slices.Equal(leaf.DNSNames, []string{"relay.invalid"}) {
			t.Errorf("DNSNames = %v, want [relay.invalid]", leaf.DNSNames)
		}
		wantIPs := append([]net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, detectedIPv4s(t)...)
		if len(wantIPs)-2 > maxDetectedAddresses {
			wantIPs = wantIPs[:2]
		}
		for _, want := range wantIPs {
			if !slices.ContainsFunc(leaf.IPAddresses, want.Equal) {
				t.Errorf("certificate does not name %v; IPAddresses = %v", want, ipStrings(leaf.IPAddresses))
			}
		}
	})

	t.Run("an IP tls.hostname", func(t *testing.T) {
		f := startRelay(t, WithTCPNodePlane(), WithConfig(func(c *Config) { c.Hostname = "127.0.0.1" }))
		roots := relaytest.CertPool(t, f.Deps.ca.Bundle())

		conn, err := tls.Dial("tcp", f.NodeAddr, &tls.Config{RootCAs: roots, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS13})
		if err != nil {
			t.Fatalf("dial %s by address: %v", f.NodeAddr, err)
		}
		defer conn.Close()
		leaf := conn.ConnectionState().PeerCertificates[0]

		if len(leaf.DNSNames) != 0 {
			t.Errorf("DNSNames = %v, want none: an IP hostname is an IP SAN", leaf.DNSNames)
		}
		if len(leaf.IPAddresses) == 0 || !leaf.IPAddresses[0].Equal(net.IPv4(127, 0, 0, 1)) {
			t.Errorf("IPAddresses = %v, want 127.0.0.1 first", ipStrings(leaf.IPAddresses))
		}
	})
}

func TestNewServer_LogsTheCAAndTheServerCertificateUnderDistinctLabels(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.ControlEnabled = true
	cfg.ControlAddr = "127.0.0.1:0"

	var logBuf bytes.Buffer
	prevDefault := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logBuf, nil)))
	t.Cleanup(func() { slog.SetDefault(prevDefault) })

	srv, deps, err := newServer(cfg, testStartupFiles(t, cfg))
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	t.Cleanup(func() { deps.store.Close() })
	t.Cleanup(srv.Stop)

	type line struct {
		Msg                   string   `json:"msg"`
		CAFingerprint         string   `json:"ca_fingerprint"`
		ServerCertFingerprint string   `json:"server_cert_fingerprint"`
		DNSNames              []string `json:"dns_names"`
		IPAddresses           []string `json:"ip_addresses"`
	}
	var caLines, certLines []line
	for _, raw := range strings.Split(strings.TrimRight(logBuf.String(), "\n"), "\n") {
		var l line
		if err := json.Unmarshal([]byte(raw), &l); err != nil {
			continue
		}
		if l.CAFingerprint != "" && l.ServerCertFingerprint != "" {
			t.Errorf("one line carries both fingerprints: %s", raw)
		}
		switch l.Msg {
		case "relay certificate authority":
			caLines = append(caLines, l)
		case "relay server certificate":
			certLines = append(certLines, l)
		}
	}

	if len(caLines) != 1 {
		t.Fatalf("%d \"relay certificate authority\" lines, want 1", len(caLines))
	}
	if caLines[0].CAFingerprint != deps.ca.Fingerprint() {
		t.Errorf("ca_fingerprint = %q, want the CA's %q", caLines[0].CAFingerprint, deps.ca.Fingerprint())
	}

	// One certificate, not one per listener.
	if len(certLines) != 1 {
		t.Fatalf("%d \"relay server certificate\" lines, want 1", len(certLines))
	}
	got := certLines[0]
	if got.ServerCertFingerprint != deps.serverCert.Fingerprint() {
		t.Errorf("server_cert_fingerprint = %q, want the certificate's %q", got.ServerCertFingerprint, deps.serverCert.Fingerprint())
	}
	if got.ServerCertFingerprint == deps.ca.Fingerprint() {
		t.Error("the server certificate and the CA log the same fingerprint")
	}
	if !slices.Equal(got.DNSNames, []string{"localhost"}) {
		t.Errorf("dns_names = %v, want [localhost]", got.DNSNames)
	}

	// Compared with the leaf from the same issuance, never a second read of the
	// host's interfaces.
	current, err := deps.serverCert.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(current.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if want := ipStrings(leaf.IPAddresses); !slices.Equal(got.IPAddresses, want) {
		t.Errorf("ip_addresses = %v, want the certificate's %v", got.IPAddresses, want)
	}
}

func TestServerCertObserver_AdvancesEveryListenerThatPresentsIt(t *testing.T) {
	scrape := func(m *metrics.Metrics) string {
		rec := httptest.NewRecorder()
		m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
		return rec.Body.String()
	}
	const (
		node    = `relay_server_cert_rotations_total{listener="node_plane"} `
		control = `relay_server_cert_rotations_total{listener="control_plane"} `
	)
	rotated := ca.Rotation{NotAfter: time.Now().Add(24 * time.Hour), RenewAt: time.Now().Add(16 * time.Hour), Fingerprint: "ab12"}

	t.Run("both listeners", func(t *testing.T) {
		m := metrics.New(metrics.GaugeSources{})
		serverCertObserver(m, metrics.ListenerNodePlane, metrics.ListenerControlPlane)(rotated)
		out := scrape(m)
		for _, want := range []string{node + "1", control + "1"} {
			if !strings.Contains(out, want+"\n") {
				t.Errorf("metrics lack %q:\n%s", want, out)
			}
		}
	})

	t.Run("the node plane only", func(t *testing.T) {
		m := metrics.New(metrics.GaugeSources{})
		serverCertObserver(m, metrics.ListenerNodePlane)(rotated)
		out := scrape(m)
		for _, want := range []string{node + "1", control + "0"} {
			if !strings.Contains(out, want+"\n") {
				t.Errorf("metrics lack %q:\n%s", want, out)
			}
		}
	})

	t.Run("a failed re-issue moves neither", func(t *testing.T) {
		m := metrics.New(metrics.GaugeSources{})
		serverCertObserver(m, metrics.ListenerNodePlane, metrics.ListenerControlPlane)(ca.Rotation{Err: errors.New("sign failed")})
		out := scrape(m)
		for _, want := range []string{node + "0", control + "0"} {
			if !strings.Contains(out, want+"\n") {
				t.Errorf("metrics lack %q:\n%s", want, out)
			}
		}
	})
}
