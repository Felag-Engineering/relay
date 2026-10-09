package main

// Regression test for GO-2026-6443: a gRPC server panic on a request carrying
// neither :authority nor Host. The advisory is a false positive for the Relay
// (analysis on #263) because grpc's HTTP/2 transport rejects such a stream with
// an HTTP 400 before any tap, interceptor or handler runs. Nothing else pins
// that, and it matters here: the node-plane listener accepts certless TLS for
// Enroll (VerifyClientCertIfGiven, ADR-0006/0031), so any peer can send that
// frame. A grpc bump that regressed the check, or a move to ServeHTTP or xDS,
// would otherwise go unnoticed.
//
// The test is deliberately coupled to the grpc version: if a future grpc
// answers with RST_STREAM instead of a 400 (gRFC A41 permits it), this fails
// and wants a human look, not a silent update.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	relayv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

// dialRawH2 opens a certless TLS connection offering ALPN h2, writes the HTTP/2
// client preface and SETTINGS, and acks the server's SETTINGS so that frame
// ordering later in the test does not depend on timing.
func dialRawH2(t *testing.T, addr string, roots *x509.CertPool) (*tls.Conn, *http2.Framer) {
	t.Helper()

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs:    roots,
		ServerName: "localhost",
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck

	state := conn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		t.Fatalf("negotiated protocol = %q, want h2", state.NegotiatedProtocol)
	}
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no server certificate: TLS did not authenticate the server")
	}
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatalf("write client preface: %v", err)
	}
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := fr.WriteSettings(); err != nil {
		t.Fatalf("write SETTINGS: %v", err)
	}

	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("waiting for server SETTINGS: %v", err)
		}
		if s, ok := f.(*http2.SettingsFrame); ok && !s.IsAck() {
			if err := fr.WriteSettingsAck(); err != nil {
				t.Fatalf("write SETTINGS ack: %v", err)
			}
			return conn, fr
		}
	}
}

// writeGRPCHeaders sends a single HEADERS frame (END_HEADERS, END_STREAM) for
// an Enroll call. :authority is emitted only when authority is non-empty, and
// Host never is.
func writeGRPCHeaders(t *testing.T, fr *http2.Framer, streamID uint32, authority string) {
	t.Helper()

	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	fields := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: relayv1.Enrollment_Enroll_FullMethodName},
	}
	if authority != "" {
		fields = append(fields, hpack.HeaderField{Name: ":authority", Value: authority})
	}
	fields = append(fields,
		hpack.HeaderField{Name: "content-type", Value: "application/grpc"},
		hpack.HeaderField{Name: "te", Value: "trailers"},
	)
	for _, f := range fields {
		if err := enc.WriteField(f); err != nil {
			t.Fatalf("hpack encode %s: %v", f.Name, err)
		}
	}
	err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: buf.Bytes(),
		EndHeaders:    true,
		EndStream:     true,
	})
	if err != nil {
		t.Fatalf("write HEADERS: %v", err)
	}
}

// readResponseHeaders returns the first HEADERS block for streamID. A read
// error, which includes the deadline, means the server stopped answering.
func readResponseHeaders(t *testing.T, fr *http2.Framer, streamID uint32) map[string]string {
	t.Helper()

	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("read frame for stream %d: %v", streamID, err)
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				if err := fr.WriteSettingsAck(); err != nil {
					t.Fatalf("write SETTINGS ack: %v", err)
				}
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				if err := fr.WritePing(true, f.Data); err != nil {
					t.Fatalf("write PING ack: %v", err)
				}
			}
		case *http2.GoAwayFrame:
			t.Fatalf("server sent GOAWAY (%v, %q) while waiting for stream %d", f.ErrCode, f.DebugData(), streamID)
		case *http2.RSTStreamFrame:
			if f.StreamID == streamID {
				t.Fatalf("stream %d reset (%v) before response headers", streamID, f.ErrCode)
			}
		case *http2.MetaHeadersFrame:
			if f.StreamID != streamID {
				continue
			}
			h := make(map[string]string, len(f.Fields))
			for _, hf := range f.Fields {
				h[hf.Name] = hf.Value
			}
			return h
		}
	}
}

// checkEarlyAbort reports whether h is grpc's rejection of a stream for lacking
// :authority/Host: HTTP 400, grpc-status Internal, and the message naming the
// authority. Matching the message keeps another early abort (a malformed
// grpc-timeout, say) from satisfying it.
func checkEarlyAbort(h map[string]string) error {
	if h[":status"] != "400" {
		return fmt.Errorf(":status = %q, want 400", h[":status"])
	}
	if want := fmt.Sprint(int(codes.Internal)); h["grpc-status"] != want {
		return fmt.Errorf("grpc-status = %q, want %s", h["grpc-status"], want)
	}
	if !strings.Contains(h["grpc-message"], "authority") {
		return fmt.Errorf("grpc-message = %q, want it to mention the authority", h["grpc-message"])
	}
	return nil
}

func TestNodePlane_MissingAuthorityRejectedEarly_RelayStaysUp(t *testing.T) {
	f := startRelay(t, WithTCPNodePlane())
	roots := relaytest.CertPool(t, f.Deps.ca.Bundle())

	_, fr := dialRawH2(t, f.NodeAddr, roots)

	// Neither :authority nor Host: rejected at the transport with a 400.
	writeGRPCHeaders(t, fr, 1, "")
	rejected := readResponseHeaders(t, fr, 1)
	if err := checkEarlyAbort(rejected); err != nil {
		t.Fatalf("stream without :authority: %v (headers %v)", err, rejected)
	}

	// The same connection survives, and the same request with :authority is
	// accepted and reaches the real Enroll path (Trailers-Only, :status 200,
	// because there is no request message). A server that accepts the stream —
	// what a regressed authority check would do with stream 1 — fails
	// checkEarlyAbort; this is the simulation the issue's second criterion asks
	// for, without forking grpc.
	writeGRPCHeaders(t, fr, 3, "localhost")
	accepted := readResponseHeaders(t, fr, 3)
	if accepted[":status"] != "200" {
		t.Errorf("stream with :authority: :status = %q, want 200 (headers %v)", accepted[":status"], accepted)
	}
	if checkEarlyAbort(accepted) == nil {
		t.Errorf("checkEarlyAbort accepted a stream the server accepted (headers %v)", accepted)
	}

	// The Relay still serves a normal certless RPC on a fresh connection.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, plaintext, err := f.Deps.tokens.Create(ctx, []string{"relay:env=test"}, time.Hour)
	if err != nil {
		t.Fatalf("seed Enrollment Token: %v", err)
	}
	cc, err := grpc.NewClient(f.NodeAddr, grpc.WithTransportCredentials(
		credentials.NewTLS(&tls.Config{RootCAs: roots, ServerName: "localhost"})))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { cc.Close() }) //nolint:errcheck

	csrPEM, _ := relaytest.NewCSR(t, "ignored-cn")
	resp, err := relayv1.NewEnrollmentClient(cc).Enroll(ctx, &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             csrPEM,
		Facts:           &relayv1.Facts{Hostname: "host-944", Os: "linux"},
	})
	if err != nil {
		t.Fatalf("Enroll after the rejected request: code %v: %v", status.Code(err), err)
	}
	if resp.GetNodeId() == "" {
		t.Error("Enroll: node_id is empty")
	}
}
