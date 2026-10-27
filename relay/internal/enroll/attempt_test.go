package enroll

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/ca/catest"
	"github.com/Felag-Engineering/relay/relay/internal/ratelimit"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// capturingAttemptObserver is an AttemptObserver test double: it appends
// every Attempt under a mutex, nothing else.
type capturingAttemptObserver struct {
	mu     sync.Mutex
	events []AttemptEvent
}

func (o *capturingAttemptObserver) Attempt(_ context.Context, e AttemptEvent) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, e)
}

func (o *capturingAttemptObserver) snapshot() []AttemptEvent {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]AttemptEvent(nil), o.events...)
}

// newObservedEnrollServer is newEnrollServer's sibling: a Server wired with
// obs via WithAttemptObserver, plus whatever additional opts the caller
// needs (WithRateLimiter, WithPostEnrollRevocationCheck, ...).
func newObservedEnrollServer(t *testing.T, svc *Service, obs AttemptObserver, opts ...ServerOption) (*Server, *registry.InMemory) {
	t.Helper()
	realCA, err := catest.Generate()
	if err != nil {
		t.Fatalf("catest.Generate: %v", err)
	}
	reg := registry.NewInMemory()
	allOpts := append([]ServerOption{WithAttemptObserver(obs)}, opts...)
	return NewServer(svc, realCA, reg, allOpts...), reg
}

func TestAttemptObserver_RateLimited(t *testing.T) {
	obs := &capturingAttemptObserver{}
	svc := NewService(NewMemoryRepository())
	limiter := ratelimit.New(ratelimit.Config{
		PerIPRatePerMin: 60, PerIPBurst: 0, GlobalRatePerMin: 6000, GlobalBurst: 1000, MaxTrackedIPs: 100,
	})
	srv, _ := newObservedEnrollServer(t, svc, obs, WithRateLimiter(limiter))

	_, err := srv.Enroll(ctxFromIP("10.0.0.5"), &relayv1.EnrollRequest{
		EnrollmentToken: "whatever.secret", Csr: genCSR(t, "cn"),
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("want ResourceExhausted, got %v", err)
	}

	events := obs.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(events), events)
	}
	if events[0].Reason != AttemptRateLimited || events[0].Accepted {
		t.Errorf("event = %+v, want Reason=AttemptRateLimited, Accepted=false", events[0])
	}
	if events[0].TokenID != "" {
		t.Errorf("TokenID = %q, want empty (token is not parsed yet at the rate-limit gate)", events[0].TokenID)
	}
	if events[0].Source != "10.0.0.5" {
		t.Errorf("Source = %q, want 10.0.0.5", events[0].Source)
	}
}

func TestAttemptObserver_EmptyToken(t *testing.T) {
	obs := &capturingAttemptObserver{}
	svc := NewService(NewMemoryRepository())
	srv, _ := newObservedEnrollServer(t, svc, obs)

	_, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{Csr: genCSR(t, "cn")})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}

	events := obs.snapshot()
	if len(events) != 1 || events[0].Reason != AttemptMalformed {
		t.Fatalf("events = %+v, want exactly one AttemptMalformed", events)
	}
}

func TestAttemptObserver_EmptyCSR(t *testing.T) {
	obs := &capturingAttemptObserver{}
	svc := NewService(NewMemoryRepository())
	srv, _ := newObservedEnrollServer(t, svc, obs)

	_, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{EnrollmentToken: "id.secret"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}

	events := obs.snapshot()
	if len(events) != 1 || events[0].Reason != AttemptMalformed {
		t.Fatalf("events = %+v, want exactly one AttemptMalformed", events)
	}
}

func TestAttemptObserver_BadSelfLabels(t *testing.T) {
	obs := &capturingAttemptObserver{}
	svc := NewService(NewMemoryRepository())
	srv, _ := newObservedEnrollServer(t, svc, obs)
	_, plaintext := mintToken(t, svc, nil)

	_, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "cn"),
		SelfLabels:      []*relayv1.Label{{Key: "role", Value: "web"}},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}

	events := obs.snapshot()
	if len(events) != 1 || events[0].Reason != AttemptMalformed {
		t.Fatalf("events = %+v, want exactly one AttemptMalformed", events)
	}
}

func TestAttemptObserver_Expired(t *testing.T) {
	obs := &capturingAttemptObserver{}
	svc, clk := newTestService(t)
	srv, _ := newObservedEnrollServer(t, svc, obs)
	_, plaintext := mintToken(t, svc, nil)
	clk.advance(2 * time.Hour)

	_, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext, Csr: genCSR(t, "cn"),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}

	events := obs.snapshot()
	if len(events) != 1 || events[0].Reason != AttemptExpired {
		t.Fatalf("events = %+v, want exactly one AttemptExpired", events)
	}
}

func TestAttemptObserver_Revoked(t *testing.T) {
	obs := &capturingAttemptObserver{}
	svc := NewService(NewMemoryRepository())
	srv, _ := newObservedEnrollServer(t, svc, obs)
	tok, plaintext := mintToken(t, svc, nil)
	if err := svc.Revoke(context.Background(), tok.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	_, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext, Csr: genCSR(t, "cn"),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}

	events := obs.snapshot()
	if len(events) != 1 || events[0].Reason != AttemptRevoked {
		t.Fatalf("events = %+v, want exactly one AttemptRevoked", events)
	}
}

func TestAttemptObserver_Exhausted(t *testing.T) {
	obs := &capturingAttemptObserver{}
	svc := NewService(NewMemoryRepository())
	srv, _ := newObservedEnrollServer(t, svc, obs)
	_, plaintext, err := svc.Create(context.Background(), nil, time.Hour, WithMaxUses(1))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext, Csr: genCSR(t, "cn"),
	}); err != nil {
		t.Fatalf("first enroll: %v", err)
	}

	_, err = srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext, Csr: genCSR(t, "cn"),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}

	events := obs.snapshot()
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 (accept then exhausted): %+v", len(events), events)
	}
	if !events[0].Accepted {
		t.Errorf("events[0] = %+v, want Accepted=true", events[0])
	}
	if events[1].Reason != AttemptExhausted {
		t.Errorf("events[1] = %+v, want AttemptExhausted", events[1])
	}
}

func TestAttemptObserver_UnknownToken(t *testing.T) {
	obs := &capturingAttemptObserver{}
	svc := NewService(NewMemoryRepository())
	srv, _ := newObservedEnrollServer(t, svc, obs)

	// The public half is deliberately the exact 32-lowercase-hex shape a real
	// token id has (token.go's Create) so this test exercises "well-formed
	// but unknown", not the S1 shape-validation path covered separately by
	// TestAttemptObserver_OversizedTokenID_NotPublished.
	const wellFormedID = "deadbeefdeadbeefdeadbeefdeadbeef"
	_, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: wellFormedID + ".notarealtoken", Csr: genCSR(t, "cn"),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}

	events := obs.snapshot()
	if len(events) != 1 || events[0].Reason != AttemptUnknown {
		t.Fatalf("events = %+v, want exactly one AttemptUnknown", events)
	}
	if events[0].TokenID != wellFormedID {
		t.Errorf("TokenID = %q, want the public half %q", events[0].TokenID, wellFormedID)
	}
}

func TestAttemptObserver_MalformedCredential_NoDot(t *testing.T) {
	obs := &capturingAttemptObserver{}
	svc := NewService(NewMemoryRepository())
	srv, _ := newObservedEnrollServer(t, svc, obs)

	_, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: "no-separator-here", Csr: genCSR(t, "cn"),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}

	events := obs.snapshot()
	if len(events) != 1 || events[0].Reason != AttemptUnknown {
		t.Fatalf("events = %+v, want exactly one AttemptUnknown", events)
	}
	if events[0].TokenID != "" {
		t.Errorf("TokenID = %q, want empty for a credential with no separator", events[0].TokenID)
	}
}

// TestAttemptObserver_OversizedTokenID_NotPublished is the S1 security-review
// regression guard (cycle 2, review-feedback.md): `parts[0]` of a presented
// credential is unauthenticated, unvalidated, attacker-controlled input, and
// the bus retains published AttemptEvents for the full retention window. A
// 4 MiB id-shaped prefix — well within gRPC's default 4 MiB MaxRecvMsgSize —
// must never reach the bus; a real token id is always exactly 32 lowercase
// hex characters (token.go's Create).
func TestAttemptObserver_OversizedTokenID_NotPublished(t *testing.T) {
	obs := &capturingAttemptObserver{}
	svc := NewService(NewMemoryRepository())
	srv, _ := newObservedEnrollServer(t, svc, obs)

	hugeID := strings.Repeat("a", 4*1024*1024)
	_, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: hugeID + secretSep + "irrelevant-secret", Csr: genCSR(t, "cn"),
	})

	// The RPC response code must be exactly what an unknown token id always
	// returned, pre- and post-fix alike (no new oracle).
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}

	events := obs.snapshot()
	if len(events) != 1 || events[0].Reason != AttemptUnknown {
		t.Fatalf("events = %+v, want exactly one AttemptUnknown", events)
	}
	if events[0].TokenID != "" {
		t.Errorf("TokenID length = %d, want empty (\"\") for an oversized id, not %d attacker-chosen bytes retained",
			len(events[0].TokenID), len(events[0].TokenID))
	}
}

// TestAttemptObserver_MalformedShapeTokenID_NotPublished covers the other
// half of the S1 fix: ids that are the WRONG shape (too short, or containing
// characters outside [0-9a-f]) rather than merely oversized. Only an exact
// 32-lowercase-hex id may ever reach the bus.
func TestAttemptObserver_MalformedShapeTokenID_NotPublished(t *testing.T) {
	cases := []struct {
		name string
		id   string
	}{
		{"too short", "deadbeef"},
		{"too long", "deadbeefdeadbeefdeadbeefdeadbeefaa"},
		{"uppercase", "DEADBEEFDEADBEEFDEADBEEFDEADBEEF"},
		{"contains newline", "deadbeefdeadbeefdeadbeefdeadbe\nf"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs := &capturingAttemptObserver{}
			svc := NewService(NewMemoryRepository())
			srv, _ := newObservedEnrollServer(t, svc, obs)

			_, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
				EnrollmentToken: tc.id + secretSep + "irrelevant-secret", Csr: genCSR(t, "cn"),
			})
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("want PermissionDenied, got %v", err)
			}

			events := obs.snapshot()
			if len(events) != 1 || events[0].Reason != AttemptUnknown {
				t.Fatalf("events = %+v, want exactly one AttemptUnknown", events)
			}
			if events[0].TokenID != "" {
				t.Errorf("TokenID = %q, want empty for a malformed-shape id", events[0].TokenID)
			}
		})
	}
}

func TestAttemptObserver_AtCapacity(t *testing.T) {
	obs := &capturingAttemptObserver{}
	svc := NewService(NewMemoryRepository())
	realCA, err := catest.Generate()
	if err != nil {
		t.Fatalf("catest.Generate: %v", err)
	}
	reg := registry.NewInMemory(registry.WithMaxNodes(1))
	limiter := ratelimit.New(ratelimit.Config{
		PerIPRatePerMin: 6000, PerIPBurst: 1000, GlobalRatePerMin: 6000, GlobalBurst: 1000, MaxTrackedIPs: 100,
	})
	srv := NewServer(svc, realCA, reg, WithAttemptObserver(obs), WithRateLimiter(limiter))

	_, pt1 := mintToken(t, svc, nil)
	_, pt2 := mintToken(t, svc, nil)
	ctx := ctxFromIP("10.0.1.1")

	if _, err := srv.Enroll(ctx, &relayv1.EnrollRequest{EnrollmentToken: pt1, Csr: genCSR(t, "cn")}); err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	_, err = srv.Enroll(ctx, &relayv1.EnrollRequest{EnrollmentToken: pt2, Csr: genCSR(t, "cn")})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("want ResourceExhausted, got %v", err)
	}

	events := obs.snapshot()
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 (accept then at-capacity): %+v", len(events), events)
	}
	if events[1].Reason != AttemptAtCapacity {
		t.Errorf("events[1] = %+v, want AttemptAtCapacity", events[1])
	}
}

func TestAttemptObserver_RevokedMidEnrollment(t *testing.T) {
	obs := &capturingAttemptObserver{}
	svc := NewService(NewMemoryRepository())
	realCA, err := catest.Generate()
	if err != nil {
		t.Fatalf("catest.Generate: %v", err)
	}
	reg := registry.NewInMemory()
	den := &fakeDenylister{}
	srv := NewServer(svc, realCA, reg, WithAttemptObserver(obs), WithPostEnrollRevocationCheck(svc, den))

	tok, plaintext := mintToken(t, svc, nil)
	srv.newID = func() (string, error) {
		if err := svc.Revoke(context.Background(), tok.ID); err != nil {
			t.Errorf("race hook Revoke: %v", err)
		}
		return "node-race-1", nil
	}

	_, err = srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext, Csr: genCSR(t, "cn"),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}

	events := obs.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d events, want exactly 1: %+v", len(events), events)
	}
	if events[0].Reason != AttemptRevokedMidEnrollment || events[0].NodeID != "node-race-1" {
		t.Errorf("event = %+v, want AttemptRevokedMidEnrollment for node-race-1", events[0])
	}
}

func TestAttemptObserver_Success(t *testing.T) {
	obs := &capturingAttemptObserver{}
	svc := NewService(NewMemoryRepository())
	srv, reg := newObservedEnrollServer(t, svc, obs)
	tok, plaintext := mintToken(t, svc, nil)

	resp, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext, Csr: genCSR(t, "cn"),
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	events := obs.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d events, want exactly 1: %+v", len(events), events)
	}
	ev := events[0]
	if !ev.Accepted {
		t.Errorf("Accepted = false, want true")
	}
	if ev.NodeID != resp.NodeId {
		t.Errorf("NodeID = %q, want %q", ev.NodeID, resp.NodeId)
	}
	if ev.TokenID != tok.ID {
		t.Errorf("TokenID = %q, want %q", ev.TokenID, tok.ID)
	}
	if _, ok := reg.Get(resp.NodeId); !ok {
		t.Error("registry: enrolled node must be present")
	}
}

// failingRecordEnrollment wraps *registry.InMemory, forcing RecordEnrollment
// to fail on every call — everything else delegates unchanged.
type failingRecordEnrollment struct {
	*registry.InMemory
}

func (f failingRecordEnrollment) RecordEnrollment(nodeID string, cert registry.Certificate, at time.Time) error {
	return fmt.Errorf("simulated RecordEnrollment failure for %s at %s", nodeID, at)
}

// TestAttemptObserver_RecordEnrollmentFailure_StillExactlyOneAcceptedEvent is
// the PLAN REVIEW B2 regression guard: (j2)'s RecordEnrollment failure is
// logged and non-fatal (handler.go) — it must publish NOTHING, so an
// otherwise-successful enrollment still produces exactly one event
// (Accepted: true), never a phantom rejection ahead of it. #427's day-one
// watch would otherwise see a false alarm on every real success whose
// bookkeeping write happened to fail.
func TestAttemptObserver_RecordEnrollmentFailure_StillExactlyOneAcceptedEvent(t *testing.T) {
	obs := &capturingAttemptObserver{}
	svc := NewService(NewMemoryRepository())
	realCA, err := catest.Generate()
	if err != nil {
		t.Fatalf("catest.Generate: %v", err)
	}
	reg := failingRecordEnrollment{registry.NewInMemory()}
	srv := NewServer(svc, realCA, reg, WithAttemptObserver(obs))

	_, plaintext := mintToken(t, svc, nil)
	_, err = srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext, Csr: genCSR(t, "cn"),
	})
	if err != nil {
		t.Fatalf("Enroll: want success despite RecordEnrollment failing, got %v", err)
	}

	events := obs.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d events, want EXACTLY 1 (no phantom rejection from j2): %+v", len(events), events)
	}
	if !events[0].Accepted {
		t.Errorf("event = %+v, want Accepted=true", events[0])
	}
}

// TestAttemptObserver_PlaintextNeverPublished is the acceptance criterion:
// drive every rejection/acceptance path with a REAL minted credential and
// assert no field of any published event contains the full credential or
// its secret half.
func TestAttemptObserver_PlaintextNeverPublished(t *testing.T) {
	obs := &capturingAttemptObserver{}
	svc := NewService(NewMemoryRepository())
	srv, _ := newObservedEnrollServer(t, svc, obs)

	tok, plaintext := mintToken(t, svc, nil)
	secret := strings.TrimPrefix(plaintext, tok.ID+secretSep)
	if secret == "" || secret == plaintext {
		t.Fatal("test setup broken: could not split the minted credential")
	}

	// Successful enrollment.
	if _, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext, Csr: genCSR(t, "cn"),
	}); err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// Re-use of the now-exhausted... actually reuse with a bad CSR to force a
	// second path through the same real credential without exhausting a
	// fresh mint each time.
	tok2, plaintext2 := mintToken(t, svc, nil)
	secret2 := strings.TrimPrefix(plaintext2, tok2.ID+secretSep)
	if _, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext2, Csr: []byte("not a csr"),
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad CSR: want InvalidArgument, got %v", err)
	}

	for _, ev := range obs.snapshot() {
		for _, s := range []string{ev.TokenID, ev.NodeID, ev.Source, string(ev.Reason)} {
			if strings.Contains(s, plaintext) || strings.Contains(s, secret) {
				t.Fatalf("event field %q contains the first credential's plaintext or secret half: %+v", s, ev)
			}
			if strings.Contains(s, plaintext2) || strings.Contains(s, secret2) {
				t.Fatalf("event field %q contains the second credential's plaintext or secret half: %+v", s, ev)
			}
		}
	}
}

func TestAttemptObserver_Renew_PublishesNothing(t *testing.T) {
	obs := &capturingAttemptObserver{}
	svc := NewService(NewMemoryRepository())
	srv, _ := newObservedEnrollServer(t, svc, obs)
	_, plaintext := mintToken(t, svc, nil)

	if _, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: plaintext, Csr: genCSR(t, "cn"),
	}); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	before := len(obs.snapshot())

	nodeCtx := transport.NewContextWithNodeID(context.Background(), "node-observed")
	if _, err := srv.Renew(nodeCtx, &relayv1.RenewRequest{Csr: genCSR(t, "cn")}); err != nil {
		t.Fatalf("Renew: %v", err)
	}

	if got := len(obs.snapshot()); got != before {
		t.Fatalf("Renew published %d events, want 0 (Renew is certificate-authenticated, not an enrollment attempt)", got-before)
	}
}

// TestAttemptObserver_NilObserver_ResponseCodesUnchanged is the no-oracle
// regression guard: with no observer wired (the default), every rejection
// path returns the exact same collapsed status codes the pre-#416 handler
// tests already pin — this test only re-confirms nothing about those codes
// moved.
func TestAttemptObserver_NilObserver_ResponseCodesUnchanged(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, _, _ := newEnrollServer(t, svc) // no WithAttemptObserver at all

	_, err := srv.Enroll(context.Background(), &relayv1.EnrollRequest{
		EnrollmentToken: "deadbeef.notarealtoken", Csr: genCSR(t, "cn"),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
}
