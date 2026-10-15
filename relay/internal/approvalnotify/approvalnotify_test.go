package approvalnotify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

var notifyNow = time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC)

func testNotice() capability.ApprovalNotice {
	return capability.ApprovalNotice{
		RequestID:   "req-1",
		PlanHash:    "hash-abc",
		Summary:     `service.restart(service="nginx") [mutate] on 12 node(s): node-a, node-b`,
		RequestedBy: "gleipnir-prod",
		Rules:       []string{"prod-mutates-need-two-people"},
		Progress:    "0 of 2",
		Count:       2,
		Channel:     "out-of-band",
		ExpiresAt:   notifyNow.Add(2 * time.Hour),
	}
}

// quietLogger keeps a delivery-failure warning out of the test output.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// received is one captured delivery.
type received struct {
	body      []byte
	signature string
	timestamp string
	event     string
}

// notifyServer returns a server capturing exactly one delivery, and a channel
// that yields it.
func notifyServer(t *testing.T, status int) (*httptest.Server, <-chan received) {
	t.Helper()
	ch := make(chan received, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ch <- received{
			body:      body,
			signature: r.Header.Get(HeaderSignature),
			timestamp: r.Header.Get(HeaderTimestamp),
			event:     r.Header.Get(HeaderEvent),
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, ch
}

func await(t *testing.T, ch <-chan received) received {
	t.Helper()
	select {
	case got := <-ch:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("no delivery within 5s")
		return received{}
	}
}

// TestDeliversTheRelayAuthoredNotice: the body carries what an approver needs
// to act, and the path to the one place they can answer.
func TestDeliversTheRelayAuthoredNotice(t *testing.T) {
	srv, ch := notifyServer(t, http.StatusOK)
	n, err := New(Config{URL: srv.URL}, WithHTTPClient(srv.Client()), WithLogger(quietLogger()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	n.NotifyParked(context.Background(), testNotice())
	got := await(t, ch)

	if got.event != EventApprovalRequested {
		t.Errorf("%s = %q, want %q", HeaderEvent, got.event, EventApprovalRequested)
	}
	var body payload
	if err := json.Unmarshal(got.body, &body); err != nil {
		t.Fatalf("decode body: %v; raw = %s", err, got.body)
	}
	if body.RequestID != "req-1" || body.PlanHash != "hash-abc" {
		t.Errorf("body = %+v, want the request and plan it names", body)
	}
	if body.Summary != testNotice().Summary {
		t.Errorf("summary = %q, want the Relay-authored text verbatim", body.Summary)
	}
	if body.DecisionPath != "/api/v1/approvals/req-1/decision" {
		t.Errorf("decision_path = %q, want the authenticated decision endpoint", body.DecisionPath)
	}
	if body.RequiredCount != 2 || body.Progress != "0 of 2" {
		t.Errorf("body = %+v, want the quorum state visible", body)
	}
}

// TestUnsignedByDefault: signing is opt-in, and an unsigned notice carries no
// half-built signature headers a receiver might mistake for verification.
func TestUnsignedByDefault(t *testing.T) {
	srv, ch := notifyServer(t, http.StatusOK)
	n, err := New(Config{URL: srv.URL}, WithHTTPClient(srv.Client()), WithLogger(quietLogger()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	n.NotifyParked(context.Background(), testNotice())
	got := await(t, ch)

	if got.signature != "" || got.timestamp != "" {
		t.Errorf("unsigned delivery carried %s=%q %s=%q", HeaderSignature, got.signature, HeaderTimestamp, got.timestamp)
	}
}

// TestSignsWithTheConfiguredSecret: the signature a receiver recomputes must
// match, and it must cover the timestamp as well as the body so a captured
// notice cannot be replayed indefinitely.
func TestSignsWithTheConfiguredSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("s3cret-value\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	srv, ch := notifyServer(t, http.StatusOK)
	n, err := New(Config{URL: srv.URL, SecretPath: path},
		WithHTTPClient(srv.Client()), WithLogger(quietLogger()),
		WithClock(func() time.Time { return notifyNow }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	n.NotifyParked(context.Background(), testNotice())
	got := await(t, ch)

	want := "sha256=" + Sign([]byte("s3cret-value"), got.timestamp, got.body)
	if got.signature != want {
		t.Errorf("signature = %q, want %q", got.signature, want)
	}
	// A signature over the body alone would verify a replay forever.
	if bare := "sha256=" + Sign([]byte("s3cret-value"), "", got.body); got.signature == bare {
		t.Error("signature does not cover the timestamp; a captured notice could be replayed indefinitely")
	}
}

// TestNotifyParkedDoesNotBlock: a park must never stall on someone else's HTTP
// server, so NotifyParked returns before the request completes.
func TestNotifyParkedDoesNotBlock(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer close(release)

	n, err := New(Config{URL: srv.URL, Timeout: 10 * time.Second},
		WithHTTPClient(srv.Client()), WithLogger(quietLogger()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	done := make(chan struct{})
	go func() {
		n.NotifyParked(context.Background(), testNotice())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("NotifyParked blocked on the receiving server")
	}
}

// TestDeliverySurvivesACancelledCaller: the request that parked returns to its
// client immediately, and cancelling delivery when it does would mean the
// notification almost never went out.
func TestDeliverySurvivesACancelledCaller(t *testing.T) {
	srv, ch := notifyServer(t, http.StatusOK)
	n, err := New(Config{URL: srv.URL}, WithHTTPClient(srv.Client()), WithLogger(quietLogger()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	n.NotifyParked(ctx, testNotice())
	cancel()

	await(t, ch) // fails the test if the delivery was cancelled with the caller
}

// TestARefusingEndpointIsNotAnError: notification is best-effort. A receiver
// that 500s costs an approver a poll and must not affect the Relay.
func TestARefusingEndpointIsSurvivable(t *testing.T) {
	srv, ch := notifyServer(t, http.StatusInternalServerError)
	n, err := New(Config{URL: srv.URL}, WithHTTPClient(srv.Client()), WithLogger(quietLogger()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	n.NotifyParked(context.Background(), testNotice())
	await(t, ch)

	// One attempt, no retry: a store-and-forward mechanism here would be a
	// delivery guarantee this control plane deliberately does not offer.
	select {
	case again := <-ch:
		t.Errorf("a second delivery attempt was made: %s", again.body)
	case <-time.After(300 * time.Millisecond):
	}
}

// -----------------------------------------------------------------------
// Configuration is fail-closed
// -----------------------------------------------------------------------

func TestNewRejectsPlaintextHTTPOffHost(t *testing.T) {
	if _, err := New(Config{URL: "http://notify.example.com/hook"}); err == nil {
		t.Fatal("plaintext http to a remote host must be refused — the notice carries the Operation, its arguments, and its targets")
	}
	if _, err := New(Config{URL: "http://127.0.0.1:9000/hook"}); err != nil {
		t.Fatalf("loopback http is a normal sidecar deployment: %v", err)
	}
}

func TestNewRejectsAnUnsupportedScheme(t *testing.T) {
	for _, raw := range []string{"file:///etc/passwd", "ftp://example.com/x", "not a url at all"} {
		if _, err := New(Config{URL: raw}); err == nil {
			t.Errorf("New(%q) succeeded, want a refusal", raw)
		}
	}
}

func TestNewRejectsAnEmptyURL(t *testing.T) {
	if _, err := New(Config{URL: "   "}); err == nil {
		t.Fatal("an empty URL must be refused rather than silently disabling notification")
	}
}

// TestSecretFilePermissionsAreEnforced: the secret is signing key material, so
// the bar is stricter than the gate config's — group- or world-READABLE is
// refused, not just writable.
//
// The mode is forced with os.Chmod rather than passed to os.WriteFile because
// WriteFile's perm argument is masked by the process umask: at umask 0o077
// every mode below would land 0o600 — exactly what the production check
// ACCEPTS — and the test would assert a refusal of an input that is no longer
// refusable, failing on its own t.Fatal (#508). chmod(2) is not umask-masked,
// so the fixture is loose by construction on every runner. Forcing a mode is
// right here for the same reason it is wrong in a production writer (#507):
// force the declared mode only where the declared mode is the tightest one, or
// where a test fixture is deliberately widened. A fixture that must be loose to
// be a valid input is the second case.
//
// The gate is `perm&0o077 != 0`: six independent bits. A single fixture that
// trips several at once (0o644 alone, as this test once was) discriminates
// none of them — a regression narrowing the mask to 0o007 or 0o070 would keep
// it green — so each case below trips exactly ONE bit, with 0o644 kept as the
// historical witness. Every bit is its own re-admission: a readable secret
// forges approval notifications, a writable one replaces the signing key
// outright.
func TestSecretFilePermissionsAreEnforced(t *testing.T) {
	for _, tc := range []struct {
		mode os.FileMode
		bit  string
	}{
		{0o640, "group-readable, other bits clear"},
		{0o620, "group-writable, other bits clear"},
		{0o610, "group-executable, other bits clear"},
		{0o604, "world-readable, group bits clear"},
		{0o602, "world-writable, group bits clear"},
		{0o601, "world-executable, group bits clear"},
		{0o644, "group- and world-readable — both bits at once"},
	} {
		t.Run(fmt.Sprintf("%04o", uint32(tc.mode)), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(path, []byte("s3cret"), 0o600); err != nil {
				t.Fatalf("write secret: %v", err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}

			_, err := New(Config{URL: "https://notify.example.com/hook", SecretPath: path})
			if err == nil {
				t.Fatalf("mode %04o (%s): a group- or world-accessible signing secret must refuse startup", uint32(tc.mode), tc.bit)
			}
			// Pin the refusal to THIS file's mode, so a rejection arriving from
			// some other check cannot stand in for the permission gate.
			if want := fmt.Sprintf("%04o", uint32(tc.mode)); !strings.Contains(err.Error(), want) {
				t.Errorf("mode %s (%s): err = %q, want it to name the offending mode", want, tc.bit, err)
			}
			if !strings.Contains(err.Error(), "0600") {
				t.Errorf("err = %q, want it to say how to fix the permissions", err)
			}
		})
	}
}

func TestSecretFileMustExistAndBeNonEmpty(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "nope")
	if _, err := New(Config{URL: "https://notify.example.com/hook", SecretPath: missing}); err == nil {
		t.Error("a configured-but-missing secret file must refuse startup, never silently send unsigned")
	}

	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("  \n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := New(Config{URL: "https://notify.example.com/hook", SecretPath: empty}); err == nil {
		t.Error("an empty secret file must refuse startup")
	}
}

// TestRedactStripsQueryAndUserinfo: an operator may have embedded a token in
// the webhook URL, and a delivery failure must not be how it reaches the log.
func TestRedactStripsQueryAndUserinfo(t *testing.T) {
	got := redact("https://user:hunter2@notify.example.com/hook?token=abc123")
	if strings.Contains(got, "hunter2") || strings.Contains(got, "abc123") {
		t.Errorf("redact = %q, want no credential material", got)
	}
}
