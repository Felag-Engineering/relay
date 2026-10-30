package approvalnotify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/hostfile"
)

var notifyNow = time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC)

func testNotice() capability.ApprovalNotice {
	return capability.ApprovalNotice{
		RequestID:   "req-1",
		PlanHash:    "hash-abc",
		Summary:     `service.restart(service="nginx") [mutate] on 12 node(s): node-a, node-b`,
		RequestedBy: "gleipnir-prod",
		Rules:       []string{"prod-mutates-need-a-human"},
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
//
// Proves AP-38.
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
	// One Decision ends a request, so the body names no progress, count or channel.
	var raw map[string]any
	if err := json.Unmarshal(got.body, &raw); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	for _, key := range []string{"progress", "required_count", "channel"} {
		if _, present := raw[key]; present {
			t.Errorf("body carries %q, want it dropped", key)
		}
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
	srv, ch := notifyServer(t, http.StatusOK)
	n, err := New(Config{URL: srv.URL, Secret: []byte("s3cret-value")},
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
//
// Proves AP-38.
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
//
// Proves AP-38.
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

// TestSecretFilePermissionsAreEnforced: a secret file is read through
// hostfile's check under its Secret rule (ADR-0043): refused if the Relay could
// write it, or if any account but the Relay and root could read it. The table
// is the modes this test has always walked, one bit each, on the layout a
// package installs (root-owned, the Relay's own group), plus a foreign group;
// each outcome is the Secret rule's verdict on that file. Group read for the
// Relay's own group, and execute bits, grant no other account access and are
// accepted (RC-9).
//
// The process facts are fixed rather than gathered, since a test may run as
// root, which the check refuses outright; the real gatherer and the real binary
// meet it on the separate-uid harness (TestStart_RefusesSecretReadableByOthers).
//
// Proves RC-48.
func TestSecretFilePermissionsAreEnforced(t *testing.T) {
	const relayUID, relayGID, wheel = 4242, 4243, 10
	proc := hostfile.Process{
		UIDs:   [3]uint32{relayUID, relayUID, relayUID},
		GIDs:   [3]uint32{relayGID, relayGID, relayGID},
		Groups: []uint32{relayGID},
	}
	const ext4 = 0xEF53
	for _, tc := range []struct {
		mode   uint32
		gid    uint32
		bit    string
		refuse hostfile.Clause // 0: accepted
	}{
		{0o640, relayGID, "group-readable by the Relay's own group", 0},
		{0o620, relayGID, "group-writable", hostfile.ClauseWriteGrant},
		{0o610, relayGID, "group-executable", 0},
		{0o604, relayGID, "world-readable", hostfile.ClauseReadableByOther},
		{0o602, relayGID, "world-writable", hostfile.ClauseWriteGrant},
		{0o601, relayGID, "world-executable", 0},
		{0o644, relayGID, "group- and world-readable", hostfile.ClauseReadableByOther},
		{0o640, wheel, "group-readable by a group the Relay is not", hostfile.ClauseReadableByOther},
	} {
		t.Run(fmt.Sprintf("%04o-gid%d", tc.mode, tc.gid), func(t *testing.T) {
			facts := hostfile.Facts{Process: proc, Path: []hostfile.Node{
				{Name: "/", Kind: hostfile.KindDir, Mode: 0o755, FSType: ext4},
				{Name: "etc", Kind: hostfile.KindDir, Mode: 0o755, FSType: ext4},
				{Name: "secret", Kind: hostfile.KindRegular, GID: tc.gid, Mode: tc.mode, FSType: ext4},
			}}
			err := hostfile.Decide(facts, hostfile.Secret)
			if tc.refuse == 0 {
				if err != nil {
					t.Fatalf("%s: refused (%v), want accepted", tc.bit, err)
				}
				return
			}
			var r *hostfile.Refusal
			if !errors.As(err, &r) || r.Clause != tc.refuse {
				t.Fatalf("%s: err = %v, want the %q refusal", tc.bit, err, tc.refuse)
			}
		})
	}

	// ReadSecretFile is that check: a symbolic link is refused by it before
	// anything is read, whoever the test runs as.
	dir := t.TempDir()
	real := filepath.Join(dir, "secret")
	if err := os.WriteFile(real, []byte("s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	_, err := ReadSecretFile(link)
	var r *hostfile.Refusal
	if !errors.As(err, &r) || r.Clause != hostfile.ClauseSymlink {
		t.Fatalf("ReadSecretFile(symlink) = %v, want the file check's symlink refusal", err)
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Errorf("refusal carries the content: %v", err)
	}
}

// TestSecretRule_RefusesADirectory: ReadSecretFile is hostfile.Open(path,
// hostfile.Secret), so the Secret rule's verdict on a leaf that is a directory
// is what ReadSecretFile meets. The process facts are fixed because a real
// directory under a test temp dir is refused earlier, for an ancestor the test
// user owns or for running as root.
//
// Proves RC-48.
func TestSecretRule_RefusesADirectory(t *testing.T) {
	const relayUID, relayGID = 4242, 4243
	const ext4 = 0xEF53
	facts := hostfile.Facts{
		Process: hostfile.Process{
			UIDs:   [3]uint32{relayUID, relayUID, relayUID},
			GIDs:   [3]uint32{relayGID, relayGID, relayGID},
			Groups: []uint32{relayGID},
		},
		Path: []hostfile.Node{
			{Name: "/", Kind: hostfile.KindDir, Mode: 0o755, FSType: ext4},
			{Name: "etc", Kind: hostfile.KindDir, Mode: 0o755, FSType: ext4},
			{Name: "secret", Kind: hostfile.KindDir, GID: relayGID, Mode: 0o750, FSType: ext4},
		},
	}
	err := hostfile.Decide(facts, hostfile.Secret)
	var r *hostfile.Refusal
	if !errors.As(err, &r) || r.Clause != hostfile.ClauseNotRegular {
		t.Fatalf("Decide(directory leaf) = %v, want the not-a-regular-file refusal", err)
	}
}

func TestSecretFileMustExistAndBeNonEmpty(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "nope")
	if _, err := ReadSecretFile(missing); err == nil {
		t.Error("a configured-but-missing secret file must refuse startup, never silently send unsigned")
	} else if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing-file error = %v, want it to satisfy errors.Is(fs.ErrNotExist)", err)
	}

	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("  \n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	f, err := os.Open(empty)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readOpenedSecret(f, empty); err == nil {
		t.Error("an empty secret file must refuse startup")
	}
}

// TestNewRefusalsCarryNoURL: the URL may carry a token, and a refusal is logged.
func TestNewRefusalsCarryNoURL(t *testing.T) {
	for _, raw := range []string{
		"http://hooks.example.test/T0K3N",
		"ftp://hooks.example.test/T0K3N",
		"https://hooks.example.test/T0K3N%zz",
	} {
		_, err := New(Config{URL: raw})
		if err == nil {
			t.Fatalf("New(%q) succeeded, want a refusal", raw)
		}
		if strings.Contains(err.Error(), "hooks.example.test") || strings.Contains(err.Error(), "T0K3N") {
			t.Errorf("New(%q) error %q carries the URL", raw, err)
		}
	}
}

// lockedBuffer is a log sink safe for the delivery goroutine and the test.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func waitForLog(t *testing.T, b *lockedBuffer, want string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := b.String(); strings.Contains(got, want) {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("log never contained %q; got %q", want, b.String())
	return ""
}

func hostPort(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

// TestDeliveryLogsCarryNoURL: no delivery outcome puts the URL, or any part of
// it, in the log. The production client runs, so its redirect policy is under test.
func TestDeliveryLogsCarryNoURL(t *testing.T) {
	run := func(t *testing.T, target string, wantMsg string, extraBanned ...string) string {
		t.Helper()
		buf := &lockedBuffer{}
		n, err := New(Config{URL: target, Timeout: 2 * time.Second},
			WithLogger(slog.New(slog.NewTextHandler(buf, nil))))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		n.NotifyParked(context.Background(), testNotice())
		got := waitForLog(t, buf, wantMsg)
		for _, banned := range append([]string{"T0K3N", hostPort(t, target)}, extraBanned...) {
			if strings.Contains(got, banned) {
				t.Errorf("log carries %q: %s", banned, got)
			}
		}
		return got
	}

	t.Run("500", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		got := run(t, srv.URL+"/T0K3N", "endpoint refused the notice")
		if !strings.Contains(got, "status=500") {
			t.Errorf("log = %s, want status=500", got)
		}
	})

	t.Run("closed", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		target := srv.URL + "/T0K3N"
		srv.Close()
		got := run(t, target, "delivery failed")
		if !strings.Contains(got, "reason=") {
			t.Errorf("log = %s, want a reason", got)
		}
	})

	t.Run("redirect", func(t *testing.T) {
		var hits atomic.Int32
		b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
		}))
		defer b.Close()
		a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, b.URL+"/T0K3N-target", http.StatusTemporaryRedirect)
		}))
		defer a.Close()
		got := run(t, a.URL+"/T0K3N", "endpoint refused the notice", hostPort(t, b.URL))
		if !strings.Contains(got, "status=307") {
			t.Errorf("log = %s, want status=307", got)
		}
		if n := hits.Load(); n != 0 {
			t.Errorf("redirect target was hit %d times, want 0", n)
		}
	})
}

func TestDeliveryFailure_IsAFixedCategory(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"dns", &url.Error{Op: "Post", URL: "https://hooks.example.test/x",
			Err: &net.DNSError{Name: "hooks.example.test", IsTimeout: false}}, "name lookup failed"},
		{"deadline", &url.Error{Op: "Post", URL: "https://hooks.example.test/x", Err: context.DeadlineExceeded}, "timed out"},
		{"refused", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, "connection refused"},
		{"other", errors.New("boom hooks.example.test"), "transport error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := deliveryFailure(tc.err)
			if got != tc.want {
				t.Errorf("deliveryFailure = %q, want %q", got, tc.want)
			}
			if strings.Contains(got, "hooks.example.test") {
				t.Errorf("category %q carries the host", got)
			}
		})
	}
}
