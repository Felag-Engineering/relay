package console

// events_audit_test.go is #539's route-specific guard for GET
// /console/events, driven through the REAL *capability.Service over a REAL
// *auditsink.Sink, exactly as read_audit_test.go drives every other audited
// route (realLaneDeps, recordingTrail, driveStream — all defined there).
//
// It exists beside read_audit_test.go rather than inside it because that
// file's sweep proves only ONE thing per route: "this route, classified
// audited, produces a record for its tool" — read_audit_test.go's own doc
// comment names that as its honest limit. It cannot generically prove WHICH
// kinds were named, that a resume is recorded as a boolean rather than the
// caller's cursor, or that the record lands before the role and limiter
// refusals and before Subscribe. Those are this ticket's entire point, so
// they get their own tests, each keyed to a mutation this file's comments
// name.
//
// C (test strategy, #539 plan): MUT revert GET /console/events' classification
// in read_audit_test.go back to exempt — TestConsole_EveryRouteIsClassifiedForReadAuditing
// still PASSES, because an exemption with a stated reason is legal syntax for
// that guard; it cannot tell a true reason from a false one. That is why B1-B7
// here are keyed to the route directly instead of being folded into the
// table: nobody should "simplify" this file away believing the table alone
// still covers it.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
)

// driveStreamHeader is driveStream (read_audit_test.go) with the ability to
// set extra request headers — B4 needs this to exercise the Last-Event-ID
// header path, which driveStream's plain path-only signature cannot reach.
func driveStreamHeader(t *testing.T, d Deps, path string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), streamTestTimeout)
	defer cancel()
	if fe, ok := d.Events.(*fakeEvents); ok {
		fe.onSubscribe = cancel
	}
	req := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+testCredential)
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	newTestHandler(d, accounts.RoleAdmin).ServeHTTP(rec, req)
	return rec
}

// B1: exactly one KindRead, naming watch_events, with the sorted kind list as
// its selector, attributed to the signed-in Account, carrying no output, and
// rendering as "watch_events" through the same vocabulary every other read
// record uses — the #463/#517/#520 check.
//
// MUT delete the RecordEventSubscription call in handleEvents -> this test's
// "len(reads) != 0" check goes red first.
func TestConsoleEvents_B1_RecordsExactlyOneWatchRead(t *testing.T) {
	trail := &recordingTrail{}
	d := realLaneDeps(trail)

	rec := driveStream(t, d, "/console/events?kinds=job,enrollment")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /console/events = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	reads := trail.ofKind(audit.KindRead)
	if len(reads) != 1 {
		t.Fatalf("subscribing wrote %d KindRead records, want exactly 1: %+v", len(reads), reads)
	}
	got := reads[0]

	if got.OperationName != toolWatchEventsForTest {
		t.Errorf("OperationName = %q, want %q", got.OperationName, toolWatchEventsForTest)
	}
	if got.Selector != "kinds=enrollment,job" {
		t.Errorf("Selector = %q, want %q — sorted, deduped, request order must not survive", got.Selector, "kinds=enrollment,job")
	}
	if got.Attribution.Verified.AccountID != testAccountID(accounts.RoleAdmin) {
		t.Errorf("Verified.AccountID = %q, want %q", got.Attribution.Verified.AccountID, testAccountID(accounts.RoleAdmin))
	}
	if len(got.Stdout) != 0 || len(got.Stderr) != 0 || got.Truncated {
		t.Errorf("read record carries output (stdout %d, stderr %d, truncated %v) — ADR-0025 "+
			"decision 2 forbids that for a KindRead", len(got.Stdout), len(got.Stderr), got.Truncated)
	}
	if name := readTargetOf(factsOfRecord(got)); name != toolWatchEventsForTest {
		t.Errorf("the record renders as %q, want %q — the #463/#517/#520 failure mode is a record "+
			"that renders as something other than the tool that wrote it", name, toolWatchEventsForTest)
	}
}

// toolWatchEventsForTest is capability's unexported toolWatchEvents,
// repeated here as a literal: this package may not import an unexported
// identifier from another one, and the record's OperationName is exactly
// what an operator reads on Activity — spelling it out here is what a
// reader compares against, the same way read_audit_test.go's rule.tool
// values are literals rather than imported constants.
const toolWatchEventsForTest = "watch_events"

// B2: two different kind sets record two different selectors — the whole
// reason the selector exists is so an auditor can tell a job-only stream
// from one that could have carried more.
//
// MUT hardcode or empty the selector -> this test goes red.
func TestConsoleEvents_B2_DifferentKindsRecordDifferently(t *testing.T) {
	jobTrail := &recordingTrail{}
	rec := driveStream(t, realLaneDeps(jobTrail), "/console/events?kinds=job")
	if rec.Code != http.StatusOK {
		t.Fatalf("?kinds=job = %d, want 200", rec.Code)
	}

	enrollTrail := &recordingTrail{}
	rec = driveStream(t, realLaneDeps(enrollTrail), "/console/events?kinds=enrollment")
	if rec.Code != http.StatusOK {
		t.Fatalf("?kinds=enrollment = %d, want 200", rec.Code)
	}

	jobReads := jobTrail.ofKind(audit.KindRead)
	enrollReads := enrollTrail.ofKind(audit.KindRead)
	if len(jobReads) != 1 || len(enrollReads) != 1 {
		t.Fatalf("got %d and %d read records, want exactly 1 each", len(jobReads), len(enrollReads))
	}
	if jobReads[0].Selector != "kinds=job" {
		t.Errorf("?kinds=job recorded selector %q, want %q", jobReads[0].Selector, "kinds=job")
	}
	if enrollReads[0].Selector != "kinds=enrollment" {
		t.Errorf("?kinds=enrollment recorded selector %q, want %q", enrollReads[0].Selector, "kinds=enrollment")
	}
	if jobReads[0].Selector == enrollReads[0].Selector {
		t.Fatal("two different subscriptions recorded the same selector — an auditor could not " +
			"tell them apart")
	}
}

// B3: caller order and repetition never change the record, and an
// enormous repeated query string still records a short, bounded selector —
// bounding what is RECORDED, not what the route ACCEPTS (canonicalise
// before the count bound, capability/readlane.go's canonicalEventKinds).
//
// MUT pass the raw query string to the lane instead of the resolved
// canonical Names -> this test goes red, because the raw string would
// either fail validation it should not (if bounded before dedup) or would
// simply record the un-deduped, unsorted text instead of "kinds=job".
func TestConsoleEvents_B3_OrderAndRepetitionDoNotChangeTheRecord(t *testing.T) {
	for _, param := range []string{"job,enrollment", "enrollment,job", "job,job,enrollment,job"} {
		trail := &recordingTrail{}
		rec := driveStream(t, realLaneDeps(trail), "/console/events?kinds="+param)
		if rec.Code != http.StatusOK {
			t.Fatalf("?kinds=%s = %d, want 200", param, rec.Code)
		}
		reads := trail.ofKind(audit.KindRead)
		if len(reads) != 1 {
			t.Fatalf("?kinds=%s wrote %d records, want 1", param, len(reads))
		}
		if reads[0].Selector != "kinds=enrollment,job" {
			t.Errorf("?kinds=%s recorded %q, want %q — caller order and repetition must not "+
				"reach the trail", param, reads[0].Selector, "kinds=enrollment,job")
		}
	}

	// 5,000 repetitions of one legal kind, comma-joined: a URL this route
	// opens a stream for TODAY (resolveEventKinds has no count cap), which
	// auditing must not break.
	repeated := strings.Repeat("job,", 4999) + "job"
	trail := &recordingTrail{}
	rec := driveStream(t, realLaneDeps(trail), "/console/events?kinds="+repeated)
	if rec.Code != http.StatusOK {
		t.Fatalf("5,000 repeated kinds = %d, want 200 — auditing must not turn a request this "+
			"route already accepts into a failure", rec.Code)
	}
	reads := trail.ofKind(audit.KindRead)
	if len(reads) != 1 {
		t.Fatalf("5,000 repeated kinds wrote %d records, want 1", len(reads))
	}
	if reads[0].Selector != "kinds=job" {
		t.Errorf("5,000 repeated kinds recorded %q, want %q", reads[0].Selector, "kinds=job")
	}
	if len(reads[0].Selector) > 256 {
		t.Errorf("recorded selector is %d bytes, want <= 256", len(reads[0].Selector))
	}
}

// B3b closes the exact vacuity a security review found in B3's own MUT line
// (#539 fix round, Finding 1): B3's cases never exercise a query string whose
// RAW split differs from its TRIMMED, validated form, so a mutation that
// replaced wanted.Names with strings.Split(r.URL.Query().Get("kinds"), ",")
// in the RecordEventSubscription call — never touching what gets
// Subscribed — passed B1 through B7 and both read_audit_test.go sweeps: for
// every query string this file used, the raw split and wanted.Names happened
// to be equal.
//
// %20job,job%20,enrollment decodes to " job,job ,enrollment", which
// resolveEventKinds accepts (it trims each token before the allowlist
// lookup) but strings.Split alone would not: it would leave " job", "job "
// and "enrollment" as three distinct, un-trimmed strings. If anything ever
// re-derives what RecordEventSubscription is called with instead of reusing
// wanted.Names, this selector stops being "kinds=enrollment,job" — either
// because canonicalEventKinds records the un-trimmed text verbatim, or
// because kindsFromNames (events.go) cannot resolve an un-trimmed name
// against consoleEventKinds and the request 500s instead of 200. Both
// outcomes fail this test; neither is possible to observe by comparing
// wanted.Kinds against wanted.Names the way the ORIGINAL (pre-fix) shape of
// this route did, which is exactly why that shape shipped with this gap.
//
// MUT (the one the security review used) replace wanted.Names with
// strings.Split(r.URL.Query().Get("kinds"), ",") in handleEvents' call to
// RecordEventSubscription -> this test goes red, on the Selector assertion.
func TestConsoleEvents_B3b_WhitespaceInTheQueryDoesNotSurviveIntoTheRecord(t *testing.T) {
	trail := &recordingTrail{}
	rec := driveStream(t, realLaneDeps(trail), "/console/events?kinds=%20job,job%20,enrollment")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /console/events?kinds=%%20job,job%%20,enrollment = %d, want 200: %s",
			rec.Code, rec.Body.String())
	}
	reads := trail.ofKind(audit.KindRead)
	if len(reads) != 1 {
		t.Fatalf("wrote %d read records, want exactly 1", len(reads))
	}
	if got := reads[0].Selector; got != "kinds=enrollment,job" {
		t.Errorf("Selector = %q, want %q — whitespace around a valid kind name must be trimmed "+
			"before it reaches the trail, exactly as it is before it reaches the allowlist", got,
			"kinds=enrollment,job")
	}
}

// B4: a resume, asserted either through the Last-Event-ID header or through
// ?last_event_id, records resume=yes and NEVER the cursor value itself
// (capability.RecordEventSubscription's doc comment: caller-asserted,
// unverified, unbounded, and uninterpretable after a restart).
//
// cursor is deliberately kept UNDER maxEventKindBytes (64) — #539 fix round,
// Finding 4. A longer cursor here (66 bytes, in an earlier version of this
// test) tripped canonicalEventKinds' own per-name length bound if a mutation
// fed the cursor through the kinds path, so "resume via header = %d, want
// 200" failed FIRST and the test never got as far as the "must not contain
// the cursor" assertion this comment used to claim was the one catching it.
//
// Shortening the cursor does NOT hand that assertion the win either,
// though, and this comment says so rather than repeat the earlier mistake:
// this file's Finding 1 fix means d.Events.Subscribe's kind list is now
// built from kindsFromNames(recorded, ...), so a mutation that appends the
// cursor to what gets recorded — the only realistic way to "pass the cursor
// as the selector" given RecordEventSubscription's signature never accepts
// one — makes kindsFromNames refuse an unrecognised "kind" and 500, at ANY
// cursor length, before Subscribe or the record's shape ever come into it.
// The "want 200" check is still what fires first; it is just a STRONGER
// reason now than a length bound that happened to be in the way. The "must
// not contain the cursor" assertion below stays as defense in depth for a
// mutation that could put the cursor into the selector WITHOUT going
// through the shared kinds/names channel — nothing in this file's current
// structure has such a path, but nothing guarantees a future one will not.
//
// MUT append the cursor to what gets recorded (the only channel
// RecordEventSubscription's signature offers to "pass the cursor as the
// selector") -> "resume via header = %d, want 200" goes red, on EVERY
// cursor length, via kindsFromNames' refusal.
func TestConsoleEvents_B4_ResumeRecordsTheBooleanNeverTheCursor(t *testing.T) {
	const cursor = "0000000000000001-47-should-not-be-recorded"

	trail := &recordingTrail{}
	header := http.Header{"Last-Event-ID": []string{cursor}}
	rec := driveStreamHeader(t, realLaneDeps(trail), "/console/events?kinds=job", header)
	if rec.Code != http.StatusOK {
		t.Fatalf("resume via header = %d, want 200", rec.Code)
	}
	reads := trail.ofKind(audit.KindRead)
	if len(reads) != 1 {
		t.Fatalf("resume via header wrote %d records, want 1", len(reads))
	}
	if !strings.Contains(reads[0].Selector, "resume=yes") {
		t.Errorf("resume via header recorded %q, want it to contain %q", reads[0].Selector, "resume=yes")
	}
	if strings.Contains(reads[0].Selector, cursor) {
		t.Errorf("resume via header recorded the CURSOR itself: %q", reads[0].Selector)
	}

	trail2 := &recordingTrail{}
	rec = driveStream(t, realLaneDeps(trail2), "/console/events?kinds=job&last_event_id="+cursor)
	if rec.Code != http.StatusOK {
		t.Fatalf("resume via query param = %d, want 200", rec.Code)
	}
	reads2 := trail2.ofKind(audit.KindRead)
	if len(reads2) != 1 {
		t.Fatalf("resume via query param wrote %d records, want 1", len(reads2))
	}
	if !strings.Contains(reads2[0].Selector, "resume=yes") {
		t.Errorf("resume via query param recorded %q, want it to contain %q", reads2[0].Selector, "resume=yes")
	}
	if strings.Contains(reads2[0].Selector, cursor) {
		t.Errorf("resume via query param recorded the CURSOR itself: %q", reads2[0].Selector)
	}

	// And the negative: no resume asked for, no resume=yes recorded.
	trail3 := &recordingTrail{}
	rec = driveStream(t, realLaneDeps(trail3), "/console/events?kinds=job")
	if rec.Code != http.StatusOK {
		t.Fatalf("no resume = %d, want 200", rec.Code)
	}
	reads3 := trail3.ofKind(audit.KindRead)
	if len(reads3) != 1 {
		t.Fatalf("no resume wrote %d records, want 1", len(reads3))
	}
	if strings.Contains(reads3[0].Selector, "resume") {
		t.Errorf("a fresh subscription recorded %q, which mentions resume at all", reads3[0].Selector)
	}
}

// B5: fail closed, AND ordered. With the trail refusing writes, this route
// must refuse before ever calling Subscribe — proven as two SEPARATE
// assertions, because a mutation that reorders record-then-Subscribe can
// make one pass while the other catches it.
//
// MUT move the record after d.Events.Subscribe -> the subscriptions() == 0
// assertion goes red while the status/body assertions still PASS (Subscribe
// having already happened does not change that RecordEventSubscription
// still fails and the handler still refuses with the same message) — which
// is why subscriptions() is checked as its own assertion rather than folded
// into the status check.
// MUT ignore the error RecordEventSubscription returns -> the status
// assertion goes red (the stream would open, 200, text/event-stream).
func TestConsoleEvents_B5_FailsClosedBeforeSubscribing(t *testing.T) {
	trail := &recordingTrail{appendErr: errTrailDown}
	d := realLaneDeps(trail)

	rec := driveStream(t, d, "/console/events?kinds=job")
	if rec.Code == http.StatusOK {
		t.Fatalf("GET /console/events = 200 with an unwritable audit trail — a read this Relay "+
			"cannot record must be refused (ADR-0025 decision 4): %s", rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"audit trail", "refused"} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal does not say %q — it reads as a generic failure:\n%s", want, body)
		}
	}
	if ct := rec.Header().Get("Content-Type"); strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("Content-Type = %q — a refused subscription must never look like an opened stream", ct)
	}

	if got := d.Events.(*fakeEvents).subscriptions(); got != 0 {
		t.Errorf("subscriptions() = %d, want 0 — Subscribe must never run when the read could not "+
			"be recorded, or the refusal's claim that nothing was disclosed is a lie", got)
	}
}

// B6: a role this Relay does not recognise is refused before the record is
// ever written — recording a 403 would count a non-access in read egress's
// enumeration, which is not what a refusal is.
//
// MUT move the RecordEventSubscription call above the role check -> this
// test goes red.
func TestConsoleEvents_B6_RoleRefusalRecordsNothing(t *testing.T) {
	trail := &recordingTrail{}
	d := realLaneDeps(trail)

	rec := get(t, newTestHandler(d, accounts.Role("auditor")), "/console/events?kinds=job")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /console/events as an unrecognised role = %d, want 403", rec.Code)
	}

	if reads := trail.ofKind(audit.KindRead); len(reads) != 0 {
		t.Errorf("a role refusal wrote %d read records, want 0: %+v", len(reads), reads)
	}
}

// B7: the per-principal limiter refuses before the record is written too —
// same reasoning as B6. maxStreamsPerPrincipal (events.go) is a const; the
// per-principal cap this test needs at 1 lives on a *streamLimiter built
// directly for this test (#539 fix round, Finding 3 — this used to shrink a
// package-wide var and restore it with t.Cleanup, which nothing stopped a
// concurrent test in this package from observing). The scenario still needs
// a SINGLE *streamLimiter shared by both requests, which
// newTestHandlerWithEventsLimiter's one construction gives it — both
// requests below go through the SAME handler.
//
// MUT move the RecordEventSubscription call above limiter.acquire -> the
// second request would ALSO record, making the final count 2 instead of 1.
func TestConsoleEvents_B7_LimiterRefusalRecordsNothing(t *testing.T) {
	trail := &recordingTrail{}
	d := realLaneDeps(trail)
	h := newTestHandlerWithEventsLimiter(d, accounts.RoleAdmin, &streamLimiter{perCap: 1})

	srv := httptest.NewServer(h)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/console/events?kinds=job", nil)
	if err != nil {
		t.Fatalf("build first request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testCredential)
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("open first stream: %v", err)
	}
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusOK {
		t.Fatalf("first stream = %d, want 200 — it must open before the second request can be "+
			"refused by the cap", res.StatusCode)
	}

	// By the time the response headers arrived, Subscribe had already run
	// (it precedes the header write in handleEvents), so the slot is held.
	if got := d.Events.(*fakeEvents).subscriptions(); got != 1 {
		t.Fatalf("subscriptions() = %d, want 1 before the second request is sent", got)
	}

	rec := get(t, h, "/console/events?kinds=job")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request = %d, want 429 — maxStreamsPerPrincipal is 1 for this test", rec.Code)
	}

	reads := trail.ofKind(audit.KindRead)
	if len(reads) != 1 {
		t.Fatalf("total read records = %d, want exactly 1 (the FIRST subscription's, none for the "+
			"429) — the limiter must refuse before a record is written", len(reads))
	}
}
