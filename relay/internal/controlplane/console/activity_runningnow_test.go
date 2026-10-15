package console

import (
	"errors"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// Running now (spec 04, D18, #795): the section above the stream that lists
// running Jobs longest-running first, five to a page, on its own cursor,
// holding the one Cancel a running Job draws on the page. One test per
// box of spec 04's "## Acceptance" section.

const (
	rnSectionStart = `<section class="runningnow"`
	rnSectionEnd   = `</section>`
)

// isRunningNowRead says a Job filter is Running now's one read: running only,
// oldest first, counted, and narrowed by nothing the stream's filters carry.
func isRunningNowRead(f capability.JobFilter) bool {
	return f.State != nil && *f.State == jobs.JobStateRunning &&
		f.Order == jobs.JobOrderOldestFirst && f.CountMatching &&
		f.Since.IsZero() && f.Until.IsZero() &&
		f.Operation == "" && f.OnBehalfOf == "" && f.JobID == ""
}

// splitRunningNow separates Running now's section from the rest of the page,
// so an assertion about "the stream" cannot be satisfied by the section.
func splitRunningNow(t *testing.T, body string) (section, stream string) {
	t.Helper()
	start := strings.Index(body, rnSectionStart)
	if start < 0 {
		t.Fatalf("the page has no Running now section:\n%s", body)
	}
	end := strings.Index(body[start:], rnSectionEnd)
	if end < 0 {
		t.Fatal("Running now's section is not closed")
	}
	end += start + len(rnSectionEnd)
	return body[start:end], body[:start] + body[end:]
}

// runningFleet is n running Jobs of one Account, job-0 the oldest. job-0 is
// three days old; each later one is an hour newer than the last.
func runningFleet(n int, accountID string) []capability.JobSummary {
	out := make([]capability.JobSummary, n)
	for i := range out {
		sum := runningJob("job-"+strconv.Itoa(i), "gleipnir-prod", accountID)
		sum.CreatedAt = testNow.Add(-time.Duration(n-i) * time.Hour)
		if i == 0 {
			sum.CreatedAt = testNow.Add(-72 * time.Hour)
		}
		sum.Selector = "role=web"
		out[i] = sum
	}
	return out
}

// jobReadCursors reads back the (stream, Running now) cursors of the LAST
// page view, which makes its two Job reads in that order.
func jobReadCursors(t *testing.T, q *fakeQueries) (stream, running string) {
	t.Helper()
	n := len(q.jobFilters)
	if n < 2 || isRunningNowRead(q.jobFilters[n-2]) || !isRunningNowRead(q.jobFilters[n-1]) {
		t.Fatalf("the last page view's Job reads are not [stream, Running now]: %+v", q.jobFilters)
	}
	return q.jobPages[n-2].Cursor, q.jobPages[n-1].Cursor
}

func TestActivity_RunningNowShowsARunningJobOfAnyAgeOnTheFirstPageLongestFirst(t *testing.T) {
	// Stored newest-first, as the stream wants them: the order Running now
	// shows is the lane's, not the fixture's.
	fleet := runningFleet(7, "acct-1")
	slices := make([]capability.JobSummary, 0, len(fleet))
	for i := len(fleet) - 1; i >= 0; i-- {
		slices = append(slices, fleet[i])
	}
	q := &fakeQueries{jobs: slices}
	body := activityRunning(t, q, accounts.RoleAdmin, "/console/activity?kind=plan&window=15m")
	section, _ := splitRunningNow(t, body)

	if n := strings.Count(section, `class="rnentry"`); n != 5 {
		t.Fatalf("entries on the first page = %d, want 5", n)
	}
	last := -1
	for i := 0; i < 5; i++ {
		at := strings.Index(section, `id="rn-job-`+strconv.Itoa(i)+`"`)
		if at < 0 {
			t.Fatalf("job-%d (the %dth longest-running) is not on the first page", i, i+1)
		}
		if at < last {
			t.Errorf("job-%d is drawn before an older running Job", i)
		}
		last = at
	}
	if strings.Contains(section, `id="rn-job-5"`) || strings.Contains(section, `id="rn-job-6"`) {
		t.Error("the first page holds more than five entries")
	}
	if !strings.Contains(section, "7 running &middot; 1&ndash;5") {
		t.Errorf("the section does not state the total and range:\n%s", section)
	}
	if !strings.Contains(section, "running for 3d 0h") {
		t.Error("the oldest running Job does not say how long it has been running")
	}

	if len(q.jobFilters) != 1 || !isRunningNowRead(q.jobFilters[0]) {
		t.Fatalf("?kind=plan&window=15m made Job reads %+v, want exactly Running now's, unnarrowed by kind or window", q.jobFilters)
	}
	if q.jobPages[0].Limit != runningNowPageSize {
		t.Errorf("Running now asked for %d Jobs, want %d", q.jobPages[0].Limit, runningNowPageSize)
	}
}

func TestActivity_EachRunningJobDrawsExactlyOneCancelInRunningNow(t *testing.T) {
	const action = `action="/console/jobs/job-1/cancel"`
	q := &fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "gleipnir-prod", "acct-1")}}
	body := activityRunning(t, q, accounts.RoleAdmin, "/console/activity")
	section, stream := splitRunningNow(t, body)

	// The same Job is on the stream's current page and in Running now.
	row := activityRowContaining(t, stream, `data-job-id="job-1"`)
	if n := strings.Count(body, action); n != 1 {
		t.Fatalf("Cancel forms for job-1 on the page = %d, want exactly 1", n)
	}
	if !strings.Contains(section, action) {
		t.Error("the one Cancel is not inside Running now")
	}
	if !strings.Contains(row, `href="#rn-job-1"`) {
		t.Errorf("the stream row does not link to its Running now entry:\n%s", row)
	}

	viewer := activityRunning(t, q, accounts.RoleViewer, "/console/activity")
	if strings.Contains(viewer, `class="jobcancel"`) {
		t.Error("a viewer is offered Cancel")
	}
	if vs, _ := splitRunningNow(t, viewer); !strings.Contains(vs, `id="rn-job-1"`) {
		t.Error("a viewer does not see the running Job in Running now")
	}

	unmounted := get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin), "/console/activity").Body.String()
	if strings.Contains(unmounted, `class="jobcancel"`) {
		t.Error("Cancel is drawn although the cancel route is not mounted")
	}
}

func TestActivity_PagingRunningNowNeverMovesTheStreamAndViceVersa(t *testing.T) {
	q := &fakeQueries{jobs: runningFleet(7, "acct-1"), jobNext: "jc-2"}
	h := newTestHandler(cancelDeps(q, &fakeCanceller{}), accounts.RoleAdmin)

	// Running now's Next link keeps the stream where it is.
	body := get(t, h, "/console/activity?jc=jc-1").Body.String()
	section, _ := splitRunningNow(t, body)
	next := unescapeHref(t, hrefContaining(t, section, "rc=rn%3A5"))
	if !strings.Contains(next, "jc=jc-1") {
		t.Errorf("Running now's Next link %q does not keep the stream's position", next)
	}
	page2 := get(t, h, next).Body.String()
	streamCursor, runningCursor := jobReadCursors(t, q)
	if streamCursor != "jc-1" || runningCursor != "rn:5" {
		t.Errorf("after paging Running now: stream cursor %q (want jc-1), Running now cursor %q (want rn:5)", streamCursor, runningCursor)
	}
	section2, _ := splitRunningNow(t, page2)
	if !strings.Contains(section2, "7 running &middot; 6&ndash;7") || strings.Count(section2, `class="rnentry"`) != 2 {
		t.Errorf("the second page of Running now is not entries 6 to 7 of 7:\n%s", section2)
	}
	if !strings.Contains(section2, "Longest-running first") {
		t.Error("the second page offers no way back to the longest-running")
	}

	// And paging the stream keeps Running now where it is.
	body = get(t, h, "/console/activity?rc=rn:5&ro=5").Body.String()
	older := unescapeHref(t, hrefContaining(t, body, "jc=jc-2"))
	if !strings.Contains(older, "rc=rn%3A5") || !strings.Contains(older, "ro=5") {
		t.Errorf("the stream's Older link %q does not keep Running now's position", older)
	}
	get(t, h, older)
	streamCursor, runningCursor = jobReadCursors(t, q)
	if streamCursor != "jc-2" || runningCursor != "rn:5" {
		t.Errorf("after paging the stream: stream cursor %q (want jc-2), Running now cursor %q (want rn:5)", streamCursor, runningCursor)
	}
}

func TestActivity_RunningNowEntryIsMarkedFinishedInPlace(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{runningJob("job-1", "gleipnir-prod", "acct-1")}}
	d := cancelDeps(q, &fakeCanceller{})
	d.Events = newFakeEvents()
	h := newTestHandler(d, accounts.RoleAdmin)

	body := get(t, h, "/console/activity").Body.String()
	section, stream := splitRunningNow(t, body)
	entry := section[strings.Index(section, `<li class="rnentry"`):]
	entry = entry[:strings.Index(entry, "</li>")]
	for _, want := range []string{
		`data-rn-job-id="job-1"`,
		`class="rnliveslot"`,
		`data-when="completed">finished after this page was rendered`,
		`data-when="cancelled">cancelled after this page was rendered`,
		`class="jobcancel"`,
	} {
		if !strings.Contains(entry, want) {
			t.Errorf("the entry lacks %q:\n%s", want, entry)
		}
	}
	// The stream's contract — only the dispatch row carries the live handle —
	// is unchanged by the section.
	if strings.Contains(section, `data-job-id=`) || strings.Contains(section, `class="evliveslot"`) {
		t.Error("an entry carries the stream's live handle")
	}
	if n := strings.Count(stream, `data-job-id="job-1"`); n != 1 {
		t.Errorf("the stream carries the live handle for job-1 %d times, want 1", n)
	}

	// Under a kind with no live rows the section is still live while
	// something is running, and nothing mounts when nothing is.
	refusal := get(t, h, "/console/activity?kind=refusal").Body.String()
	if !strings.Contains(refusal, "data-live-region") || !strings.Contains(refusal, `src="/console/assets/activity.js"`) {
		t.Error("?kind=refusal with a running Job does not mount the live region for Running now")
	}
	idle := cancelDeps(&fakeQueries{}, &fakeCanceller{})
	idle.Events = newFakeEvents()
	off := get(t, newTestHandler(idle, accounts.RoleAdmin), "/console/activity?kind=refusal").Body.String()
	if strings.Contains(off, "data-live-region") || strings.Contains(off, "activity.js") {
		t.Error("?kind=refusal with nothing running mounts a live region for a view that can never update")
	}
}

func TestActivity_RunningNowFollowsAccountAndNothingElse(t *testing.T) {
	fleet := runningFleet(7, "acct-1")
	for i := range fleet {
		fleet[i].CreatedAt = testNow.Add(-time.Duration(i+1) * time.Minute)
		// So the stream's ?outcome=success keeps these rows.
		fleet[i].Counts = map[jobs.Outcome]int{jobs.OutcomeSuccess: 1}
	}
	q := &fakeQueries{jobs: fleet, jobNext: "jc-2"}
	h := newTestHandler(cancelDeps(q, &fakeCanceller{}), accounts.RoleAdmin)

	body := get(t, h, "/console/activity?account=acct-1&op=service.restart&on_behalf_of=someone&outcome=success&window=1h&rc=rn:5&ro=5").Body.String()
	f := q.jobFilters[len(q.jobFilters)-1]
	if !isRunningNowRead(f) {
		t.Fatalf("Running now's read was narrowed by a stream filter: %+v", f)
	}
	if f.RequesterAccountID != "acct-1" {
		t.Errorf("Running now was asked for Account %q, want acct-1", f.RequesterAccountID)
	}

	// Links that keep the Account keep Running now's position; the ones that
	// change the Account reset it, because its set changes.
	hasPosition := func(href string) bool { return strings.Contains(href, "rc=rn%3A5") && strings.Contains(href, "ro=5") }
	if href := unescapeHref(t, hrefContaining(t, body, "kind=plan")); !hasPosition(href) {
		t.Errorf("a kind chip %q drops Running now's position", href)
	}
	refresh := regexp.MustCompile(`class="refreshbtn" href="([^"]*)"`).FindStringSubmatch(body)
	if refresh == nil || !hasPosition(unescapeHref(t, refresh[1])) {
		t.Errorf("Refresh drops Running now's position: %v", refresh)
	}
	if href := unescapeHref(t, hrefContaining(t, body, "jc=jc-2")); !hasPosition(href) {
		t.Errorf("Older %q drops Running now's position", href)
	}
	everyone := regexp.MustCompile(`<a href="([^"]*)">Show every Account</a>`).FindStringSubmatch(body)
	if everyone == nil {
		t.Fatal("no Show every Account link")
	}
	if href := unescapeHref(t, everyone[1]); strings.Contains(href, "rc=") || strings.Contains(href, "ro=") || strings.Contains(href, "account=") {
		t.Errorf("Show every Account %q keeps Running now's position or the Account", href)
	}
}

func TestActivity_RunningNowEmptyStates(t *testing.T) {
	h := func(q *fakeQueries) http.Handler {
		return newTestHandler(cancelDeps(q, &fakeCanceller{}), accounts.RoleAdmin)
	}
	section := func(q *fakeQueries, path string) string {
		s, _ := splitRunningNow(t, get(t, h(q), path).Body.String())
		return s
	}

	if s := section(&fakeQueries{}, "/console/activity"); !strings.Contains(s, "Nothing is running.") {
		t.Errorf("an empty section does not say so plainly:\n%s", s)
	}
	if s := section(&fakeQueries{}, "/console/activity?account=acct-1"); !strings.Contains(s, "This Account has nothing running.") {
		t.Errorf("an empty section under ?account= does not say that Account has nothing running:\n%s", s)
	}
	// A position past the end is not "nothing is running".
	if s := section(&fakeQueries{jobs: runningFleet(3, "acct-1")}, "/console/activity?rc=rn:9&ro=9"); !strings.Contains(s, "Nothing further is running.") || strings.Contains(s, "Nothing is running.") {
		t.Errorf("a page past the end does not say nothing further is running:\n%s", s)
	}
}

func TestActivity_RunningNowDrawsTheRawExecTierAsTheStreamDoes(t *testing.T) {
	rawExec := runningFleet(1, "acct-1")[0]
	rawExec.JobID, rawExec.ActionKind, rawExec.OperationName = "job-raw", jobs.ActionRawExec, ""
	named := runningFleet(1, "acct-1")[0]
	named.JobID, named.ActionKind, named.OperationName = "job-named", jobs.ActionOperation, "raw_exec"

	q := &fakeQueries{jobs: []capability.JobSummary{rawExec, named}}
	body := activityRunning(t, q, accounts.RoleAdmin, "/console/activity")
	section, stream := splitRunningNow(t, body)

	const chip = `<span class="chip" data-tier="raw_exec">Raw Exec</span>`
	entry := func(id string) string {
		s := section[strings.Index(section, `id="rn-`+id+`"`):]
		return s[:strings.Index(s, "</li>")]
	}
	if !strings.Contains(activityRowContaining(t, stream, `data-job-id="job-raw"`), chip) {
		t.Fatal("the stream row does not draw the Raw Exec chip this test compares against")
	}
	if !strings.Contains(entry("job-raw"), chip) {
		t.Errorf("the Raw Exec entry does not carry the stream's chip:\n%s", entry("job-raw"))
	}
	n := entry("job-named")
	if strings.Contains(n, "data-tier") {
		t.Errorf("an Operation named raw_exec carries the tier marker in Running now:\n%s", n)
	}
	if !strings.Contains(n, "<code>run_operation · raw_exec</code>") {
		t.Errorf("an Operation named raw_exec is not marked as a run_operation in Running now:\n%s", n)
	}
}

func TestActivity_RunningNowRangeIsNotClaimedWhenItCannotBeBacked(t *testing.T) {
	q := &fakeQueries{jobs: runningFleet(7, "acct-1")}
	body := activityRunning(t, q, accounts.RoleAdmin, "/console/activity?rc=rn:5&ro=99")
	section, _ := splitRunningNow(t, body)

	if !strings.Contains(section, "7 running") {
		t.Errorf("the total is not stated:\n%s", section)
	}
	if strings.Contains(section, "&ndash;") {
		t.Errorf("a stale ro makes the section claim a range the count cannot back:\n%s", section)
	}
}

// ?ro= only numbers the range. A hand-edited ?rc= with none has no known start,
// so the total stands alone; and an absurd ?ro= is dropped before it reaches
// arithmetic where Offset+n could wrap into a negative range.
func TestActivity_RunningNowDrawsNoRangeItCannotNumber(t *testing.T) {
	for name, path := range map[string]string{
		"rc without ro":      "/console/activity?rc=rn:5",
		"ro at the int max":  "/console/activity?rc=rn:5&ro=" + strconv.Itoa(math.MaxInt),
		"ro just past bound": "/console/activity?rc=rn:5&ro=" + strconv.Itoa(maxRunningOffset+1),
	} {
		q := &fakeQueries{jobs: runningFleet(7, "acct-1")}
		section, _ := splitRunningNow(t, activityRunning(t, q, accounts.RoleAdmin, path))

		if !strings.Contains(section, "7 running") {
			t.Errorf("%s: the total is not stated:\n%s", name, section)
		}
		if strings.Contains(section, "&ndash;") {
			t.Errorf("%s: a range is drawn that nothing can number:\n%s", name, section)
		}
		if strings.Contains(section, "ro=") {
			t.Errorf("%s: an unknown start is numbered in a link:\n%s", name, section)
		}
	}
}

func TestActivity_AFailedOrUnauditableRunningNowReadRefusesThePage(t *testing.T) {
	onRunningNow := func(f capability.JobFilter) bool { return isRunningNowRead(f) }

	failed := &fakeQueries{jobs: runningFleet(1, "acct-1"), jobsErrOn: onRunningNow}
	rec := get(t, newTestHandler(cancelDeps(failed, &fakeCanceller{}), accounts.RoleAdmin), "/console/activity")
	if rec.Code == http.StatusOK {
		t.Error("a failed Running now read still served the page")
	}
	if strings.Contains(rec.Body.String(), `class="jobcancel"`) {
		t.Error("a failed Running now read offers Cancel")
	}

	// The stream's read succeeds here; only an unauditable Running now read
	// can refuse the page, through the latch.
	unaudited := &fakeQueries{jobsErr: errors.Join(capability.ErrReadUnaudited, errQueryFailed)}
	rec = get(t, newTestHandler(cancelDeps(unaudited, &fakeCanceller{}), accounts.RoleViewer), "/console/activity?kind=refusal")
	if rec.Code == http.StatusOK {
		t.Fatal("an unauditable Running now read still served the page (ADR-0025 decision 4)")
	}
	for _, want := range []string{"audit trail", "refused"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("the refusal page does not say %q", want)
		}
	}
}

// A cursor from the other lane, pasted into ?rc=, is a refusal, never a quiet
// return to page one: a page-one reset would loop a paging client forever.
func TestActivity_AMalformedRunningNowCursorIsRefusedNotReset(t *testing.T) {
	q := &fakeQueries{jobs: runningFleet(7, "acct-1")}
	rec := get(t, newTestHandler(cancelDeps(q, &fakeCanceller{}), accounts.RoleAdmin), "/console/activity?rc=jc-2")

	if rec.Code == http.StatusOK {
		t.Fatalf("a foreign ?rc= was served: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `id="rn-job-0"`) {
		t.Error("a foreign ?rc= rendered page one of Running now")
	}
}

func TestRunningFor(t *testing.T) {
	for _, c := range []struct {
		ago  time.Duration
		want string
	}{
		{30 * time.Second, "under a minute"},
		{5 * time.Minute, "5m"},
		{2*time.Hour + 7*time.Minute, "2h 7m"},
		{50*time.Hour + 30*time.Minute, "2d 2h"},
	} {
		if got := runningFor(testNow.Add(-c.ago), testNow); got != c.want {
			t.Errorf("runningFor(%v ago) = %q, want %q", c.ago, got, c.want)
		}
	}
}
