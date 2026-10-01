package console

// scale_test.go holds the two acceptance criteria that were asserted by a
// constant table and by an intermediate view struct, moved onto the RENDERED
// HTML: 01-fleet-view.md's "10,000 Nodes render without a list" (Acceptance
// box 3) and 13-job-detail.md's "a Job over 10,000 Nodes renders without a
// list" (Acceptance box 1). Both size bugs this package has shipped — the
// fleet wall and Job detail — were invisible to a struct-level assertion;
// only the rendered body sees them.
//
// Every bound below is asserted TWICE: once against the production constant
// it is derived from, so a deliberate change to the disclosure ladder moves
// this test with it; and once against a bare literal, because a
// constant-derived bound alone is satisfied by raising the constant —
// deviationRows = 500 would keep a constants-only test green while the page
// grew a 20,000-row list. Each literal is the number a human would call a
// list, not a number the code derives.

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// tenThousandNodes builds 10,000 registry.Node records over distinctValues
// values of labelKey, with offline(i) deciding which are connected. Every
// generated string is alphanumeric-with-hyphens (node-0, shard-17), so
// assertCSPClean's handler-attribute regexp — which also matches ordinary
// prose — cannot false-positive on fixture text.
//
// Every Node shares one PolicyFingerprint and DaemonVersion, exactly as
// fleetFixture's Nodes do, so the fixture's deviation tables are driven by
// offline alone and the row counts below are reproducible.
func tenThousandNodes(labelKey string, distinctValues int, offline func(i int) bool) []registry.Node {
	nodes := make([]registry.Node, 0, 10000)
	for i := 0; i < 10000; i++ {
		nodes = append(nodes, registry.Node{
			NodeID:            "node-" + strconv.Itoa(i),
			NodeLabels:        map[string]string{labelKey: labelKey + "-" + strconv.Itoa(i%distinctValues)},
			PolicyFingerprint: "aaaa111122223333",
			DaemonVersion:     "0.6.0",
			LastSeen:          testNow.Add(-4 * time.Second),
			Connected:         !offline(i),
		})
	}
	return nodes
}

// TestFleet_TenThousandNodesRenderWithoutAList is 01-fleet-view.md's
// Acceptance box 3, proven on the rendered HTTP response body of
// GET /console/ — the whole Register/Secure/Authenticator stack, not
// buildFleetView's struct.
func TestFleet_TenThousandNodesRenderWithoutAList(t *testing.T) {
	t.Run("a legible taxonomy", func(t *testing.T) {
		// 10,000 Nodes over 4 node:env values, every third Node offline so all
		// four cards open and the deviation table is drawn.
		nodes := tenThousandNodes("env", 4, func(i int) bool { return i%3 == 0 })
		d := renderableDeps()
		d = withFleet(d, nodes...)
		h := newTestHandler(d, accounts.RoleAdmin)

		rec := get(t, h, "/console/?group=env")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /console/?group=env = %d, want 200", rec.Code)
		}
		body := rec.Body.String()

		// "<tr" — the fleet template renders one <tr> per deviation row plus
		// one <thead><tr> per open card, which is the +1 below.
		rows := strings.Count(body, "<tr")
		if rows > 4*(deviationRows+1) {
			t.Errorf("rendered %d <tr>, want at most %d (4 cards * (deviationRows+1) for the thead row)", rows, 4*(deviationRows+1))
		}
		if rows > 200 {
			t.Errorf("rendered %d <tr>, want at most 200 (literal backstop)", rows)
		}
		if rows <= 4 {
			t.Errorf("rendered only %d <tr> — a page with no table at all", rows)
		}

		// One anchor per LISTED Node — the direct measurement of "is this a
		// list of the fleet".
		listed := strings.Count(body, `class="nodeid"`)
		if listed > 4*deviationRows {
			t.Errorf("listed %d Nodes, want at most %d (4 cards * deviationRows)", listed, 4*deviationRows)
		}
		if listed > 150 {
			t.Errorf("listed %d Nodes, want at most 150 (literal backstop)", listed)
		}
		if listed == 0 {
			t.Error("listed zero Nodes on a 10,000-Node fleet")
		}

		// The wall draws one cell per matched Node — that IS the design.
		// The backstop is on wallCap's own VALUE, not on the fixture size:
		// with exactly 10,000 fixture Nodes, "cells > 10000" can never fire
		// no matter how large wallCap grows, so it was a dead check.
		// Asserting wallCap directly is what fails when the constant is
		// raised.
		cells := strings.Count(body, `<a class="cell"`)
		if cells != wallCap {
			t.Errorf("drew %d wall cells, want exactly %d (wallCap)", cells, wallCap)
		}
		if wallCap > 10000 {
			t.Errorf("wallCap = %d, want at most 10000 (literal backstop)", wallCap)
		}

		if strings.Contains(body, "not drawn") {
			t.Error(`the page says a wall cell was "not drawn", but 10,000 Nodes == wallCap exactly — nothing should have been elided`)
		}

		// A generous byte ceiling: nothing above bounds the SIZE of the page,
		// only counts of specific elements within it, and a legible render
		// was measured at ~1.46 MB. See docs/design/console/01-fleet-view.md's
		// Acceptance box 3 note (and issue #470) for what "without a list"
		// should mean.
		if len(body) > 2_000_000 {
			t.Errorf("the rendered page is %d bytes; a fleet view that grows with the fleet has not solved the problem", len(body))
		}
	})

	t.Run("a high-cardinality key", func(t *testing.T) {
		// 10,000 Nodes over 250 node:shard values of 40 each, ALL offline —
		// the worst case: every drawn card then has more deviations than it
		// may list, so the two disclosure ladders (groupCards and
		// deviationRows) bind simultaneously.
		nodes := tenThousandNodes("shard", 250, func(int) bool { return true })
		d := renderableDeps()
		d = withFleet(d, nodes...)
		h := newTestHandler(d, accounts.RoleAdmin)

		rec := get(t, h, "/console/?group=shard")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /console/?group=shard = %d, want 200", rec.Code)
		}
		body := rec.Body.String()

		cards := strings.Count(body, `<section class="group`)
		if cards != groupCards {
			t.Errorf("drew %d group cards, want exactly %d (groupCards)", cards, groupCards)
		}
		if cards > 50 {
			t.Errorf("drew %d group cards, want at most 50 (literal backstop on groupCards)", cards)
		}

		rows := strings.Count(body, "<tr")
		if rows > groupCards*(deviationRows+1) {
			t.Errorf("rendered %d <tr>, want at most %d (groupCards * (deviationRows+1))", rows, groupCards*(deviationRows+1))
		}
		if rows > 1200 {
			t.Errorf("rendered %d <tr>, want at most 1200 (literal backstop)", rows)
		}

		listed := strings.Count(body, `class="nodeid"`)
		if listed > groupCards*deviationRows {
			t.Errorf("listed %d Nodes, want at most %d (groupCards * deviationRows)", listed, groupCards*deviationRows)
		}
		// Deliberately just above the current 1,000: a backstop that fails if
		// either constant is raised, not an endorsement of this size — see
		// docs/design/console/01-fleet-view.md's Acceptance box 3 note and
		// issue #470.
		if listed > 1100 {
			t.Errorf("listed %d Nodes, want at most 1100 (literal backstop)", listed)
		}
		// Every fixture Node is offline (the worst case), so a page that
		// drew forty EMPTY cards plus the truncation message would satisfy
		// every assertion above; this is the positive floor that rules that
		// out.
		if listed == 0 {
			t.Error("listed zero Nodes across 40 group cards, all offline")
		}

		if !strings.Contains(body, "groups are not shown") {
			t.Error(`the page truncated to groupCards cards but did not say so — a truncated page that looks complete is the worse failure`)
		}

		// A generous byte ceiling, as above. This is the worst-case render:
		// groupCards*deviationRows table rows is 1,000 by the current
		// constants — a scrollable list by any ordinary reading of
		// docs/design/console/01-fleet-view.md's Acceptance box 3 (the owner
		// question tracked there and on issue #470).
		if len(body) > 2_000_000 {
			t.Errorf("the rendered page is %d bytes; a fleet view that grows with the fleet has not solved the problem", len(body))
		}

		// Deliberately NOT asserted: the wall elision sentence. buildFleetView
		// truncates groups to groupCards (fleet.go:494-496) BEFORE buildWall
		// runs (fleet.go:501), so the wall only ever saw the 40 already-
		// truncated groups (1,600 Nodes) — the page's "N more Nodes are not
		// drawn — the wall caps at 10000 cells" sentence attributes that
		// elision to wallCap, which is not the cause. Reported on issue #470;
		// not fixed here.
	})
}

// tenThousandTaskJob builds a JobSummary and matching TaskRows: 9,000
// successes and the remaining 1,000 spread across the other seven outcomes,
// with every Task carrying a DISTINCT Stdout. That detail is load-bearing:
// with identical output the clusterer collapses the rows, and the test would
// measure clustering rather than the disclosure ladder.
func tenThousandTaskJob() capability.JobSummary {
	return oneJob(tenThousandTasks(), jobs.RiskClassMutate)
}

func tenThousandTasks() []capability.TaskRow {
	var tasks []capability.TaskRow
	for i := 0; i < 9000; i++ {
		tasks = append(tasks, mutateTask(fmt.Sprintf("node-success-%05d", i), jobs.OutcomeSuccess, fmt.Sprintf("ok-%05d", i)))
	}

	// The seven non-success outcomes, spread over the remaining 1,000 Tasks
	// so every group's own Count comfortably clears jobGroupRows (25).
	others := []struct {
		outcome jobs.Outcome
		name    string
		count   int
	}{
		{jobs.OutcomeDeniedByPolicy, "denied", 143},
		{jobs.OutcomeFailure, "failure", 143},
		{jobs.OutcomeTimeout, "timeout", 143},
		{jobs.OutcomeUnreachable, "unreachable", 143},
		{jobs.OutcomeVersionRefused, "versionrefused", 143},
		{jobs.OutcomeUnsupported, "unsupported", 143},
		{jobs.OutcomeCancelled, "cancelled", 142},
	}
	for _, o := range others {
		for i := 0; i < o.count; i++ {
			tasks = append(tasks, mutateTask(fmt.Sprintf("node-%s-%05d", o.name, i), o.outcome, fmt.Sprintf("out-%s-%05d", o.name, i)))
		}
	}
	return tasks
}

// TestJob_TenThousandNodesRenderWithoutAList is 13-job-detail.md's
// Acceptance box 1, proven on the rendered body of GET /console/jobs/{job_id}
// — with the fake read lane as the structural second witness (taskLimits,
// jobLimits).
//
// This sits beside job_test.go's pre-existing TestJob_TenThousandNodesRendersNoList,
// one word apart in name and different in what each owns: that test asserts
// the row count and the query-lane CALL COUNT (jobCalls, auditCalls) over a
// single fixture shape with every outcome present but not evenly spread. This
// one adds the per-group FETCH BOUND (taskLimits, one bounded page per
// non-success outcome and none for success), the ?show=success disclosure
// path, and the two wrapped-sentence assertions — none of which the older
// test covers. Both stay; neither subsumes the other.
func TestJob_TenThousandNodesRenderWithoutAList(t *testing.T) {
	sum := tenThousandTaskJob()

	t.Run("default render", func(t *testing.T) {
		q := &fakeQueries{jobs: []capability.JobSummary{sum}, tasks: tenThousandTasks()}
		body := jobBody(t, jobDeps(q), jobPath(""))

		if got := strings.Count(body, `<details class="ogroup"`); got != 8 {
			t.Errorf("rendered %d outcome groups, want 8 — all eight outcomes must render (13-job-detail.md box 2), "+
				"or the row bound below would be met by dropping groups instead of bounding them", got)
		}

		rows := strings.Count(body, `class="trow"`)
		if rows > 7*jobGroupRows {
			t.Errorf("rendered %d Task rows, want at most %d (7 non-success groups * jobGroupRows)", rows, 7*jobGroupRows)
		}
		if rows > 200 {
			t.Errorf("rendered %d Task rows, want at most 200 (literal backstop)", rows)
		}
		if rows <= 100 {
			t.Errorf("rendered only %d Task rows on a 10,000-Task Job — the disclosure ladder is not showing anything", rows)
		}

		// The template wraps this sentence across a source line
		// (job.go:1201-1203), so the rendered body carries a newline and two
		// spaces where the raw string would not — squashSpace normalises
		// that rather than pinning where the template happens to wrap.
		if got := squashSpace(body); !strings.Contains(got,
			"None of these 9000 Nodes is listed: at this size the count is the answer and the list is not.") {
			t.Error("the success group did not state that its count is the answer and the list is not")
		}

		if len(q.taskLimits) != 7 {
			t.Errorf("made %d Task queries, want 7 (one bounded page per non-success outcome, none for success)", len(q.taskLimits))
		}
		for _, limit := range q.taskLimits {
			if limit <= 0 || limit > jobGroupRows {
				t.Errorf("a Task query asked for %d rows, want a bounded page of at most %d (jobGroupRows)", limit, jobGroupRows)
			}
			if limit > 25 {
				t.Errorf("a Task query asked for %d rows, want at most 25 (literal backstop)", limit)
			}
		}
		if want := []int{1}; !slices.Equal(q.jobLimits, want) {
			t.Errorf("q.jobLimits = %v, want %v — the counts come from ONE aggregate row", q.jobLimits, want)
		}

		// The exact total is on the page, proving the count did not come
		// from the rows. The page does not render it group-separated, so
		// "10,000" is not the string to look for.
		if !strings.Contains(body, "10000") {
			t.Error(`the page does not state the exact total "10000"`)
		}
	})

	t.Run("until explicitly requested", func(t *testing.T) {
		q := &fakeQueries{jobs: []capability.JobSummary{sum}, tasks: tenThousandTasks()}
		body := jobBody(t, jobDeps(q), jobPath("show=success"))

		rows := strings.Count(body, `class="trow"`)
		if rows > 7*jobGroupRows+jobGroupExpanded {
			t.Errorf("rendered %d Task rows, want at most %d (7 groups at jobGroupRows, success expanded to jobGroupExpanded)",
				rows, 7*jobGroupRows+jobGroupExpanded)
		}
		if rows > 300 {
			t.Errorf("rendered %d Task rows, want at most 300 (literal backstop)", rows)
		}
		if rows <= 200 {
			t.Errorf("rendered only %d Task rows with the success group expanded", rows)
		}

		// When a group is expanded, jobRowLimit returns jobGroupExpanded
		// (job.go:861-871), so ShowAllHref stays empty and the "List the
		// first N" fragment does not render for success — it does for the
		// seven non-success groups, still capped at 25, which is why that
		// substring is not the witness here. This note wraps across
		// job.go:1201-1202, so squashSpace is needed here too; "the 100
		// listed" is unique to the success group (the other seven each say
		// "the 25 listed").
		if got := squashSpace(body); !strings.Contains(got,
			"The count above is exact; everything below is computed over the 100 listed.") {
			t.Error("the expanded success group did not state the bound it honoured")
		}

		// Eight fetches: seven non-success groups still at jobGroupRows, and
		// the expanded success page capped at jobGroupExpanded — never at the
		// group size.
		want := []int{25, 25, 25, 25, 25, 25, 25, 100}
		if !slices.Equal(q.taskLimits, want) {
			t.Errorf("q.taskLimits = %v, want %v", q.taskLimits, want)
		}
	})
}

// squashSpace collapses runs of whitespace, so an assertion about a SENTENCE
// survives the template being re-wrapped.
func squashSpace(s string) string { return strings.Join(strings.Fields(s), " ") }
