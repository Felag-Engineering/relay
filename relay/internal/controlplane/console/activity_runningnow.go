package console

// activity_runningnow.go is Activity's Running now section (spec 04, D18): the
// Jobs still running, longest-running first, five to a page on their own
// cursor, holding the one Cancel a running Job draws on the page.
//
// It exists so a running Job is never out of sight however far back it
// started: the stream is ordered by time, so a Job that has run for hours sits
// pages down it, and a time window would hide it altogether. So the section
// follows ?account= and nothing else.
//
// The order, the paging and the total all come from the capability layer's
// Job query (JobFilter.Order, PageRequest.Cursor, JobPage.Matching), in one
// audited read. Nothing here sorts, filters or counts what the seam returned:
// that would be a second implementation of what the read lane already decides.

import (
	"context"
	"net/url"
	"strconv"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// runningNowPageSize is how many running Jobs one page of the section holds.
// A code constant, unreachable from any request (invariant 11).
const runningNowPageSize = 5

// maxRunningOffset bounds ?ro=. It only numbers a range, and a count beyond
// this cannot be real, so a larger one is dropped rather than carried into
// arithmetic where it could overflow into a negative range.
const maxRunningOffset = 1_000_000

// runningPos is Running now's own position: the store-owned opaque cursor, and
// how many entries precede this page. Offset is presentation only — it numbers
// "6–10" — and travels as its own parameter rather than inside the cursor, on
// lanePos's reasoning for jdone and adone: the cursor is the store's to encode.
type runningPos struct {
	Cursor string
	Offset int
}

// runningNowEntry is one running Job in the section. It deliberately shares
// nothing with activityRow's live handle (data-job-id, evliveslot): the
// stream's contract is that only the dispatch row carries that handle.
type runningNowEntry struct {
	JobID   string
	Anchor  string
	JobHref string

	Operation string
	Summary   string
	// RawExecTier is read from the Job's ActionKind by jobRowName and from
	// nothing else, exactly as on the stream.
	RawExecTier bool

	Principal     string
	Verified      bool
	RequesterKind string

	Started    string
	RunningFor string
	Resolved   int
	Total      int

	// CancelAction is set only for a role the route is mounted for and a Job
	// with Tasks still unresolved: Job detail's gate.
	CancelAction string
}

// runningNowView is the section as the template draws it.
type runningNowView struct {
	Entries []runningNowEntry

	// Matching is the total running, ignoring paging. From and To number the
	// entries on this page and are both zero when the count cannot back a
	// range (a stale or hand-edited ro), so the section states only the total.
	Matching int
	From, To int

	NextHref, FirstHref string
	Paged               bool
	AccountScoped       bool
}

// fetchRunningNow is the section's one audited read.
//
// Kind, window, Operation, on_behalf_of and outcome are deliberately absent
// from the filter: the section "follows ?account= and nothing else".
func fetchRunningNow(ctx context.Context, d Deps, caller capability.Principal, f activityFilter) (capability.JobPage, error) {
	running := jobs.JobStateRunning
	return d.Queries.QueryJobs(ctx, caller, capability.JobFilter{
		State:              &running,
		RequesterAccountID: f.Account,
		Order:              jobs.JobOrderOldestFirst,
		CountMatching:      true,
	}, capability.PageRequest{Limit: runningNowPageSize, Cursor: f.Running.Cursor})
}

// buildRunningNow renders one page the seam returned, in the order it came.
// It never re-sorts and never re-filters by State: the read lane decided both.
func buildRunningNow(pg capability.JobPage, f activityFilter, now time.Time, offerCancel bool) runningNowView {
	v := runningNowView{
		Matching:      pg.Matching,
		Paged:         f.Running != (runningPos{}),
		AccountScoped: f.Account != "",
	}
	for _, sum := range pg.Jobs {
		operation, tier := jobRowName(sum)
		e := runningNowEntry{
			JobID:         sum.JobID,
			Anchor:        "rn-" + sum.JobID,
			JobHref:       "/console/jobs/" + url.PathEscape(sum.JobID),
			Operation:     operation,
			Summary:       operation,
			RawExecTier:   tier,
			Principal:     sum.Requester,
			Verified:      sum.RequesterAccountID != "",
			RequesterKind: verifiedKind(sum.RequesterAccountID != "", sum.RequesterKind),
			Started:       sum.CreatedAt.UTC().Format("2006-01-02 15:04:05Z"),
			RunningFor:    runningFor(sum.CreatedAt, now),
			Resolved:      sum.Total - sum.Unresolved,
			Total:         sum.Total,
		}
		if e.Summary == "" {
			e.Summary = "dispatch"
		}
		if offerCancel && sum.Unresolved > 0 {
			e.CancelAction = cancelJobAction(sum.JobID)
		}
		v.Entries = append(v.Entries, e)
	}

	n := len(v.Entries)
	// A range is drawn only where its start is known: page one, or a later page
	// whose ?ro= said how many precede it. A hand-edited ?rc= with no ?ro= gets
	// the total alone rather than a range that would mislabel it "1–5".
	startKnown := !v.Paged || f.Running.Offset > 0
	if n > 0 && startKnown && f.Running.Offset+n <= pg.Matching {
		v.From, v.To = f.Running.Offset+1, f.Running.Offset+n
	}
	if pg.Next != "" {
		next := f
		next.Running = runningPos{Cursor: pg.Next}
		if startKnown {
			next.Running.Offset = f.Running.Offset + n
		}
		v.NextHref = next.href(f.Job, f.Audit)
	}
	if v.Paged {
		first := f
		first.Running = runningPos{}
		v.FirstHref = first.href(f.Job, f.Audit)
	}
	return v
}

// runningFor says how long a Job has been running, coarsely: it is an
// at-a-glance figure beside the exact start time, not a measurement.
func runningFor(start, now time.Time) string {
	d := now.Sub(start)
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + "m"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d/time.Hour)) + "h " + strconv.Itoa(int(d%time.Hour/time.Minute)) + "m"
	default:
		return strconv.Itoa(int(d/(24*time.Hour))) + "d " + strconv.Itoa(int(d%(24*time.Hour)/time.Hour)) + "h"
	}
}
