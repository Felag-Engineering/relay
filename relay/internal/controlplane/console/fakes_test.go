package console

// fakes_test.go holds the in-memory seams the screen tests render against.
//
// They are structs and maps rather than a store, a CA and a listener, which is
// the point of seams.go's narrow interfaces: a test that has to stand up a
// Relay to assert what a page says will not be written, and a page nobody
// asserts anything about drifts from its specification silently.

import (
	"context"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// fakeFleet is a registry read seam over a slice.
type fakeFleet struct{ nodes []registry.Node }

func (f fakeFleet) List() []registry.Node { return f.nodes }

func (f fakeFleet) Get(nodeID string) (registry.Node, bool) {
	for _, n := range f.nodes {
		if n.NodeID == nodeID {
			return n, true
		}
	}
	return registry.Node{}, false
}

// fakePolicy is a policyview read seam.
type fakePolicy map[string]policyview.Snapshot

func (f fakePolicy) Get(nodeID string) (policyview.Snapshot, bool) {
	s, ok := f[nodeID]
	return s, ok
}

// reportedSnapshot stamps s with the receipt time policyview.Cache.Set would
// have stamped it with, so a screen test can assert the rendered timestamp
// without standing up the cache. In production the field is only ever written
// inside Set, from the Relay's own clock.
func reportedSnapshot(s policyview.Snapshot, at time.Time) policyview.Snapshot {
	s.ReportedAt = at
	return s
}

// countingFleet records how many times a screen enumerated the fleet.
//
// It exists for one assertion: the comparison screen resolves the Nodes it was
// named and never calls List. That is what keeps it a hand-assembled 2-3 Node
// view rather than a fleet surface.
type countingFleet struct {
	fakeFleet
	lists *int
}

func (f countingFleet) List() []registry.Node {
	*f.lists++
	return f.fakeFleet.List()
}

// fakeAudit is an audit read seam over a slice, ordered oldest-first as the
// real repository orders it.
type fakeAudit struct {
	records []audit.Record
	err     error
}

func (f fakeAudit) List(context.Context) ([]audit.Record, error) { return f.records, f.err }

func (f fakeAudit) ByNode(_ context.Context, nodeID string) ([]audit.Record, error) {
	return f.filter(func(r audit.Record) bool { return r.NodeID == nodeID }), f.err
}

func (f fakeAudit) filter(keep func(audit.Record) bool) []audit.Record {
	var out []audit.Record
	for _, r := range f.records {
		if keep(r) {
			out = append(out, r)
		}
	}
	return out
}

// fakeApprovals is an approval read seam.
type fakeApprovals struct{ pending []approval.Request }

func (f fakeApprovals) PendingApprovals(context.Context) ([]approval.Request, error) {
	return f.pending, nil
}

func (f fakeApprovals) Approval(_ context.Context, id string) (approval.Request, error) {
	for _, r := range f.pending {
		if r.ID == id {
			return r, nil
		}
	}
	return approval.Request{}, errNotFound
}

type constErr string

func (e constErr) Error() string { return string(e) }

const errNotFound = constErr("not found")

// fakeQueries is the capability layer's read lane (#441) over in-memory
// slices.
//
// Limit and Outcome are HONOURED, and the per-method call counts are kept: a
// fake that ignored the page size would let a "renders no list at 10,000"
// test pass while the real screen fetched ten thousand rows, which is the one
// property this seam exists to make provable. Nothing here strips output
// either — the real QueryTasks does, and a test that wants to prove the
// Console gates on the declared risk class needs a seam that hands the bytes
// over anyway.
type fakeQueries struct {
	jobs  []capability.JobSummary
	tasks []capability.TaskRow
	rows  []capability.AuditRow

	// taskJobID is the Job the tasks belong to. Empty means "any", for the
	// fixtures that do not care.
	taskJobID string

	jobsErr  error
	tasksErr error
	auditErr error

	jobCalls   int
	auditCalls int
	// taskLimits records the Limit of every QueryTasks call, in order, so a
	// test can assert both how many Task queries one render costs and that
	// none of them was unbounded.
	taskLimits []int
}

func (f *fakeQueries) QueryAudit(_ context.Context, _ capability.Principal, filter capability.AuditFilter, page capability.PageRequest) (capability.AuditPage, error) {
	f.auditCalls++
	if f.auditErr != nil {
		return capability.AuditPage{}, f.auditErr
	}
	var out []capability.AuditRow
	for _, row := range f.rows {
		if filter.JobID != "" && row.JobID != filter.JobID {
			continue
		}
		if len(filter.Kinds) > 0 && !containsString(filter.Kinds, row.Kind) {
			continue
		}
		out = append(out, row)
	}
	return capability.AuditPage{Rows: limitRows(out, page.Limit), Limit: page.Limit}, nil
}

func (f *fakeQueries) AuditCounts(context.Context, capability.Principal, capability.AuditFilter, time.Duration) ([]capability.PrincipalBucket, error) {
	return nil, nil
}

func (f *fakeQueries) AuditReach(context.Context, capability.Principal, capability.AuditFilter) (capability.Reach, error) {
	return capability.Reach{}, nil
}

func (f *fakeQueries) QueryJobs(_ context.Context, _ capability.Principal, filter capability.JobFilter, page capability.PageRequest) (capability.JobPage, error) {
	f.jobCalls++
	if f.jobsErr != nil {
		return capability.JobPage{}, f.jobsErr
	}
	var out []capability.JobSummary
	for _, j := range f.jobs {
		if filter.JobID != "" && j.JobID != filter.JobID {
			continue
		}
		out = append(out, j)
	}
	return capability.JobPage{Jobs: limitRows(out, page.Limit), Limit: page.Limit}, nil
}

func (f *fakeQueries) QueryTasks(_ context.Context, _ capability.Principal, filter capability.TaskFilter, page capability.PageRequest) (capability.TaskPage, error) {
	f.taskLimits = append(f.taskLimits, page.Limit)
	if f.tasksErr != nil {
		return capability.TaskPage{}, f.tasksErr
	}
	var out []capability.TaskRow
	for _, t := range f.tasks {
		// JobID is honoured, not assumed: every fixture here holds one Job, so
		// a screen that fetched the WRONG Job's Tasks would otherwise render
		// perfectly and no test would notice.
		if filter.JobID != "" && f.taskJobID != "" && filter.JobID != f.taskJobID {
			continue
		}
		if filter.Outcome != nil && t.Outcome != *filter.Outcome {
			continue
		}
		out = append(out, t)
	}
	return capability.TaskPage{Tasks: limitRows(out, page.Limit), Limit: page.Limit}, nil
}

func limitRows[T any](rows []T, limit int) []T {
	if limit <= 0 || limit > len(rows) {
		return rows
	}
	return rows[:limit]
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// fakeFreeze is the Freeze read seam.
type fakeFreeze struct {
	frozen bool
	err    error
}

func (f fakeFreeze) Frozen(context.Context) (bool, error) { return f.frozen, f.err }

// testNow is the fixed clock every screen test renders against, so a rendered
// relative time is an assertable string rather than a race with the wall clock.
var testNow = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

// renderableDeps is the smallest Deps that lets every read screen render.
// Screen tests start here and override the one seam they are about.
func renderableDeps() Deps {
	return Deps{
		Fleet: fakeFleet{nodes: []registry.Node{{NodeID: "node-a", Connected: true}}},
		Audit: fakeAudit{},
		Now:   func() time.Time { return testNow },
	}
}

// withExecution returns d with the console_execution mirror set, so a test
// reads as "this Relay has execution on" rather than as a struct literal that
// has to repeat every seam.
func withExecution(d Deps, on bool) Deps {
	d.Execution = on
	return d
}
