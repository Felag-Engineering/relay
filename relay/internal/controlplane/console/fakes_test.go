package console

// fakes_test.go holds the in-memory seams the screen tests render against.
//
// They are structs and maps rather than a store, a CA and a listener, which is
// the point of seams.go's narrow interfaces: a test that has to stand up a
// Relay to assert what a page says will not be written, and a page nobody
// asserts anything about drifts from its specification silently.

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/events"
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

// fakeApprovals is the approval read seam: the queue, one record, the
// same-shape lookup, and the two Grant reads.
//
// It is a POINTER type because shapeCalls has to survive the call. The
// assertion that matters most here is a NEGATIVE one — the Console must never
// ask about a record whose shape was never computed — and a counter on a value
// receiver would be incremented on a copy and read as zero however the handler
// behaved.
type fakeApprovals struct {
	pending []approval.Request

	// resolved are records reachable by id but not in the queue: the prior
	// approval a diff compares against is, by definition, no longer pending.
	resolved []approval.Request

	// grants are every Grant this Relay holds, live or not. ActiveGrants
	// filters them exactly as the capability layer does; GrantForApproval does
	// not, which is the whole reason that read exists.
	grants []approval.Grant

	grantsErr error

	// shapeCalls counts LastApprovedOfSameShape calls.
	shapeCalls int
}

func (f *fakeApprovals) PendingApprovals(context.Context) ([]approval.Request, error) {
	return f.pending, nil
}

func (f *fakeApprovals) Approval(_ context.Context, id string) (approval.Request, error) {
	for _, r := range append(append([]approval.Request(nil), f.pending...), f.resolved...) {
		if r.ID == id {
			return r, nil
		}
	}
	return approval.Request{}, errNotFound
}

// LastApprovedOfSameShape mirrors the store's own predicate rather than
// indexing a map the test filled in: approved, same shape key, not this record.
//
// The distinction is not pedantry. A fixture that mapped "prior" to "current"
// by hand would still find a prior after a change that made the two records'
// shape keys DIFFER — which is precisely the regression the Grant diff test is
// there to catch.
func (f *fakeApprovals) LastApprovedOfSameShape(_ context.Context, r approval.Request) (approval.Request, error) {
	f.shapeCalls++
	for _, prior := range f.resolved {
		if prior.State == approval.StateApproved && prior.ID != r.ID && prior.ShapeKey == r.ShapeKey {
			return prior, nil
		}
	}
	return approval.Request{}, approval.ErrNotFound
}

func (f *fakeApprovals) ActiveGrants(context.Context) ([]approval.Grant, error) {
	if f.grantsErr != nil {
		return nil, f.grantsErr
	}
	var out []approval.Grant
	for _, g := range f.grants {
		if g.Active(testNow) {
			out = append(out, g)
		}
	}
	return out, nil
}

func (f *fakeApprovals) GrantForApproval(_ context.Context, requestID string) (approval.Grant, error) {
	// The store is down, which is NOT ErrGrantNotFound: the two answers are
	// what the capability layer keeps distinct by letting the sentinel travel
	// unwrapped, and a fake that collapsed them could not test the difference.
	if f.grantsErr != nil {
		return approval.Grant{}, f.grantsErr
	}
	for _, g := range f.grants {
		if g.RequestID == requestID {
			return g, nil
		}
	}
	return approval.Grant{}, approval.ErrGrantNotFound
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
		// ApprovalID and GrantID are honoured for the same reason JobID is:
		// the approval object joins the park record on approval_id and the
		// released-Job list on grant_id, and a fake that returned every row
		// would let a screen that dropped either filter render perfectly.
		if filter.ApprovalID != "" && row.ApprovalID != filter.ApprovalID {
			continue
		}
		if filter.GrantID != "" && row.GrantID != filter.GrantID {
			continue
		}
		if len(filter.Kinds) > 0 && !containsString(filter.Kinds, row.Kind) {
			continue
		}
		out = append(out, row)
	}

	// Cursor paging, because the released-Job walk depends on it: the trail
	// fans a dispatch out to one row PER NODE, so a Grant over many Nodes
	// needs several pages before a second Job appears at all.
	start := 0
	if page.Cursor != "" {
		n, err := strconv.Atoi(page.Cursor)
		if err != nil {
			return capability.AuditPage{}, capability.ErrInvalidCursor
		}
		start = n
	}
	if start > len(out) {
		start = len(out)
	}
	out = out[start:]
	next := ""
	if page.Limit > 0 && len(out) > page.Limit {
		next = strconv.Itoa(start + page.Limit)
	}
	return capability.AuditPage{Rows: limitRows(out, page.Limit), Next: next, Limit: page.Limit}, nil
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

// fakeTrust is the fingerprint seam: two strings and nothing else, which is
// the whole shape of TrustReader.
type fakeTrust struct{ ca, server string }

func (f fakeTrust) CAFingerprint() string     { return f.ca }
func (f fakeTrust) ServerFingerprint() string { return f.server }

// testCAFingerprint and testServerFingerprint are shaped like the real thing:
// 64 lowercase hex characters, so a test asserting the screen shortens one and
// keeps the full value in a title is asserting against a realistic value.
const (
	testCAFingerprint     = "5f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
	testServerFingerprint = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
)

// fakeEvents is the live seam, wrapping a REAL *events.Bus rather than a
// hand-rolled stub: the resume, gap and eviction semantics a day-one test
// exercises are then the ones that ship, not a second implementation of them.
//
// It records the Subscriptions it hands out so a test can assert the handler
// CLOSED its own — a leaked Subscription stays in the bus forever and every
// later publish fans out to a channel nobody reads.
type fakeEvents struct {
	bus *events.Bus

	mu   sync.Mutex
	subs []*events.Subscription
}

func newFakeEvents(opts ...events.Option) *fakeEvents {
	return &fakeEvents{bus: events.NewBus(opts...)}
}

func (f *fakeEvents) Subscribe(kinds []events.Kind, lastEventID string) *events.Subscription {
	sub := f.bus.Subscribe(kinds, lastEventID)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subs = append(f.subs, sub)
	return sub
}

func (f *fakeEvents) Recent(kinds []events.Kind, n int) []events.Event {
	return f.bus.Recent(kinds, n)
}

func (f *fakeEvents) RetentionWindow() time.Duration { return f.bus.RetentionWindow() }

// publish puts one enrollment attempt on the bus, exactly as internal/eventsink
// does in production.
func (f *fakeEvents) publish(e events.EnrollmentEvent) { f.bus.PublishEnrollment(e) }

// subscriptions counts the Subscriptions handed out so far.
func (f *fakeEvents) subscriptions() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.subs)
}

// subscription returns the nth Subscription handed out, or nil.
func (f *fakeEvents) subscription(n int) *events.Subscription {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n >= len(f.subs) {
		return nil
	}
	return f.subs[n]
}

// dayOneDeps is a fresh Relay: no Nodes, an empty trail, the fingerprints and
// the event seam wired. This is what the Console looks like on first boot, and
// several properties in spec 10 are only visible in it.
func dayOneDeps() Deps {
	d := renderableDeps()
	d.Fleet = fakeFleet{}
	d.Trust = fakeTrust{ca: testCAFingerprint, server: testServerFingerprint}
	d.Events = newFakeEvents()
	return d
}

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
