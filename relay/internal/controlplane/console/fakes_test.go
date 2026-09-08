package console

// fakes_test.go holds the in-memory seams the screen tests render against.
//
// They are structs and maps rather than a store, a CA and a listener, which is
// the point of seams.go's narrow interfaces: a test that has to stand up a
// Relay to assert what a page says will not be written, and a page nobody
// asserts anything about drifts from its specification silently.

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/events"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
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

// errQueryFailed is what a per-filter failure hook returns: a store that is
// wired and running and failed this one query, which is a different page from
// a seam that was never wired.
const errQueryFailed = constErr("the query lane failed")

// fakeQueries is the capability layer's read lane (#441) over in-memory
// slices.
//
// Filters, limits and cursors are HONOURED, and every filter and page limit
// is recorded: a fake that ignored the page size would let a "renders no list
// at 10,000" test pass while the real screen fetched ten thousand rows, and a
// fake that ignored Operations would let read egress's join guard rot
// silently. Nothing here strips output either — the real QueryTasks does, and
// a test that wants to prove the Console gates on the declared risk class
// needs a seam that hands the bytes over anyway.
//
// AuditReach's DistinctTargets is computed with THE SAME key function the
// screen uses, which makes the headline and the table agree BY CONSTRUCTION.
// That is convenient and it is also exactly what hides the one divergence
// worth knowing about: the store's COALESCE stops at the first target key
// PRESENT and readTargetName stops at the first one NON-EMPTY. Only a
// store-level test can see that; nothing here can.
type fakeQueries struct {
	jobs  []capability.JobSummary
	tasks []capability.TaskRow
	rows  []capability.AuditRow

	// taskJobID is the Job the tasks belong to. Empty means "any", for the
	// fixtures that do not care.
	taskJobID string

	jobsErr   error
	tasksErr  error
	auditErr  error
	reachErr  error
	countsErr error

	// reachStub and countsStub answer the two AGGREGATE methods with canned
	// values, per filter. The aggregates are the page's exact figures and the
	// pages below them are deliberately short, so a test that needs "the
	// headline says 3 and the sample holds 1" cannot express itself through
	// rows alone — the in-memory computation would make the two agree.
	reachStub  func(capability.AuditFilter) capability.Reach
	countsStub func(capability.AuditFilter) []capability.PrincipalBucket

	// The PER-FILTER failure hooks. reachErr/auditErr/countsErr above are
	// all-or-nothing, which cannot express the case that matters: ONE query
	// of nine failing while the rest succeed. A screen's graceful-degradation
	// branches are only reachable — and only assertable — through these.
	reachErrOn  func(capability.AuditFilter) bool
	auditErrOn  func(capability.AuditFilter) bool
	countsErrOn func(capability.AuditFilter) bool

	jobCalls   int
	auditCalls int

	// The recorded filters. Read egress asserts on these: that no
	// dispatch-kind filter ever carries an empty Operations list, that a
	// scoped page scopes EVERY filter, and that an over-long caller value
	// never reaches the lane at all. Activity asserts on them too: a screen
	// that applied a filter in Go after fetching an unfiltered page renders
	// identically and paginates wrongly, and nothing but this would notice.
	auditFilters []capability.AuditFilter
	jobFilters   []capability.JobFilter
	reachFilters []capability.AuditFilter
	countFilters []capability.AuditFilter
	buckets      []time.Duration

	// auditPages and jobPages record every PageRequest in full, so a test can
	// assert that "older" carried BOTH lanes' cursors. auditLimits and
	// jobLimits keep just the Limit, which is what the "none of them was
	// unbounded" assertions read.
	auditPages []capability.PageRequest
	jobPages   []capability.PageRequest

	auditLimits []int
	jobLimits   []int
	taskLimits  []int

	// subscriptionKinds and subscriptionResumed record every
	// RecordEventSubscription call (#539), in order — the events-route
	// equivalent of auditFilters/jobFilters above. subscriptionErr makes the
	// call fail, for the fail-closed refusal path.
	subscriptionKinds   [][]string
	subscriptionResumed []bool
	subscriptionErr     error

	// nodes is the registry half of the lane (#450). A screen test that
	// renders the fleet or a Node puts them HERE rather than on fakeFleet:
	// the audited lane is the door those screens now use, and a fixture that
	// filled only fakeFleet would render an empty fleet and quietly assert
	// nothing.
	nodes    []registry.Node
	nodesErr error

	// listNodeCalls and describedNodes record the registry half's traffic.
	// describedNodes is what proves the pin bar resolves through the lane
	// rather than through a second door, and what a "does this screen
	// enumerate the fleet" assertion reads.
	listNodeCalls  int
	describedNodes []string

	// auditNext and jobNext are the cursors the fake reports as "there is
	// more", overriding the truncation rule below. A page whose Cursor is
	// already set returns no further one, so a test can follow "older"
	// exactly once without looping.
	auditNext string
	jobNext   string
}

// nextCursor is the fake's "there is more" rule for the stub protocol. The
// Job lane always uses it; the audit lane uses it only when a test set a stub,
// having a second, offset-based protocol of its own (see QueryAudit).
//
// By default it mirrors the real lane: a page that truncated reports a
// cursor, which is what makes "this table is a sample" assertable. An
// explicitly-set stub cursor overrides that and is one-shot — a request that
// already carried a cursor gets no further one — so a test can follow
// "older" exactly once instead of looping forever, which is the paging bug
// this branch exists to fix.
func nextCursor(stub, requested string, truncated bool) string {
	if stub != "" {
		if requested != "" {
			return ""
		}
		return stub
	}
	if truncated {
		return "cursor"
	}
	return ""
}

// matchRow applies the filter fields the screens actually use.
func matchRow(f capability.AuditFilter, row capability.AuditRow) bool {
	switch {
	case f.JobID != "" && row.JobID != f.JobID:
		return false
	// ApprovalID and GrantID are honoured for the same reason JobID is: the
	// approval object joins the park record on approval_id and the
	// released-Job list on grant_id, and a fake that returned every row would
	// let a screen that dropped either filter render perfectly.
	case f.ApprovalID != "" && row.ApprovalID != f.ApprovalID:
		return false
	case f.GrantID != "" && row.GrantID != f.GrantID:
		return false
	case len(f.Kinds) > 0 && !containsString(f.Kinds, row.Kind):
		return false
	case len(f.Operations) > 0 && !containsString(f.Operations, row.OperationName):
		return false
	case f.AccountID != "" && row.Verified.AccountID != f.AccountID:
		return false
	case f.NodeID != "" && row.NodeID != f.NodeID:
		return false
	case f.Outcome != nil && row.Outcome != *f.Outcome:
		return false
	case !f.Since.IsZero() && row.Timestamp.Before(f.Since):
		return false
	case !f.Until.IsZero() && row.Timestamp.After(f.Until):
		return false
	case f.ArgValuePrefix != "" && !strings.HasPrefix(row.Args[f.ArgKey], f.ArgValuePrefix):
		return false
	}
	return true
}

func (f *fakeQueries) matching(filter capability.AuditFilter) []capability.AuditRow {
	var out []capability.AuditRow
	for _, row := range f.rows {
		if matchRow(filter, row) {
			out = append(out, row)
		}
	}
	return out
}

func (f *fakeQueries) QueryAudit(_ context.Context, _ capability.Principal, filter capability.AuditFilter, page capability.PageRequest) (capability.AuditPage, error) {
	f.auditCalls++
	f.auditFilters = append(f.auditFilters, filter)
	f.auditPages = append(f.auditPages, page)
	f.auditLimits = append(f.auditLimits, page.Limit)
	if f.auditErr != nil {
		return capability.AuditPage{}, f.auditErr
	}
	if f.auditErrOn != nil && f.auditErrOn(filter) {
		return capability.AuditPage{}, errQueryFailed
	}
	out := f.matching(filter)

	// Two paging protocols, because the two screens need different things of
	// this fake and neither can serve the other.
	//
	// A test that sets auditNext drives the STUB protocol: the first page
	// reports that opaque cursor and a request already carrying one reports
	// none, so "Older" can be followed exactly once instead of forever —
	// the paging-termination bug this branch exists to fix. A stub is not an
	// offset and must never be parsed as one.
	//
	// Otherwise the cursor is a REAL offset, which the approval object's
	// released-Job walk depends on: the trail fans a dispatch out to one row
	// PER NODE, so a Grant over many Nodes needs several pages before a
	// second Job appears at all.
	if f.auditNext != "" {
		kept := limitRows(out, page.Limit)
		next := nextCursor(f.auditNext, page.Cursor, len(kept) < len(out))
		return capability.AuditPage{Rows: kept, Next: next, Limit: page.Limit}, nil
	}

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

func (f *fakeQueries) AuditCounts(_ context.Context, _ capability.Principal, filter capability.AuditFilter, bucket time.Duration) ([]capability.PrincipalBucket, error) {
	f.countFilters = append(f.countFilters, filter)
	f.buckets = append(f.buckets, bucket)
	if f.countsErr != nil {
		return nil, f.countsErr
	}
	if f.countsErrOn != nil && f.countsErrOn(filter) {
		return nil, errQueryFailed
	}
	if f.countsStub != nil {
		return f.countsStub(filter), nil
	}
	type key struct {
		accountID string
		start     time.Time
	}
	counts := map[key]*capability.PrincipalBucket{}
	var order []key
	for _, row := range f.matching(filter) {
		k := key{accountID: row.Verified.AccountID, start: row.Timestamp.Truncate(bucket)}
		b, seen := counts[k]
		if !seen {
			b = &capability.PrincipalBucket{
				AccountID: k.accountID, AccountName: row.Verified.AccountName, Start: k.start,
			}
			counts[k] = b
			order = append(order, k)
		}
		b.Count++
	}
	out := make([]capability.PrincipalBucket, 0, len(order))
	for _, k := range order {
		out = append(out, *counts[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].AccountID != out[j].AccountID {
			return out[i].AccountID < out[j].AccountID
		}
		return out[i].Start.Before(out[j].Start)
	})
	return out, nil
}

func (f *fakeQueries) AuditReach(_ context.Context, _ capability.Principal, filter capability.AuditFilter) (capability.Reach, error) {
	f.reachFilters = append(f.reachFilters, filter)
	if f.reachErr != nil {
		return capability.Reach{}, f.reachErr
	}
	if f.reachErrOn != nil && f.reachErrOn(filter) {
		return capability.Reach{}, errQueryFailed
	}
	if f.reachStub != nil {
		return f.reachStub(filter), nil
	}
	targets, nodes := map[string]bool{}, map[string]bool{}
	reach := capability.Reach{}
	for _, row := range f.matching(filter) {
		reach.Calls++
		targets[readTargetOf(factsOfRow(row))] = true
		if row.NodeID != "" {
			nodes[row.NodeID] = true
		}
	}
	reach.DistinctTargets = len(targets)
	reach.DistinctNodes = len(nodes)
	return reach, nil
}

// ListNodes and DescribeNode are the lane's registry half (#450).
//
// They do NOT audit — nothing in this file does. That is deliberate and it is
// also the limit of what any screen test built on this fake can prove: it can
// assert that a screen asks the LANE, and it cannot assert that the lane
// records anything. The record itself is proved in read_audit_test.go against
// a real *capability.Service over a real *auditsink.Sink, because a fake that
// answered "yes, audited" would be asserting its own implementation.
func (f *fakeQueries) ListNodes(context.Context, capability.Principal) ([]registry.Node, error) {
	f.listNodeCalls++
	if f.nodesErr != nil {
		return nil, f.nodesErr
	}
	return f.nodes, nil
}

func (f *fakeQueries) DescribeNode(_ context.Context, _ capability.Principal, nodeID string) (capability.NodeDetail, error) {
	f.describedNodes = append(f.describedNodes, nodeID)
	if f.nodesErr != nil {
		return capability.NodeDetail{}, f.nodesErr
	}
	for _, n := range f.nodes {
		if n.NodeID != nodeID {
			continue
		}
		d := capability.NodeDetail{Node: n}
		// The peer counts are computed the way the real lane computes them,
		// not stubbed: a screen asserting "3 Nodes share this fingerprint"
		// must be asserting the same arithmetic production runs.
		for _, other := range f.nodes {
			if n.PolicyFingerprint != "" && other.PolicyFingerprint == n.PolicyFingerprint {
				d.PolicyPeers++
			}
			if n.TemplateSetFingerprint != "" && other.TemplateSetFingerprint == n.TemplateSetFingerprint {
				d.TemplatePeers++
			}
		}
		return d, nil
	}
	return capability.NodeDetail{}, capability.ErrNodeNotFound
}

// RecordEventSubscription is the events route's half of the read lane
// (#539). It never builds a real audit.Record — nothing that is not the
// production sink should be able to claim it audited anything
// (read_audit_test.go's own doc comment) — so tests that need a REAL record
// use realLaneDeps instead. This fake exists only to (a) let screen tests
// that do not care about auditing render at all, and (b) let a test assert
// what handleEvents PASSED, via subscriptionKinds/subscriptionResumed.
func (f *fakeQueries) RecordEventSubscription(_ context.Context, _ capability.Principal, kinds []string, resumed bool) error {
	f.subscriptionKinds = append(f.subscriptionKinds, kinds)
	f.subscriptionResumed = append(f.subscriptionResumed, resumed)
	return f.subscriptionErr
}

func (f *fakeQueries) QueryJobs(_ context.Context, _ capability.Principal, filter capability.JobFilter, page capability.PageRequest) (capability.JobPage, error) {
	f.jobCalls++
	f.jobFilters = append(f.jobFilters, filter)
	f.jobPages = append(f.jobPages, page)
	f.jobLimits = append(f.jobLimits, page.Limit)
	if f.jobsErr != nil {
		return capability.JobPage{}, f.jobsErr
	}
	var out []capability.JobSummary
	for _, j := range f.jobs {
		switch {
		case filter.JobID != "" && j.JobID != filter.JobID:
		case filter.RiskClass != nil && j.RiskClass != *filter.RiskClass:
		case filter.RequesterAccountID != "" && j.RequesterAccountID != filter.RequesterAccountID:
		case filter.Operation != "" && j.OperationName != filter.Operation:
		case !filter.Since.IsZero() && j.CreatedAt.Before(filter.Since):
		case !filter.Until.IsZero() && j.CreatedAt.After(filter.Until):
		default:
			out = append(out, j)
		}
	}
	kept := limitRows(out, page.Limit)
	next := nextCursor(f.jobNext, page.Cursor, len(kept) < len(out))
	return capability.JobPage{Jobs: kept, Next: next, Limit: page.Limit}, nil
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

	// onSubscribe, when set, is called synchronously from Subscribe AFTER
	// the real bus has handed out a Subscription. read_audit_test.go's
	// driveStream uses it to cancel the request's own context at exactly
	// the point a real disconnecting client would — deterministically,
	// with no sleep and no goroutine, which is what lets a streaming route
	// be driven by the classification sweep at all (#539).
	onSubscribe func()

	mu   sync.Mutex
	subs []*events.Subscription
}

func newFakeEvents(opts ...events.Option) *fakeEvents {
	return &fakeEvents{bus: events.NewBus(opts...)}
}

func (f *fakeEvents) Subscribe(kinds []events.Kind, lastEventID string) *events.Subscription {
	sub := f.bus.Subscribe(kinds, lastEventID)
	f.mu.Lock()
	f.subs = append(f.subs, sub)
	f.mu.Unlock()
	if f.onSubscribe != nil {
		f.onSubscribe()
	}
	return sub
}

func (f *fakeEvents) Recent(kinds []events.Kind, n int) []events.Event {
	return f.bus.Recent(kinds, n)
}

func (f *fakeEvents) RetentionWindow() time.Duration { return f.bus.RetentionWindow() }

// publish puts one enrollment attempt on the bus, exactly as internal/eventsink
// does in production.
func (f *fakeEvents) publish(e events.EnrollmentEvent) { f.bus.PublishEnrollment(e) }

// publishJob puts one Job-grained transition on the bus, as the execution
// path does in production.
func (f *fakeEvents) publishJob(e events.JobEvent) { f.bus.PublishJob(e) }

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
		// Every screen that reads through the capability layer's read lane
		// needs one wired, or its route answers 500 — a fixture route that
		// 500s is not a fixture. Activity (#422) reads that lane exclusively
		// and refuses rather than rendering an empty feed when it is missing,
		// so every sweep that renders every screen needs one.
		Queries: &fakeQueries{},
		Now:     func() time.Time { return testNow },
	}
}

// withExecution returns d with the console_execution mirror set, so a test
// reads as "this Relay has execution on" rather than as a struct literal that
// has to repeat every seam.
func withExecution(d Deps, on bool) Deps {
	d.Execution = on
	return d
}

// sweepFixture is fleetFixture (screens_test.go) wired with the objects the
// parameterised routes name in fixtureIDs: job-1 and ap-1. Node detail already
// resolves against fleetFixture's node-web-1.
//
// A route-table sweep that asserts "reachable ⇒ non-404" needs every walked
// object to genuinely exist, or a missing fixture 404s for EVERY role — the
// same shape as a role-gate refusal — and the sweep cannot tell "this role
// cannot reach it" apart from "this fixture has no such object". #464's
// per-role reachability tests use this rather than fleetFixture directly for
// exactly that reason.
func sweepFixture() Deps {
	d := fleetFixture()
	d.Approvals = &fakeApprovals{pending: []approval.Request{
		{ID: "ap-1", ExpiresAt: testNow.Add(time.Hour), Require: approval.Requirement{Count: 1}},
	}}
	d.Audit = fakeAudit{records: []audit.Record{
		{Kind: audit.KindDispatch, JobID: "job-1", NodeID: "node-web-1", OperationName: "service.restart", Timestamp: testNow},
	}}
	d.Queries = &fakeQueries{
		jobs: []capability.JobSummary{{
			JobID: "job-1", CreatedAt: testNow, OperationName: "service.restart",
			RiskClass: jobs.RiskClassMutate, Total: 1,
			Counts: map[jobs.Outcome]int{jobs.OutcomeSuccess: 1},
		}},
		tasks: []capability.TaskRow{{
			TaskID: "task-1", NodeID: "node-web-1", Outcome: jobs.OutcomeSuccess,
			RiskClass: jobs.RiskClassMutate, Stdout: []byte("restarted"),
		}},
		rows: []capability.AuditRow{{Kind: audit.KindDispatch, JobID: "job-1", OperationName: "service.restart"}},
	}
	return d
}
