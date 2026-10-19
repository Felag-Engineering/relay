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

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/relay/relay/internal/events"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/policyview"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// reportedSnapshot stamps s with the receipt time policyview.Cache.Set would
// have stamped it with, so a screen test can assert the rendered timestamp
// without standing up the cache. In production the field is only ever written
// inside Set, from the Relay's own clock.
func reportedSnapshot(s policyview.Snapshot, at time.Time) policyview.Snapshot {
	s.ReportedAt = at
	return s
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

// fakeApprovals is the approval read seam: the one-record read Job detail
// makes.
type fakeApprovals struct {
	pending []approval.Request

	// resolved are records reachable by id but not in pending.
	resolved []approval.Request

	// approvalErr fails the one-record read as a wired store would: a runtime
	// failure, not an absence.
	approvalErr error
}

// Approval returns the real sentinel for an unknown id, as the capability
// layer does, so a test can tell "no such Request" from a store failure.
func (f *fakeApprovals) Approval(_ context.Context, id string) (approval.Request, error) {
	if f.approvalErr != nil {
		return approval.Request{}, f.approvalErr
	}
	for _, r := range append(append([]approval.Request(nil), f.pending...), f.resolved...) {
		if r.ID == id {
			return r, nil
		}
	}
	return approval.Request{}, approval.ErrNotFound
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
// fake that ignored Operations would let a join guard rot silently. Nothing
// here strips output either — the real QueryTasks does, and
// a test that wants to prove the Console gates on the declared risk class
// needs a seam that hands the bytes over anyway.
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

	// auditErrOn is the PER-FILTER failure hook. auditErr above is
	// all-or-nothing, which cannot express the case that matters: ONE query
	// failing while the rest succeed. A screen's graceful-degradation
	// branches are only reachable — and only assertable — through this.
	auditErrOn func(capability.AuditFilter) bool
	// jobsErrOn is the Job lane's twin: it fails ONE Job read (Running now's,
	// say) while the stream's succeeds.
	jobsErrOn func(capability.JobFilter) bool

	jobCalls   int
	auditCalls int

	// The recorded filters. Activity asserts on them: a screen
	// that applied a filter in Go after fetching an unfiltered page renders
	// identically and paginates wrongly, and nothing but this would notice.
	auditFilters []capability.AuditFilter
	jobFilters   []capability.JobFilter

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

	// nodes is the registry half of the lane (#450, and since #680 the ONLY
	// door: FleetReader/PolicyReader are gone). A screen test that renders
	// the fleet or a Node puts them here, through withFleet.
	nodes    []registry.Node
	nodesErr error

	// policy is the DISPLAY-ONLY Policy view DescribeNode attaches to its
	// result (#680), keyed by node id — set through withPolicy. A node id
	// absent from this map answers PolicyReported=false, never an empty
	// Policy.
	policy map[string]policyview.Snapshot

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
	// Job detail joins the park record on approval_id and the
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
	// Otherwise the cursor is a REAL offset, which a released-Job
	// walk depends on: the trail fans a dispatch out to one row
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

// ListNodes and DescribeNode are the lane's registry half (#450).
//
// They do NOT audit — nothing in this file does. That is deliberate and it is
// also the limit of what any screen test built on this fake can prove: it can
// assert that a screen asks the LANE, and it cannot assert that the lane
// records anything. The record itself is proved in read_audit_test.go against
// a real *capability.ReadLane over a real *auditsink.Sink, because a fake that
// answered "yes, audited" would be asserting its own implementation.
// ListNodes ignores selector — the fake does not resolve Selectors, and the
// lane's own tests (readlane_registry_test.go) prove that resolution; a
// screen test asserting a Selector actually filters the fleet does so
// against the real lane (read_audit_test.go's realLaneDeps), not this fake.
func (f *fakeQueries) ListNodes(context.Context, capability.Principal, string) (capability.NodeListing, error) {
	f.listNodeCalls++
	if f.nodesErr != nil {
		return capability.NodeListing{}, f.nodesErr
	}
	return capability.NodeListing{Nodes: f.nodes}, nil
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
		if snap, ok := f.policy[nodeID]; ok {
			d.Policy = snap
			d.PolicyReported = true
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
//
// It echoes kinds back UNCHANGED rather than canonicalising them the way the
// real lane does: handleEvents now builds Subscribe's argument from this
// return value (#539 fix round, Finding 1), and a fake that "helpfully"
// sorted/deduped here would hide a handler bug that skipped canonical
// resolution. Screen tests using this fake pass an already-valid kind name
// (e.g. "job"), so the pass-through is transparent for them.
func (f *fakeQueries) RecordEventSubscription(_ context.Context, _ capability.Principal, kinds []string, resumed bool) ([]string, error) {
	f.subscriptionKinds = append(f.subscriptionKinds, kinds)
	f.subscriptionResumed = append(f.subscriptionResumed, resumed)
	if f.subscriptionErr != nil {
		return nil, f.subscriptionErr
	}
	return kinds, nil
}

func (f *fakeQueries) QueryJobs(_ context.Context, _ capability.Principal, filter capability.JobFilter, page capability.PageRequest) (capability.JobPage, error) {
	f.jobCalls++
	f.jobFilters = append(f.jobFilters, filter)
	f.jobPages = append(f.jobPages, page)
	f.jobLimits = append(f.jobLimits, page.Limit)
	if f.jobsErr != nil {
		return capability.JobPage{}, f.jobsErr
	}
	if f.jobsErrOn != nil && f.jobsErrOn(filter) {
		return capability.JobPage{}, errQueryFailed
	}
	var out []capability.JobSummary
	for _, j := range f.jobs {
		switch {
		case filter.JobID != "" && j.JobID != filter.JobID:
		case filter.State != nil && j.State != *filter.State:
		case filter.RiskClass != nil && j.RiskClass != *filter.RiskClass:
		case filter.RequesterAccountID != "" && j.RequesterAccountID != filter.RequesterAccountID:
		case filter.Operation != "" && j.OperationName != filter.Operation:
		case !filter.Since.IsZero() && j.CreatedAt.Before(filter.Since):
		case !filter.Until.IsZero() && j.CreatedAt.After(filter.Until):
		default:
			out = append(out, j)
		}
	}
	if filter.Order == jobs.JobOrderOldestFirst {
		return oldestFirstJobPage(out, filter, page)
	}
	kept := limitRows(out, page.Limit)
	next := nextCursor(f.jobNext, page.Cursor, len(kept) < len(out))
	return capability.JobPage{Jobs: kept, Next: next, Limit: page.Limit}, nil
}

// oldestFirstJobPage answers an oldest-first read the way the real lane does:
// ascending by (CreatedAt, JobID), paged by a fake offset cursor ("rn:<n>"),
// with the matching total counted before paging when it was asked for. The
// stub cursor jobNext belongs to the newest-first stream and is not honoured
// here. A cursor that is not one this fake minted is refused, as the real lane
// refuses a foreign one, rather than reset to page one.
func oldestFirstJobPage(matches []capability.JobSummary, filter capability.JobFilter, page capability.PageRequest) (capability.JobPage, error) {
	sorted := append([]capability.JobSummary(nil), matches...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if !sorted[i].CreatedAt.Equal(sorted[j].CreatedAt) {
			return sorted[i].CreatedAt.Before(sorted[j].CreatedAt)
		}
		return sorted[i].JobID < sorted[j].JobID
	})
	out := capability.JobPage{Limit: page.Limit}
	if filter.CountMatching {
		out.Matching = len(sorted)
	}
	offset := 0
	if page.Cursor != "" {
		n, ok := strings.CutPrefix(page.Cursor, "rn:")
		var err error
		if offset, err = strconv.Atoi(n); !ok || err != nil {
			return capability.JobPage{}, capability.ErrInvalidCursor
		}
	}
	if offset > len(sorted) {
		offset = len(sorted)
	}
	rest := sorted[offset:]
	out.Jobs = limitRows(rest, page.Limit)
	if len(out.Jobs) < len(rest) {
		out.Next = "rn:" + strconv.Itoa(offset+len(out.Jobs))
	}
	return out, nil
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

// cancelCall records one CancelJob invocation's arguments (#595).
type cancelCall struct {
	Principal capability.Principal
	JobID     string
}

// fakeCanceller is the Cancel write seam. It records every call rather than
// deciding anything — the role floor and the audit row are the capability
// layer's, and a fake that "helpfully" refused a role would be asserting
// against its own implementation instead of the real RoleGate.
type fakeCanceller struct {
	calls []cancelCall
	err   error
}

func (f *fakeCanceller) CancelJob(_ context.Context, p capability.Principal, jobID string) error {
	f.calls = append(f.calls, cancelCall{Principal: p, JobID: jobID})
	return f.err
}

// The five calls fakeAccountAdmin records, each carrying exactly what the
// handler passed, so a test asserts what reached the seam rather than that
// something did.
type createAccountCall struct {
	Principal capability.Principal
	Account   accounts.Account
}

type setRoleCall struct {
	Principal capability.Principal
	ID        string
	Role      accounts.Role

	// From and Conditional are set only by SetAccountRoleFrom: the role the
	// write was a compare-and-set against (#912).
	From        accounts.Role
	Conditional bool
}

type setEnabledCall struct {
	Principal capability.Principal
	ID        string
	Enabled   bool
}

type mintCall struct {
	Principal capability.Principal
	AccountID string
	Name      string
	TTL       time.Duration
}

type revokeTokenCall struct {
	Principal capability.Principal
	TokenID   string
}

// sweepMintedTokenID and sweepMintedPlaintext are what fakeAccountAdmin's
// mint returns. The plaintext is distinctive on purpose, for the reason
// sweepTokenSecretHash gives: a substring search for it cannot match the rest
// of the Console by accident.
const (
	sweepMintedTokenID   = "tok-minted-1"
	sweepMintedPlaintext = accounts.TokenPrefix + "minted-plaintext-must-appear-once-4a1d" // test fixture, not a real credential
)

// fakeAccountAdmin is the AccountAdministrator write seam (#655). It records
// every call rather than deciding anything — the admin floor, the self-target
// rule, the last-enabled-admin rule and every audit row are the capability
// layer's, and a fake that "helpfully" enforced one would be asserting
// against its own implementation instead of the real domain.
//
// order, when non-nil, is a shared recorder both this fake and fakeAuth append
// to, so a test can assert StepUp happened strictly BEFORE the capability
// call.
type fakeAccountAdmin struct {
	creates []createAccountCall
	roles   []setRoleCall
	enables []setEnabledCall
	mints   []mintCall
	revokes []revokeTokenCall

	createErr error
	roleErr   error
	enableErr error

	// mintErr is returned TOGETHER WITH a live token and a live plaintext,
	// deliberately, because that is the only shape that actually occurs:
	// capability.MintAPIToken returns `tok, plaintext, fmt.Errorf(...)` when
	// the mint succeeded and the audit append failed
	// (capability/accountadmin.go, the "record audit entry" branch). A fake
	// returning a zero Plaintext here would prove nothing about the branch
	// the Console must survive, so do not "simplify" it back to one.
	mintErr   error
	revokeErr error

	order *[]string
}

func (f *fakeAccountAdmin) CreateAccount(_ context.Context, p capability.Principal, a accounts.Account) (accounts.Account, error) {
	f.creates = append(f.creates, createAccountCall{Principal: p, Account: a})
	f.record("CreateAccount")
	if f.createErr != nil {
		return accounts.Account{}, f.createErr
	}
	a.ID = "acct-created"
	return a, nil
}

func (f *fakeAccountAdmin) SetAccountRole(_ context.Context, p capability.Principal, id string, role accounts.Role) error {
	f.roles = append(f.roles, setRoleCall{Principal: p, ID: id, Role: role})
	f.record("SetAccountRole")
	return f.roleErr
}

func (f *fakeAccountAdmin) SetAccountRoleFrom(_ context.Context, p capability.Principal, id string, from, to accounts.Role) error {
	f.roles = append(f.roles, setRoleCall{Principal: p, ID: id, Role: to, From: from, Conditional: true})
	f.record("SetAccountRole")
	return f.roleErr
}

func (f *fakeAccountAdmin) SetAccountEnabled(_ context.Context, p capability.Principal, id string, enabled bool) error {
	f.enables = append(f.enables, setEnabledCall{Principal: p, ID: id, Enabled: enabled})
	f.record("SetAccountEnabled")
	return f.enableErr
}

func (f *fakeAccountAdmin) MintAPIToken(_ context.Context, p capability.Principal, accountID, name string, ttl time.Duration) (accounts.APIToken, accounts.Plaintext, error) {
	f.mints = append(f.mints, mintCall{Principal: p, AccountID: accountID, Name: name, TTL: ttl})
	f.record("MintAPIToken")
	tok := accounts.APIToken{ID: sweepMintedTokenID, AccountID: accountID, Name: name, CreatedAt: testNow}
	if ttl > 0 {
		tok.ExpiresAt = testNow.Add(ttl)
	}
	// The live plaintext accompanies the error on purpose — see mintErr.
	return tok, accounts.NewPlaintext(sweepMintedPlaintext), f.mintErr
}

func (f *fakeAccountAdmin) RevokeAPIToken(_ context.Context, p capability.Principal, id string) error {
	f.revokes = append(f.revokes, revokeTokenCall{Principal: p, TokenID: id})
	f.record("RevokeAPIToken")
	return f.revokeErr
}

func (f *fakeAccountAdmin) record(verb string) {
	if f.order != nil {
		*f.order = append(*f.order, verb)
	}
}

// fakeAuth implements the Console's six-method Authenticator (login.go)
// over nothing but recorded calls and configurable errors — no real store,
// no real session. Login and Logout are here only to satisfy the interface;
// stepup_test.go exercises real sessions through loginFixture (a REAL
// consoleauth.Service), which is what proves the session-lane properties
// this fake cannot: fakeAuth exists for the seam-level refusal branches
// (throttled, bad credential, no session), where a real store would only
// obscure what a handler does with the error it gets back.
type fakeAuth struct {
	loginErr  error
	logoutErr error
	stepUpErr error
	// stepUpID is the rotated identifier StepUp returns; unset, StepUp
	// returns the id it was given (no rotation).
	stepUpID consoleauth.SessionID
	// requireErr is what RequireStepUp returns when set; otherwise fresh
	// decides between nil and ErrStepUpRequired.
	requireErr   error
	fresh        bool
	requireCalls int
	// csrf is the token CSRFToken reports when no rotation happened; unset,
	// one is derived from the id.
	csrf        string
	stepUpCalls []struct {
		ID       consoleauth.SessionID
		Password accounts.Password
		Source   string
	}
	window time.Duration
	order  *[]string
}

func (f *fakeAuth) Login(context.Context, consoleauth.Attempt) (consoleauth.SessionID, consoleauth.Session, error) {
	return consoleauth.SessionID{}, consoleauth.Session{}, f.loginErr
}

func (f *fakeAuth) Logout(context.Context, consoleauth.SessionID, string) error {
	return f.logoutErr
}

func (f *fakeAuth) StepUp(_ context.Context, id consoleauth.SessionID, password accounts.Password, source string) (consoleauth.SessionID, error) {
	f.stepUpCalls = append(f.stepUpCalls, struct {
		ID       consoleauth.SessionID
		Password accounts.Password
		Source   string
	}{ID: id, Password: password, Source: source})
	if f.order != nil {
		*f.order = append(*f.order, "StepUp")
	}
	if f.stepUpErr != nil {
		return consoleauth.SessionID{}, f.stepUpErr
	}
	if !f.stepUpID.IsZero() {
		return f.stepUpID, nil
	}
	return id, nil
}

func (f *fakeAuth) RequireStepUp(consoleauth.SessionID) error {
	f.requireCalls++
	if f.order != nil {
		*f.order = append(*f.order, "RequireStepUp")
	}
	switch {
	case f.requireErr != nil:
		return f.requireErr
	case f.fresh:
		return nil
	}
	return consoleauth.ErrStepUpRequired
}

// CSRFToken reports f.csrf when no rotation happened, so a test that never
// rotates sees no phantom token change; after a rotation it derives a token
// from the new id.
func (f *fakeAuth) CSRFToken(id consoleauth.SessionID) consoleauth.CSRFToken {
	if f.stepUpID.IsZero() && f.csrf != "" {
		return consoleauth.ParseCSRFToken(f.csrf)
	}
	return consoleauth.ParseCSRFToken("fake-csrf-" + id.Reveal())
}

func (f *fakeAuth) StepUpWindow() time.Duration { return f.window }

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

// fakeAccounts is the Account read seam over in-memory slices.
//
// Every refusal branch handleAccounts has is drivable from here: err fails the
// Account list, tokensErr fails only the token panel, and an unset tokens
// entry is an Account with no tokens rather than an error.
//
// accountErr fails the SINGLE-Account read that handleSetAccountRole makes
// (#655), so the read-failure branch — which must demand step-up rather than
// skip it — is drivable too.
type fakeAccounts struct {
	accounts   []accounts.Account
	tokens     map[string][]accounts.APIToken
	err        error
	tokensErr  error
	accountErr error
}

func (f *fakeAccounts) Accounts(context.Context, capability.Principal) ([]accounts.Account, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.accounts, nil
}

func (f *fakeAccounts) Account(_ context.Context, _ capability.Principal, id string) (accounts.Account, error) {
	if f.accountErr != nil {
		return accounts.Account{}, f.accountErr
	}
	for _, a := range f.accounts {
		if a.ID == id {
			return a, nil
		}
	}
	return accounts.Account{}, accounts.ErrNotFound
}

func (f *fakeAccounts) APITokens(_ context.Context, _ capability.Principal, accountID string) ([]accounts.APIToken, error) {
	if f.tokensErr != nil {
		return nil, f.tokensErr
	}
	return f.tokens[accountID], nil
}

// foundingAdminFixture is the ONE Account a fresh Relay actually has.
//
// Every field is what EnsureFoundingAdmin (internal/store/accounts.go) really
// seeds: the reserved name, human, admin, enabled. LastSeenAt is deliberately
// ZERO — the row is created at startup, before anybody has signed in — which
// is what makes the day-one render exercise stamp's "—" rather than a
// timestamp somebody chose to make the assertion convenient.
func foundingAdminFixture() accounts.Account {
	return accounts.Account{
		ID:        "acct-founding",
		Name:      accounts.FoundingAdminName,
		Kind:      accounts.KindHuman,
		Role:      accounts.RoleAdmin,
		Enabled:   true,
		CreatedAt: testNow,
	}
}

// dayOneDeps is a fresh Relay: no Nodes, an empty trail, the fingerprints and
// the event seam wired. This is what the Console looks like on first boot, and
// several properties in spec 10 are only visible in it.
func dayOneDeps() Deps {
	d := renderableDeps()
	d = withFleet(d)
	d.Trust = fakeTrust{ca: testCAFingerprint, server: testServerFingerprint}
	d.Events = newFakeEvents()
	// Restated rather than inherited from renderableDeps, exactly as the
	// fleet is above: this is what a fresh Relay IS. EnsureFoundingAdmin seeded an
	// enabled human admin at startup who has never authenticated, so "day
	// one" for the Accounts screen is one row and not an empty table — see
	// accounts.go's header and the named skip in dayone_test.go.
	d.Accounts = &fakeAccounts{accounts: []accounts.Account{foundingAdminFixture()}}
	return d
}

// testNow is the fixed clock every screen test renders against, so a rendered
// relative time is an assertable string rather than a race with the wall clock.
var testNow = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

// renderableDeps is the smallest Deps that lets every read screen render.
// Screen tests start here and override the one seam they are about.
func renderableDeps() Deps {
	return Deps{
		Audit: fakeAudit{},
		// Every screen that reads through the capability layer's read lane
		// needs one wired, or its route answers 500 — a fixture route that
		// 500s is not a fixture. Activity (#422) reads that lane exclusively
		// and refuses rather than rendering an empty feed when it is missing,
		// so every sweep that renders every screen needs one. Its one Node
		// (#680: the fleet listing and node detail have no other door) is
		// what used to live on the now-deleted FleetReader seam.
		Queries: &fakeQueries{nodes: []registry.Node{{NodeID: "node-a", Connected: true}}},
		// THE SMALLEST TRUTHFUL ACCOUNT FIXTURE IS ONE, NOT ZERO. A Relay
		// that mounts the Console has run EnsureFoundingAdmin in the same
		// startup branch, so it cannot hold fewer Accounts than this — and a
		// fixture with none would make every incidental sweep render a state
		// production never reaches.
		Accounts: &fakeAccounts{accounts: []accounts.Account{foundingAdminFixture()}},
		Now:      func() time.Time { return testNow },
	}
}

// withFleet replaces d.Queries' registry half with nodes, copying the
// underlying *fakeQueries first so two Deps built from the same base never
// alias one fixture's mutation into another's (#680; replaces the deleted
// d.Fleet = fakeFleet{...} assignment — see fleetFixture and its callers).
// A d.Queries that is not yet a *fakeQueries starts from an empty one.
func withFleet(d Deps, nodes ...registry.Node) Deps {
	cp := fakeQueriesCopy(d)
	cp.nodes = nodes
	d.Queries = cp
	return d
}

// withPolicy replaces d.Queries' DISPLAY-ONLY Policy view with m, on the
// same copy-first discipline withFleet uses (#680; replaces the deleted
// d.Policy = fakePolicy{...} assignment).
func withPolicy(d Deps, m map[string]policyview.Snapshot) Deps {
	cp := fakeQueriesCopy(d)
	cp.policy = m
	d.Queries = cp
	return d
}

// fakeQueriesCopy returns a copy of d.Queries' underlying *fakeQueries, or a
// fresh one if d.Queries is not yet one — the shared first step withFleet
// and withPolicy both take.
func fakeQueriesCopy(d Deps) *fakeQueries {
	q, ok := d.Queries.(*fakeQueries)
	if !ok || q == nil {
		return &fakeQueries{}
	}
	cp := *q
	return &cp
}

// fleetNodes reads back the nodes a fixture built with withFleet holds,
// for the unit tests that call buildFleetView directly rather than through
// HTTP (#680; replaces the deleted d.Fleet.List() reads).
func fleetNodes(d Deps) []registry.Node {
	q, ok := d.Queries.(*fakeQueries)
	if !ok || q == nil {
		return nil
	}
	return q.nodes
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
		// Partly signed, by one human and one machine decider, so the
		// snapshot producer renders the Decisions table and both kind labels
		// (00-foundations.md, "Kind label") rather than an empty card.
		{ID: "ap-1", ExpiresAt: testNow.Add(time.Hour), Require: approval.Requirement{Count: 3},
			Decisions: []approval.Decision{
				{Account: "mike", AccountID: "acct-mike", Approve: true, Channel: approval.ChannelOutOfBand, DeciderHuman: true, At: testNow.Add(-time.Hour)},
				{Account: "gleipnir-prod", AccountID: sweepMachineAccountID, Approve: true, Channel: approval.ChannelInBand, OnBehalfOf: "carol", At: testNow.Add(-30 * time.Minute)},
			}},
	}}
	// Auth is wired so the route sweeps and the snapshot producer see the REAL
	// Accounts forms; AccountAdmin pairs with it.
	d.Auth = &fakeAuth{}
	// AccountAdmin is wired for the same reason: an unwired write seam would
	// silently make every sweep render the Accounts screen's honest-absence
	// branch instead of the five forms, so the CSRF-token sweep and the
	// snapshot producer would be asserting about a page that does not ship.
	d.AccountAdmin = &fakeAccountAdmin{}
	d.Audit = fakeAudit{records: []audit.Record{
		{Kind: audit.KindDispatch, JobID: "job-1", NodeID: "node-web-1", OperationName: "service.restart", Timestamp: testNow},
	}}
	d.Queries = &fakeQueries{
		// The fleet fleetFixture already put on the lane, carried forward:
		// this literal REPLACES d.Queries rather than extending it, and a
		// replacement with no nodes field would silently empty the fleet
		// every sweep test renders against (#680).
		nodes: fleetNodes(d),
		jobs: []capability.JobSummary{{
			JobID: "job-1", CreatedAt: testNow, OperationName: "service.restart",
			RiskClass: jobs.RiskClassMutate, Total: 1,
			Counts: map[jobs.Outcome]int{jobs.OutcomeSuccess: 1},
			// The requester as the Job row records it (#616), kind included,
			// so the sweeps and snapshots draw the requester's kind label.
			Requester: "gleipnir-prod", RequesterAccountID: sweepMachineAccountID, RequesterKind: "machine",
		}},
		tasks: []capability.TaskRow{{
			TaskID: "task-1", NodeID: "node-web-1", Outcome: jobs.OutcomeSuccess,
			RiskClass: jobs.RiskClassMutate, Stdout: []byte("restarted"),
		}},
		rows: []capability.AuditRow{
			{Kind: audit.KindDispatch, JobID: "job-1", OperationName: "service.restart"},
			// An agentCallKinds-matching row attributed to the machine
			// Account below, so the sweeps render the Accounts screen's
			// last-tool-call CELL rather than always taking its
			// honest-absence branch.
			{
				Kind:          audit.KindRead,
				OperationName: "list_nodes",
				Timestamp:     testNow.Add(-90 * time.Second),
				Verified: capability.VerifiedIdentity{
					AccountID:   sweepMachineAccountID,
					AccountName: "gleipnir-prod",
					Role:        string(accounts.RoleOperator),
				},
			},
		},
	}
	d.Accounts = sweepAccounts()
	return d
}

// sweepMachineAccountID is the machine Account the sweep fixture's agent-call
// row is attributed to. Named so the row and the Account cannot drift.
const sweepMachineAccountID = "acct-gleipnir"

// sweepAccounts is the RICH Account fixture: every shape the screen renders
// differently is present exactly once.
//
// The founding admin (never authenticated), a second human admin, a human
// viewer, a machine Account with calls on the trail, and a disabled Account —
// so the "disabled" word, the machine/human kind split and the two
// last-authentication branches are all walked by any sweep that renders this
// screen.
//
// One token carries a REAL SecretHash. A "no secret ever renders" test against
// a fixture with nothing to leak proves nothing at all.
func sweepAccounts() *fakeAccounts {
	return &fakeAccounts{
		accounts: []accounts.Account{
			foundingAdminFixture(),
			{
				ID: "acct-mike", Name: "mike", Kind: accounts.KindHuman,
				Role: accounts.RoleAdmin, Enabled: true,
				CreatedAt: testNow.Add(-30 * 24 * time.Hour), LastSeenAt: testNow.Add(-2 * time.Hour),
			},
			{
				ID: "acct-ana", Name: "ana", Kind: accounts.KindHuman,
				Role: accounts.RoleViewer, Enabled: true,
				CreatedAt: testNow.Add(-20 * 24 * time.Hour), LastSeenAt: testNow.Add(-45 * time.Minute),
			},
			{
				ID: sweepMachineAccountID, Name: "gleipnir-prod", Kind: accounts.KindMachine,
				Role: accounts.RoleOperator, Enabled: true,
				CreatedAt: testNow.Add(-10 * 24 * time.Hour), LastSeenAt: testNow.Add(-90 * time.Second),
			},
			{
				ID: "acct-retired", Name: "retired-ci", Kind: accounts.KindMachine,
				Role: accounts.RoleOperator, Enabled: false,
				CreatedAt: testNow.Add(-90 * 24 * time.Hour), LastSeenAt: testNow.Add(-60 * 24 * time.Hour),
			},
		},
		tokens: map[string][]accounts.APIToken{
			sweepMachineAccountID: {
				{
					ID: "tok-live", AccountID: sweepMachineAccountID, Name: "ci-deploy",
					SecretHash: []byte(sweepTokenSecretHash),
					CreatedAt:  testNow.Add(-10 * 24 * time.Hour),
					LastUsedAt: testNow.Add(-90 * time.Second),
				},
				{
					ID: "tok-revoked", AccountID: sweepMachineAccountID, Name: "laptop",
					CreatedAt: testNow.Add(-40 * 24 * time.Hour),
					ExpiresAt: testNow.Add(24 * time.Hour),
					RevokedAt: testNow.Add(-24 * time.Hour),
				},
			},
		},
	}
}

// sweepTokenSecretHash is the byte sequence that must never reach a rendered
// page. Distinctive on purpose: a substring search for it cannot match the
// rest of the Console by accident.
const sweepTokenSecretHash = "secret-hash-must-never-render-9f2c"

// consoleCallsRows is one page mixing an AI-agent's calls (API Token) with
// the signed-in operator's own page loads (Console session). The operator's
// reads name tools the AI-agent never calls, so a substring test cannot confuse
// the two.
func consoleCallsRows() []capability.AuditRow {
	agent := capability.VerifiedIdentity{
		AccountID: "acct-agent", AccountName: "gleipnir-prod", Role: "operator",
		Method: string(capability.AuthMethodAPIToken),
	}
	operator := capability.VerifiedIdentity{
		AccountID: "acct-mike", AccountName: "mike", Role: "admin",
		Method: string(capability.AuthMethodConsoleSession),
	}
	at := func(s int) time.Time { return testNow.Add(-time.Duration(s) * time.Second) }
	return []capability.AuditRow{
		{Kind: audit.KindRead, OperationName: "query_audit", Timestamp: at(5), Verified: operator},
		{Kind: audit.KindRead, OperationName: "query_jobs", Timestamp: at(6), Verified: operator},
		{Kind: audit.KindDispatch, ActionKind: "operation", OperationName: "service.restart",
			JobID: "job-9", NodeID: "node-a", Outcome: jobs.OutcomeSuccess, Timestamp: at(30), Verified: agent},
		{Kind: audit.KindRead, OperationName: "query_tasks", Timestamp: at(40), Verified: operator},
		{Kind: audit.KindRead, OperationName: "list_nodes", Timestamp: at(60), Verified: agent},
	}
}

func consoleCallsDeps() Deps {
	d := renderableDeps()
	d.Queries = &fakeQueries{rows: consoleCallsRows()}
	return d
}

// consoleActor is a Console-session identity: what a session cookie
// establishes, whoever or whatever is driving the browser.
var consoleActor = capability.VerifiedIdentity{
	AccountID: "acct-mike", AccountName: "mike", Role: "admin",
	Method: string(capability.AuthMethodConsoleSession),
}

// countingAccounts counts every call into the Account registry seam.
type countingAccounts struct{ calls int }

func (c *countingAccounts) Accounts(context.Context, capability.Principal) ([]accounts.Account, error) {
	c.calls++
	return nil, nil
}

func (c *countingAccounts) Account(context.Context, capability.Principal, string) (accounts.Account, error) {
	c.calls++
	return accounts.Account{}, nil
}

func (c *countingAccounts) APITokens(context.Context, capability.Principal, string) ([]accounts.APIToken, error) {
	c.calls++
	return nil, nil
}
