package capability

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

// pipeline_order_test.go proves EX-3 and EX-4 at the capability seam: one
// dispatch consults its stages in the order the execution spec fixes, and each
// stage can only refuse, park or pass the call on.
//
// A "stage" here is one of EX-3's pipeline stages, not a Job's Stage
// (GLOSSARY.md, Stage). Every injectable seam appends to one ordered log, and
// each case compares the whole collapsed sequence, so one equality covers "in
// order", "no later stage consulted after a refusal" and "the refusal is
// audited, last". The empty-Selector refusal, the zero-match refusal and the
// EX-61 stage consult no seam: they are placed by which stages ran before them
// and that none ran after. A call that matched no Node, a Native or Raw Exec
// call and a Template call with a preset class never read a Node's report, so
// template resolution leaves no trace for them.

const (
	orderFreeze      = "freeze"
	orderResolve     = "selector resolution"
	orderTemplate    = "template resolution"
	orderAuthz       = "authorization"
	orderIdemLookup  = "idempotency lookup"
	orderCap         = "blast-radius cap"
	orderApproval    = "approval gate"
	orderDispatch    = "dispatch"
	orderTasksStored = "tasks stored"
	orderTaskSent    = "task sent"
	orderAudit       = "audit"
)

// orderLog is the one ordered record of which stage was consulted. The fan-out
// and Start's background accounting write to it from other goroutines.
type orderLog struct {
	mu     sync.Mutex
	events []string
}

func (l *orderLog) record(stage string) {
	l.mu.Lock()
	l.events = append(l.events, stage)
	l.mu.Unlock()
}

// stages returns the log with consecutive repeats collapsed: two Nodes read in
// one stage are one event, while a stage consulted again later still shows.
func (l *orderLog) stages() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, e := range l.events {
		if len(out) == 0 || out[len(out)-1] != e {
			out = append(out, e)
		}
	}
	return out
}

type orderFreezeStore struct {
	log *orderLog

	frozen    bool
	frozenErr error
}

func (f *orderFreezeStore) Frozen(context.Context) (bool, error) {
	f.log.record(orderFreeze)
	return f.frozen, f.frozenErr
}

func (f *orderFreezeStore) Engage(context.Context, string) error          { return nil }
func (f *orderFreezeStore) Release(context.Context, string, string) error { return nil }

// orderRegistry records Selector resolution, which reads the registry only
// through List.
type orderRegistry struct {
	registry.Repository
	log *orderLog
}

func (r *orderRegistry) List() []registry.Node {
	r.log.record(orderResolve)
	return r.Repository.List()
}

// orderVocab records Template resolution, which reads each matched Node's
// report through Get.
type orderVocab struct {
	log   *orderLog
	snaps staticVocab
}

func (v *orderVocab) Get(nodeID string) (nodevocab.Snapshot, bool) {
	v.log.record(orderTemplate)
	return v.snaps.Get(nodeID)
}

type orderAuthorizer struct {
	log *orderLog

	err error

	mu     sync.Mutex
	gotAct jobs.Action
}

func (a *orderAuthorizer) Authorize(_ context.Context, _ Principal, act jobs.Action, _ Selector) error {
	a.log.record(orderAuthz)
	a.mu.Lock()
	a.gotAct = act
	a.mu.Unlock()
	return a.err
}

func (a *orderAuthorizer) AuthorizeControl(context.Context, Principal, ControlAction) error {
	return nil
}

func (a *orderAuthorizer) act() jobs.Action {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.gotAct
}

// orderIdem records the lookup. Claim is the dispatch's Job-ID reservation, not
// an EX-3 stage, so it is counted and never logged.
type orderIdem struct {
	jobs.IdempotencyRepository
	log *orderLog

	lookupErr error

	mu     sync.Mutex
	claims int
}

func (i *orderIdem) Lookup(ctx context.Context, accountID, key string, notBefore time.Time) (jobs.IdempotencyRecord, bool, error) {
	i.log.record(orderIdemLookup)
	if i.lookupErr != nil {
		return jobs.IdempotencyRecord{}, false, i.lookupErr
	}
	return i.IdempotencyRepository.Lookup(ctx, accountID, key, notBefore)
}

func (i *orderIdem) Claim(ctx context.Context, rec jobs.IdempotencyRecord, notBefore time.Time) (jobs.IdempotencyRecord, bool, error) {
	i.mu.Lock()
	i.claims++
	i.mu.Unlock()
	return i.IdempotencyRepository.Claim(ctx, rec, notBefore)
}

func (i *orderIdem) claimCount() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.claims
}

type orderCapChecker struct {
	log *orderLog

	err error

	mu      sync.Mutex
	class   jobs.RiskClass
	matched int
}

func (c *orderCapChecker) Check(class jobs.RiskClass, matched int) error {
	c.log.record(orderCap)
	c.mu.Lock()
	c.class, c.matched = class, matched
	c.mu.Unlock()
	return c.err
}

func (c *orderCapChecker) saw() (jobs.RiskClass, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.class, c.matched
}

type orderApprovalGate struct {
	log *orderLog

	gated bool

	mu  sync.Mutex
	got approval.Dispatch
}

func (g *orderApprovalGate) Evaluate(d approval.Dispatch) (approval.Requirement, []string, bool) {
	g.log.record(orderApproval)
	g.mu.Lock()
	g.got = d
	g.mu.Unlock()
	return approval.Requirement{TTL: time.Hour}, []string{"order"}, g.gated
}

func (g *orderApprovalGate) saw() approval.Dispatch {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.got
}

type orderApprovals struct {
	*memApprovals

	byPlanHashErr error
}

func (a *orderApprovals) ByPlanHash(ctx context.Context, planHash string) (approval.Request, error) {
	if a.byPlanHashErr != nil {
		return approval.Request{}, a.byPlanHashErr
	}
	return a.memApprovals.ByPlanHash(ctx, planHash)
}

// orderJobs records the dispatch: CreateJob is the only way the engine mints a
// Job into the store.
type orderJobs struct {
	jobs.JobRepository
	log *orderLog

	createErr error

	mu      sync.Mutex
	created int
}

func (j *orderJobs) CreateJob(ctx context.Context, job jobs.Job) error {
	j.log.record(orderDispatch)
	if j.createErr != nil {
		return j.createErr
	}
	if err := j.JobRepository.CreateJob(ctx, job); err != nil {
		return err
	}
	j.mu.Lock()
	j.created++
	j.mu.Unlock()
	return nil
}

func (j *orderJobs) count() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.created
}

// orderTasks records the store's own Task write, so a Task persisted by any path
// is seen, not only one that went through the IntentRecorder.
type orderTasks struct {
	jobs.TaskRepository
	log *orderLog

	mu      sync.Mutex
	created int
}

func (t *orderTasks) CreateTask(ctx context.Context, task jobs.Task) error {
	t.log.record(orderTasksStored)
	if err := t.TaskRepository.CreateTask(ctx, task); err != nil {
		return err
	}
	t.mu.Lock()
	t.created++
	t.mu.Unlock()
	return nil
}

func (t *orderTasks) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.created
}

// orderIntents records the intent write. It shares its log label with
// orderTasks.CreateTask, which runs inside it, so the two collapse to one stage.
type orderIntents struct {
	inner *nonAtomicIntents
	log   *orderLog
}

func (n *orderIntents) RecordIntent(ctx context.Context, e AuditEntry, tasks []jobs.Task) error {
	n.log.record(orderTasksStored)
	return n.inner.RecordIntent(ctx, e, tasks)
}

func (n *orderIntents) entries() []AuditEntry { return n.inner.recorded() }

type orderConduit struct {
	log *orderLog

	mu   sync.Mutex
	sent []string
}

func (c *orderConduit) Connected(string) bool { return true }

func (c *orderConduit) Dispatch(_ context.Context, nodeID string, _ jobs.Task) (jobs.Result, error) {
	c.log.record(orderTaskSent)
	c.mu.Lock()
	c.sent = append(c.sent, nodeID)
	c.mu.Unlock()
	return jobs.Result{Outcome: jobs.OutcomeSuccess}, nil
}

func (c *orderConduit) Cancel(context.Context, string, string) error { return nil }

func (c *orderConduit) Query(context.Context, string, jobs.Action) (jobs.Verdict, error) {
	return jobs.Verdict{}, nil
}

func (c *orderConduit) sentTo() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Sorted(slices.Values(c.sent))
}

// orderAuditSink records an audit write and then keeps it, so a refusal, a park,
// a dispatch outcome and an audited read are all seen.
type orderAuditSink struct {
	*spyAuditSink
	log *orderLog
}

func (a *orderAuditSink) Record(ctx context.Context, e AuditEntry) error {
	a.log.record(orderAudit)
	return a.spyAuditSink.Record(ctx, e)
}

func (a *orderAuditSink) RecordRead(ctx context.Context, p Principal, tool, selector, nodeID, jobID string) error {
	a.log.record(orderAudit)
	return a.spyAuditSink.RecordRead(ctx, p, tool, selector, nodeID, jobID)
}

// events is every AuditEntry the call recorded.
func (a *orderAuditSink) events() []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]AuditEntry(nil), a.entries...)
}

// reads is how many read-audit rows the call wrote.
func (a *orderAuditSink) reads() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.readCalls)
}

// orderRefusals is the refusal kinds the metrics recorded, read under the lock.
func orderRefusals(m *recordingMetrics) []RefusalKind {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]RefusalKind(nil), m.refusals...)
}

var (
	orderCaller       = Principal{AccountID: "acct-order", Account: "alice"}
	orderWeb          = Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
	orderNoMatch      = Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "db"}}}
	orderTemplateCall = jobs.Action{Kind: jobs.ActionOperation, OperationName: "svc.status"}
)

const orderKey = "order-key"

// orderRig is a real Job engine over a real SQLite store, with a recording fake
// on every injectable seam.
type orderRig struct {
	log       *orderLog
	st        *store.Store
	freeze    *orderFreezeStore
	vocab     *orderVocab
	authz     *orderAuthorizer
	idem      *orderIdem
	cap       *orderCapChecker
	gate      *orderApprovalGate
	approvals *orderApprovals
	jobs      *orderJobs
	tasks     *orderTasks
	intents   *orderIntents
	conduit   *orderConduit
	audit     *orderAuditSink
	metrics   *recordingMetrics
	svc       *testSvc
}

func newOrderRig(t *testing.T, nodeIDs ...string) *orderRig {
	t.Helper()
	if len(nodeIDs) == 0 {
		nodeIDs = []string{"node-a", "node-b"}
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	// Registered first so it runs last: the Drain cleanup below must finish
	// before the store closes.
	t.Cleanup(func() { st.Close() })

	reg := registry.NewInMemory()
	snaps := staticVocab{}
	for _, id := range nodeIDs {
		report := registry.Report{NodeID: id, TemplateSetFingerprint: reportedTemplateSet}.
			WithNodeLabels(map[string]string{"role": "web"})
		if _, err := reg.Upsert(report); err != nil {
			t.Fatalf("seed registry: %v", err)
		}
		snaps[id] = reported(readTemplate("svc.status"), readTemplate("log.tail", "unit"))
	}

	log := &orderLog{}
	tasks := &orderTasks{TaskRepository: st.Tasks(), log: log}
	r := &orderRig{
		log:       log,
		st:        st,
		freeze:    &orderFreezeStore{log: log},
		vocab:     &orderVocab{log: log, snaps: snaps},
		authz:     &orderAuthorizer{log: log},
		idem:      &orderIdem{IdempotencyRepository: st.IdempotencyKeys(), log: log},
		cap:       &orderCapChecker{log: log},
		gate:      &orderApprovalGate{log: log},
		approvals: &orderApprovals{memApprovals: newMemApprovals()},
		jobs:      &orderJobs{JobRepository: st.Jobs(), log: log},
		tasks:     tasks,
		intents:   &orderIntents{inner: &nonAtomicIntents{tr: tasks}, log: log},
		conduit:   &orderConduit{log: log},
		audit:     &orderAuditSink{spyAuditSink: &spyAuditSink{}, log: log},
		metrics:   &recordingMetrics{},
	}
	r.svc = build(t, seams{
		reg:           &orderRegistry{Repository: reg, log: log},
		authz:         r.authz,
		cap:           r.cap,
		audit:         r.audit,
		freeze:        r.freeze,
		metrics:       r.metrics,
		gate:          r.gate,
		approvals:     r.approvals,
		approvalAuthz: &spyApprovalAuthorizer{},
		nodeVocab:     r.vocab,
		idem:          r.idem,
		jobsRepo:      r.jobs,
		tasksRepo:     tasks,
		conduit:       r.conduit,
		intents:       r.intents,
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := r.svc.Drain(ctx); err != nil {
			t.Errorf("background Jobs did not drain before the store closed: %v", err)
		}
	})
	return r
}

// start runs one keyed dispatch. A Job that started fans out and audits in the
// background, so a success waits for Done before anything is read; every error
// path audits before Start returns.
func (r *orderRig) start(t *testing.T, sel Selector, act jobs.Action) error {
	t.Helper()
	sj, err := r.svc.Start(context.Background(), orderCaller, sel, act, StartOptions{IdempotencyKey: orderKey})
	if err != nil {
		return err
	}
	select {
	case <-sj.Done:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for the Job to finish")
	}
	return nil
}

func orderIs[T error](err error) bool {
	var target T
	return errors.As(err, &target)
}

// Proves EX-3, EX-4.
func TestPipeline_StagesRunInSpecOrder(t *testing.T) {
	var (
		F, R, T, A, I = orderFreeze, orderResolve, orderTemplate, orderAuthz, orderIdemLookup
		C, P, D, S    = orderCap, orderApproval, orderDispatch, orderTasksStored
		X, U          = orderTaskSent, orderAudit
	)
	denied := errors.New("denied")
	lookupDown := errors.New("idempotency db down")
	freezeDown := errors.New("freeze db down")
	approvalsDown := errors.New("approval db down")
	capErr := &CapExceededError{Class: jobs.RiskClassRead, Matched: 2, Cap: 1}
	logTail := func(args map[string]string) jobs.Action {
		return jobs.Action{Kind: jobs.ActionOperation, OperationName: "log.tail", OperationArgs: args}
	}
	disagreeAct := logTail(map[string]string{"unit": "nginx"})
	disagreeing := func(t *testing.T, r *orderRig) {
		r.vocab.snaps["node-a"] = reported(readTemplate("log.tail", "unit"))
		r.vocab.snaps["node-b"] = reported(readTemplate("log.tail", "unit", "lines"))
	}
	unitt := logTail(map[string]string{"unitt": "nginx"})
	nativeUnitt := jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", OperationArgs: map[string]string{"unitt": "x"}}
	emptySel := Selector{}

	tests := []struct {
		name        string
		sel         *Selector
		act         *jobs.Action
		setup       func(*testing.T, *orderRig)
		want        []string
		wantErr     func(error) bool
		wantAudit   AuditKind
		wantRefusal []RefusalKind
		wantJob     bool
		wantTasks   int
		wantSent    int
		wantClaim   bool
	}{
		{
			name: "every stage passes", want: []string{F, R, T, A, I, C, P, D, S, X, U},
			wantAudit: AuditKindDispatch, wantJob: true, wantTasks: 2, wantSent: 2, wantClaim: true,
		},
		{
			name: "the Freeze is engaged", setup: func(_ *testing.T, r *orderRig) { r.freeze.frozen = true },
			want: []string{F, U}, wantErr: orderIs[*FrozenError], wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalFrozen},
		},
		{
			name: "the Freeze state is unreadable", setup: func(_ *testing.T, r *orderRig) { r.freeze.frozenErr = freezeDown },
			want: []string{F, U}, wantErr: func(err error) bool { return errors.Is(err, freezeDown) }, wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalInternal},
		},
		{
			name: "the Selector is empty", sel: &emptySel,
			want: []string{F, U}, wantErr: orderIs[*EmptySelectorError], wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalMalformed},
		},
		{
			name: "authorization refuses", setup: func(_ *testing.T, r *orderRig) { r.authz.err = denied },
			want: []string{F, R, T, A, U}, wantErr: func(err error) bool { return errors.Is(err, denied) },
			wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalUnauthorized},
		},
		{
			name: "the idempotency lookup fails", setup: func(_ *testing.T, r *orderRig) { r.idem.lookupErr = lookupDown },
			want: []string{F, R, T, A, I, U}, wantErr: func(err error) bool { return errors.Is(err, lookupDown) },
			wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalInternal},
		},
		{
			name: "the key was used with other arguments",
			setup: func(t *testing.T, r *orderRig) {
				now := time.Now().UTC()
				rec := jobs.IdempotencyRecord{
					AccountID: orderCaller.AccountID, Key: orderKey, RequestDigest: "a-different-request",
					JobID: "job-earlier", CreatedAt: now,
				}
				if _, won, err := r.st.IdempotencyKeys().Claim(context.Background(), rec, now.Add(-IdempotencyWindow)); err != nil || !won {
					t.Fatalf("seed claim: won=%v err=%v", won, err)
				}
			},
			want: []string{F, R, T, A, I, U}, wantErr: orderIs[*IdempotencyConflictError],
			wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalMalformed},
		},
		{
			name: "the Selector matches no Node", sel: &orderNoMatch,
			want: []string{F, R, A, I, U}, wantErr: orderIs[*NoNodesMatchedError],
			wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalNoNodesMatched},
		},
		{
			name: "no matched Node reports the Template", act: &jobs.Action{Kind: jobs.ActionOperation, OperationName: "nope.notreal"},
			want: []string{F, R, T, A, I, U}, wantErr: orderIs[*UnknownOperationError],
			wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalUnknownOperation},
		},
		{
			name: "the reporting Nodes disagree on the slots", act: &disagreeAct, setup: disagreeing,
			want: []string{F, R, T, A, I, U}, wantErr: orderIs[*MalformedCallError],
			wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalMalformed},
		},
		{
			name: "the argument names do not match the slots", act: &unitt,
			want: []string{F, R, T, A, I, U}, wantErr: orderIs[*MalformedCallError],
			wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalMalformed},
		},
		{
			name: "an adapter preset the Template's class", act: &jobs.Action{Kind: jobs.ActionOperation, OperationName: "svc.status", RiskClass: jobs.RiskClassRead},
			want: []string{F, R, A, I, U}, wantErr: orderIs[*TemplateClassPresetError],
			wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalInternal},
		},
		{
			name: "a Native argument name is unknown", act: &nativeUnitt,
			want: []string{F, R, A, I, U}, wantErr: orderIs[*MalformedCallError],
			wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalMalformed},
		},
		{
			name: "Raw Exec argv is empty", act: &jobs.Action{Kind: jobs.ActionRawExec},
			want: []string{F, R, A, I, U}, wantErr: orderIs[*MalformedCallError],
			wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalMalformed},
		},
		{
			name: "the Task timeout is above the ceiling", act: &jobs.Action{Kind: jobs.ActionOperation, OperationName: "svc.status", TimeoutSeconds: 301},
			want: []string{F, R, T, A, I, U}, wantErr: orderIs[*TimeoutError],
			wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalMalformed},
		},
		{
			name: "the blast-radius cap refuses", setup: func(_ *testing.T, r *orderRig) { r.cap.err = capErr },
			want: []string{F, R, T, A, I, C, U}, wantErr: orderIs[*CapExceededError],
			wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalBlastCap},
		},
		{
			name: "the approval store is unreadable",
			setup: func(_ *testing.T, r *orderRig) {
				r.gate.gated = true
				r.approvals.byPlanHashErr = approvalsDown
			},
			want: []string{F, R, T, A, I, C, P, U}, wantErr: func(err error) bool { return errors.Is(err, approvalsDown) },
			wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalInternal},
		},
		{
			name: "the approval gate parks", setup: func(_ *testing.T, r *orderRig) { r.gate.gated = true },
			want: []string{F, R, T, A, I, C, P, U}, wantErr: orderIs[*ParkedError],
			wantAudit: AuditKindApprovalRequested, wantRefusal: []RefusalKind{RefusalPendingApproval},
		},
		{
			name: "the dispatcher errors", setup: func(_ *testing.T, r *orderRig) { r.jobs.createErr = errors.New("disk full") },
			want:    []string{F, R, T, A, I, C, P, D, U},
			wantErr: func(err error) bool { return strings.Contains(err.Error(), "create job") }, wantAudit: AuditKindDispatch, wantClaim: true,
		},
		{
			name: "frozen with an empty Selector", sel: &emptySel, setup: func(_ *testing.T, r *orderRig) { r.freeze.frozen = true },
			want: []string{F, U}, wantErr: orderIs[*FrozenError], wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalFrozen},
		},
		{
			name: "an empty Selector from an unauthorized caller", sel: &emptySel, setup: func(_ *testing.T, r *orderRig) { r.authz.err = denied },
			want: []string{F, U}, wantErr: orderIs[*EmptySelectorError], wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalMalformed},
		},
		{
			name: "an unauthorized caller matching no Node", sel: &orderNoMatch, setup: func(_ *testing.T, r *orderRig) { r.authz.err = denied },
			want: []string{F, R, A, U}, wantErr: func(err error) bool { return errors.Is(err, denied) && !orderIs[*NoNodesMatchedError](err) },
			wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalUnauthorized},
		},
		{
			name: "a malformed call matching no Node", sel: &orderNoMatch, act: &nativeUnitt,
			want: []string{F, R, A, I, U}, wantErr: orderIs[*NoNodesMatchedError],
			wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalNoNodesMatched},
		},
		{
			name: "a malformed call over the cap", act: &unitt, setup: func(_ *testing.T, r *orderRig) { r.cap.err = capErr },
			want: []string{F, R, T, A, I, U}, wantErr: orderIs[*MalformedCallError],
			wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalMalformed},
		},
		{
			name: "over the cap where the gate would park",
			setup: func(_ *testing.T, r *orderRig) {
				r.cap.err = capErr
				r.gate.gated = true
			},
			want: []string{F, R, T, A, I, C, U}, wantErr: orderIs[*CapExceededError],
			wantAudit: AuditKindRefusal, wantRefusal: []RefusalKind{RefusalBlastCap},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newOrderRig(t)
			if tc.setup != nil {
				tc.setup(t, r)
			}
			sel, act := orderWeb, orderTemplateCall
			if tc.sel != nil {
				sel = *tc.sel
			}
			if tc.act != nil {
				act = *tc.act
			}

			err := r.start(t, sel, act)

			if got := r.log.stages(); !slices.Equal(got, tc.want) {
				t.Errorf("stages consulted %v, want %v", got, tc.want)
			}
			switch {
			case tc.wantErr != nil:
				if err == nil || !tc.wantErr(err) {
					t.Errorf("err = %v, not the expected refusal", err)
				}
			default:
				if err != nil {
					t.Errorf("err = %v, want nil", err)
				}
			}

			events := r.audit.events()
			if len(events) != 1 {
				t.Fatalf("audit events = %d, want exactly 1: %+v", len(events), events)
			}
			if events[0].Kind != tc.wantAudit {
				t.Errorf("audit kind = %v, want %v", events[0].Kind, tc.wantAudit)
			}
			if tc.wantAudit == AuditKindRefusal && err != nil && events[0].Reason != FirstRefusal(err).Error() {
				t.Errorf("audited reason %q is not the refusal returned %q", events[0].Reason, FirstRefusal(err).Error())
			}

			if got := r.audit.reads(); got != 0 {
				t.Errorf("read-audit rows = %d, want 0 on a dispatch", got)
			}
			refusals := orderRefusals(r.metrics)
			if !slices.Equal(refusals, tc.wantRefusal) {
				t.Errorf("refusal metrics = %v, want %v", refusals, tc.wantRefusal)
			}

			wantJobs := 0
			if tc.wantJob {
				wantJobs = 1
			}
			if got := r.jobs.count(); got != wantJobs {
				t.Errorf("Jobs stored = %d, want %d", got, wantJobs)
			}
			if got := r.tasks.count(); got != tc.wantTasks {
				t.Errorf("Tasks stored = %d, want %d", got, tc.wantTasks)
			}
			if got := len(r.conduit.sentTo()); got != tc.wantSent {
				t.Errorf("Tasks sent = %d, want %d", got, tc.wantSent)
			}
			wantClaims := 0
			if tc.wantClaim {
				wantClaims = 1
			}
			if got := r.idem.claimCount(); got != wantClaims {
				t.Errorf("idempotency claims = %d, want %d", got, wantClaims)
			}

			// Invariant 5: the cap is consulted on the Relay before any Task is persisted.
			got := r.log.stages()
			storedAt, capAt := slices.Index(got, orderTasksStored), slices.Index(got, orderCap)
			if storedAt >= 0 && (capAt < 0 || capAt > storedAt) {
				t.Errorf("invariant 5: a Task was persisted before the blast-radius cap was consulted")
			}
		})
	}
}

// Proves EX-4.
func TestPipeline_NoStageWidensALaterStage(t *testing.T) {
	r := newOrderRig(t, "node-a", "node-b", "node-c")
	r.vocab.snaps = staticVocab{
		"node-a": reported(readTemplate("svc.status")),
		"node-b": reported(mutateTemplate("svc.status")),
	}

	if err := r.start(t, orderWeb, orderTemplateCall); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if got := r.authz.act().RiskClass; got != jobs.RiskClassMutate {
		t.Errorf("authorization saw class %v, want the resolved mutate", got)
	}
	class, matched := r.cap.saw()
	if class != jobs.RiskClassMutate || matched != 2 {
		t.Errorf("cap saw (%v, %d), want (mutate, 2): the reporting Nodes, never the 3 matched", class, matched)
	}
	if d := r.gate.saw(); d.RiskClass != jobs.RiskClassMutate || d.FanOut != 2 {
		t.Errorf("approval gate saw class %v fan-out %d, want mutate and 2", d.RiskClass, d.FanOut)
	}
	entries := r.intents.entries()
	if len(entries) != 1 {
		t.Fatalf("intent entries = %d, want 1", len(entries))
	}
	if entries[0].Action.RiskClass != jobs.RiskClassMutate {
		t.Errorf("dispatched class %v, want what the cap cleared (mutate)", entries[0].Action.RiskClass)
	}
	if entries[0].CapCleared != 2 {
		t.Errorf("cap cleared = %d, want 2", entries[0].CapCleared)
	}
	if got := r.tasks.count(); got != 3 {
		t.Errorf("Tasks stored = %d, want 3: the 2 cleared and the excluded node-c's", got)
	}
	if got, want := r.conduit.sentTo(), []string{"node-a", "node-b"}; !slices.Equal(got, want) {
		t.Errorf("Tasks sent to %v, want %v: a Node that reported nothing is never sent one (EX-6)", got, want)
	}
}
