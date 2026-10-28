package capability

import (
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// testSvc is the type every test in this package holds a built capability layer
// as: the Execution and the leaf services it is composed with, embedded so a test
// calls any of their methods unqualified. The five method sets are disjoint
// apart from the unexported clock, which no test calls unqualified.
// Tests build one through build or buildRaw and never name the constructors or
// fields directly, so the capability layer's shape can change behind this one
// file.
type testSvc struct {
	*Execution
	*ReadLane
	*Control
	*AccountAdmin
	*PolicyAliasAdmin
	*Approvals
}

// seams is the set of collaborators a test hands to build or buildRaw. A zero
// field means "not supplied": build leaves the no-op default in place, and
// buildRaw leaves the zero value a struct literal would. Field names copy
// Execution's own so buildRaw reads one-to-one against the literals it replaced.
type seams struct {
	reg registry.Repository

	authz     Authorizer
	cap       CapChecker
	disp      dispatcher // buildRaw only: NewExecution has no dispatcher seam
	audit     AuditSink
	freeze    FreezeStore
	metrics   MetricsSink
	jobEvents JobEventSink

	gate             ApprovalGate
	approvals        ApprovalStore
	approvalAuthz    ApprovalAuthorizer
	mcpTasks         MCPTaskStore
	approvalNotifier ApprovalNotifier

	auditQ     AuditQuery
	jobQ       JobQuery
	policyView PolicyViewSource
	nodeVocab  TemplateVocabularySource
	aliases    PolicyAliasSource

	// certWindow is the state:cert-expiring window handed to the ReadLane when
	// settings is nil. settings, when set, is the one source the read lane and
	// the Job engine read; a test that changes settings mid-test supplies it.
	certWindow time.Duration
	settings   OperatorSettingsSource

	accountsStore AccountStore
	apiTokens     APITokenStore
	idem          jobs.IdempotencyRepository
	now           func() time.Time

	// The Job engine, build only. Any of jobsRepo, tasksRepo or conduit set
	// means "wire execution".
	jobsRepo  jobs.JobRepository
	tasksRepo jobs.TaskRepository
	conduit   Conduit
	newID     idGen
	intents   IntentRecorder // nil: a nonAtomicIntents over tasksRepo, as NewExecution's tests
}

func (s seams) hasExecution() bool {
	return s.jobsRepo != nil || s.tasksRepo != nil || s.conduit != nil
}

// build assembles an Execution from the supplied seams, as NewExecution does
// but over no-op defaults for an omitted one, so a test states only what it
// cares about. When an execution seam is set it wires the real Job engine and
// keeps NewExecution's fail-open guard (checkRealDispatch).
func build(t *testing.T, s seams) *testSvc {
	t.Helper()
	if s.disp != nil {
		t.Fatalf("build: disp is buildRaw-only; set svc.disp after build")
	}
	if s.intents != nil && !s.hasExecution() {
		t.Fatalf("build: intents is set but no execution seam is")
	}
	if s.newID != nil && !s.hasExecution() {
		t.Fatalf("build: newID is set but no execution seam is")
	}
	audit, authz, freeze := s.audit, s.authz, s.freeze
	if audit == nil {
		audit = noopAuditSink{}
	}
	if authz == nil {
		authz = allowAllAuthorizer{}
	}
	if freeze == nil {
		freeze = noopFreezeStore{}
	}
	rec := NewRecorder(audit, s.metrics, nil)
	control := newControl(rec, authz, freeze)
	settings := s.settings
	if settings == nil {
		settings = &StaticOperatorSettings{S: OperatorSettings{CertExpiringWithin: s.certWindow, DispatchConcurrency: DefaultDispatchConcurrency}}
	}
	var read *ReadLane
	if s.auditQ != nil || s.jobQ != nil {
		read = NewReadLane(rec, s.reg, s.auditQ, s.jobQ, s.policyView, s.nodeVocab, settings, s.now, WithPolicyAliasSource(s.aliases))
	} else {
		read = newReadLane(rec, s.reg, nil, nil, s.policyView, s.nodeVocab, settings, s.now, WithPolicyAliasSource(s.aliases))
	}
	aliasRec, _ := audit.(PolicyAliasRecorder)
	aliasAdmin := newPolicyAliasAdmin(control, s.aliases, aliasRec)
	var acct *AccountAdmin
	if s.accountsStore != nil || s.apiTokens != nil {
		acct = NewAccountAdmin(control, s.accountsStore, s.apiTokens)
	} else {
		acct = newAccountAdmin(control, nil, nil)
	}

	// The same s.now reaches the read lane and the Approvals, as WithClock did.
	var appr *Approvals
	if s.gate != nil || s.approvals != nil || s.approvalAuthz != nil {
		// Panics on a partial set, as WithApprovals did.
		appr = NewApprovals(rec, s.gate, s.approvals, s.approvalAuthz, s.mcpTasks, s.approvalNotifier, s.now)
	} else {
		notifier := s.approvalNotifier
		if notifier == nil {
			notifier = noopApprovalNotifier{}
		}
		appr = newApprovals(rec, noopApprovalGate{}, nil, nil, s.mcpTasks, notifier, s.now)
	}

	if s.hasExecution() && (s.jobsRepo == nil || s.tasksRepo == nil || s.conduit == nil) {
		t.Fatalf("build: execution needs jobsRepo, tasksRepo and conduit together")
	}
	capc := s.cap
	if capc == nil {
		capc = noopCapChecker{}
	}
	var disp dispatcher = noopDispatcher{}
	if s.hasExecution() {
		intents := s.intents
		if intents == nil {
			intents = &nonAtomicIntents{tr: s.tasksRepo}
		}
		eng := newJobEngine(s.jobsRepo, s.tasksRepo, s.conduit, settings, s.newID)
		eng.intents = intents
		disp = eng
	}
	x := newExecution(control, read, appr, capc, s.idem, disp, s.jobEvents)
	// The same guard NewExecution runs, whenever a real engine is wired.
	if s.hasExecution() {
		checkRealDispatch(x)
	}
	return &testSvc{x, read, control, acct, aliasAdmin, appr}
}

// buildRaw is a struct literal: no defaults and no construction guards, for
// tests that exercise one method against exactly the seams they name.
func buildRaw(t *testing.T, s seams) *testSvc {
	t.Helper()
	if s.hasExecution() || s.intents != nil || s.newID != nil {
		t.Fatalf("buildRaw: a struct literal has no Job engine; use build")
	}
	rec := &Recorder{audit: s.audit, metrics: s.metrics}
	control := &Control{rec: rec, authz: s.authz, freeze: s.freeze}
	var rawSettings OperatorSettingsSource
	switch {
	case s.settings != nil:
		rawSettings = s.settings
	case s.certWindow != 0:
		rawSettings = &StaticOperatorSettings{S: OperatorSettings{CertExpiringWithin: s.certWindow}}
	}
	read := &ReadLane{
		rec: rec, reg: s.reg, auditQ: s.auditQ, jobQ: s.jobQ,
		policyView: s.policyView, nodeVocab: s.nodeVocab, aliases: s.aliases,
		settings: rawSettings, now: s.now,
	}
	acct := &AccountAdmin{control: control, accountStore: s.accountsStore, tokens: s.apiTokens}
	aliasRec, _ := s.audit.(PolicyAliasRecorder)
	aliasAdmin := &PolicyAliasAdmin{control: control, src: s.aliases, rec: aliasRec}
	appr := &Approvals{
		rec: rec, gate: s.gate, store: s.approvals, authz: s.approvalAuthz,
		tasks: s.mcpTasks, notifier: s.approvalNotifier, now: s.now,
	}
	svc := &Execution{
		control:   control,
		read:      read,
		approvals: appr,
		cap:       s.cap,
		disp:      s.disp,
		jobEvents: s.jobEvents,
		idem:      s.idem,
	}
	return &testSvc{svc, read, control, acct, aliasAdmin, appr}
}

// testSettings is the shared, never-mutated source for tests that need a
// valid one. A test that changes settings builds its own.
var testSettings = &StaticOperatorSettings{S: OperatorSettings{DispatchConcurrency: DefaultDispatchConcurrency}}

// caps is a fixed source carrying these blast caps.
func caps(readCap, mutateCap int) *StaticOperatorSettings {
	return &StaticOperatorSettings{S: OperatorSettings{ReadBlastCap: readCap, MutateBlastCap: mutateCap}}
}

// concurrencyOf is a fixed source carrying this dispatch concurrency.
func concurrencyOf(n int) *StaticOperatorSettings {
	return &StaticOperatorSettings{S: OperatorSettings{DispatchConcurrency: n}}
}
