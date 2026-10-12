package capability

import (
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// testSvc is the type every test in this package holds a built capability layer
// as: the Service and the leaf services it is composed with, embedded so a test
// calls any of their methods unqualified. The four method sets are disjoint.
// Tests build one through build or buildRaw and never name the constructors or
// fields directly, so the capability layer's shape can change behind this one
// file.
type testSvc struct {
	*Service
	*ReadLane
	*Control
	*AccountAdmin
}

// seams is the set of collaborators a test hands to build or buildRaw. A zero
// field means "not supplied": build leaves New's default in place, and
// buildRaw leaves the zero value a struct literal would. Field names copy
// Service's own so buildRaw reads one-to-one against the literals it replaced.
type seams struct {
	reg registry.Repository

	authz     Authorizer
	cap       CapChecker
	disp      dispatcher // buildRaw only: New has no option for it
	audit     AuditSink
	freeze    FreezeStore
	metrics   MetricsSink
	jobEvents JobEventSink

	gate             ApprovalGate
	approvals        ApprovalStore
	approvalAuthz    ApprovalAuthorizer
	grants           ApprovalGrantStore
	mcpTasks         MCPTaskStore
	approvalNotifier ApprovalNotifier

	auditQ     AuditQuery
	jobQ       JobQuery
	policyView PolicyViewSource
	nodeVocab  TemplateVocabularySource

	// certWindow is the state:cert-expiring window handed to the ReadLane.
	certWindow time.Duration

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
	intents   IntentRecorder // nil: a nonAtomicIntents over tasksRepo, as testExecution
}

func (s seams) hasExecution() bool {
	return s.jobsRepo != nil || s.tasksRepo != nil || s.conduit != nil
}

// build is New with an option emitted for each supplied seam. An omitted seam
// keeps New's default, so a test states only what it cares about.
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
	var read *ReadLane
	if s.auditQ != nil || s.jobQ != nil {
		read = NewReadLane(rec, s.reg, s.auditQ, s.jobQ, s.policyView, s.nodeVocab, s.certWindow, s.now)
	} else {
		read = newReadLane(rec, s.reg, nil, nil, s.policyView, s.nodeVocab, s.certWindow, s.now)
	}
	var acct *AccountAdmin
	if s.accountsStore != nil || s.apiTokens != nil {
		acct = NewAccountAdmin(control, s.accountsStore, s.apiTokens)
	} else {
		acct = newAccountAdmin(control, nil, nil)
	}

	var opts []Option
	if s.cap != nil {
		opts = append(opts, WithCapChecker(s.cap))
	}
	if s.jobEvents != nil {
		opts = append(opts, WithJobEvents(s.jobEvents))
	}
	if s.gate != nil || s.approvals != nil || s.approvalAuthz != nil {
		opts = append(opts, WithApprovals(s.gate, s.approvals, s.approvalAuthz))
	}
	if s.grants != nil {
		opts = append(opts, WithApprovalGrants(s.grants))
	}
	if s.mcpTasks != nil {
		opts = append(opts, WithMCPTasks(s.mcpTasks))
	}
	if s.approvalNotifier != nil {
		opts = append(opts, WithApprovalNotifier(s.approvalNotifier))
	}
	if s.idem != nil {
		opts = append(opts, WithIdempotency(s.idem))
	}
	if s.now != nil {
		opts = append(opts, WithClock(s.now))
	}
	if s.hasExecution() {
		intents := s.intents
		if intents == nil {
			intents = &nonAtomicIntents{tr: s.tasksRepo}
		}
		eo := []ExecOption{withExecIntents(intents)}
		if s.newID != nil {
			eo = append(eo, WithExecNewID(s.newID))
		}
		opts = append(opts, WithExecution(s.jobsRepo, s.tasksRepo, s.conduit, eo...))
	}
	return &testSvc{New(control, read, opts...), read, control, acct}
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
	read := &ReadLane{
		rec: rec, reg: s.reg, auditQ: s.auditQ, jobQ: s.jobQ,
		policyView: s.policyView, nodeVocab: s.nodeVocab,
		certExpiringWithin: s.certWindow, now: s.now,
	}
	acct := &AccountAdmin{control: control, accountStore: s.accountsStore, tokens: s.apiTokens}
	svc := &Service{
		control:          control,
		read:             read,
		cap:              s.cap,
		disp:             s.disp,
		jobEvents:        s.jobEvents,
		gate:             s.gate,
		approvals:        s.approvals,
		approvalAuthz:    s.approvalAuthz,
		grants:           s.grants,
		mcpTasks:         s.mcpTasks,
		approvalNotifier: s.approvalNotifier,
		idem:             s.idem,
		now:              s.now,
	}
	return &testSvc{svc, read, control, acct}
}
