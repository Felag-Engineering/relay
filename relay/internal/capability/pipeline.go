package capability

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// Execution is the dispatch pipeline: Run, Start, Drain, Plan, CancelJob and
// the MCP task verbs. Construct it with NewExecution; the composition root
// owns the one instance.
type Execution struct {
	// control carries the Freeze, the Authorizer and (through its Recorder) the
	// audit trail, metrics and log. read is the registry and the read lane;
	// approvals is the approval callout (ADR-0027). NewExecution requires all
	// three to share one Recorder.
	control   *Control
	read      *ReadLane
	approvals *Approvals

	cap  CapChecker
	disp dispatcher

	// jobEvents is the event seam's Job-grained publisher (#416,
	// JobEventSink, seams.go) — the same "purely observational" contract as
	// metrics. propagated onto the real Job engine (jobEngine.events) by
	// newExecution, because both Execution.CancelJob and jobEngine.run need
	// the same sink.
	jobEvents JobEventSink

	// idem persists dispatch idempotency keys (start.go). Nil means a call
	// carrying a key is refused (ErrIdempotencyUnavailable), never run unkeyed.
	idem jobs.IdempotencyRepository

	// bg tracks the background Jobs Start has launched; bgMu guards bg.Add
	// against Drain's Wait, and draining makes Start refuse once Drain began.
	bg       sync.WaitGroup
	bgMu     sync.Mutex
	draining bool

	// claims is the in-process half of the idempotency keys this Execution has
	// claimed and not yet settled, keyed by accountID + "\x00" + key.
	// reattachPersistWait bounds how long a re-issue waits for such a claimer
	// to finish persisting; a field only so a test can shorten it.
	// Invariant: a settled claim is never visible in claims (settle removes the
	// entry before closing settled).
	claimsMu            sync.Mutex
	claims              map[string]*keyClaim
	reattachPersistWait time.Duration
}

// NewExecution returns the dispatch pipeline over control, read and approvals,
// with the real Job engine built here from jr, tr, conduit and concurrency
// (fans a resolved Selector to one persisted Task per matched Node, fails
// offline Nodes fast, ADR-0004, and dispatches the rest through conduit
// concurrently, at most concurrency at a time). The Freeze, the role floor
// and the audit trail come from control; Selector resolution and the read
// lane come from read; the approval callout comes from approvals. All three
// must share one Recorder so the layer has a single audit trail.
//
// Required: control, read, approvals, capc (the blast-radius cap, ADR-0004),
// jr, tr, conduit, and concurrency >= 1 (it bounds reach and is startup-only,
// invariant 11). A nil one is a composition-root wiring bug, not a
// recoverable runtime condition, so NewExecution panics.
//
// Safe absences: a nil idem means a call carrying an idempotency key is
// refused (ErrIdempotencyUnavailable), never run unkeyed; a nil newID means
// the production Job-ID generator; a nil jobEvents means the no-op sink,
// which is purely observational and never security-relevant.
//
// There is deliberately no exported dispatcher seam: dispatcher is unexported
// (see dispatch.go), so only files inside this package can supply one.
//
// Contract enforced here: a real dispatcher is always wired here, so
// NewExecution always requires a real Authorizer, CapChecker, AuditSink and
// FreezeStore — the first, third and fourth through NewControl and
// NewRecorder, and the second through NewBlastCap — rather than silently
// letting the engine ride an allow-all/no-op seam, and panics otherwise. A
// real dispatcher paired with an allow-all Authorizer, a no-op CapChecker, or
// a no-op AuditSink is a fail-open: every Node would match, every Action
// would be permitted, and nothing would be recorded. A real dispatcher paired
// with a noopFreezeStore is the same class of bug: an un-stoppable executor,
// since "never frozen" means the emergency stop (ADR-0013) can never actually
// halt it. The AuditSink must also implement IntentRecorder: the Job's
// Tasks are persisted through it, in one transaction with its
// dispatch-intent record. See dispatcher's doc comment in dispatch.go.
func NewExecution(control *Control, read *ReadLane, approvals *Approvals, capc CapChecker, idem jobs.IdempotencyRepository, jr jobs.JobRepository, tr jobs.TaskRepository, conduit Conduit, concurrency int, newID func() (string, error), jobEvents JobEventSink) *Execution {
	if control == nil {
		panic("capability: NewExecution: control must not be nil")
	}
	if read == nil {
		panic("capability: NewExecution: read lane must not be nil")
	}
	if approvals == nil {
		panic("capability: NewExecution: approvals must not be nil")
	}
	if read.rec != control.rec {
		panic("capability: NewExecution: the read lane and the Control must share one Recorder; two Recorders would split the audit trail")
	}
	if approvals.rec != control.rec {
		panic("capability: NewExecution: the approvals service and the Control must share one Recorder; two Recorders would split the audit trail")
	}
	if capc == nil {
		panic("capability: NewExecution: capChecker must not be nil")
	}
	if jr == nil || tr == nil || conduit == nil {
		panic("capability: NewExecution: jobsRepo, tasksRepo, and conduit must not be nil")
	}
	if concurrency < 1 {
		panic("capability: NewExecution: dispatch concurrency must be at least 1")
	}
	x := newExecution(control, read, approvals, capc, idem, newJobEngine(jr, tr, conduit, concurrency, newID), jobEvents)
	checkRealDispatch(x)
	return x
}

// newExecution assembles an Execution with no checks. Only NewExecution and
// _test.go files call it (fixture_test.go, export_test.go); it is the only
// route to an Execution over the no-op dispatcher.
func newExecution(control *Control, read *ReadLane, approvals *Approvals, capc CapChecker, idem jobs.IdempotencyRepository, disp dispatcher, jobEvents JobEventSink) *Execution {
	if jobEvents == nil {
		jobEvents = noopJobEventSink{}
	}
	x := &Execution{
		control:   control,
		read:      read,
		approvals: approvals,
		cap:       capc,
		disp:      disp,
		idem:      idem,
		jobEvents: jobEvents,

		claims:              make(map[string]*keyClaim),
		reattachPersistWait: defaultReattachPersistWait,
	}
	// Propagate the Job-event sink onto the real Job engine, if one is
	// wired, because both Execution.CancelJob (below) and jobEngine.run
	// (execution.go) need the same sink.
	if e, ok := x.disp.(*jobEngine); ok {
		e.events = x.jobEvents
		e.log = control.rec.log
		// Likewise the dispatch-intent recorder: the AuditSink that
		// records the Job's outcome is the one that can record its intent in
		// the Tasks' transaction.
		if e.intents == nil {
			if r, ok := control.rec.audit.(IntentRecorder); ok {
				e.intents = r
			}
		}
	}
	return x
}

// checkRealDispatch refuses a real dispatcher riding the allow-all/no-op
// seams, and panics otherwise (a composition-root wiring bug, not a
// recoverable runtime condition). It is shared by NewExecution and the test
// builder build (fixture_test.go).
func checkRealDispatch(x *Execution) {
	if _, ok := x.control.authz.(allowAllAuthorizer); ok {
		panic("capability: NewExecution: a real dispatcher requires a real Authorizer (NewControl); allowAllAuthorizer would fail open")
	}
	if _, ok := x.cap.(noopCapChecker); ok {
		panic("capability: NewExecution: a real dispatcher requires a real CapChecker (NewBlastCap); noopCapChecker would fail open")
	}
	if _, ok := x.control.rec.audit.(noopAuditSink); ok {
		panic("capability: NewExecution: a real dispatcher requires a real AuditSink (NewRecorder); noopAuditSink would record nothing")
	}
	if _, ok := x.control.freeze.(noopFreezeStore); ok {
		panic("capability: NewExecution: a real dispatcher requires a real FreezeStore (NewControl); noopFreezeStore is never frozen, making the emergency stop unreachable")
	}
	if e, ok := x.disp.(*jobEngine); ok && e.intents == nil {
		panic("capability: NewExecution: a real dispatcher requires an AuditSink that records dispatch intent (IntentRecorder); without it Tasks cannot be persisted")
	}
}

// recorder is the audit trail, metrics and log the Execution records to: the
// Control's Recorder, which NewExecution requires the read lane to share.
func (s *Execution) recorder() *Recorder { return s.control.rec }

func (s *Execution) recordRefusal(ctx context.Context, p Principal, sel Selector, act jobs.Action, kind RefusalKind, refusalErr error) error {
	return s.recorder().recordRefusal(ctx, p, sel, act, kind, refusalErr)
}

func (s *Execution) refuseControl(ctx context.Context, p Principal, refusalErr error) error {
	return s.recorder().refuseControl(ctx, p, refusalErr)
}

func (s *Execution) logger() *slog.Logger { return s.recorder().logger() }

// clock is the approval clock, which also stamps idempotency claims (start.go,
// prepareDispatch) — one clock, as before.
func (s *Execution) clock() time.Time { return s.approvals.clock() }

// Run is the pipeline every surface must call to act on Nodes: check the
// Freeze, resolve the Selector, resolve a Template Operation's class and
// fan-out (ADR-0042, computing only), authorize the Principal, refuse a
// Selector that matched no Nodes, refuse an unknown or malformed Template
// call, check the blast-radius cap, consult the approval gate, dispatch, then
// audit — in that order. The Freeze gate, authorize, the no-Nodes-matched
// check, the Template refusal and the cap check each short-circuit the
// remaining stages on error (no
// dispatch — nothing was executed), but each refusal is itself audited
// (recordRefusal) — refusals are the most interesting audit events
// (acceptance criterion for #102). Once dispatch is attempted, the audit
// record is always written, even if the dispatcher itself returns an error:
// a dispatcher may execute some Nodes before failing on others, and a
// partially-executed dispatch must never go unaudited. In that case Run
// returns the dispatch error (joined with any audit-write error via
// errors.Join) alongside the partial results. Principal is threaded through
// to the AuditSink so every recorded entry attributes who asked, even before
// real authn exists.
//
// The Freeze check (ADR-0013) is the OUTERMOST gate, run before Selector
// resolution and before authz: a frozen Relay refuses all new dispatch,
// every risk class, regardless of who asks or how many Nodes would have
// matched — there is no reason to spend registry-resolution work whose
// result the refusal path would only discard. A Frozen read error fails
// closed (refuses dispatch); a guardrail must never fail open, even at the
// cost of availability during a store blip.
//
// Deliberate info-disclosure trade-off: because the Freeze gate runs before
// authz, a caller who is not authorized for act/sel still learns "the Relay
// is frozen" before being told "denied". This is acceptable because every
// caller reaching Run is already mTLS-authenticated (ADR-0005/0006) — there
// is no anonymous caller to leak the Freeze state to — and no real
// per-Principal Authorizer exists this milestone anyway.
func (s *Execution) Run(ctx context.Context, p Principal, sel Selector, act jobs.Action) ([]NodeResult, error) {
	pr, err := s.prepareDispatch(ctx, p, sel, act, "")
	if err != nil {
		return nil, err
	}
	if pr.reattach != nil {
		return pr.reattach.results, nil
	}
	res, dispatchErr := s.disp.run(ctx, pr.d)
	return s.account(ctx, p, sel, pr, res, dispatchErr, false)
}

// prep is what prepareDispatch hands back: either a dispatch ready to run, or a
// re-attachment to a Job that already exists. Run and Start share it, so the
// two can never diverge on a gate.
type prep struct {
	d   dispatch
	act jobs.Action
	ap  approvalDecision

	// reserved is true when d.jobID was reserved before dispatch (an approval's
	// release claim, AP-77, or an idempotency key, #895): the Job's pipeline and
	// accounting then outlive the caller's context.
	reserved bool

	// claim is the idempotency key this call won, nil when it carried none. The
	// caller must settle it once the Job is persisted or the dispatch failed.
	claim *keyClaim

	reattach *reattachment
}

// reattachment is an answer that dispatched nothing: the Job an earlier call
// created. results is populated only where the caller wants a NodeResult per
// Node (Run's approval re-attach); Start reads jobID alone.
type reattachment struct {
	jobID   string
	results []NodeResult
}

// prepareDispatch is Run's pipeline up to, and not including, the dispatcher:
// Freeze, Selector resolution, authorization, the no-Nodes-matched and Template
// refusals, the blast cap, the approval gate and the Job-ID claims. key is an
// idempotency key and is only ever non-empty from Start; "" is exactly Run.
func (s *Execution) prepareDispatch(ctx context.Context, p Principal, sel Selector, act jobs.Action, key string) (prep, error) {
	reqAct := act
	frozen, err := s.control.freeze.Frozen(ctx)
	if err != nil {
		return prep{}, s.recordRefusal(ctx, p, sel, act, RefusalInternal, fmt.Errorf("capability: read freeze state: %w", err))
	}
	if frozen {
		return prep{}, s.recordRefusal(ctx, p, sel, act, RefusalFrozen, &FrozenError{})
	}

	matched := sel.Resolve(s.read.reg, s.read.stateEval())

	// Every Action's class is fixed here (invariant 13): a Native Operation's
	// from opvocab, Raw Exec's as mutate, and a Template Operation's — with its
	// fan-out — over the matched Nodes' own reports (ADR-0042, template.go).
	// resolveAction only COMPUTES: its refusal, including an Action that
	// arrived with a class preset, is acted on below, after authorization, so a
	// caller who may not ask learns nothing about which Nodes carry which
	// Templates.
	ra := s.resolveAction(act, matched)
	act = ra.act
	nodes := ra.nodes

	// withoutAssertions: an authorization decision must not be able to read
	// anything the caller asserted (see assertions.go).
	if err := s.control.authz.Authorize(withoutAssertions(ctx), p, act, sel); err != nil {
		return prep{}, s.recordRefusal(ctx, p, sel, act, RefusalUnauthorized, err)
	}

	// An idempotency key is handled after Freeze and authorization, so a
	// caller who may not dispatch learns nothing about keys, and before the
	// zero-match, cap and approval stages, so a re-issue is neither refused
	// because the fleet changed since the original call nor spends a Grant use.
	digest := ""
	if key != "" {
		if err := validateIdempotencyKey(key); err != nil {
			return prep{}, s.recordRefusal(ctx, p, sel, act, RefusalMalformed, err)
		}
		if _, ok := s.disp.(starter); !ok || s.idem == nil || p.AccountID == "" {
			return prep{}, s.recordRefusal(ctx, p, sel, act, RefusalInternal, ErrIdempotencyUnavailable)
		}
		digest = jobs.RequestDigest(sel.String(), reqAct)
		rec, found, err := s.idem.Lookup(ctx, p.AccountID, key, s.clock().Add(-IdempotencyWindow))
		if err != nil {
			return prep{}, s.recordRefusal(ctx, p, sel, act, RefusalInternal, fmt.Errorf("capability: look up idempotency key: %w", err))
		}
		if found {
			return s.keyedReattach(ctx, p, sel, act, digest, rec)
		}
	}

	// A Selector that resolved to zero Nodes is refused HERE — after
	// authorization, before the blast cap, the approval gate and the
	// dispatcher — so:
	//   (a) no Job ID is minted, CreateJob is never called, and no zero-Node
	//       request is parked: there is no Node to show an approver and
	//       nothing for a dispatcher to run.
	//   (b) it deliberately comes AFTER authorization: a caller who may not
	//       ask gets the same "unauthorized" refusal whatever the fleet
	//       holds, and learns nothing about whether any Selector matches
	//       (AGENTS.md section 9: prefer the more restrictive option).
	//   (c) it is audited as a refusal (recordRefusal), not as a job-level
	//       dispatch row.
	//   (d) Execution.Plan reports the same condition as NoNodesMatched rather
	//       than refusing it — ADR-0011: "A Plan never hard-fails on
	//       guardrails — it reports."
	if len(matched) == 0 {
		return prep{}, s.recordRefusal(ctx, p, sel, act, RefusalNoNodesMatched, &NoNodesMatchedError{Selector: sel.String()})
	}

	// A Template no matched Node reports, a malformed Template call, or an
	// Action of any kind an adapter tried to classify (ADR-0042, invariant 13). Like
	// no_nodes_matched: after authorization, before the cap, and with no Job.
	if ra.refusal != nil {
		return prep{}, s.recordRefusal(ctx, p, sel, act, ra.refusalKind, ra.refusal)
	}

	// The cap counts the Nodes that will actually be dispatched: a Node
	// excluded from a Template dispatch is never sent anything (ADR-0042).
	if err := s.cap.Check(act.RiskClass, len(nodes)); err != nil {
		return prep{}, s.recordRefusal(ctx, p, sel, act, RefusalBlastCap, err)
	}

	// The approval gate (ADR-0027) sits HERE — after Selector resolution,
	// authz, and the blast cap, and before any Task exists.
	//
	// After, because the approver must be shown the resolved fan-out: an
	// approval that did not know how many Nodes it covered would be the
	// approval-view fidelity gap by construction. Before the dispatcher,
	// because parking must leave no Job and no Pending Tasks behind — rows a
	// restart reconciler could mistake for interrupted work.
	//
	// A park is not a refusal, so it does not go through recordRefusal: nothing
	// was denied and nothing ran. It is audited as its own kind.
	ap, err := s.approvals.checkApproval(ctx, p, sel, act, nodeIDs(nodes))
	if err != nil {
		return prep{}, s.recordRefusal(ctx, p, sel, act, RefusalInternal, err)
	}
	// The Request checkApproval found had ALREADY released a Job (AP-77): a
	// sequential re-drive of an already-answered approval. Re-attach and
	// dispatch nothing — see Execution.reattach.
	if ap.reattachJobID != "" {
		return s.approvalReattach(ctx, p, sel, nodes, ap.requestID, ap.reattachJobID)
	}
	if ap.parked != nil {
		s.recorder().metrics.IncRefusal(RefusalPendingApproval)
		// approval_requested means A REQUEST WAS CREATED. A re-drive
		// that bounced off an already-pending Request — which is how a caller
		// polls while waiting — is recorded under its own kind, so the trail's
		// count of asks stays truthful while the polling stays visible.
		kind := AuditKindApprovalRequested
		if ap.created == nil {
			kind = AuditKindApprovalPendingObserved
		}
		entry := AuditEntry{
			Kind: kind, Principal: p, Selector: sel, Action: act,
			Reason: ap.parked.Error(), ApprovalID: ap.parked.RequestID, PlanHash: ap.parked.PlanHash,
			Asserted: AssertionsFromContext(ctx),
		}
		if auditErr := s.recorder().audit.Record(ctx, entry); auditErr != nil {
			// An unaudited park is a dispatch nobody can account for. Surface
			// the write failure alongside the park rather than swallowing it.
			//
			// Askable is cleared here too: a surface must never render a
			// question about a park that was never durably audited — and,
			// below, never notified either, since NotifyParked is skipped on
			// this same error path.
			ap.parked.Askable = false
			return prep{}, errors.Join(ap.parked, fmt.Errorf("capability: record audit entry: %w", auditErr))
		}
		// Notify only on a park this call CREATED, and only after it is durably
		// recorded and audited: a notification about a request that failed to
		// persist would page a human towards nothing. Re-driving a dispatch that
		// is already waiting deliberately does not re-notify — see
		// approvalDecision.created.
		if ap.created != nil {
			s.approvals.notifyParked(ctx, *ap.created)
		}
		// Attach an MCP task handle, if Tasks are wired. Last, and never
		// fatally: the park is already durable and already audited, and
		// ADR-0028 requires the universal result path to stay whole with the
		// shim deleted — so a handle store that is down costs a client its poll
		// handle and costs the dispatch nothing.
		ap.parked.TaskID, ap.parked.TaskExpiresAt = s.approvals.mintTaskHandle(ctx, p, ap.parked.RequestID)
		return prep{}, ap.parked
	}

	d := newDispatch(p, sel, nodes, act)
	d.excluded = ra.excluded
	d.nodeClass = ra.nodeClass
	d.approvalID, d.grantID = ap.requestID, ap.grantID

	// A single-Plan approval's release is now CLAIMED before dispatch, not
	// bound after it (AP-77). The join between the approval and the Job it
	// releases is made by this claim, before any Job or Task exists — so a
	// client timeout, a dropped connection, or a cancelled request after
	// dispatch starts can never leave the Job unbound: there is nothing
	// left to lose, because the bind already committed.
	//
	// Grant-released dispatches (ap.grantID non-empty) are never claimed here:
	// a Request carries one job_id, which is right when one approval releases
	// one Job, but a batch/window Grant (ADR-0027 decision 12) releases MANY,
	// and binding each in turn would leave the authorizing Request pointing at
	// whichever Job happened to run last, silently losing the rest. The
	// grant-to-Jobs join is the audit trail's GrantID, which is why that field
	// exists; a Grant deliberately does not reuse this one-to-one column.
	//
	// A Grant can never reach here for a plan an approval already released:
	// checkApproval's re-attach lookup (Satisfied && Released) runs BEFORE it
	// ever claims a Grant, so a Grant issued to cover a plan AFTER a
	// single-Plan approval released it does NOT authorize a second Job while
	// that approval is still in force — the re-drive re-attaches instead, and
	// the Grant's own uses are untouched
	// (TestRun_ReleasedApprovalReAttachesEvenWhenAGrantCoversThePlan). Once the
	// approval's deadline passes, Satisfied goes false, the released Request no
	// longer shadows the Grant, and the Grant releases the dispatch normally.
	//
	// A keyed dispatch reserves its Job ID the same way and claims the
	// key against it BEFORE the approval's BindJob, so neither join can be lost
	// to a dropped stream. A keyed dispatch released by a Grant still never
	// binds the Request: BindJob runs only under the condition above.
	//
	// The compensating writes below (Release, Rebind) run on a detached,
	// bounded context: a dropped stream cancels ctx, and a key left bound for
	// 24h to a Job that never existed is avoidable.
	reserved := false
	var claim *keyClaim
	bindApproval := ap.grantID == "" && ap.requestID != ""
	if key != "" || bindApproval {
		jobID, err := s.disp.reserveJobID()
		if err != nil {
			return prep{}, s.recordRefusal(ctx, p, sel, act, RefusalInternal, fmt.Errorf("capability: reserve job id: %w", err))
		}
		if key != "" {
			existing, won, err := s.idem.Claim(ctx, jobs.IdempotencyRecord{
				AccountID: p.AccountID, Key: key, RequestDigest: digest, JobID: jobID, CreatedAt: s.clock(),
			}, s.clock().Add(-IdempotencyWindow))
			if err == nil && won {
				// A re-issue can read the row in the instant before this
				// registration; it then finds no live claimer and answers
				// Pending from the row itself, which is still true and still
				// never suggests a new key (resolveKeyedReattach).
				claim = s.registerClaim(p.AccountID, key, jobID)
			}
			if err != nil {
				return prep{}, s.recordRefusal(ctx, p, sel, act, RefusalInternal, fmt.Errorf("capability: claim idempotency key: %w", err))
			}
			if !won {
				return s.keyedReattach(ctx, p, sel, act, digest, existing)
			}
		}
		if bindApproval {
			claimed, err := s.approvals.bindRelease(ctx, ap.requestID, jobID)
			switch {
			case err == nil:
			case errors.Is(err, approval.ErrAlreadyReleased) && claimed.JobID != "":
				// Lost the claim to a concurrent dispatch of the same plan. Nothing
				// is dispatched here (AP-77) — re-attach to the winner's Job.
				if claim != nil {
					cctx, cancel := compensateContext(ctx)
					s.logKeyWrite(cctx, "rebind", s.idem.Rebind(cctx, p.AccountID, key, jobID, claimed.JobID))
					cancel()
					s.settle(claim)
				}
				return s.approvalReattach(ctx, p, sel, nodes, ap.requestID, claimed.JobID)
			default:
				// ErrNotReleasable (the deadline passed between read and claim),
				// ErrNotFound, a store failure, or — defensively — ErrAlreadyReleased
				// with no JobID to re-attach to (the store's belt-and-braces
				// backstop should never produce this, but a re-attach to nothing
				// must never be attempted). Fail closed: nothing is dispatched, and
				// the next re-drive re-evaluates from scratch.
				s.releaseClaim(ctx, claim)
				return prep{}, s.recordRefusal(ctx, p, sel, act, RefusalInternal, fmt.Errorf("capability: claim approval release: %w", err))
			}
		}
		d.jobID = jobID
		reserved = true
	}

	return prep{d: d, act: act, ap: ap, reserved: reserved, claim: claim}, nil
}

// approvalReattach is reattach in prep's shape.
func (s *Execution) approvalReattach(ctx context.Context, p Principal, sel Selector, nodes []registry.Node, requestID, jobID string) (prep, error) {
	results, err := s.reattach(ctx, p, sel, nodes, requestID, jobID)
	if err != nil {
		return prep{}, err
	}
	return prep{reattach: &reattachment{jobID: jobID, results: results}}, nil
}

// reattach re-attaches a dispatch to a Job an approval already released
// (AP-77), recording an audited read instead of dispatching anything.
//
// It is reached two ways: checkApproval found a Satisfied, Released Request
// (a sequential re-drive), or Execution.Run lost the release claim to a
// concurrent winner (BindJob's ErrAlreadyReleased). Either way nothing may be
// dispatched — the plan hash matched, so nodes are exactly the approved
// Nodes, and their outcomes live on the Job identified by jobID, which every
// adapter already re-reads (renderJob).
//
// The read is recorded BEFORE anything is returned, and fails closed
// (ErrReadUnaudited): an unaudited re-attach must not hand out a Job
// (ADR-0025), the same precedent AP-67's adapter-level re-attach set. The
// join from this read to the approval is approval_requests.job_id = jobID.
func (s *Execution) reattach(ctx context.Context, p Principal, sel Selector, nodes []registry.Node, requestID, jobID string) ([]NodeResult, error) {
	if err := s.read.recordQueryRead(ctx, p, toolApprovalReattach, sel.String(), "", jobID); err != nil {
		return nil, fmt.Errorf("capability: re-attach to approval %s's released job: %w", requestID, err)
	}
	// One NodeResult per resolved Node, carrying the bound JobID: these are
	// exactly the approved Nodes, and outcomes/output are read from the Job
	// by the caller, as every surface already does via renderJob. This call
	// ran nothing, so it reports no outcome of its own — Outcome stays
	// OutcomeUnspecified rather than fabricating a result this call never
	// produced.
	out := make([]NodeResult, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, NodeResult{NodeID: n.NodeID, JobID: jobID, Outcome: jobs.OutcomeUnspecified})
	}
	return out, nil
}

// account is Run's post-dispatch half: it binds the Job onto an MCP task
// handle, counts the outcomes, and writes the KindDispatch audit record. It is
// shared by Run and Start. alwaysLog logs an audit-write failure even off the
// reserved path, for Start's background accounting, whose caller is gone.
func (s *Execution) account(ctx context.Context, p Principal, sel Selector, pr prep, res dispatchResult, dispatchErr error, alwaysLog bool) ([]NodeResult, error) {
	act, ap, reserved := pr.act, pr.ap, pr.reserved

	// acctCtx is the context every post-dispatch accounting write below uses.
	// On the RESERVED path (reserved == true), the release claim above already
	// committed before s.disp.run was ever called (AP-77) — exactly the
	// condition jobEngine.run itself now detaches its own persist-then-dispatch
	// pipeline for (execution.go's runCtx) — so a client timeout/drop/cancel
	// landing during or right after dispatch must not be allowed to strand the
	// accounting for a Job that has already run: bindTaskHandleJob and the
	// KindDispatch audit record below are the last two writes this call still
	// owes an approval that already released real work, and dropping them
	// would leave that Job with no durable trail. Detached
	// (context.WithoutCancel) for the same reason as runCtx, and additionally
	// BOUNDED (context.WithTimeout) because, unlike runCtx, this ctx is never
	// implicitly bounded by anything downstream — no daemon-side wall clock
	// backs a local store write — so an unbounded detach here would trade "can
	// be abandoned by the caller" for "can hang the calling goroutine forever
	// on a wedged store". AssertionsFromContext reads through acctCtx rather
	// than ctx directly below: context.WithoutCancel/WithTimeout both preserve
	// Value() lookups, so the caller's asserted attribution (Assertions,
	// assertions.go) is unaffected either way.
	//
	// Non-reserved dispatches (a Grant release, or no approval involved at
	// all) keep using ctx unchanged: no Job was claimed ahead of them, so a
	// cancel here can only ever abandon work that either never started or
	// belongs to no prior commitment — the behaviour this package has always
	// had.
	acctCtx := ctx
	if reserved {
		var cancelAcct context.CancelFunc
		acctCtx, cancelAcct = context.WithTimeout(context.WithoutCancel(ctx), reservedPostDispatchAccountingTimeout)
		defer cancelAcct()
	}

	// And onto the MCP task handle that was waiting for it, so a poll after the
	// release reports `completed` rather than `working` forever. Unlike the
	// binding above this one covers grant-released dispatches too: a handle is
	// per parked dispatch, so there is exactly one Job to record against it.
	s.approvals.bindTaskHandleJob(acctCtx, ap.requestID, res.jobID)

	for _, r := range res.results {
		s.recorder().metrics.IncDispatch(r.Outcome)
	}

	// The AuditSink is recorded unconditionally, even when the dispatcher
	// errors: dispatch.run may execute some Nodes before failing on others
	// (the #99 contract), and a partially-executed dispatch must never be
	// unaudited. results-so-far are recorded whether or not dispatchErr is
	// nil.
	//
	// Residual risk (inherited from #97/#98, out of #102's scope): Args/
	// RawExecArgv below are copied verbatim from act, so a secret passed in
	// an Operation's arguments would land in the audit trail as-is. #102
	// does not close this — it is flagged here so it is not mistaken for a
	// gap in #102's redaction guarantee.
	entry := AuditEntry{Kind: AuditKindDispatch, Principal: p, Selector: sel, Action: act, JobID: res.jobID, Results: res.results, ApprovalID: ap.requestID, GrantID: ap.grantID, Asserted: AssertionsFromContext(acctCtx)}
	auditErr := s.recorder().audit.Record(acctCtx, entry)
	if auditErr != nil {
		// The dispatch itself already happened; a failed audit write must
		// not silently vanish, so it is surfaced as an error alongside the
		// (still valid) results rather than swallowed.
		auditErr = fmt.Errorf("capability: record audit entry: %w", auditErr)
		if reserved || alwaysLog {
			// On the reserved path specifically, the caller this error is
			// about to be returned to may already be gone (the same client
			// drop acctCtx above was detached to survive) — an approved
			// dispatch would then have run with an incomplete or missing
			// dispatch audit record and nobody watching the return value to
			// notice. "Incomplete", not just "missing": a timeout partway
			// through a per-Node audit append (the #99 contract that lets a
			// dispatch partially execute and still be audited) can leave a
			// partial record rather than none at all. Put it somewhere an
			// operator IS watching: the structured log, exactly like
			// authorizeMachineCancel's job-requester-lookup failure above.
			// Logged on acctCtx, not ctx: acctCtx is what is live at this
			// point, and log/slog reads it only for its attached values
			// (unaffected by WithoutCancel/WithTimeout), never for its own
			// cancellation. result_count, not the results themselves: the
			// results carry argv (#102's residual risk above), which never
			// belongs in a log line.
			s.logger().ErrorContext(acctCtx, "capability: reserved-path dispatch audit write failed; an approved dispatch has an incomplete or missing audit record",
				"job_id", res.jobID, "approval_id", ap.requestID, "result_count", len(res.results), "error", auditErr)
		}
	}

	if err := errors.Join(dispatchErr, auditErr); err != nil {
		return res.results, err
	}
	return res.results, nil
}

// reservedPostDispatchAccountingTimeout bounds the detached context Run uses
// for post-dispatch accounting (bindTaskHandleJob, the KindDispatch audit
// record) on the reserved-Job-ID path (AP-77 continuation): long enough that
// a healthy local SQLite write never trips it — the same store calls
// jobEngine.run's own runCtx already makes on this path, unbounded, backed
// only by the driver's busy_timeout (store.go's busyTimeoutMillis) — and
// short enough that a wedged store cannot hang the calling goroutine forever
// once the client that started the call is long gone.
const reservedPostDispatchAccountingTimeout = 30 * time.Second

// ErrJobNotRequestedByCaller is CancelJob's refusal for a machine Account
// asking to cancel a Job that is not its own (owner decision 2026-09-17,
// execution.md §Cancellation, #614). Exported and typed so a surface can
// recognize the refusal via errors.Is without string-matching (mirrors
// FrozenError/CapExceededError).
//
// One message covers two different facts on purpose — "this Job was
// requested by a different Account" and "this Job's requester is not
// recorded at all" — and the caller must not be able to tell which. The
// requester is recorded on the Job at creation, and a Job with no
// recorded requester (one created before that) is refused exactly like
// another Account's Job: distinguishing "not recorded" from "somebody
// else's" would let a machine Account learn that a Job it cannot cancel
// exists and is still in flight, one bit at a time. Never inferred: an
// unresolvable requester is refused exactly like a resolved one that does
// not match.
var ErrJobNotRequestedByCaller = errors.New(
	"capability: cancel refused: this Job was not requested by the caller, or its requester is not recorded")

// CancelJob stops jobID's Tasks (ADR-0013): undispatched Tasks are
// marked cancelled without ever being sent, in-flight Tasks are asked to
// cancel over their Tunnels, and already-resolved Tasks keep their truthful
// outcome. It delegates to the sealed dispatcher (see dispatch.go) so
// tasksRepo/Conduit stay inside the engine, mirroring how Run delegates to
// s.disp.run.
//
// The floor is `operator` for every Account, human or machine — that half
// is unchanged. What differs by Kind is the SCOPE (owner decision
// 2026-09-17, execution.md §Cancellation, #614, narrowing #595's original
// "any Job" reading): a human Account may still cancel any Job, but a
// machine Account may cancel only a Job whose recorded requester is that
// same Account — see authorizeMachineCancel. AuthorizeControl runs FIRST,
// before disp.cancel, so a refused caller neither touches a Task nor learns
// whether the Job exists (see TestCancelJobRefusalDoesNotRevealWhetherTheJobExists).
// It reads the context with withoutAssertions, for the same reason Run and
// Plan do: an authorization decision must never be swayed by caller-asserted
// attribution (assertions.go).
//
// A deliberate asymmetry falls out of the SCOPE difference above: a human
// Account cancelling an unknown Job ID reaches disp.cancel directly and gets
// jobs.ErrJobNotFound, while a machine Account asking about that same id
// gets the uniform ErrJobNotRequestedByCaller instead — because only a
// machine Account's cancel is scoped at all, and GET /api/v1/jobs/{id}
// already answers "does this Job exist" for any authenticated caller, so
// neither answer discloses anything new.
//
// A refusal from the role floor is recorded through refuseControl with the
// Principal and the reason, and deliberately without the Job ID: the
// refusal precedes any existence check, so the id is caller-authored text,
// and the trail's job_id column is otherwise always a Relay-minted id that
// surfaces build links from. A refusal from the machine-scoping check is
// recorded through refuseCancel instead, and carries the Job ID ONLY when
// authorizeMachineCancel's lookup actually found jobID — an unknown id, a
// query error, or no job query wired all leave it empty, exactly like the
// role-floor case, because none of those confirm the id names a real Job
// (see authorizeMachineCancel).
//
// p is recorded via AuditSink.RecordCancel (v0.0.6 [5/8], owner DECISION 2):
// cancellation is durably recorded on each affected Task via
// OutcomeCancelled regardless of who asked (ADR-0013), but the audit trail
// must still answer "who asked for the stop", so this call ADDS a
// principal-attributed audit row on top of that per-Task record. Mirroring
// EngageFreeze/ReleaseFreeze: the cancel itself is attempted first, and the
// audit write is skipped if it errors — there is nothing true to record
// (e.g. jobs.ErrJobNotFound: no Task was ever touched).
//
// CancelTask (mcptask.go) calls this and inherits the gate for a Task that
// already has a Job. A still-parked task handle — one CreateTaskHandle
// created but no dispatch has claimed yet — is cancelled without ever
// reaching CancelJob, so that path stays owner-scoped and ungated; only a
// Job-backed cancel is gated here.
func (s *Execution) CancelJob(ctx context.Context, p Principal, jobID string) error {
	if err := s.control.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlCancelJob); err != nil {
		return s.refuseControl(ctx, p, err)
	}
	if !p.Human() {
		auditJobID, err := s.authorizeMachineCancel(ctx, jobID, p.AccountID)
		if err != nil {
			return s.refuseCancel(ctx, p, auditJobID, err)
		}
	}
	if err := s.disp.cancel(ctx, jobID); err != nil {
		return err
	}
	// Published after the cancel succeeded, and never in a way that changes
	// the returned error (JobEventSink) — observational only, exactly
	// like the MetricsSink calls elsewhere in this file. Nil-checked because
	// this package's own white-box tests construct &Execution{} literals
	// (buildRaw), bypassing newExecution's noopJobEventSink default.
	if s.jobEvents != nil {
		s.jobEvents.RecordJob(JobEvent{Transition: JobCancelled, JobID: jobID, Principal: p})
	}
	return s.recorder().audit.RecordCancel(ctx, p, jobID)
}

// authorizeMachineCancel decides CancelJob's machine-Account scope (owner
// decision 2026-09-17, execution.md §Cancellation, #614): may accountID
// cancel jobID? It queries s.jobQ directly rather than through
// ReadLane.QueryJobs — this is an authorization decision, not a
// caller-invoked read, so it must not append its own entry to the read-lane
// trail (recordQueryRead); CancelJob's own refuseCancel/RecordCancel is what
// gets recorded for it.
//
// It returns (auditJobID, err): err is nil on success, and on refusal is
// always ErrJobNotRequestedByCaller — the caller-visible answer must not
// distinguish "no requester recorded" from "requested by somebody else" (see
// ErrJobNotRequestedByCaller's doc comment). auditJobID is the STORE's own
// echo of the Job it resolved (page.Jobs[0].JobID, never the caller-supplied
// jobID argument) when the lookup actually found that exact Job — whether or
// not its requester matched — and empty otherwise: jobID empty or failing
// validateJobID (refused before any query, see below), s.jobQ unwired, the
// query itself failing, no row returned, or a returned row whose OWN JobID
// does not echo what was asked for. Only CancelJob's refuseCancel reads
// auditJobID, and only to decide what — if anything — lands in the trail's
// job_id column: never caller-supplied text the Relay never validated, and
// never a different Job's id the store happened to return.
//
// jobID is rejected BEFORE it ever reaches s.jobQ if it is empty or fails
// validateJobID. Both matter for different reasons: JobFilter's zero value
// (empty JobID) matches EVERY Job, not none (JobQuery's own contract) — so
// an empty jobID would query "the newest Job" rather than "no Job", and
// authorize a cancel of some job the caller never named, as long as ITS
// requester happened to be the caller. validateJobID's length bound exists
// independently so the slog line below can never be handed an unbounded
// caller string.
//
// Fail CLOSED, and identically from the CALLER's perspective, in every case
// above: only auditJobID (an internal, unexported detail) tells them apart.
// Never infer ownership from anything short of an exact match, and never
// trust a query result for a Job other than the one that was asked about —
// requiring page.Jobs[0].JobID == jobID before any ownership comparison is
// what closes that off even if a JobQuery implementation (or a test spy)
// ever returned the wrong row for an exact-JobID filter.
func (s *Execution) authorizeMachineCancel(ctx context.Context, jobID, accountID string) (auditJobID string, err error) {
	if jobID == "" || validateJobID(jobID) != nil {
		return "", ErrJobNotRequestedByCaller
	}
	if s.read.jobQ == nil {
		return "", ErrJobNotRequestedByCaller
	}
	page, queryErr := s.read.jobQ.QueryJobs(ctx, JobFilter{JobID: jobID}, PageRequest{Limit: 1})
	if queryErr != nil {
		// Logged here, not folded into the caller-facing reason: the query
		// failure is operational detail (a store blip, a malformed filter)
		// that must not change what a refused caller is told, and must not
		// require a caller to be trusted with it to diagnose the Relay.
		s.logger().ErrorContext(ctx, "capability: cancel: job-requester lookup failed",
			"job_id", jobID, "account_id", accountID, "error", queryErr)
		return "", ErrJobNotRequestedByCaller
	}
	if len(page.Jobs) != 1 || page.Jobs[0].JobID != jobID {
		return "", ErrJobNotRequestedByCaller
	}
	// The lookup resolved jobID to that exact Job — record ITS id (the
	// store's own echo, not the caller's argument) on a refusal from here on,
	// regardless of whether the requester below turns out to match.
	auditJobID = page.Jobs[0].JobID
	requester := page.Jobs[0].RequesterAccountID
	if requester == "" || requester != accountID {
		return auditJobID, ErrJobNotRequestedByCaller
	}
	return auditJobID, nil
}

// refuseCancel audits a CancelJob refusal from authorizeMachineCancel. It is
// refuseControl's sibling for the one refusal CancelJob can attribute to a
// real Job: jobID is authorizeMachineCancel's auditJobID, empty unless its
// lookup actually resolved the caller-supplied id to a Job that exists — see
// authorizeMachineCancel's doc comment for why an unresolved id is never
// recorded here either, exactly like refuseControl's role-floor refusal.
func (s *Execution) refuseCancel(ctx context.Context, p Principal, jobID string, refusalErr error) error {
	s.recorder().metrics.IncRefusal(RefusalUnauthorized)
	entry := AuditEntry{Kind: AuditKindRefusal, Principal: p, JobID: jobID, Reason: refusalErr.Error(), Asserted: AssertionsFromContext(ctx)}
	var auditErr error
	if err := s.recorder().audit.Record(ctx, entry); err != nil {
		auditErr = fmt.Errorf("capability: record audit entry: %w", err)
	}
	return errors.Join(refusalErr, auditErr)
}
