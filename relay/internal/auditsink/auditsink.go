// Package auditsink is the real capability.AuditSink: an adapter that maps
// capability.AuditEntry/capability.FreezeEvent onto the append-only
// audit.Repository (internal/store's SQLite implementation).
//
// It lives in its own package, not package capability or package audit,
// because it must reference both: capability's non-test files are locked to
// a small import allowlist (TestCapabilityImportsOnlyRegistryAndJobs) that
// bars database/sql and internal/audit, and audit is deliberately a thin,
// SQL-free domain package that must not depend on capability. auditsink is
// the only place both meet.
//
// Redaction: Record/RecordFreeze copy ONLY the domain fields named below —
// Principal's attribution string, the Selector as written, the Action's
// kind/name/args/argv, per-Node Outcome, and (for a mutate-class Task, under
// the full-output-always posture ADR-0025 amends) each NodeResult's captured
// Stdout/Stderr and the daemon-side Truncated flag, copied verbatim — the
// sink never scrubs or redacts them (Policy, ADR-0002, is where
// secret-emitting commands are prevented, not here). Also copied verbatim
// (ADR-0027 decision 10): PlanHash (every Kind that carries one) and, on
// AuditKindApprovalDecided only,
// ApprovalAnswer and DecisionChannel — the structured answer a decision
// carries alongside its prose Reason. Nothing else is added: no enrichment
// from tokens, keys, or other in-memory secrets the sink never even sees.
// RecordIntent's dispatch_intent record copies the same domain fields, plus a
// Relay-authored Reason built from closed vocabularies, counts and Relay-minted
// Node IDs (intentReason); it never carries output. RecordProtocolViolation copies only Relay-authored fields and never any
// Node-produced bytes, on any risk class.
//
// Logging: Record additionally emits exactly one structured slog Info
// "audit decision" line per call, for each of the three Kinds it persists
// (dispatch, refusal, plan) — the store and the log are written from the
// same call so they cannot drift. That line carries ONLY the kind,
// Principal's attribution string, the Selector as written, the Action's
// kind and (for a typed Operation) name, the job_id (dispatch, omitted when
// empty), the aggregate matched count and per-outcome counts (dispatch), and
// the refusal reason (refusal) — a decision's routing/attribution metadata,
// never its content. It never logs an Action's OperationArgs or
// RawExecArgv, any NodeResult's Stdout/Stderr/Truncated, or any token/key
// material; the log is supplementary and never influences a decision.
// RecordIntent logs the same way for dispatch_intent: the job_id and
// the Node count, never the Node IDs or args. RecordFreeze and RecordCancel
// are unchanged and remain unlogged. Errors
// from Record/RecordFreeze/RecordCancel propagate up to Execution.Run, which
// wraps but does not dump the entry's contents.
package auditsink

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// idGen mints a new unique audit Record ID. A seam so tests can inject
// deterministic IDs; the production default is audit.NewID.
type idGen func() (string, error)

// Sink is the real capability.AuditSink, backed by an audit.Repository.
type Sink struct {
	repo  audit.Repository
	newID idGen
	now   func() time.Time
	log   *slog.Logger
}

var (
	_ capability.AuditSink      = (*Sink)(nil)
	_ capability.IntentRecorder = (*Sink)(nil)
)

// Option configures a Sink built by New.
type Option func(*Sink)

// WithNewID overrides the Sink's idGen seam (production default: audit.NewID).
func WithNewID(f idGen) Option {
	return func(s *Sink) { s.newID = f }
}

// WithClock overrides the Sink's clock seam (production default: time.Now,
// UTC).
func WithClock(f func() time.Time) Option {
	return func(s *Sink) { s.now = f }
}

// WithLogger overrides the Sink's logger seam (production default:
// slog.Default()), so tests can assert on the decision lines Record emits
// with a buffer-backed handler. A nil l falls back to slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(s *Sink) {
		if l == nil {
			l = slog.Default()
		}
		s.log = l
	}
}

// New returns a Sink backed by repo.
func New(repo audit.Repository, opts ...Option) *Sink {
	// newID defaults to audit.NewID: "audit-" plus 16 hex digits of the mint
	// time in Unix nanoseconds and 16 hex digits of crypto/rand — the same
	// 38-character shape as the older random ids, but MONOTONIC,
	// so the trail's (ts, audit_id) tie-break orders rows by when they were
	// appended. That matters most here: Record's dispatch fan-out copies one
	// clock reading onto every per-Node Record, so a whole fan-out shares a ts
	// and its order IS the id order. See audit.NewID for the properties and
	// their bounds. Used unwrapped: audit.NewID already says "audit: generate
	// record id: ...", and a wrap here would announce one failure twice.
	s := &Sink{
		repo:  repo,
		newID: audit.NewID,
		now:   func() time.Time { return time.Now().UTC() },
		log:   slog.Default(),
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Record implements capability.AuditSink. A Dispatch entry with Results
// fans out to one audit.Record PER NodeResult (ADR-0004: Tasks are the audit
// unit) so each is independently queryable by NodeID; a Dispatch entry with
// no Results (a dispatcher that failed before producing any) still gets
// exactly one job-level Record with an empty NodeID. A zero-match dispatch
// is refused in capability.Execution.Run and arrives here as a Refusal entry.
// A Refusal entry (authz-deny, cap-reject, or no_nodes_matched: the
// dispatcher was never reached) gets exactly one Record with the refusal's
// Reason, jobs.OutcomeUnspecified, no NodeID, and JobID copied verbatim from
// e.JobID — empty for a role-floor refusal that
// precedes any existence check (refuseControl), and set only when
// Execution.CancelJob's machine-Account scoping refused after
// resolving jobID to a real Job (refuseCancel/authorizeMachineCancel); never
// caller-supplied text the Relay never validated. A Plan entry (ADR-0011:
// a no-execution PolicyQuery probe)
// gets exactly one Record, Principal+Selector+Action only — no JobID/NodeID/
// Outcome, since a Plan never creates a Job or Task. Per-Record Append
// failures are joined, not short-circuited, so one failing write does not
// silently drop the rest.
//
// Record also emits exactly one structured "audit decision" log line per
// call (see the package doc's Logging section), regardless of whether the
// store Append below succeeds — the decision remains visible in logs even
// if the SQLite write fails.
func (s *Sink) Record(ctx context.Context, e capability.AuditEntry) error {
	// Without this the entry would fall through below and be recorded as a
	// dispatch: an intent that never ran, rendered as an outcome.
	if e.Kind == capability.AuditKindDispatchIntent {
		return errors.New("auditsink: a dispatch intent is recorded only with its Tasks, via RecordIntent")
	}
	base := s.baseRecord(e.Principal, e.Asserted, e.Selector, e.Action)

	// The approval link (ADR-0027), copied onto every Kind that can carry
	// one: the park, the decision, and the dispatch the approval released.
	//
	// Set here rather than per-branch precisely because it must not be
	// per-branch. "What ran under this approval" is only a truthful query if
	// every row an approval touched carries it, and a branch added later that
	// forgot to copy it would not fail — it would silently answer the question
	// with a smaller set, which is the worst way for an audit query to be
	// wrong.
	base.ApprovalID = e.ApprovalID
	base.GrantID = e.GrantID
	base.PlanHash = e.PlanHash

	if e.Kind == capability.AuditKindRefusal {
		base.Kind = audit.KindRefusal
		base.Reason = e.Reason
		base.JobID = e.JobID
		err := s.append(ctx, base)
		s.logDecision(audit.KindRefusal, e, 0, "")
		return err
	}

	if e.Kind == capability.AuditKindPlan {
		base.Kind = audit.KindPlan
		err := s.append(ctx, base)
		s.logDecision(audit.KindPlan, e, 0, "")
		return err
	}

	// A parked dispatch (ADR-0027). It must be handled BEFORE the
	// dispatch fall-through below: an entry with no Results looks exactly like
	// a Dispatch with no Results, so without this branch a park would be
	// recorded as something that ran. Reason carries the Relay-authored
	// summary and the request ID, which is what makes the park answerable
	// later.
	if e.Kind == capability.AuditKindApprovalRequested {
		base.Kind = audit.KindApprovalRequested
		base.Reason = e.Reason
		err := s.append(ctx, base)
		s.logDecision(audit.KindApprovalRequested, e, 0, "")
		return err
	}

	// A request for a batch/window Grant. Same no-Results shape as a
	// park and handled before the same fall-through, for the same reason: it
	// would otherwise be recorded as a Dispatch with no Results. Its own kind
	// because a Grant is an ask for standing authority over many dispatches,
	// which is not the act approval_requested names.
	if e.Kind == capability.AuditKindApprovalGrantRequested {
		base.Kind = audit.KindApprovalGrantRequested
		base.Reason = e.Reason
		err := s.append(ctx, base)
		s.logDecision(audit.KindApprovalGrantRequested, e, 0, "")
		return err
	}

	// A re-drive of an already-parked dispatch: same shape as a park,
	// but nothing was created — the caller bounced off the existing pending
	// Request. Recorded under its own kind so approval_requested keeps meaning
	// "a request was created", and handled before the fall-through for the same
	// no-Results reason as its neighbours.
	if e.Kind == capability.AuditKindApprovalPendingObserved {
		base.Kind = audit.KindApprovalPendingObserved
		base.Reason = e.Reason
		err := s.append(ctx, base)
		s.logDecision(audit.KindApprovalPendingObserved, e, 0, "")
		return err
	}

	// A decision on a parked dispatch (ADR-0027). Like a park it must be
	// handled before the dispatch fall-through, and for the same reason: it
	// carries no Results, so the fall-through would record it as a Dispatch
	// with no Results — an answer to a question rendered as something that ran.
	if e.Kind == capability.AuditKindApprovalDecided {
		base.Kind = audit.KindApprovalDecided
		base.Reason = e.Reason
		base.ApprovalAnswer = approvalAnswer(e.ApprovalAnswer)
		base.DecisionChannel = decisionChannel(e.DecisionChannel)
		err := s.append(ctx, base)
		s.logDecision(audit.KindApprovalDecided, e, 0, "")
		return err
	}

	base.JobID = e.JobID
	if len(e.Results) == 0 {
		base.Kind = audit.KindDispatch
		err := s.append(ctx, base)
		s.logDecision(audit.KindDispatch, e, 0, "")
		return err
	}

	// read-class Operations record WHAT was read, never what came back
	// (ADR-0025). The Task row still carries the output for the caller
	// to fetch; the audit trail — which outlives the Job — keeps only the
	// access record.
	//
	// Keyed on risk class rather than on a name list, so a Template Operation
	// inherits the posture from its declared class instead of needing to be
	// remembered here — and keyed PER RESULT: a Template's Tasks each run
	// under their own Node's reported class (ADR-0042), so one Node reporting
	// mutate cannot cause another Node's read output to be retained. A result
	// with no class of its own falls back to the dispatch's.
	var errs []error
	for _, r := range e.Results {
		class := r.RiskClass
		if class == jobs.RiskClassUnspecified {
			class = e.Action.RiskClass
		}
		retainOutput := class != jobs.RiskClassRead

		rec := base
		rec.Kind = audit.KindDispatch
		rec.NodeID = r.NodeID
		rec.Outcome = r.Outcome
		if retainOutput {
			rec.Stdout = r.Stdout
			rec.Stderr = r.Stderr
			rec.Truncated = r.Truncated
		}
		if err := s.append(ctx, rec); err != nil {
			errs = append(errs, err)
		}
	}
	s.logDecision(audit.KindDispatch, e, len(e.Results), outcomeCounts(e.Results))
	return errors.Join(errs...)
}

// RecordIntent implements capability.IntentRecorder: it persists tasks as
// Pending and appends the Job's one dispatch_intent record in a single
// transaction, so the intent exists before any Task can be dispatched.
// The per-Node outcome rows that Record appends later reference it through the
// shared job_id.
//
// Surface rides in the verified lane's Method/Source, as for every other kind.
// The record never carries Stdout, Stderr or Truncated (ADR-0025).
func (s *Sink) RecordIntent(ctx context.Context, e capability.AuditEntry, tasks []jobs.Task) error {
	if e.Kind != capability.AuditKindDispatchIntent {
		return errors.New("auditsink: RecordIntent takes only a dispatch intent entry")
	}
	if len(tasks) == 0 {
		return errors.New("auditsink: a dispatch intent needs at least one Task")
	}
	rec := s.baseRecord(e.Principal, e.Asserted, e.Selector, e.Action)
	rec.Kind = audit.KindDispatchIntent
	rec.JobID = e.JobID
	rec.ApprovalID = e.ApprovalID
	rec.GrantID = e.GrantID
	rec.Reason = intentReason(e, tasks)

	id, err := s.newID()
	if err != nil {
		s.logDecision(audit.KindDispatchIntent, e, len(tasks), "")
		return fmt.Errorf("auditsink: record dispatch intent: generate audit record id: %w", err)
	}
	rec.ID = id
	err = s.repo.AppendWithTasks(ctx, rec, tasks)
	s.logDecision(audit.KindDispatchIntent, e, len(tasks), "")
	if err != nil {
		return fmt.Errorf("auditsink: record dispatch intent: %w", err)
	}
	return nil
}

// intentReason renders a dispatch_intent record's Reason as space-separated
// key=value text, in this order: risk_class (read or mutate), blast_cap=passed,
// cap_cleared, excluded, node_count, node_ids.
//
// cap_cleared is the Nodes the blast cap cleared; some may later resolve
// Unreachable or VersionRefused and never be sent. excluded is the Nodes
// persisted pre-resolved because the Template is unsupported there — the only
// excluded Nodes that get a Task. node_ids are Relay-minted enrollment IDs, in
// Task order, so no Node-writable bytes enter the trail.
//
// The Reason deliberately has NO cap limit value (invariant 11; job.go's Plan
// comment) and NO output (ADR-0025).
func intentReason(e capability.AuditEntry, tasks []jobs.Task) string {
	ids := make([]string, len(tasks))
	for i, t := range tasks {
		ids[i] = t.NodeID
	}
	return fmt.Sprintf("risk_class=%s blast_cap=passed cap_cleared=%d excluded=%d node_count=%d node_ids=%s",
		jobs.RiskClassName(e.Action.RiskClass), e.CapCleared, len(tasks)-e.CapCleared, len(tasks), strings.Join(ids, ","))
}

// RecordRead appends one metadata-only read-access record (ADR-0025):
// who read, which tool, what they aimed it at, and when.
//
// It takes the Principal explicitly rather than reading a context, because the
// caller (the MCP read surface's adapter) is the boundary that resolved it —
// and because a value this sink invented itself would not be a verified
// attribution.
//
// There is deliberately no result parameter. A read record that carried its
// result would copy the material this decision exists to limit into a trail
// that outlives the Job.
func (s *Sink) RecordRead(ctx context.Context, p capability.Principal, tool, selector, nodeID, jobID string) error {
	return s.append(ctx, audit.Record{
		Timestamp:     s.now(),
		Kind:          audit.KindRead,
		Principal:     p.Attribution(),
		Attribution:   attribution(p, capability.AssertionsFromContext(ctx)),
		OperationName: tool,
		Selector:      selector,
		NodeID:        nodeID,
		JobID:         jobID,
	})
}

// RecordFreeze implements capability.AuditSink. It records exactly one
// Record per Freeze engage/release (ADR-0013): Kind is KindFreezeEngage or
// KindFreezeRelease depending on e.Engage, with Principal and Reason set and
// no Selector/NodeID/JobID/Action — Freeze is Relay-wide.
func (s *Sink) RecordFreeze(ctx context.Context, e capability.FreezeEvent) error {
	rec := audit.Record{
		Timestamp:   s.now(),
		Principal:   e.Principal.Attribution(),
		Attribution: attribution(e.Principal, e.Asserted),
		Reason:      e.Reason,
	}
	if e.Engage {
		rec.Kind = audit.KindFreezeEngage
	} else {
		rec.Kind = audit.KindFreezeRelease
	}
	return s.append(ctx, rec)
}

// RecordCancel implements capability.AuditSink (v0.0.6 [5/8], owner DECISION
// 2). It records exactly one audit.Record per cancel action: Kind is
// KindJobCancel, Principal is p's attribution, JobID is jobID — no Selector/
// NodeID/Action, since a cancel targets an existing Job by ID, not a fresh
// dispatch (mirrors RecordFreeze's Relay-wide shape, minus the Reason field).
func (s *Sink) RecordCancel(ctx context.Context, p capability.Principal, jobID string) error {
	rec := audit.Record{
		Timestamp:   s.now(),
		Kind:        audit.KindJobCancel,
		Principal:   p.Attribution(),
		Attribution: attribution(p, capability.AssertionsFromContext(ctx)),
		JobID:       jobID,
	}
	return s.append(ctx, rec)
}

// protocolViolationReason renders ev as the record's Reason: stable,
// machine-greppable "key=value" fields, never prose. Every value comes
// from a closed vocabulary or a Relay-minted id — a Node cannot write a
// byte of it, which is what keeps an append-only table out of reach of
// the subject it is evidence about.
//
//	rule=<relay_only_outcome|unresolved_outcome> reported_outcome=<NAME> task_id=<id>
func protocolViolationReason(ev jobs.ProtocolViolationEvent) string {
	name := ev.Violation.ReportedOutcome
	if name == "" {
		name = "unnamed"
	}
	return fmt.Sprintf("rule=%s reported_outcome=%s task_id=%s",
		ev.Violation.Rule, name, ev.TaskID)
}

// RecordProtocolViolation records a relay-daemon's wire-contract violation
// as a KindProtocolViolation row: no Principal (no Account acted —
// see the Kind's doc comment), no Outcome, no Stdout/Stderr/Truncated
// (nothing to put in them — see the Kind's doc comment and this package's
// Redaction paragraph).
func (s *Sink) RecordProtocolViolation(ctx context.Context, ev jobs.ProtocolViolationEvent) error {
	return s.append(ctx, audit.Record{
		Timestamp:     s.now(),
		Kind:          audit.KindProtocolViolation,
		NodeID:        ev.NodeID,
		JobID:         ev.JobID,
		OperationName: ev.OperationName,
		Reason:        protocolViolationReason(ev),
	})
}

// accountAdminReason renders e's Reason string, carrying the field names
// the trail has always used for these actions, so existing trail queries
// and dashboards built against those strings keep working:
//
//	account_create   account_id=… name=… kind=… role=…
//	account_role     account_id=… role=…
//	account_enable   account_id=…
//	account_disable  account_id=…
//	api_token_mint   account_id=… api_token_id=…
//	api_token_revoke api_token_id=…
func accountAdminReason(e capability.AccountAdminEvent) string {
	switch e.Kind {
	case capability.AccountAdminCreate:
		return fmt.Sprintf("account_id=%s name=%s kind=%s role=%s", e.AccountID, e.AccountName, e.AccountKind, e.Role)
	case capability.AccountAdminRole:
		return fmt.Sprintf("account_id=%s role=%s", e.AccountID, e.Role)
	case capability.AccountAdminEnable, capability.AccountAdminDisable:
		return "account_id=" + e.AccountID
	case capability.AccountAdminTokenMint:
		return fmt.Sprintf("account_id=%s api_token_id=%s", e.AccountID, e.TokenID)
	case capability.AccountAdminTokenRevoke:
		return "api_token_id=" + e.TokenID
	default:
		return ""
	}
}

// accountAdminAuditKind maps a capability.AccountAdminKind to the audit.Kind
// string it is stored under, mirroring audit.KindAccount*/KindAPIToken*
// (audit.go). An unrecognized kind maps to "" rather than panicking — see
// RecordAccountAdmin's doc comment.
func accountAdminAuditKind(k capability.AccountAdminKind) string {
	switch k {
	case capability.AccountAdminCreate:
		return audit.KindAccountCreate
	case capability.AccountAdminRole:
		return audit.KindAccountRole
	case capability.AccountAdminEnable:
		return audit.KindAccountEnable
	case capability.AccountAdminDisable:
		return audit.KindAccountDisable
	case capability.AccountAdminTokenMint:
		return audit.KindAPITokenMint
	case capability.AccountAdminTokenRevoke:
		return audit.KindAPITokenRevoke
	default:
		return ""
	}
}

// RecordAccountAdmin implements capability.AuditSink: one Record per
// Account/API-Token administration act, Principal-attributed exactly like
// RecordCancel, with Reason carrying the same field-per-kind strings
// recordLifecycle wrote directly before this surface moved into the
// capability layer (accountAdminReason above).
//
// An unrecognized Kind (only possible if a future value is added here
// without a matching case in accountAdminAuditKind/accountAdminReason) is
// still recorded, under Kind "" rather than dropped — a silently-missing
// administration record is worse than a wrongly-labelled one, and
// TestSink_RecordAccountAdminMapsEveryKind pins every kind this package
// knows about to a non-empty audit Kind.
func (s *Sink) RecordAccountAdmin(ctx context.Context, p capability.Principal, e capability.AccountAdminEvent) error {
	rec := audit.Record{
		Timestamp:   s.now(),
		Kind:        accountAdminAuditKind(e.Kind),
		Principal:   p.Attribution(),
		Attribution: attribution(p, e.Asserted),
		Reason:      accountAdminReason(e),
	}
	return s.append(ctx, rec)
}

// baseRecord builds the audit.Record fields common to every Kind: attributed
// Principal, the Selector as written, and the Action's shape. Kind, JobID,
// NodeID, Outcome, and Reason are filled in by the caller per Kind.
func (s *Sink) baseRecord(p capability.Principal, a capability.Assertions, sel capability.Selector, act jobs.Action) audit.Record {
	return audit.Record{
		Timestamp:     s.now(),
		Principal:     p.Attribution(),
		Attribution:   attribution(p, a),
		Selector:      sel.String(),
		ActionKind:    actionKindString(act.Kind),
		OperationName: act.OperationName,
		Args:          act.OperationArgs,
		RawExecArgv:   act.RawExecArgv,
	}
}

// actionKindString renders a jobs.ActionKind as the string audit.Record
// stores, mirroring internal/store's tasks.go action_kind mapping.
func actionKindString(k jobs.ActionKind) string {
	switch k {
	case jobs.ActionOperation:
		return "operation"
	case jobs.ActionRawExec:
		return "raw_exec"
	default:
		return "unspecified"
	}
}

// approvalAnswer renders a capability.ApprovalAnswer as the string
// audit.Record stores. The empty capability.ApprovalAnswerUnrecorded maps
// to audit's own empty — both mean the same third state, "no answer was
// recorded" (never collapsed into "denied").
//
// It WHITELISTS rather than casting, and the difference is not theoretical
// even though no caller can trip it today. The column has no CHECK
// constraint, and the two readers of it disagree about unknown values: the
// Console's approvalStateChip whitelists and renders no chip, while the
// Activity CSV export writes the stored string verbatim. A cast would let a
// future producer put a value on the evidence export that the screen denies
// exists — one record named two ways, which is the family of bug the structured
// answer exists to end. Whitelisting here fails closed onto the well-tested
// third state, so the two surfaces agree by construction rather than by both
// remembering.
func approvalAnswer(a capability.ApprovalAnswer) string {
	switch a {
	case capability.ApprovalAnswerApproved:
		return audit.ApprovalAnswerApproved
	case capability.ApprovalAnswerDenied:
		return audit.ApprovalAnswerDenied
	default:
		return ""
	}
}

// decisionChannel renders an approval.Channel as the string audit.Record
// stores. ChannelUnspecified maps to "" and NOT to "unspecified": the trail's
// empty means "not recorded", and "unspecified" would be a fourth value
// nothing else understands.
func decisionChannel(c approval.Channel) string {
	if c == approval.ChannelUnspecified {
		return ""
	}
	return c.String()
}

// logDecision emits exactly one structured slog Info "audit decision" line
// for the Kind of decision e describes. It carries ONLY attribution/routing
// metadata — never e.Action.OperationArgs, e.Action.RawExecArgv, or any
// NodeResult's Stdout/Stderr/Truncated — so a decision line can never leak
// request content or captured output, even though the store retains both.
// matched and counts are dispatch-only (zero value/empty otherwise, and a
// Dispatch entry with no Results passes matched=0 and an empty counts
// string).
func (s *Sink) logDecision(kind string, e capability.AuditEntry, matched int, counts string) {
	attrs := []any{
		"kind", kind,
		"principal", e.Principal.Attribution(),
		"selector", e.Selector.String(),
		"action_kind", actionKindString(e.Action.Kind),
	}
	if e.Action.Kind == jobs.ActionOperation {
		attrs = append(attrs, "operation", e.Action.OperationName)
	}
	switch kind {
	case audit.KindDispatch:
		if e.JobID != "" {
			attrs = append(attrs, "job_id", e.JobID)
		}
		attrs = append(attrs, "matched", matched, "outcome_counts", counts)
	case audit.KindDispatchIntent:
		// The Node count only: never the Node IDs or any args.
		attrs = append(attrs, "job_id", e.JobID, "node_count", matched)
	case audit.KindRefusal:
		attrs = append(attrs, "reason", e.Reason)
	}
	s.log.Info("audit decision", attrs...)
}

// outcomeOrder is outcomeCounts' fixed rendering order, so a decision line
// is deterministic across runs. It is self-contained to this package (not a
// reuse of internal/metrics's unexported jobs.OutcomeName): OutcomeVersionRefused
// gets its own bucket here rather than folding into "unspecified".
var outcomeOrder = []jobs.Outcome{
	jobs.OutcomeSuccess,
	jobs.OutcomeFailure,
	jobs.OutcomeTimeout,
	jobs.OutcomeDeniedByPolicy,
	jobs.OutcomeCancelled,
	jobs.OutcomeUnreachable,
	jobs.OutcomeVersionRefused,
	jobs.OutcomeUnsupported,
	jobs.OutcomeUnspecified,
}

// outcomeCounts renders the aggregate per-Outcome tally across results as a
// compact string, e.g. "success=2,denied_by_policy=1", in outcomeOrder,
// omitting outcomes with a zero count. A nil/empty results yields "".
func outcomeCounts(results []capability.NodeResult) string {
	counts := make(map[jobs.Outcome]int, len(outcomeOrder))
	for _, r := range results {
		counts[r.Outcome]++
	}
	var b strings.Builder
	for _, o := range outcomeOrder {
		n := counts[o]
		if n == 0 {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%s=%d", jobs.OutcomeName(o), n)
	}
	return b.String()
}

// attribution maps the capability layer's verified Principal and
// caller-asserted metadata onto the audit record's two lanes.
//
// This mapping is the only place the two representations meet, and it is
// deliberately total: the verified fields come exclusively from the Principal
// the authentication boundary produced, and the asserted fields exclusively
// from what the caller supplied. There is no path by which a value can cross
// from one lane to the other.
func attribution(p capability.Principal, a capability.Assertions) audit.Attribution {
	return audit.Attribution{
		Verified: audit.Verified{
			AccountID:   p.AccountID,
			AccountName: p.Account,
			Role:        p.Role,
			TokenID:     p.TokenID,
			Method:      string(p.AuthMethod),
			Source:      p.Source,
		},
		Asserted: audit.Asserted{
			OnBehalfOf:  a.OnBehalfOf,
			Traceparent: a.Traceparent,
			SessionRef:  a.SessionRef,
			ChangeRef:   a.ChangeRef,
		},
	}
}

func (s *Sink) append(ctx context.Context, rec audit.Record) error {
	id, err := s.newID()
	if err != nil {
		return fmt.Errorf("auditsink: generate audit record id: %w", err)
	}
	rec.ID = id
	if err := s.repo.Append(ctx, rec); err != nil {
		return fmt.Errorf("auditsink: append audit record: %w", err)
	}
	return nil
}

// RecordLogin implements consoleauth.Auditor: one audit.Record per
// authentication event on the Console's human lane (spec
// docs/design/console/12-login.md).
//
// # Which lane each field lands in
//
// A SUCCESSFUL sign-in has a verified identity, so it fills the verified lane
// exactly as any other authenticated act does. A FAILED one has no verified
// identity at all — that is what failing means — so the verified lane carries
// only the source, and what the caller claimed goes in the ASSERTED lane, where
// unauthenticated claims belong.
//
// The asserted lane carries what consoleauth hands it. On a failed or
// throttled sign-in that is the matched Account's name or nothing (D19),
// decided in consoleauth when the attempt is recorded. Nothing a failure
// carries lands in the verified lane.
func (s *Sink) RecordLogin(ctx context.Context, e consoleauth.LoginEvent) error {
	rec := audit.Record{
		Timestamp: s.now(),
		Kind:      e.Kind,
		Principal: e.Account,
		Reason:    e.Reason,
		Attribution: audit.Attribution{
			Verified: audit.Verified{
				AccountID:   e.AccountID,
				AccountName: e.Account,
				Role:        e.Role,
				Method:      e.Method,
				Source:      e.Source,
			},
			Asserted: audit.Asserted{
				// Bounded like every other asserted field: a successful
				// sign-in still records exactly what was typed, and the sink
				// must not trust its caller to have bounded it (the
				// unbounded-field lesson).
				OnBehalfOf: truncate(e.SubmittedName, audit.MaxAssertedFieldBytes),
			},
		},
	}
	if e.Account != "" && e.Role != "" {
		rec.Principal = e.Account + ":" + e.Role
	}
	return s.append(ctx, rec)
}

// truncate bounds a caller-supplied string to n bytes, cutting on a rune
// boundary so a truncated record never holds an invalid UTF-8 fragment.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
