// Package jobs holds the Relay's domain model for Jobs, Stages, and Tasks —
// the unit of dispatch, at-most-once execution, and blast-radius control
// (ADR-0004). A Job comprises one Task per matched Node, grouped into Stages;
// v1 permits exactly one Stage per Job so a post-1.0 staged rollout lands
// without a data migration.
//
// These are domain mirrors of the relayv1 wire vocabulary (Outcome,
// RiskClass, Operation/RawExec), following the registry.Facts precedent: this
// package carries no proto dependency and, critically, no database/sql
// dependency either — that boundary is what makes a later Postgres swap a
// single-package (internal/store) change.
package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrSingleStageOnly is returned by AddStage when the Job already has a
// Stage. v1 enforces exactly one Stage per Job in code, not by convention;
// the schema (internal/store) backs this with a CHECK/UNIQUE constraint.
var ErrSingleStageOnly = errors.New("jobs: a Job may have exactly one stage in v1")

// ErrJobNotFound is returned when an operation targets a Job that does not exist.
var ErrJobNotFound = errors.New("jobs: job not found")

// ErrJobAlreadyHalted is returned by RecordHalt when the Job already carries a
// halt: a Job halts once, and the first halt is the record.
var ErrJobAlreadyHalted = errors.New("jobs: job has already halted")

// ErrTaskNotFound is returned when an operation targets a Task that does not exist.
var ErrTaskNotFound = errors.New("jobs: task not found")

// ErrInvalidTaskState is returned when a Task state transition is attempted
// out of order: MarkDispatched on a Task that is not Pending, or Resolve or
// MarkCancelledBeforeSend or MarkHaltedBeforeSend on a Task that is not
// Dispatched. Task.Transition
// holds the table of legal transitions; the store re-checks it against the
// persisted row. This is the at-most-once reconciliation guard —
// a Relay restart must never re-dispatch a Task it already resolved, and must
// never resolve a Task it never dispatched.
var ErrInvalidTaskState = errors.New("jobs: invalid task state transition")

// Outcome mirrors relayv1.Outcome. The zero value, OutcomeUnspecified,
// means "not yet resolved" (a Pending or Dispatched Task has no Outcome).
type Outcome int

const (
	OutcomeUnspecified Outcome = iota
	OutcomeSuccess
	OutcomeFailure
	OutcomeTimeout
	OutcomeDeniedByPolicy
	OutcomeCancelled
	OutcomeUnreachable
	OutcomeVersionRefused
	// OutcomeUnsupported is daemon-reported: the Operation name is not in
	// that Node's vocabulary — an unloaded Template Operation or an unknown
	// name (ADR-0021). Nothing executed and Policy was never consulted, so it
	// is neither a failure nor a denial. Once templates exist the vocabulary
	// is per-Node; describe_node/list_operations report what a given Node has.
	OutcomeUnsupported
)

// ResolvedOutcomes returns the eight Outcomes a resolved Task can report, in
// the order every surface renders them: OutcomeUnspecified is not among them.
// Each call returns a new slice, so a caller may reorder or extend it.
func ResolvedOutcomes() []Outcome {
	return []Outcome{
		OutcomeSuccess,
		OutcomeFailure,
		OutcomeTimeout,
		OutcomeDeniedByPolicy,
		OutcomeCancelled,
		OutcomeUnreachable,
		OutcomeVersionRefused,
		OutcomeUnsupported,
	}
}

// OutcomeName renders o as its lowercase wire name. It is the one rendering
// every surface, sink and metric uses, so the same Task reads the same through
// every door. All eight outcomes keep their own name: three are different kinds
// of "it did not run" that must not be collapsed — `unsupported` means Policy
// was never asked, `unreachable` means the Task never left the Relay, and
// `version_refused` means it was refused at dispatch. Anything else, including
// the zero value and any out-of-range Outcome, is "unspecified".
//
// A plain function rather than a String method, so %v and slog keep rendering
// the underlying value wherever an Outcome is logged.
func OutcomeName(o Outcome) string {
	switch o {
	case OutcomeSuccess:
		return "success"
	case OutcomeFailure:
		return "failure"
	case OutcomeTimeout:
		return "timeout"
	case OutcomeDeniedByPolicy:
		return "denied_by_policy"
	case OutcomeCancelled:
		return "cancelled"
	case OutcomeUnreachable:
		return "unreachable"
	case OutcomeVersionRefused:
		return "version_refused"
	case OutcomeUnsupported:
		return "unsupported"
	default:
		return "unspecified"
	}
}

// VersionRefusedMessage is the legible, per-Node reason recorded as a
// version-refused Task's Stderr (mirrors how a daemon denial explains itself,
// and matches the FrozenError quality bar: explain, cite the ADR, say what to
// do). It is Relay-synthesized text, not daemon output — no Task reporting
// this outcome was ever sent.
const VersionRefusedMessage = "capability: dispatch refused: this Node's relay-daemon reports a version below " +
	"the Relay's configured minimum (ADR-0014); the Task was never sent. Upgrade the daemon on this Node " +
	"through your config-management / IaC pipeline — the Relay never pushes binaries."

// NodeOfflineMessage is the Relay-authored reason recorded as the Stderr of a
// Task that was in flight to a Node when the Node went offline. The Task WAS
// dispatched and may have run, so the text claims no more than the Relay
// knows: no result arrived. It is Relay-synthesized, not daemon output.
const NodeOfflineMessage = "dispatch: no result: this Task's Node went offline while the Task was in flight " +
	"(its stream to the Relay ended: missed heartbeats, a dead link or a disconnect), so whether it ran is " +
	"unknown. The Relay does not re-send it (ADR-0004); check the Node and re-target if the work is still needed."

// NodeOfflineResult is the Result of a Task in flight to a Node that went
// offline: a failure with no exit status (-1, the no-exit-status sentinel the
// protocol-violation path also uses) and NodeOfflineMessage. It is
// Relay-synthesized, written by the capability layer and by the dispatch
// Reconciler, so it is defined once here.
func NodeOfflineResult() Result {
	return Result{Outcome: OutcomeFailure, ExitCode: -1, Stderr: []byte(NodeOfflineMessage)}
}

// ErrStreamReplaced is returned by a Conduit's Dispatch, wrapped, when the
// Node's Tunnel stream ended because a newer stream replaced it. The Node is
// not offline: the Task stays in flight, and the new stream's reconnect
// re-sends it for its result (the relay-daemon dedups by task_id, ADR-0004).
// The caller therefore must not resolve the Task as node-offline.
var ErrStreamReplaced = errors.New("jobs: the node's stream was replaced by a newer one")

// ViolationRule names the specific way a relay-daemon's TaskResult broke the
// wire contract: what dispatch.result() refuses at the wire boundary,
// before a Result is ever persisted or a Task resolved with what the daemon
// actually sent.
type ViolationRule int

const (
	// ViolationNone is the zero value: the wire TaskResult was one a
	// relay-daemon is permitted to send, so a zero-value ProtocolViolation
	// means "no violation".
	ViolationNone ViolationRule = iota
	// ViolationRelayOnlyOutcome: the daemon reported an Outcome /proto
	// reserves for the Relay to synthesize ("a daemon never emits this").
	ViolationRelayOnlyOutcome
	// ViolationUnresolvedOutcome: the daemon reported a finished Task with no
	// Outcome at all (the enum's zero value means "not yet resolved").
	ViolationUnresolvedOutcome
)

// String renders r for a log attribute (dispatch's slog.Warn at the wire
// boundary), so the value stays legible rather than a bare int.
//
// ViolationNone has its own case rather than falling into default: default
// is reserved for a rule value this method genuinely does not recognize, so
// it never claims "no violation" about one that might not be none at all
// (code review, cycle 2).
func (r ViolationRule) String() string {
	switch r {
	case ViolationNone:
		return "none"
	case ViolationRelayOnlyOutcome:
		return "relay_only_outcome"
	case ViolationUnresolvedOutcome:
		return "unresolved_outcome"
	default:
		return fmt.Sprintf("unknown_violation_rule(%d)", int(r))
	}
}

// ProtocolViolation records that a relay-daemon reported something the wire
// contract does not permit. The zero value means no violation.
type ProtocolViolation struct {
	Rule ViolationRule
	// ReportedOutcome is the wire enum's own name (e.g.
	// "OUTCOME_VERSION_REFUSED"), not a relayv1.Outcome: this package carries
	// no proto dependency (see the package doc comment), so dispatch fills
	// this in from relayv1.Outcome_name at the wire boundary.
	ReportedOutcome string
}

// Violated reports whether v records an actual protocol violation.
func (v ProtocolViolation) Violated() bool { return v.Rule != ViolationNone }

// Explanation renders v as Relay-authored, caller-facing text explaining why
// a Task resolved failure with no daemon-produced output: the wire boundary
// discarded what the Node reported, so this is the one place a Result's
// Stderr carries Relay prose instead of Node bytes. Direct precedent for
// Relay-synthesized text living in this package: VersionRefusedMessage above.
//
// Drafting rules, mirroring capability/refusal.go's five-rule idiom:
//  1. Never say "never sent", "was not sent" or "nothing executed" — that is
//     false: the Task WAS dispatched and may have run.
//  2. Names no file path and no Account.
//  3. Relay-authored, never daemon output — this is prose, never an echo of
//     anything the Node actually sent.
//  4. Cites the contract (/proto), never an internal invariant number:
//     internal numbering does not belong in caller-facing bytes.
func (v ProtocolViolation) Explanation() string {
	if !v.Violated() {
		return ""
	}
	name := v.ReportedOutcome
	if name == "" {
		name = "an unnamed value"
	}
	base := "dispatch: this Node's relay-daemon reported something the wire contract " +
		"(/proto) does not permit, so the Relay discarded its report. The Task WAS " +
		"dispatched to this Node and may have executed: what actually happened there " +
		"is unknown, and this row must not be read as proof that the Task did not " +
		"run. Treat the Node as misbehaving and investigate it."
	switch v.Rule {
	case ViolationRelayOnlyOutcome:
		return base + fmt.Sprintf(" The reported outcome (%s) is one /proto reserves for "+
			"the Relay to synthesize; no daemon may send it.", name)
	case ViolationUnresolvedOutcome:
		return base + " The report carried no outcome at all, which a finished Task's " +
			"result may never do."
	}
	// A ViolationRule Violated() reports true but with no case above: a future
	// rule added to the const block without a matching case here. Returning ""
	// would be indistinguishable from "no violation", so this stays non-empty
	// even though it names no specific rule (TestEveryWireOutcomeIsClassified's
	// non-empty-Stderr assertion is what would catch this going forward).
	return base
}

// ProtocolViolationEvent is one relay-daemon's protocol violation as
// observed at the wire boundary, carried to the
// audit lane so the violation is a durable, queryable event and not only
// a log line.
//
// It carries NO Stdout, Stderr or Truncated field and must never grow
// one. Every field is Relay-authored or Relay-minted: the ids come from
// the Task the Relay itself dispatched, and Violation's two fields come
// from a closed rule vocabulary and the generated wire enum's own name
// table. That is what makes recording it independent of ADR-0025's
// read-output retention rule — there is no Node-authored byte in it.
type ProtocolViolationEvent struct {
	NodeID        string
	TaskID        string
	JobID         string
	OperationName string // empty for Raw Exec and for an unset Action
	Violation     ProtocolViolation
}

// RiskClass mirrors relayv1.RiskClass. The zero value, RiskClassUnspecified,
// keeps the enum's zero value defined, matching how Outcome mirrors Unspecified.
type RiskClass int

const (
	RiskClassUnspecified RiskClass = iota
	RiskClassRead
	RiskClassMutate
)

// RiskClassName renders r as its lowercase wire name, "read" or "mutate".
// The string is persisted and hashed (internal/store, internal/approval), so it
// is contract, not presentation. RiskClassUnspecified — and any out-of-range
// value — renders as "unspecified" rather than panicking; it should never
// appear in practice (ADR-0012).
func RiskClassName(r RiskClass) string {
	switch r {
	case RiskClassRead:
		return "read"
	case RiskClassMutate:
		return "mutate"
	default:
		return "unspecified"
	}
}

// ParseRiskClass is RiskClassName's inverse: it accepts exactly "read" or
// "mutate". Anything else, the empty string included, returns false, so a
// caller decides for itself what an absent class means.
func ParseRiskClass(s string) (RiskClass, bool) {
	switch s {
	case "read":
		return RiskClassRead, true
	case "mutate":
		return RiskClassMutate, true
	default:
		return RiskClassUnspecified, false
	}
}

// DispatchState is a Task's position in the at-most-once execution lifecycle:
// Pending (created, not yet sent) -> Dispatched (sent to the daemon, no
// result yet) -> Resolved (result recorded). In-flight dispatch state —
// Dispatched with no result — is what a Relay restart must recover to decide
// whether re-dispatch is safe (ADR-0004). The legal moves between states are
// the table in Task.Transition.
type DispatchState int

const (
	DispatchStatePending DispatchState = iota
	DispatchStateDispatched
	DispatchStateResolved
)

// ActionKind distinguishes a structured Operation from Raw Exec.
type ActionKind int

const (
	ActionUnspecified ActionKind = iota
	ActionOperation
	ActionRawExec
)

// Action is the work a Task performs on its Node: either a structured,
// typed Operation (name + validated args, never a shell) or Raw Exec
// (arbitrary argv, gated by Policy regex). Mirrors the TaskRequest oneof.
// TimeoutSeconds is the per-Task timeout the dispatching surface asked for
// (0 = daemon/engine default); the Job engine copies it onto each Task it
// creates (capability/execution.go) — the daemon is the sole enforcer, this
// is only how the value reaches it (v0.0.6 [5/8], owner DECISION 3).
type Action struct {
	Kind           ActionKind
	OperationName  string
	OperationArgs  map[string]string
	RawExecArgv    []string
	RiskClass      RiskClass
	TimeoutSeconds int32
}

// Requester is the verified Account that asked for a Job, recorded when the
// Job is created. The zero value means NO requester is recorded: a
// Job created before the Relay recorded one, or by a caller with no Account.
// It must never be inferred from anything else (execution.md Cancellation:
// fail closed).
//
// Kind stays a plain string mirroring the accounts.Kind wire values ("human"
// or "machine", or "" for unknown). This package must not import
// internal/accounts, for the same reason given on capability.Principal.Kind:
// an unknown Kind is treated as machine by every consumer.
type Requester struct {
	AccountID   string
	AccountName string
	Kind        string
}

// Recorded reports whether r names a requester at all.
func (r Requester) Recorded() bool { return r.AccountID != "" }

// Job is the unit of audit and blast-radius control: one Job comprises one
// Task per matched Node, grouped into Stages. The requesting Account is
// recorded on the Job at creation (Requester); the Selector and the rest of
// the dispatch provenance still live in audit.
type Job struct {
	ID        string
	CreatedAt time.Time
	Requester Requester
	// Halt is why the Job stopped sending; the zero value means it never halted.
	Halt Halt
}

// Halt is why a mutate Job stopped sending (execution.md, Halting a failing
// mutation): the first Task the engine reported failure or timeout for, that
// Task's Node and outcome, whether that outcome is recorded, and when. The zero
// value means the Job has not halted. It is written once, by the Job engine.
type Halt struct {
	TaskID  string
	NodeID  string
	Outcome Outcome
	// Resolved reports that Outcome is the halting Task's recorded resolution.
	// False means the engine reported Outcome for a Task that holds no recorded
	// result (a Conduit error, a replaced stream, a worker panic, a failed store
	// write): its real outcome may still arrive. False is the zero value on
	// purpose, so a Halt built without it claims less, never more.
	Resolved bool
	At       time.Time
}

// Halted reports whether h records a halt.
func (h Halt) Halted() bool { return h.TaskID != "" }

// Reason renders h as Relay-authored, caller-facing text. It names the Node and
// the outcome, holds no Node-authored byte (a Node ID is Relay-minted at
// enrollment) and says "resolved" only when h.Resolved.
//
// The text is part of the record: each Task the halt left unsent stores it
// verbatim as its stderr at the halt, while a surface recomputes it from the
// persisted Halt. A wording change therefore alters what new records say and
// the rendered halt of older Jobs, never the stderr older Tasks already hold.
func (h Halt) Reason() string {
	return h.lead() + fmt.Sprintf("A mutate Job sends no further Task once one fails or times out, so a bad "+
		"change reaches at most one batch of Nodes. A Task this halt left unsent was never sent, and nothing "+
		"ran for it on its Node; Tasks already in flight finish and report their own outcomes. Check Node %q, "+
		"then re-target the Nodes this Job did not reach if the change is still wanted.", h.NodeID)
}

// lead is the sentence Reason and RestartReason open with: the halting Task's
// Node and outcome.
func (h Halt) lead() string {
	if !h.Resolved {
		return fmt.Sprintf("halted: this mutate Job stops sending after its Task on Node %q reported %s "+
			"with no recorded result; that Task's real outcome may still arrive. ", h.NodeID, OutcomeName(h.Outcome))
	}
	return fmt.Sprintf("halted: this mutate Job stops sending after its Task on Node %q resolved %s. ",
		h.NodeID, OutcomeName(h.Outcome))
}

// RestartReason renders h for a Task the Relay found marked dispatched with no
// result when it restarted, and so did not re-send. It is Relay-authored and
// holds no Node-authored byte. Unlike Reason it never says the Task was never
// sent or that nothing ran: a Task is marked dispatched before it is sent, so
// it may have reached its Node before the restart.
func (h Halt) RestartReason() string {
	return h.lead() + "The Relay restarted while this Task was marked dispatched with no result, and it " +
		"sends no Task of a halted Job after a restart, so this Task was not re-sent and whether it " +
		"reached its Node before the restart is unknown: it may have run. Check this Task's Node " +
		"before re-targeting it."
}

// RestartResult is the Result of a Task resolved with RestartReason: like
// NodeOfflineResult a failure carrying -1, the no-exit-status sentinel, never
// cancelled, because the Task may have run.
func (h Halt) RestartResult() Result {
	return Result{Outcome: OutcomeFailure, ExitCode: -1, Stderr: []byte(h.RestartReason())}
}

// Stage is a batch of Tasks within a Job. v1 permits exactly one Stage per
// Job (Index is always 0); AddStage enforces this.
type Stage struct {
	ID    string
	JobID string
	Index int
}

// Task is the execution of one Action on a single Node, as part of a Job's
// Stage. TaskID is unique and is the at-most-once execution key (ADR-0004).
type Task struct {
	ID      string
	JobID   string
	StageID string
	NodeID  string
	Action  Action

	State          DispatchState
	Outcome        Outcome
	ExitCode       int32
	Stdout         []byte
	Stderr         []byte
	TimeoutSeconds int32

	CreatedAt    time.Time
	DispatchedAt time.Time
	ResolvedAt   time.Time
}

// Result is the outcome of a resolved Task, as reported by the relay-daemon
// (or synthesized by the Relay, e.g. OutcomeUnreachable). A Result may also
// be wholly Relay-authored where the wire boundary refused the daemon's
// report as a protocol violation (ProtocolViolation.Explanation): in
// that case Stderr carries Relay text and no daemon bytes survive.
type Result struct {
	Outcome  Outcome
	ExitCode int32
	Stdout   []byte
	Stderr   []byte
	// Truncated is the daemon-side size-cap flag (proto TaskResult.truncated):
	// a single flag over the whole result, not per-stream.
	Truncated bool
}

// Verdict is a connected Node's PolicyVerdict, converted to its proto-free
// domain mirror (ADR-0011): the daemon's live enforcement engine answered
// "would Policy allow this", never a Relay-side evaluation (invariant 12).
// It is returned by Conduit.Query — the proto-free counterpart to Dispatch
// returning Result — so internal/dispatch.Router can satisfy the extended
// Conduit without capability importing the wire proto.
//
// unknown(offline) is deliberately NOT a Verdict value: a matched-but-
// disconnected Node never reaches Query at all, so "unknown" is a Relay-side
// conclusion about connectivity (capability's NodeVerdict), not something
// the daemon ever answers.
type Verdict struct {
	Allowed      bool
	DecidingRule string
	// Unsupported reports that the queried Operation is not in that Node's
	// vocabulary, so its Policy was never asked (ADR-0021): the plan-mode
	// mirror of OutcomeUnsupported, which is what a real dispatch of the same
	// action to that Node would report. Always accompanied by Allowed=false;
	// DecidingRule then explains the vocabulary miss rather than naming a
	// Policy rule.
	Unsupported bool

	// The daemon's own account of which pass and rule decided (ADR-0011). They
	// are display-only: nothing on the Relay branches on them (invariant 12).
	// All stay empty when Unsupported is set or the daemon does not report them
	// (a daemon older than the field), so an empty Pass is "not reported", never
	// "no rule decided"; only "default" says deny-by-default.

	// Pass is the daemon's pass name: "precondition", "deny", "guard", "allow"
	// or "default".
	Pass string
	// RuleSection is "operation", "deny", "raw_exec_allow" or "raw_exec_deny";
	// empty when no rule decided.
	RuleSection string
	// RuleIndex is the rule's index within RuleSection; meaningful only when
	// RuleSection is set.
	RuleIndex int
	// RuleLine is the rule's 1-based source line; 0 when the daemon's loader
	// did not know it.
	RuleLine int
	// MatchedOn is the daemon's text, verbatim: positions and indices, never
	// an argument value.
	MatchedOn string
}

// JobRepository persists Jobs and their Stages.
type JobRepository interface {
	// CreateJob persists a new Job, including its Requester, in one write.
	CreateJob(ctx context.Context, job Job) error

	// AddStage adds a Stage to a Job. Returns ErrSingleStageOnly if the Job
	// already has a Stage — v1's one-stage-per-Job constraint, enforced in
	// code (the schema's CHECK/UNIQUE is defense-in-depth, not the primary guard).
	AddStage(ctx context.Context, stage Stage) error

	// GetJob returns the Job with the given ID, or ErrJobNotFound.
	GetJob(ctx context.Context, id string) (Job, error)

	// RecordHalt records h on jobID once. It returns ErrJobNotFound for an
	// unknown Job and ErrJobAlreadyHalted when the Job already carries a halt,
	// and it refuses an h whose Task is not a Task of jobID on h.NodeID, whose
	// Outcome is not failure or timeout, or whose Resolved is true while the
	// store does not hold that Task Resolved with Outcome.
	RecordHalt(ctx context.Context, jobID string, h Halt) error

	// Stages returns all Stages for jobID (at most one, in v1), ordered by Index.
	Stages(ctx context.Context, jobID string) ([]Stage, error)
}

// HaltedJobRepository is what a Relay restart reads to settle halted Jobs
// (execution.md, Halting a failing mutation).
type HaltedJobRepository interface {
	// GetJob returns the Job with the given ID, or ErrJobNotFound.
	GetJob(ctx context.Context, id string) (Job, error)

	// UnsettledTasksOfHaltedJobs returns every Pending or Dispatched Task whose
	// Job carries a halt, ordered by Job then Task ID.
	UnsettledTasksOfHaltedJobs(ctx context.Context) ([]Task, error)
}

// TaskRepository persists Tasks and their dispatch state. Each Mark* method
// and Resolve persists the TaskEvent of the matching kind (see
// Task.Transition) and re-checks its source state against the stored row.
type TaskRepository interface {
	// CreateTask persists a new Task with State = DispatchStatePending.
	CreateTask(ctx context.Context, task Task) error

	// MarkDispatched transitions a Task from Pending to Dispatched, recording
	// the dispatch time. Returns ErrTaskNotFound if the Task does not exist,
	// or ErrInvalidTaskState if the Task is not currently Pending.
	MarkDispatched(ctx context.Context, taskID string, at time.Time) error

	// Resolve transitions a Task from Dispatched to Resolved, recording the
	// Result and resolve time. Returns ErrTaskNotFound if the Task does not
	// exist, or ErrInvalidTaskState if the Task is not currently Dispatched.
	Resolve(ctx context.Context, taskID string, r Result) error

	// MarkUnreachable transitions a Task from Pending directly to Resolved
	// with OutcomeUnreachable, recording the resolve time but no
	// DispatchedAt — the Task was never sent (ADR-0004's offline fail-fast:
	// a matched-but-disconnected Node's Task must reach a terminal, truthful
	// outcome without ever claiming to have been dispatched). Returns
	// ErrTaskNotFound if the Task does not exist, or ErrInvalidTaskState if
	// the Task is not currently Pending.
	MarkUnreachable(ctx context.Context, taskID string, at time.Time) error

	// MarkVersionRefused transitions a Task from Pending directly to Resolved
	// with OutcomeVersionRefused and Stderr = VersionRefusedMessage, leaving
	// DispatchedAt unset — the Task was never sent because its Node's
	// relay-daemon is below the Relay's configured minimum version
	// (ADR-0014). Returns ErrTaskNotFound if the Task does not exist, or
	// ErrInvalidTaskState if the Task is not currently Pending.
	MarkVersionRefused(ctx context.Context, taskID string, at time.Time) error

	// MarkUnsupported transitions a Task from Pending directly to Resolved
	// with OutcomeUnsupported and Stderr = reason, leaving DispatchedAt unset
	// — the Relay excluded the Task's Node from a Template dispatch because
	// that Node does not report the Template, or has not reported its
	// vocabulary at all (ADR-0042), so the Task was never sent. reason is
	// Relay-authored and fixed, never daemon bytes. Returns ErrTaskNotFound if
	// the Task does not exist, or ErrInvalidTaskState if the Task is not
	// currently Pending.
	MarkUnsupported(ctx context.Context, taskID, reason string, at time.Time) error

	// MarkCancelled transitions a Task from Pending directly to Resolved with
	// OutcomeCancelled, leaving DispatchedAt unset — the Task was cancelled
	// before it was ever sent (ADR-0013). Returns ErrTaskNotFound if the Task
	// does not exist, or ErrInvalidTaskState if the Task is not currently
	// Pending.
	MarkCancelled(ctx context.Context, taskID string, at time.Time) error

	// MarkHalted transitions a Task from Pending directly to Resolved with
	// OutcomeCancelled and Stderr = reason, leaving DispatchedAt unset: its
	// mutate Job halted before the Task was sent (TaskEventHalt). reason is
	// Relay-authored (Halt.Reason). Returns ErrTaskNotFound if the Task does not
	// exist, or ErrInvalidTaskState if the Task is not currently Pending.
	MarkHalted(ctx context.Context, taskID, reason string, at time.Time) error

	// MarkCancelledBeforeSend transitions a Task from Dispatched to Resolved
	// with OutcomeCancelled, clears DispatchedAt and records the resolve time —
	// the row is identical to MarkCancelled's. The engine marked the Task
	// Dispatched (persist-then-send), but its Job's cancel was seen before the
	// send began, so the Task never left the Relay. Only the engine that
	// MarkDispatched the Task calls it, and only when nothing was sent. Returns
	// ErrTaskNotFound if the Task does not exist, or ErrInvalidTaskState if the
	// Task is not currently Dispatched.
	MarkCancelledBeforeSend(ctx context.Context, taskID string, at time.Time) error

	// MarkHaltedBeforeSend transitions a Task from Dispatched to Resolved with
	// OutcomeCancelled and Stderr = reason, and clears DispatchedAt: the engine
	// marked the Task Dispatched, but its mutate Job halted before the send
	// began, so the Task never left the Relay (TaskEventHaltBeforeSend). The row
	// is MarkHalted's. Only the engine that MarkDispatched the Task calls it, and
	// only when nothing was sent. Returns ErrTaskNotFound if the Task does not
	// exist, or ErrInvalidTaskState if it is not currently Dispatched.
	MarkHaltedBeforeSend(ctx context.Context, taskID, reason string, at time.Time) error

	// Get returns the Task with the given ID, or ErrTaskNotFound.
	Get(ctx context.Context, taskID string) (Task, error)

	// InFlight returns every Task in DispatchStateDispatched with no result
	// yet — the set a Relay restart must reconcile to preserve at-most-once
	// execution (ADR-0004).
	InFlight(ctx context.Context) ([]Task, error)

	// ByJob returns all Tasks belonging to jobID.
	ByJob(ctx context.Context, jobID string) ([]Task, error)
}
