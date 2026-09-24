// Package audit holds the Relay's append-only record of dispatched Tasks —
// the "who did what to which Node" trail (ADR-0004). Like internal/jobs, this
// package carries no database/sql dependency; internal/store holds the SQLite
// implementation.
//
// Scope note: this issue (v0.0.5 [2/8]) defines the Record shape, the table,
// and this interface. Who calls Append — wiring audit writes into the
// dispatch path — is a later v0.0.5 issue ([7/8]).
package audit

import (
	"context"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// Kind distinguishes what kind of event a Record describes: a dispatch
// attempt, a refusal (authz-deny or cap-reject, never dispatched), a Freeze
// engage/release (ADR-0013), a Job cancel (v0.0.6 [5/8], owner DECISION 2),
// a Control API lifecycle action (Enrollment Token mint/revoke, Node
// revoke — #116, ADR-0010), or a Plan (#119, ADR-0011: a no-execution
// PolicyQuery probe, distinct from a real dispatch). Kind is a plain
// unconstrained TEXT column in the schema (migrations/0002) — no CHECK
// constraint — so adding KindPlan here needs no migration.
const (
	KindDispatch      = "dispatch"
	KindRefusal       = "refusal"
	KindFreezeEngage  = "freeze_engage"
	KindFreezeRelease = "freeze_release"
	KindJobCancel     = "job_cancel"
	KindTokenMint     = "token_mint"
	KindTokenRevoke   = "token_revoke"
	KindNodeRevoke    = "node_revoke"
	KindPlan          = "plan"

	// KindProtocolViolation is a relay-daemon reporting something the wire
	// contract (/proto) does not permit — the refusal #632 added at the wire
	// boundary, made queryable (#638). Distinct from KindDispatch because it
	// is not a Task's outcome: the Task still resolves, truthfully, as a
	// Relay-authored failure and keeps its own dispatch row. Distinct from
	// KindRefusal because nothing was denied — the Relay refused a REPORT,
	// not a request.
	//
	// Its own kind rather than prose in a dispatch row's Reason because
	// "which Nodes are misbehaving" must be a WHERE clause, and because a
	// dispatch row's Stderr — where #632's explanation rides — is not
	// retained for a read-class Task (ADR-0025, auditsink's retainOutput). A
	// kind is queryable on every surface that already filters the trail by
	// kind, with no new filter to build.
	//
	// NodeID is the SUBJECT: the Node that sent the impermissible report.
	// Principal is empty — no Account did this, and the empty verified lane
	// is what keeps any surface from rendering the Node as an authenticated
	// actor. The Job and the Account that asked for it are one join away on
	// job_id.
	//
	// It carries no Stdout/Stderr/Truncated, on any risk class: the wire
	// boundary discards the daemon's bytes before this record exists
	// (internal/dispatch/convert.go), so the row is Relay-authored end to end.
	//
	// RESIDUAL, stated because it is the one thing this kind does not
	// guarantee: the writer at the wire boundary is deliberately FAIL-OPEN
	// (internal/dispatch's recordViolation says why — failing the dispatch
	// would strand the Task and hand a compromised Node a resend loop). If
	// the store cannot be written, NO ROW EXISTS for that violation; the
	// trace is a log line plus the
	// relay_protocol_violations_unrecorded_total counter, which is why that
	// counter exists.
	KindProtocolViolation = "protocol_violation"

	// KindApprovalRequested is a dispatch parked for a human (#269, ADR-0027).
	// Distinct from KindDispatch because nothing ran, and distinct from
	// KindRefusal because nothing was denied — a park is a suspension, and
	// filing it under either neighbour would make the audit trail assert
	// something untrue about it.
	KindApprovalRequested = "approval_requested"

	// KindApprovalPendingObserved is a re-drive of an already-parked dispatch
	// (#379): the caller attempted the same Plan again and bounced off the
	// existing pending Request, creating nothing. Distinct from
	// KindApprovalRequested so that kind keeps meaning "a request was created"
	// — re-driving is how a caller polls while waiting for a decision, and an
	// agent polling every few seconds must not inflate the count of asks or
	// bury a genuine second request among its polls. The polling itself stays
	// on the record under this kind: an auditor plausibly wants to see an agent
	// hammering a parked request, just not filed as repeat asks.
	KindApprovalPendingObserved = "approval_pending_observed"

	// KindApprovalGrantRequested is a request for a batch/window Grant (#546,
	// ADR-0027 decision 12): an ask for STANDING authority over many future
	// dispatches, not a single Plan waiting for a single answer.
	//
	// Distinct from KindApprovalRequested for the reason #379 split
	// KindApprovalPendingObserved out of it — so that kind keeps meaning one
	// thing. Filed together, "somebody asked for a window covering every
	// mutate on the fleet for the next hour" rendered identically to "one
	// dispatch is parked", and the blast radii are not comparable: a Grant
	// releases many Jobs, a park releases one.
	//
	// GrantID distinguishes them structurally and always has. A separate kind
	// is the stronger form of the same fact: a surface that forgets to check
	// GrantID renders a wrong sentence, whereas one that forgets this kind
	// fails audit's partition test instead (see Kinds).
	//
	// This is the ASK, not the grant of it. The Grant row exists from this
	// moment but cannot be claimed until the Request reaches approved, which
	// the store's claim query enforces — so the window this names is still
	// shut. RevokeGrant's closing of it is a KindApprovalDecided carrying a
	// GrantID, not this kind.
	KindApprovalGrantRequested = "approval_grant_requested"

	// KindApprovalExpired is a parked dispatch that ran out of time (#269,
	// ADR-0027). Recorded because an approval that lapsed is a fact the trail
	// must carry: without it a parked dispatch just vanishes from the record
	// and "what happened to that request?" has no answer.
	KindApprovalExpired = "approval_expired"

	// KindApprovalDecided is one human's answer to a parked dispatch (#270,
	// ADR-0027). Distinct from KindDispatch because a decision runs nothing,
	// and distinct from KindApprovalRequested because it is the other half of
	// the exchange: together with the request and the eventual dispatch, these
	// three kinds are what make "who asked / for whom / who approved / what
	// happened" one query rather than four correlated by timestamp.
	//
	// Recorded for denials and for partial approvals too, not only for the
	// decision that releases a Job.
	//
	// The answer itself (#545) is the ApprovalAnswer column, not prose in
	// Reason: Reason remains the human sentence, but a query or a renderer
	// must never parse it to learn which way the decision went.
	KindApprovalDecided = "approval_decided"

	// KindRead is a non-dispatching read-tool call — list_nodes,
	// describe_node, list_operations, get_job (#288, ADR-0025). These never
	// reach a Node, so they produce no Job and no Task, but they do disclose
	// the fleet's shape (and, via get_job, previously-captured command
	// output). Recorded as metadata only: who, which tool, what it was aimed
	// at, when. Never the result.
	KindRead = "read"

	// Identity-management kinds (#297, ADR-0010). Administering the control
	// plane's own identities is itself an audited, attributed act: "who
	// created this Account", "who made it an admin", and "who minted it a
	// credential" are the first questions asked after a compromise, and they
	// are unanswerable if identity changes are the one thing that happens
	// silently.
	//
	// KindAPITokenMint/Revoke are deliberately distinct from
	// KindTokenMint/Revoke above, which are *Enrollment* Tokens: the two join
	// Nodes and authenticate callers respectively, and conflating them in a
	// query would mix fleet growth with credential issuance.
	KindAccountCreate  = "account_create"
	KindAccountRole    = "account_role"
	KindAccountEnable  = "account_enable"
	KindAccountDisable = "account_disable"
	// The Console's human authentication lane (#418,
	// docs/design/console/12-login.md). Every attempt is recorded, successful
	// or not — this is the first link in the chain the UI advisory requires
	// end-to-end: login -> action -> audit record.
	//
	// KindLoginFailed deliberately carries NO indication of which half was
	// wrong. A trail that recorded "unknown account" separately from "wrong
	// password" would be the same enumeration oracle the login response
	// refuses to be, readable by anyone with audit access.
	//
	// KindLoginThrottled is distinct from KindLoginFailed because nothing was
	// checked: the attempt was refused before any credential was compared, so
	// counting it as a failure would overstate how many guesses were actually
	// made.
	KindLoginSucceeded = "login_succeeded"
	KindLoginFailed    = "login_failed"
	KindLoginThrottled = "login_throttled"
	KindLogout         = "logout"

	// KindStepUp/Failed/Throttled are the step-up door (#477, ADR-0026
	// decision 3), reached only from an ALREADY-AUTHENTICATED session — never
	// by an anonymous caller, which is what the sign-in door above is for. The
	// two doors answer different questions: KindLoginFailed/Throttled is
	// "someone is guessing at the front door"; the three below are "something
	// inside this session is trying to escalate", which is ADR-0026's own
	// threat model for a hijacked session reaching for a mutate apply. Pooling
	// them into the sign-in kinds would answer neither question well, and the
	// step-up-ness would survive only as prose in Reason — a field no query
	// (audit.Query / capability.AuditFilter) can filter on, not even by
	// prefix. See AuthFailureKinds for how the split is kept from costing the
	// pooled "is someone grinding a password" query.
	//
	// KindStepUp is the SUCCESSFUL re-proof of human presence: the fact that
	// authorizes a mutate apply (ADR-0026 decision 3) or a privilege-granting
	// action (ADR-0009). Distinct from KindLoginSucceeded so a kind-filtered
	// consumer can tell "signed in" from "re-proved presence mid-session".
	//
	// KindStepUpFailed carries no indication of which half was wrong, for the
	// same enumeration reason KindLoginFailed states above: a step-up runs
	// against the session's own Account, but a trail that named it anyway
	// would still be the oracle the login response refuses to be, readable by
	// anyone with audit access.
	//
	// KindStepUpThrottled is distinct from KindStepUpFailed because nothing
	// was checked, for the same reason KindLoginThrottled is distinct from
	// KindLoginFailed: the attempt was refused before any credential was
	// compared, so counting it as a failure would overstate how many guesses
	// were actually made.
	KindStepUp          = "step_up"
	KindStepUpFailed    = "step_up_failed"
	KindStepUpThrottled = "step_up_throttled"

	KindAPITokenMint   = "api_token_mint"
	KindAPITokenRevoke = "api_token_revoke"
)

// ApprovalAnswer values name the structured answer a KindApprovalDecided
// Record carries (#545, ADR-0027 decision 10). EMPTY means "this row records
// no approve/deny answer" — a grant revocation, or a row written before
// #545 — and NEVER "denied": conflating "no value" with "a value that means
// no" is the #487 bug. Values are byte-identical to
// approval.StateApproved/StateDenied.String() (#498's vocabulary); this
// package does not import internal/approval to get them, so a test pins the
// equality instead.
const (
	ApprovalAnswerApproved = "approved"
	ApprovalAnswerDenied   = "denied"
)

// allKinds is every Kind above, in declaration order. Kinds returns a copy of
// it.
var allKinds = []string{
	KindDispatch,
	KindRefusal,
	KindFreezeEngage,
	KindFreezeRelease,
	KindJobCancel,
	KindTokenMint,
	KindTokenRevoke,
	KindNodeRevoke,
	KindPlan,
	KindProtocolViolation,
	KindApprovalRequested,
	KindApprovalGrantRequested,
	KindApprovalPendingObserved,
	KindApprovalExpired,
	KindApprovalDecided,
	KindRead,
	KindAccountCreate,
	KindAccountRole,
	KindAccountEnable,
	KindAccountDisable,
	KindLoginSucceeded,
	KindLoginFailed,
	KindLoginThrottled,
	KindLogout,
	KindStepUp,
	KindStepUpFailed,
	KindStepUpThrottled,
	KindAPITokenMint,
	KindAPITokenRevoke,
}

// Kinds returns every Kind this package defines, in declaration order.
//
// It exists so that a consumer which PARTITIONS the vocabulary can be tested
// against the whole of it. The Console's Activity screen requests the trail by
// naming kinds explicitly (one lane serves dispatch, another serves the rest),
// so a Kind added above and classified nowhere would silently stop appearing
// on the surface billed as the trail. With this, that omission fails a test
// instead.
//
// The returned slice is a copy: the package's own list is not a caller's to
// reorder or truncate.
func Kinds() []string {
	return append([]string(nil), allKinds...)
}

// authFailureKinds is every Kind recording a credential that was submitted
// and not accepted, at either the sign-in door or the step-up door. Named
// once here rather than left for AuthFailureKinds to build on every call, for
// the same reason allKinds is a package var and not a literal inside Kinds.
var authFailureKinds = []string{
	KindLoginFailed,
	KindLoginThrottled,
	KindStepUpFailed,
	KindStepUpThrottled,
}

// notAnAuthFailureKinds is every OTHER Kind: the ones that record something
// besides a refused credential. It exists only so the two lists together form
// a CLOSED PARTITION of Kinds(), which is what makes
// TestAuthFailureKinds_PartitionsTheWholeVocabulary able to fail on a kind
// nobody classified.
//
// Why a second list rather than a rule over names: the first version of that
// test derived membership from the "_failed"/"_throttled" suffix, and a
// security review showed it did not catch the case it was written for. A new
// kind spelled step_up_denied (or login_refused, or password_mismatch) that
// somebody forgot to add to authFailureKinds has no suffix, so the suffix test
// saw nothing to complain about and passed — it only ever fired on a kind
// ADDED to the group, which is not the mistake anyone makes. The suffix rule
// also silently COMPELLED the wrong answer in the other direction: a future
// enrollment_failed or dispatch_failed would have been forced into the
// credential-grinding query, where a Node enrollment failure would be counted
// as an attack on a password.
//
// Listing both sides costs one line per new kind and makes that line a
// decision. Anything unclassified fails the test until someone says which it
// is, which is the property the group needs and the suffix could not give.
var notAnAuthFailureKinds = []string{
	KindDispatch,
	KindRefusal,
	KindFreezeEngage,
	KindFreezeRelease,
	KindJobCancel,
	KindTokenMint,
	KindTokenRevoke,
	KindNodeRevoke,
	KindPlan,
	KindProtocolViolation,
	KindApprovalRequested,
	KindApprovalGrantRequested,
	KindApprovalPendingObserved,
	KindApprovalExpired,
	KindApprovalDecided,
	KindRead,
	KindAccountCreate,
	KindAccountRole,
	KindAccountEnable,
	KindAccountDisable,
	KindLoginSucceeded,
	KindLogout,
	KindStepUp,
	KindAPITokenMint,
	KindAPITokenRevoke,
}

// AuthFailureKinds is every Kind recording a credential that was submitted
// and not accepted, at EITHER door — the sign-in form or the step-up prompt.
//
// It exists so "someone is grinding a password" stays ONE thing to ask for
// after #477 split the step-up door out of the sign-in kinds. The trap it
// closes: a consumer that hand-lists KindLoginFailed and KindLoginThrottled is
// not wrong today, and goes blind the moment an attacker pivots from the
// sign-in form to the step-up prompt — the cheaper target precisely because
// the session already exists. Reaching for this instead of naming the kinds
// again is what keeps that pivot from going unnoticed.
//
// Never KindStepUp or KindLoginSucceeded: a query built from this list is
// asking "who failed", and a success counted as a failure would make the
// grinding query lie in the one direction that matters.
//
// The returned slice is a copy, exactly like Kinds(): the package's own list
// is not a caller's to reorder or truncate.
func AuthFailureKinds() []string {
	return append([]string(nil), authFailureKinds...)
}

// Record is one append-only audit entry: a single Task's dispatch, a
// refusal, or a Freeze engage/release, as issued by a principal. Fields are
// self-contained primitives (no pointers into Job/Task state) so a Record
// remains meaningful even after the Job or Task it describes is gone.
type Record struct {
	// ID is unique, and since #656 also MONOTONIC: NewID mints it so that
	// lexicographic order over ids is mint order. That is what makes the
	// (Timestamp, ID) tie-break below mean "append order" rather than
	// "whichever random hex won".
	ID        string
	Timestamp time.Time
	Kind      string

	// Principal is the human-readable "name:role" rendering of the acting
	// Account, kept because it is what an operator reads at a glance.
	// Attribution below is the structured form, and is authoritative: query
	// against it, not against this string.
	Principal string

	// Attribution carries the verified and asserted identity lanes (#300).
	// The lanes are structurally distinct here and in the schema — see
	// attribution.go for why that separation is load-bearing rather than
	// cosmetic.
	Attribution Attribution

	Selector      string
	JobID         string
	NodeID        string
	ActionKind    string
	OperationName string
	Args          map[string]string
	RawExecArgv   []string
	// Outcome is only meaningful when Kind == KindDispatch (one Task's
	// result). For KindRefusal, KindFreezeEngage, and KindFreezeRelease rows
	// Outcome is always jobs.OutcomeUnspecified (the zero value) and must not
	// be confused with a real per-Node "didn't execute" outcome — a naive
	// `WHERE outcome = 0` query would otherwise silently mix refusals in with
	// unresolved dispatch outcomes.
	Outcome jobs.Outcome
	Reason  string
	// Stdout, Stderr, and Truncated are the full captured per-Task output and
	// the daemon-side truncated flag (#122 full-output-always: the Relay
	// stores what it received, entire — the only cap is the daemon-side
	// size limit). Meaningful only for KindDispatch rows that reached
	// execution, or that carry a Relay-synthesized refusal message (e.g.
	// version-refused); empty for refusals, plans, freeze, and cancel rows.
	// Truncated is the daemon-side cap flag: a single flag over the whole
	// result, not per-stream (mirrors jobs.Result.Truncated).
	Stdout    []byte
	Stderr    []byte
	Truncated bool

	// ApprovalID and GrantID join a record to the approval callout that
	// authorized it (ADR-0027). Both are empty for the overwhelming majority of
	// records, and empty means "no approval was involved" — never "unknown".
	//
	// They exist as columns rather than as prose in Reason because the
	// questions they answer are asked under time pressure and must be a WHERE
	// clause: "what ran under this approval", and — for a batch/window Grant,
	// which covers many dispatches — "what did that window actually release".
	//
	// ApprovalID is set on a park, on a decision, and on every dispatch either
	// a single approval or a Grant released. For a Grant it is the Grant's own
	// authorizing Request, which is what makes every covered Job share one
	// approval ID.
	//
	// GrantID is set only when a Grant released the dispatch. Its presence is
	// the difference between "a human approved THIS plan" and "a human approved
	// a window this plan fell inside" — a distinction an auditor needs and
	// cannot recover from ApprovalID alone.
	ApprovalID string
	GrantID    string

	// ApprovalAnswer, DecisionChannel, and PlanHash are the structured
	// counterpart to a KindApprovalDecided row's prose Reason (#545,
	// ADR-0027 decision 10: "approved_by (verified, WITH CHANNEL AND
	// PLAN-HASH)"). Empty for the overwhelming majority of rows, and empty
	// means "not applicable / not recorded" — never a value. ApprovalAnswer
	// is one of the ApprovalAnswer* constants above, or empty (see their
	// doc for why empty is a third state, not "denied").
	ApprovalAnswer  string
	DecisionChannel string
	PlanHash        string
}

// Repository is the interface for the audit trail. Append-only: there is no
// update or delete.
//
// Every reader below returns Records ordered by Timestamp, ties broken by ID.
// That pair is a TOTAL order (#656): ID is minted monotonically by NewID, so
// two Records sharing a Timestamp — which a dispatch fan-out guarantees, since
// every per-Node Record copies one clock reading — come back in the same
// order on every read, rather than in one that changes with each write.
//
// That order is the order the ids were MINTED in, which for the cases this
// exists for is the order the Records were appended: a fan-out and an
// AppendAll batch are both built in one pass, minting as they go. The two
// differ only for concurrent Record calls that land on one Timestamp, where
// "which was appended first" is not a question with an answer anyway.
type Repository interface {
	// Append persists a new Record.
	Append(ctx context.Context, r Record) error

	// AppendAll persists every Record in rs atomically: on a nil error all of
	// them were written, on a non-nil error none were. An empty rs is a
	// no-op. Callers that write an unbounded number of records bound the
	// slice themselves: the store serialises every request through one
	// connection, and the whole call holds it.
	AppendAll(ctx context.Context, rs []Record) error

	// List returns all Records, ordered by Timestamp, ties broken by ID.
	List(ctx context.Context) ([]Record, error)

	// ByJob returns all Records for jobID, ordered by Timestamp, ties
	// broken by ID.
	ByJob(ctx context.Context, jobID string) ([]Record, error)

	// ByNode returns all Records for nodeID, ordered by Timestamp, ties
	// broken by ID — the
	// "which Node" accountability query (AGENTS.md). Time-range querying is
	// deferred to the first query surface; no acceptance need yet.
	ByNode(ctx context.Context, nodeID string) ([]Record, error)

	// ByAccount returns all Records for an Account ID, ordered by Timestamp,
	// ties broken by ID —
	// the verified-lane query. It takes the ID rather than the name so the
	// trail stays queryable across a rename, which is the reason the ID is
	// recorded at all.
	ByAccount(ctx context.Context, accountID string) ([]Record, error)

	// ByApproval returns all Records authorized by an approval Request,
	// ordered by Timestamp, ties broken by ID — including the park and the
	// decision themselves, so
	// one query answers "who asked, who approved, and what then ran". For a
	// batch/window Grant's Request this is every dispatch the window released.
	ByApproval(ctx context.Context, approvalID string) ([]Record, error)

	// ByGrant returns all Records released by a batch/window Grant, ordered by
	// Timestamp, ties broken by ID. Narrower than ByApproval on the same Request: this is the
	// dispatches only, which is what "what did that window actually do" means.
	ByGrant(ctx context.Context, grantID string) ([]Record, error)

	// ByOnBehalfOf returns all Records carrying an exact asserted OnBehalfOf
	// value, ordered by Timestamp, ties broken by ID — the asserted-lane query.
	//
	// Deliberately a separate method from ByAccount rather than a shared
	// "principal" filter: a caller reading this trail must not be able to
	// confuse "the Relay authenticated this Account" with "someone typed this
	// string", and two differently-named methods make the lane you are
	// querying impossible to miss at the call site.
	ByOnBehalfOf(ctx context.Context, onBehalfOf string) ([]Record, error)
}
