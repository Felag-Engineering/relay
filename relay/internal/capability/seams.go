package capability

import (
	"context"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/relay/relay/internal/policyview"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// ControlAction names one administrative act on the control plane ITSELF —
// the acts that are not dispatches and so carry no jobs.Action and no
// Selector, but still have a role floor.
//
// It exists because "who may ask" is not only a question for things that
// reach a Node. Minting an Enrollment Token, revoking one, revoking a Node,
// engaging or releasing the Freeze, and cancelling a Job never touch the
// dispatch pipeline, so a role gate on dispatch alone would leave every one
// of them reachable by a viewer. Naming them here —
// in the capability layer, beside the Action-shaped question — is what lets
// a single Authorizer answer both, so MCP, the Control API, and the Console
// inherit one table rather than each surface carrying its own (invariant 10).
//
// The values are stable, low-cardinality identifiers: they appear in refusal
// reasons that land in the audit trail.
type ControlAction string

const (
	// ControlMintEnrollmentToken is POST /api/v1/enrollment-tokens. A token's
	// scope becomes the enrolling Node's relay: labels — the namespace
	// reserved for the security-sensitive lane (invariant 7, ADR-0020) — so
	// minting is a claim the control plane vouches for, not a convenience.
	ControlMintEnrollmentToken ControlAction = "mint_enrollment_token"

	// ControlRevokeEnrollmentToken is DELETE /api/v1/enrollment-tokens/{id},
	// which cascade-revokes every Node the token enrolled.
	ControlRevokeEnrollmentToken ControlAction = "revoke_enrollment_token"

	// ControlRevokeNode is POST /api/v1/nodes/{node_id}/revoke: the middle
	// rung of ADR-0020's incident ladder (quarantine < revoke < Freeze).
	ControlRevokeNode ControlAction = "revoke_node"

	// ControlFreezeEngage is POST /api/v1/freeze/engage (ADR-0013).
	ControlFreezeEngage ControlAction = "freeze_engage"

	// ControlFreezeRelease is POST /api/v1/freeze/release (ADR-0013).
	ControlFreezeRelease ControlAction = "freeze_release"

	// ControlCancelJob is POST /api/v1/jobs/{id}/cancel, MCP's cancel_job and
	// tasks/cancel, and the Console's Cancel control. The ROLE floor
	// is operator and not human-only: an AI-agent must be able to cancel its
	// own dispatch (execution.md §Cancellation, owner decision
	// 2026-09-14). The SCOPE differs by Kind (owner decision
	// 2026-09-17): a human Account may cancel any Job, a machine Account
	// only one whose recorded requester is itself — see
	// Execution.CancelJob/authorizeMachineCancel.
	ControlCancelJob ControlAction = "cancel_job"

	// Account and API-Token administration: GET/POST
	// /api/v1/accounts[...] and .../tokens. All eight sit at admin
	// (authz.requiredControlRole) — identity management is admin-only in
	// full, the same posture the Control API's now-deleted requireAdmin
	// enforced per handler. See accountadmin.go for why this surface lives
	// in the capability layer rather than an adapter (invariant 10).

	// ControlAccountRead is GET /api/v1/accounts and GET
	// /api/v1/accounts/{id}: listing or reading an Account.
	ControlAccountRead ControlAction = "account_read"

	// ControlAccountCreate is POST /api/v1/accounts.
	ControlAccountCreate ControlAction = "account_create"

	// ControlAccountRole is POST /api/v1/accounts/{id}/role: the single most
	// security-relevant edit on this surface.
	ControlAccountRole ControlAction = "account_role"

	// ControlAccountEnable is POST /api/v1/accounts/{id}/enable.
	ControlAccountEnable ControlAction = "account_enable"

	// ControlAccountDisable is POST /api/v1/accounts/{id}/disable.
	ControlAccountDisable ControlAction = "account_disable"

	// ControlAPITokenRead is GET /api/v1/accounts/{id}/tokens: listing an
	// Account's API Tokens (the redacted view).
	ControlAPITokenRead ControlAction = "api_token_read"

	// ControlAPITokenMint is POST /api/v1/accounts/{id}/tokens: issuing a new
	// credential.
	ControlAPITokenMint ControlAction = "api_token_mint"

	// ControlAPITokenRevoke is DELETE /api/v1/api-tokens/{token_id}.
	ControlAPITokenRevoke ControlAction = "api_token_revoke"

	// ControlPolicyAlias is setting, renaming or clearing a Policy alias:
	// admin and human Account only. It takes no step-up, because an alias
	// gates nothing.
	ControlPolicyAlias ControlAction = "policy_alias"

	// ControlTagWrite is adding, replacing or removing a tag: label: a human
	// Account at operator or above. It takes no step-up, because a tag gates
	// nothing (ADR-0050 decisions 2 and 5).
	ControlTagWrite ControlAction = "tag_write"
)

// PolicyAliasSource is the read side of Policy aliases: every alias the Relay
// holds, fingerprint to alias. It is read-only, and an alias never reaches
// Selector resolution, a Plan or a dispatch.
type PolicyAliasSource interface {
	List(ctx context.Context) (map[string]string, error)
}

// PolicyAliasRecorder makes a Policy alias change AND appends its audit record
// in one transaction: nil means both landed, an error means neither did. It is
// kept off AuditSink, exactly like IntentRecorder, so a sink that cannot make
// the two atomic cannot claim to.
type PolicyAliasRecorder interface {
	RecordPolicyAlias(ctx context.Context, e PolicyAliasEvent) error
}

// PolicyAliasEvent is one alias change. Old and New are "" for "no alias". It
// has no Node, Label or Selector field: an alias attaches to a fingerprint.
type PolicyAliasEvent struct {
	Principal   Principal
	Fingerprint string
	Old         string
	New         string
	Asserted    Assertions
}

// TagWriteRecorder makes a batch of tag changes AND appends their audit records
// in one transaction: nil means every change and record landed, an error means
// none did. It is kept off AuditSink, exactly like PolicyAliasRecorder, so a
// sink that cannot make the two atomic cannot claim to.
type TagWriteRecorder interface {
	RecordTagWrite(ctx context.Context, e TagWriteEvent) error
}

// TagWriteEvent is a batch of tag changes by one Principal. Each change is one
// audit record, carrying its Node and its old and new value.
type TagWriteEvent struct {
	Principal Principal
	Changes   []registry.TagChange
	Asserted  Assertions
}

// TagNodeReader is the read the tag write needs: one Node's current tags.
// registry.Repository satisfies it.
type TagNodeReader interface {
	Get(nodeID string) (registry.Node, bool)
}

// AccountStore is the Account half of the collaborator accountadmin.go needs:
// five methods narrowed from accounts.Repository. Deliberately not
// accounts.Repository itself: GetByName/TouchLastSeen belong to the
// authentication boundary, not to administering Accounts.
type AccountStore interface {
	Create(ctx context.Context, a accounts.Account) (accounts.Account, error)
	Get(ctx context.Context, id string) (accounts.Account, error)
	List(ctx context.Context) ([]accounts.Account, error)
	SetRole(ctx context.Context, id string, from, to accounts.Role) error
	SetEnabled(ctx context.Context, id string, enabled bool) error
}

// APITokenStore is the API-Token half, narrowed exactly as
// api.APITokenService was: Verify is deliberately absent — this surface
// ISSUES credentials, the authenticator CHECKS them, and neither needs the
// other's power.
type APITokenStore interface {
	Mint(ctx context.Context, accountID, name string, ttl time.Duration) (accounts.APIToken, accounts.Plaintext, error)
	Revoke(ctx context.Context, id string) error
	List(ctx context.Context, accountID string) ([]accounts.APIToken, error)
}

// ControlAuthorizer decides whether p may perform a ControlAction — the
// administrative half of the authorization question, split out as its own
// interface so a surface that only needs *this* half (the Control API's
// enrollment and revocation routes, which never dispatch) can depend on it
// without holding anything that can reach a Node.
type ControlAuthorizer interface {
	AuthorizeControl(ctx context.Context, p Principal, act ControlAction) error
}

// Authorizer decides whether p may perform act against sel, and whether p
// may perform an administrative ControlAction. This seam is how surfaces
// (MCP, Control API, Admin Console) plug into the pipeline.
//
// The two questions live on ONE interface deliberately. They are the same
// question asked about different objects, and the production implementation
// (authz.RoleGate) is one object holding one ladder; splitting them into two
// independently-wired seams is how a deployment ends up with a real gate on
// dispatch and an allow-all gate on enrollment.
type Authorizer interface {
	Authorize(ctx context.Context, p Principal, act jobs.Action, sel Selector) error
	ControlAuthorizer
}

// allowAllAuthorizer authorizes every request. Only in-package tests install
// it: NewExecution and NewAccountAdmin refuse it.
//
// NewExecution's fail-open guard refuses to build an Execution that pairs this with a
// real dispatcher, which is what keeps it out of production for BOTH halves
// of the interface — a Relay whose Freeze anyone may engage is the same class
// of wiring bug as one whose Raw Exec anyone may run.
type allowAllAuthorizer struct{}

func (allowAllAuthorizer) Authorize(context.Context, Principal, jobs.Action, Selector) error {
	return nil
}

func (allowAllAuthorizer) AuthorizeControl(context.Context, Principal, ControlAction) error {
	return nil
}

// CapChecker enforces the blast-radius cap (ADR-0004) before any dispatch.
// The real read-cap/mutate-cap enforcement — including the Raw-Exec-always-
// mutate-cap rule (ADR-0012) — is BlastCap (caps.go); the pipeline passes the
// resolved RiskClass and matched-Node count.
type CapChecker interface {
	Check(class jobs.RiskClass, matched int) error
}

// noopCapChecker enforces no cap. Only in-package tests install it:
// NewExecution refuses it.
type noopCapChecker struct{}

func (noopCapChecker) Check(jobs.RiskClass, int) error {
	return nil
}

// AuditSink records a completed dispatch, a refusal, a Freeze
// engage/release, or a Job cancel. The real adapter to audit.Repository
// (deliberately not imported here; capability stays free of the audit
// package) is internal/auditsink.
type AuditSink interface {
	Record(ctx context.Context, e AuditEntry) error

	// RecordFreeze records a Freeze engage/release event (ADR-0013).
	RecordFreeze(ctx context.Context, e FreezeEvent) error

	// RecordCancel records a Job cancel action, attributed to p (v0.0.6
	// [5/8], owner DECISION 2). Cancellation is durably recorded on each
	// affected Task via OutcomeCancelled regardless (ADR-0013) — this adds
	// the principal-attributed audit row so *who* asked for the stop is
	// queryable, mirroring RecordFreeze. Execution.CancelJob calls this only
	// after the cancel itself was attempted successfully; see CancelJob's
	// doc comment.
	RecordCancel(ctx context.Context, p Principal, jobID string) error

	// RecordRead records one metadata-only read-access event (ADR-0025,
	// including the trail's own read lane): who read, which tool,
	// what they aimed it at, and when — never the result. tool is a
	// low-cardinality name (readlane.go's constants); selector, nodeID, and
	// jobID are whichever of "what was aimed at" apply, empty otherwise.
	//
	// *auditsink.Sink already implements exactly this signature
	// (auditsink.go), so it joins the AuditSink interface rather than
	// getting its own seam — the same reason Record/RecordFreeze/
	// RecordCancel are one interface (this file's doc comment above): a
	// separately-wired read auditor is how a deployment ends up with audited
	// dispatch and an unaudited trail, and NewExecution's real-dispatcher fail-open
	// guard (pipeline.go) then covers the read lane for free, with no new
	// guard to remember.
	RecordRead(ctx context.Context, p Principal, tool, selector, nodeID, jobID string) error

	// RecordAccountAdmin records one Account or API-Token administration act
	// — creating an Account, changing its role, enabling/disabling
	// it, or minting/revoking an API Token. It joins this interface rather
	// than getting its own seam for the same reason RecordRead does: a
	// separately-wired administration auditor is how a deployment ends up
	// with audited dispatch and unaudited identity changes, and NewExecution's
	// real-dispatcher/NewReadLane fail-open guards then cover it for free.
	//
	// Reads (Accounts/Account/APITokens) never call this — see
	// accountadmin.go's file header for why that is load-bearing, not an
	// oversight.
	RecordAccountAdmin(ctx context.Context, p Principal, e AccountAdminEvent) error
}

// AccountAdminKind distinguishes which Account/API-Token administration act
// an AccountAdminEvent describes, mirroring audit.KindAccount*/KindAPIToken*
// (capability may not import internal/audit — .golangci.yml's capability-imports
// rule — so this mirrors rather than shares that vocabulary; auditsink, the one
// package that imports both, pins the two equal).
type AccountAdminKind int

const (
	AccountAdminCreate AccountAdminKind = iota
	AccountAdminRole
	AccountAdminEnable
	AccountAdminDisable
	AccountAdminTokenMint
	AccountAdminTokenRevoke
)

// AccountAdminEvent is what accountadmin.go passes to
// AuditSink.RecordAccountAdmin. THE STRUCT HAS NO FIELD A Plaintext COULD
// OCCUPY — the mint audit row's guarantee, expressed as a type: MintAPIToken
// records TokenID here, never the minted credential.
type AccountAdminEvent struct {
	Kind AccountAdminKind

	// AccountID and AccountName name the Account the act was performed on
	// (every Kind) or, for a create, the Account just created.
	AccountID   string
	AccountName string

	// Role is set for AccountAdminCreate (the Account's initial role) and
	// AccountAdminRole (the new role); empty otherwise.
	Role string

	// AccountKind is set for AccountAdminCreate only: the created Account's
	// accounts.Kind (human/machine), carried as a plain string so this
	// package's import allowlist stays unaffected either way. Without it the
	// trail cannot answer "was this Account created as a machine identity",
	// which matters on a compromise — the account_id/account_name/role
	// columns already on this event describe the TARGET, never the acting
	// Principal, and Kind is the fourth fact about that target.
	AccountKind string

	// TokenID is set for AccountAdminTokenMint/Revoke; empty otherwise.
	// Never the token's secret — see this type's doc comment above.
	TokenID string

	// Asserted is the caller-claimed attribution lane, read off the
	// request context. Recorded, never consulted.
	Asserted Assertions
}

// AuditKind distinguishes what kind of Run outcome an AuditEntry describes.
type AuditKind int

const (
	AuditKindDispatch AuditKind = iota
	AuditKindRefusal

	// AuditKindPlan is a no-execution Plan (ADR-0011): Principal,
	// Selector, and Action are set exactly as for AuditKindDispatch, but
	// JobID/Results/Reason are always empty — a Plan creates no Job/Task, so
	// there is nothing to reference by ID and no per-Node NodeResult set,
	// only the transient (unaudited) per-Node Verdicts returned to the
	// caller directly.
	AuditKindPlan

	// AuditKindApprovalRequested is a dispatch parked for a human (ADR-0027):
	// Principal, Selector, and Action are set exactly as for a dispatch, plus
	// ApprovalID and PlanHash, and Reason carries the Relay-authored summary.
	// JobID and Results are empty — nothing ran and no Job exists yet.
	//
	// It is a distinct kind rather than a Refusal because it is not one:
	// nothing was denied. Filing parks under refusals would make the approval
	// mechanism look like breakage on every dashboard that counts them, which
	// is how a safety feature gets switched off.
	AuditKindApprovalRequested

	// AuditKindApprovalGrantRequested is a request for a batch/window Grant
	// (ADR-0027 decision 12) — an ask for STANDING authority over many
	// future dispatches, written by RequestGrant. Distinct from
	// AuditKindApprovalRequested so that kind keeps meaning "one Plan is
	// parked": a Grant and a park have blast radii that are not comparable,
	// and filing them together made the trail say they were the same act.
	// ApprovalID, PlanHash and GrantID are all set on it.
	AuditKindApprovalGrantRequested

	// AuditKindApprovalPendingObserved is a re-drive of a dispatch that is
	// ALREADY parked: checkApproval found an existing pending Request
	// rather than creating one. Fields are set exactly as for
	// AuditKindApprovalRequested — ApprovalID and PlanHash name the request the
	// caller bounced off.
	//
	// It is a distinct kind because re-driving is how a caller polls while
	// waiting, and filing every poll as approval_requested would let the trail
	// inflate until "how many approvals were asked for" needs de-duplication to
	// answer — and would bury a genuine second request among the polls. Kept as
	// a record at all (rather than silently dropped, as the notifier correctly
	// does) because an AI-agent hammering a parked request is something an auditor
	// plausibly wants to see; it just isn't a repeat ask.
	AuditKindApprovalPendingObserved

	// AuditKindApprovalDecided is one recorded answer to a parked dispatch
	// (ADR-0027): Principal is the decider, ApprovalID and PlanHash name
	// what they answered, and Reason states the answer, the resulting request
	// state, the quorum progress, and the decider's own note.
	//
	// Selector, Action, JobID, and Results are all empty. A decision is not a
	// dispatch and does not describe one — it is an act on the approval object,
	// and the Job it eventually releases is joined through ApprovalID rather
	// than by copying the Action into a second place where the two could
	// disagree.
	//
	// Every decision is recorded, not only the one that completes a quorum, so
	// "one approver signed and then it expired" is answerable. A partial
	// approval that leaves no trace is how an audit trail loses the interesting
	// half of the story.
	//
	// ApprovalAnswer and DecisionChannel are set by DecideApproval on
	// this kind only, and are deliberately empty on the grant-revocation entry
	// RevokeGrant writes — a revocation is not a Decision, so nobody answered
	// a parked Job.
	AuditKindApprovalDecided

	// AuditKindDispatchIntent is a Job's dispatch intent: Principal,
	// Selector, Action, JobID, ApprovalID, GrantID and Asserted are set, plus
	// CapCleared. It is recorded with the Job's Tasks in one transaction, by
	// IntentRecorder.RecordIntent and never by AuditSink.Record, so it exists
	// before any Task can be dispatched. Results and Reason are empty.
	// Appended at the end so no existing AuditKind value moves.
	AuditKindDispatchIntent
)

// ApprovalAnswer is the structured answer a Decision carries. package
// capability may not import internal/audit (.golangci.yml's capability-imports rule),
// so this mirrors — rather than shares — audit.ApprovalAnswer*; auditsink,
// the one package that imports capability, audit, AND approval, pins the two
// vocabularies equal.
//
// ApprovalAnswerUnrecorded (the zero value) means "no answer" — a grant
// revocation, or an AuditEntry a future kind writes without one — and NEVER
// "denied": "no value" is not "a value that means no".
type ApprovalAnswer string

const (
	ApprovalAnswerUnrecorded ApprovalAnswer = ""
	ApprovalAnswerApproved   ApprovalAnswer = "approved"
	ApprovalAnswerDenied     ApprovalAnswer = "denied"
)

// AuditEntry is everything the pipeline knows about one Run call, passed to
// AuditSink.Record. Principal is threaded through here so every future real
// AuditSink can attribute the entry without the pipeline itself needing to
// know audit's storage shape.
//
// For AuditKindDispatch, JobID and Results are set and Reason is empty. For
// AuditKindRefusal (authz-deny, cap-reject, a zero-match dispatch
// (no_nodes_matched), or CancelJob's machine-Account scoping),
// Reason is set and Results is empty — the dispatcher was never reached —
// but JobID is NOT always empty: refuseControl's role-floor refusal leaves
// it empty (it precedes any existence check, so the id is unvalidated caller
// text), while refuseCancel's machine-scoping refusal sets it to the store's
// own echo of the Job authorizeMachineCancel's lookup actually found — never
// a caller-supplied id the Relay never validated.
// For AuditKindPlan, only Principal/Selector/Action are set — JobID,
// Results, and Reason are all empty, since a Plan never dispatches (no
// Job/Task exists to reference) even when it reports a would-be-rejected
// cap/Freeze/no-Nodes-matched condition.
type AuditEntry struct {
	Kind      AuditKind
	Principal Principal
	Selector  Selector
	Action    jobs.Action
	JobID     string
	Results   []NodeResult
	Reason    string

	// ApprovalID and PlanHash tie a record to the approval callout (ADR-0027).
	// Both are set on AuditKindApprovalRequested; ApprovalID is also set on an
	// AuditKindDispatch that an approval released, so "who approved what
	// actually ran" is one join rather than a correlation by timestamp.
	ApprovalID string
	PlanHash   string

	// GrantID is the batch/window Grant that released this dispatch (ADR-0027
	// decision 12), empty when a single-Plan approval or no gate did. Recorded
	// so a grant's full blast radius — every Job it released, across its whole
	// window — is one query rather than a reconstruction from timestamps.
	GrantID string

	// Asserted is the caller-claimed attribution lane, read off the
	// request context by Execution.Run/Plan. Recorded, never consulted — see
	// assertions.go.
	Asserted Assertions

	// ApprovalAnswer and DecisionChannel are the structured counterpart to a
	// KindApprovalDecided entry's prose Reason (ADR-0027 decision 10).
	// Set by DecideApproval, and deliberately EMPTY on the grant-revocation
	// entry RevokeGrant writes — a revocation is not a Decision; nobody
	// answered a parked Job.
	//
	// DecisionChannel is approval.Channel, not a string, so the value cannot
	// be forged into a channel the surface did not stamp.
	ApprovalAnswer  ApprovalAnswer
	DecisionChannel approval.Channel

	// CapCleared is the number of Nodes the blast cap cleared for dispatch; set
	// only on AuditKindDispatchIntent.
	CapCleared int
}

// IntentRecorder persists a Job's Pending Tasks and its dispatch-intent audit
// record in one transaction: nil = both landed, error = neither.
// Kept off AuditSink deliberately: a sink that cannot persist Tasks must not
// be able to claim it can.
type IntentRecorder interface {
	RecordIntent(ctx context.Context, e AuditEntry, tasks []jobs.Task) error
}

// FreezeEvent is a Freeze engage/release, passed to AuditSink.RecordFreeze
// (ADR-0013). Freeze is Relay-wide, so unlike AuditEntry there is no
// Selector/NodeID to record. Reason is expected to be set on release.
type FreezeEvent struct {
	Principal Principal
	Engage    bool
	Reason    string
	Asserted  Assertions
}

// noopAuditSink is the v0.0.5 default: nothing is recorded.
type noopAuditSink struct{}

func (noopAuditSink) Record(context.Context, AuditEntry) error {
	return nil
}

func (noopAuditSink) RecordFreeze(context.Context, FreezeEvent) error {
	return nil
}

func (noopAuditSink) RecordCancel(context.Context, Principal, string) error {
	return nil
}

func (noopAuditSink) RecordRead(context.Context, Principal, string, string, string, string) error {
	return nil
}

func (noopAuditSink) RecordAccountAdmin(context.Context, Principal, AccountAdminEvent) error {
	return nil
}

// FreezeStore is the persisted, Relay-wide emergency stop (ADR-0013): "I
// don't trust what's driving this, stop dispatching everything." Execution.Run
// consults Frozen before every dispatch (both risk classes); EngageFreeze/
// ReleaseFreeze call Engage/Release. This seam takes only a context, so it is
// allowlist-safe for capability's import-boundary guard
// (.golangci.yml's capability-imports rule); the SQLite-backed
// implementation (internal/store, behind internal/freeze.Repository, whose
// method set mirrors this one) is wired in via NewControl, kept out of
// package capability for the same import-boundary reason as Conduit/
// AuditSink.
type FreezeStore interface {
	// Frozen reports whether the Freeze is currently engaged.
	Frozen(ctx context.Context) (bool, error)

	// Engage sets the Freeze, recording principal as who engaged it.
	Engage(ctx context.Context, principal string) error

	// Release clears the Freeze, recording principal as who released it and
	// reason as why.
	Release(ctx context.Context, principal, reason string) error
}

// noopFreezeStore is the v0.0.5 default: "never frozen". This is a missing
// stop-button, not a fail-open of authz/cap/audit — but see NewExecution's fail-open
// guard (pipeline.go), which requires a real FreezeStore alongside a real
// dispatcher for exactly that reason: an un-stoppable real executor is the
// same class of composition-root wiring bug.
type noopFreezeStore struct{}

func (noopFreezeStore) Frozen(context.Context) (bool, error) {
	return false, nil
}

func (noopFreezeStore) Engage(context.Context, string) error {
	return nil
}

func (noopFreezeStore) Release(context.Context, string, string) error {
	return nil
}

// RefusalKind classifies why Execution.Run or Execution.Plan short-circuited
// before dispatch, for MetricsSink.IncRefusal. It is a fixed, small enum —
// never the human-readable refusal error text — so /metrics stays free of
// unbounded cardinality.
type RefusalKind int

const (
	RefusalFrozen RefusalKind = iota
	RefusalUnauthorized
	RefusalBlastCap
	RefusalInternal

	// RefusalPendingApproval counts dispatches parked for a human (ADR-0027).
	// It rides the refusal counter because it is a "did not dispatch" outcome
	// and belongs on the same dashboard, but it is NOT a refusal: nothing was
	// denied. Kept a distinct value precisely so an operator can tell "the
	// gate is working" apart from "the fleet is rejecting work".
	RefusalPendingApproval

	// RefusalNoNodesMatched counts a dispatch refused because its Selector
	// resolved to zero Nodes. This is a real refusal, not a park:
	// nothing was dispatched and no Job was created.
	RefusalNoNodesMatched

	// RefusalUnknownOperation counts a dispatch refused because its Operation
	// is neither Native nor reported as a Template Operation by any matched
	// Node (ADR-0042). No Job was created.
	RefusalUnknownOperation

	// RefusalMalformed counts a dispatch refused for malformed input: a
	// Template's argument names not matching its slots or its matched Nodes
	// disagreeing about them (ADR-0042), or an invalid idempotency key, or
	// a key reused with different arguments. Never a Policy verdict.
	RefusalMalformed
)

// MetricsSink records best-effort observability counters for the capability
// pipeline: a dispatch outcome per Node, or a refusal kind. Mirrors AuditSink's
// seam doc: this must never affect a dispatch decision — it is purely
// observational. The real adapter (internal/metrics) is wired in via
// NewRecorder; this seam only imports jobs, staying within capability's
// import allowlist (execution_test.go guard).
type MetricsSink interface {
	IncDispatch(outcome jobs.Outcome)
	IncRefusal(kind RefusalKind)
}

// noopMetricsSink is the default: nothing is recorded.
type noopMetricsSink struct{}

func (noopMetricsSink) IncDispatch(jobs.Outcome) {}

func (noopMetricsSink) IncRefusal(RefusalKind) {}

// JobTransition is one Job-grained lifecycle fact the event seam
// publishes for the Admin Console's live view.
type JobTransition int

const (
	JobCreated JobTransition = iota
	JobCompleted
	JobCancelled
)

// JobEvent is one Job-grained transition, published through JobEventSink.
// Purely observational, exactly like MetricsSink's doc above: it must never
// affect a dispatch decision, and nothing here can — it is built and
// published AFTER the decision it describes was already made.
//
// Outcomes carries per-outcome COUNTS — never []NodeResult. This is
// deliberate and is the second place (alongside internal/events itself)
// the no-read-output property is made structural: NodeResult carries
// Stdout/Stderr (dispatch.go), and the audit path already proves how easily
// output rides along on a "Job-grained" record (AuditEntry.Results,
// auditsink copies Stdout/Stderr verbatim). Counts are the Job-grained
// fact; the internal/eventsink adapter that maps this onto the bus
// never holds output at all.
type JobEvent struct {
	Transition JobTransition
	JobID      string
	Principal  Principal
	Selector   Selector
	Action     jobs.Action
	Nodes      int
	Outcomes   map[jobs.Outcome]int
}

// JobEventSink records a Job-grained transition. Mirrors MetricsSink's
// shape exactly (no ctx, no error) so it stays inside capability's narrow
// import allowlist (.golangci.yml's capability-imports rule).
type JobEventSink interface {
	RecordJob(e JobEvent)
}

// noopJobEventSink is the default: nothing is recorded.
type noopJobEventSink struct{}

func (noopJobEventSink) RecordJob(JobEvent) {}

// PolicyViewSource is the DISPLAY-ONLY read of a Node's daemon-reported
// effective Policy (policyview.Cache). Get only — Set is deliberately
// absent, so the lane structurally cannot write a Node's reported Policy
// (invariant 2, ADR-0002): the Tunnel handler is the only writer and it
// holds the concrete *policyview.Cache pointer, which never crosses into
// this package. A nil seam (the default) means "not wired", and
// DescribeNode reports PolicyReported=false for it — never an empty Policy
// (QRY-7: absence is never rendered as an unrestricted or empty Policy).
type PolicyViewSource interface {
	Get(nodeID string) (policyview.Snapshot, bool)
}

// TemplateVocabularySource is the read of a Node's daemon-reported Template
// Operation vocabulary (nodevocab.Cache): displayed by the read lane,
// and read by template.go to decide a Template dispatch's fan-out and risk
// class (ADR-0042) — never to decide an allow or a deny (invariant 12).
// Get only, for the same reason PolicyViewSource's is: the concrete
// *nodevocab.Cache pointer (which carries Set) stays with the Tunnel handler
// and the composition root, never this package. A nil seam means "not
// wired": DescribeNode and ListOperations report Reported=false for it
// rather than an empty vocabulary, and a Template dispatch excludes every
// Node.
type TemplateVocabularySource interface {
	Get(nodeID string) (nodevocab.Snapshot, bool)
}

// FrozenError is returned by Execution.Run when the Relay-wide Freeze is
// engaged: dispatch is refused before any Task is sent. It is exported and
// typed so a surface can recognize a Freeze refusal via errors.As without
// string-matching (mirrors CapExceededError, caps.go).
type FrozenError struct{}

func (*FrozenError) Error() string {
	return "capability: dispatch refused: the Relay-wide Freeze is engaged (ADR-0013); no new Tasks dispatch " +
		"until an admin releases the Freeze. Use a Policy preflight to preview verdicts while frozen."
}
