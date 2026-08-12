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
	KindAPITokenMint   = "api_token_mint"
	KindAPITokenRevoke = "api_token_revoke"
)

// Record is one append-only audit entry: a single Task's dispatch, a
// refusal, or a Freeze engage/release, as issued by a principal. Fields are
// self-contained primitives (no pointers into Job/Task state) so a Record
// remains meaningful even after the Job or Task it describes is gone.
type Record struct {
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
}

// Repository is the interface for the audit trail. Append-only: there is no
// update or delete.
type Repository interface {
	// Append persists a new Record.
	Append(ctx context.Context, r Record) error

	// List returns all Records, ordered by Timestamp.
	List(ctx context.Context) ([]Record, error)

	// ByJob returns all Records for jobID, ordered by Timestamp.
	ByJob(ctx context.Context, jobID string) ([]Record, error)

	// ByNode returns all Records for nodeID, ordered by Timestamp — the
	// "which Node" accountability query (CLAUDE.md). Time-range querying is
	// deferred to the first query surface; no acceptance need yet.
	ByNode(ctx context.Context, nodeID string) ([]Record, error)

	// ByAccount returns all Records for an Account ID, ordered by Timestamp —
	// the verified-lane query. It takes the ID rather than the name so the
	// trail stays queryable across a rename, which is the reason the ID is
	// recorded at all.
	ByAccount(ctx context.Context, accountID string) ([]Record, error)

	// ByOnBehalfOf returns all Records carrying an exact asserted OnBehalfOf
	// value, ordered by Timestamp — the asserted-lane query.
	//
	// Deliberately a separate method from ByAccount rather than a shared
	// "principal" filter: a caller reading this trail must not be able to
	// confuse "the Relay authenticated this Account" with "someone typed this
	// string", and two differently-named methods make the lane you are
	// querying impossible to miss at the call site.
	ByOnBehalfOf(ctx context.Context, onBehalfOf string) ([]Record, error)
}
