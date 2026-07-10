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
// engage/release (ADR-0013), or a Control API lifecycle action (Enrollment
// Token mint/revoke, Node revoke — #116, ADR-0010).
const (
	KindDispatch      = "dispatch"
	KindRefusal       = "refusal"
	KindFreezeEngage  = "freeze_engage"
	KindFreezeRelease = "freeze_release"
	KindTokenMint     = "token_mint"
	KindTokenRevoke   = "token_revoke"
	KindNodeRevoke    = "node_revoke"
)

// Record is one append-only audit entry: a single Task's dispatch, a
// refusal, or a Freeze engage/release, as issued by a principal. Fields are
// self-contained primitives (no pointers into Job/Task state) so a Record
// remains meaningful even after the Job or Task it describes is gone.
type Record struct {
	ID            string
	Timestamp     time.Time
	Kind          string
	Principal     string
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
}
