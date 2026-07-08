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

// Record is one append-only audit entry: a single Task's dispatch, as issued
// by a principal against a Selector. Fields are self-contained primitives (no
// pointers into Job/Task state) so a Record remains meaningful even after the
// Job or Task it describes is gone.
type Record struct {
	ID            string
	Timestamp     time.Time
	Principal     string
	Selector      string
	JobID         string
	ActionKind    string
	OperationName string
	Args          map[string]string
	RawExecArgv   []string
	Outcome       jobs.Outcome
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
}
