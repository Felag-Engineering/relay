// Package freeze holds the Relay's domain model for the persisted,
// Relay-wide emergency stop (ADR-0013): "I don't trust what's driving this,
// stop dispatching everything." Like internal/jobs and internal/audit, this
// package carries no database/sql dependency — internal/store holds the
// SQLite implementation — so a later Postgres swap is a single-package
// change, not a change to every caller of Repository.
//
// A Freeze that a crash forgets is not a Freeze: engage/release are
// persisted, not held only in the Relay's memory, so the stop survives a
// Relay restart.
package freeze

import (
	"context"
	"time"
)

// State is the Freeze's current status: whether it is engaged, who last
// changed it, why (set on release), and when.
type State struct {
	Engaged   bool
	Principal string
	Reason    string
	UpdatedAt time.Time
}

// Repository persists the Relay-wide Freeze. Its method set deliberately
// mirrors capability.FreezeStore so a Repository value is directly
// assignable to that seam at the composition root (cmd/relay/main.go).
type Repository interface {
	// Frozen reports whether the Freeze is currently engaged. This is the
	// hot-path read consulted before every dispatch (capability.Service.Run).
	Frozen(ctx context.Context) (bool, error)

	// Engage sets the Freeze, recording principal as who engaged it.
	Engage(ctx context.Context, principal string) error

	// Release clears the Freeze, recording principal as who released it and
	// reason as why.
	Release(ctx context.Context, principal, reason string) error
}
