// Package store is the Relay's SQLite-backed persistence layer: it gives the
// Relay durable memory for the Node registry, Jobs/Stages/Tasks, the audit
// trail, and the Relay-wide Freeze, so all of them survive a restart
// (ADR-0004, ADR-0013).
//
// This package is the ONLY place database/sql (and modernc.org/sqlite) may
// appear in the Relay. Its accessors return the domain interfaces defined in
// internal/registry, internal/jobs, internal/audit, and internal/freeze —
// never a concrete SQL-backed type — so a later Postgres swap is a change to
// this package alone, with no caller changes (per the ROADMAP's
// deferred-Postgres note).
package store

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver; pure Go, no CGO

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/freeze"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/mcptask"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// Store is the Relay's single SQLite-backed persistence handle.
type Store struct {
	db               *sql.DB
	maxNodes         int    // 0 = unlimited; see WithMaxNodes
	minDaemonVersion string // ADR-0014 gate; empty = off; see WithMinDaemonVersion
	logger           *slog.Logger

	// regOnce/reg memoise the registry, which unlike the other repositories
	// carries in-memory state (the live Tunnel set). See Registry().
	regOnce sync.Once
	reg     *sqliteRegistry
}

// Option configures a Store at Open time.
type Option func(*Store)

// WithMaxNodes caps the number of Nodes the registry will accept via INSERT.
// When the cap is reached, Upsert returns registry.ErrAtCapacity for new
// Nodes; updates to existing Nodes are always allowed. Pass 0 (the default)
// to leave the registry unbounded. This mirrors registry.WithMaxNodes; the
// cap now lives here because the registry it applies to is store-backed.
func WithMaxNodes(n int) Option {
	return func(s *Store) {
		s.maxNodes = n
	}
}

// WithMinDaemonVersion sets the minimum relay-daemon version (ADR-0014) used
// to derive each Node's Outdated flag on read. Pass "" (the default) to leave
// the gate off — every Node is then always non-outdated. This mirrors
// registry.WithMinDaemonVersion; it is a Relay-side startup config value
// only, never settable through any API (invariant #11, ADR-0010).
func WithMinDaemonVersion(v string) Option {
	return func(s *Store) {
		s.minDaemonVersion = v
	}
}

// WithLogger overrides the Store's logger seam (production default:
// slog.Default()), used to warn once per Open when schema_migrations holds
// a version newer than this binary ships (#492's tolerate-don't-refuse
// decision). A nil l falls back to slog.Default(), mirroring
// auditsink.WithLogger. Exists so a test can assert the warning actually
// fires, with its attributes, rather than only that Open/migrate returns
// nil.
func WithLogger(l *slog.Logger) Option {
	return func(s *Store) {
		if l == nil {
			l = slog.Default()
		}
		s.logger = l
	}
}

// Open opens (creating if necessary) the SQLite database at path, applies
// pragmas for correctness on a single-writer workload (WAL mode, foreign
// keys, a busy timeout so concurrent readers don't immediately fail, and a
// single connection so SQLite's single-writer constraint is never raced),
// and applies every embedded migration that has not yet been applied.
func Open(path string, opts ...Option) (*Store, error) {
	// SQLite does not create missing parent directories itself (nor does the
	// WAL journal_mode pragma), so create it first. 0o700 also keeps the
	// store directory (Node cert fingerprints, relay: labels) owner-only.
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create store dir %q: %w", dir, err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database %q: %w", path, err)
	}

	// A single connection is the simplest correctness guarantee for the
	// write path at this stage: SQLite allows only one writer at a time, and
	// serializing all access through one *sql.DB connection avoids
	// SQLITE_BUSY races without a connection-pool-aware retry strategy.
	db.SetMaxOpenConns(1)

	pragmas := []string{
		`PRAGMA journal_mode = WAL`,
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close() //nolint:errcheck
			return nil, fmt.Errorf("apply pragma %q: %w", p, err)
		}
	}

	// Options are applied before migrate so a caller-supplied WithLogger is
	// in effect for the schema-newer-than-binary warning; every other Option
	// only affects behaviour that runs after Open returns.
	s := &Store{db: db, logger: slog.Default()}
	for _, o := range opts {
		o(s)
	}

	if err := migrate(context.Background(), db, s.logger); err != nil {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("migrate %q: %w", path, err)
	}

	// The approval shape-key backfill (#415) is Go rather than migration SQL
	// because it must call the same approval.HashGrantShape the write path
	// calls: two implementations of one hash is exactly the failure the
	// property "recomputing a key yields the same key" exists to exclude. It is
	// idempotent, so running it on every Open converges once and then costs one
	// indexed probe.
	if err := backfillShapeKeys(context.Background(), db); err != nil {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("backfill approval shape keys %q: %w", path, err)
	}

	return s, nil
}

// Close releases the underlying database handle.
func (s *Store) Close() error {
	return s.db.Close()
}

// Registry returns the SQLite-backed registry.Repository.
//
// MEMOISED, unlike the other repositories on this Store, and deliberately so:
// since #440 the registry holds one piece of state that is not in SQLite — the
// live Tunnel set behind SetConnected/Node.Connected. Handing out a fresh
// instance per call would give each caller its own empty connection set, so the
// transport would mark a Node connected on one object while a screen read
// connectedness off another and rendered the whole fleet offline.
//
// The other accessors here are stateless wrappers over *sql.DB and are correct
// to construct per call; this one is not, and the difference is worth the
// asymmetry rather than making every caller remember to share one.
func (s *Store) Registry() registry.Repository {
	s.regOnce.Do(func() {
		s.reg = &sqliteRegistry{
			db:               s.db,
			maxNodes:         s.maxNodes,
			minDaemonVersion: s.minDaemonVersion,
			connected:        make(map[string]struct{}),
		}
	})
	return s.reg
}

// LabelsDeclined returns the read-back label filter's live counters (#565):
// the number of stored pairs getNode's wellFormedLabels has declined to
// serve so far this process, by namespace. This is the read side of
// relay_labels_declined_total.
//
// The atomics live in internal/store, on sqliteRegistry, because the
// increment site is the SQLite read-back filter itself; internal/metrics
// reads them through a GaugeSources closure exactly as it already reads
// registry.Count, so neither package imports the other (metrics' package doc
// pins its dependencies to capability + jobs).
//
// Calls s.Registry() first to force regOnce: a /metrics scrape can be the
// first caller to ever touch the registry, and the counters live on the
// memoised *sqliteRegistry, not on Store itself.
func (s *Store) LabelsDeclined() (node, relay int64) {
	s.Registry()
	return s.reg.declined[nsNode].Load(), s.reg.declined[nsRelay].Load()
}

// Jobs returns the SQLite-backed jobs.JobRepository.
func (s *Store) Jobs() jobs.JobRepository {
	return &sqliteJobs{db: s.db}
}

// Tasks returns the SQLite-backed jobs.TaskRepository.
func (s *Store) Tasks() jobs.TaskRepository {
	return &sqliteTasks{db: s.db}
}

// Audit returns the SQLite-backed audit.Repository.
func (s *Store) Audit() audit.Repository {
	return &sqliteAudit{db: s.db}
}

// AuditQueries returns the SQLite-backed audit.QueryRepository — the trail's
// filtered/paginated/aggregating read lane (#441), the capability layer's
// seam for it. Backed by the SAME *sqliteAudit type as Audit(): the two are
// deliberately separate interfaces (append+by-key vs. query-only), not
// separate implementations, so there is exactly one place the audit table's
// SELECT logic lives.
func (s *Store) AuditQueries() audit.QueryRepository {
	return &sqliteAudit{db: s.db}
}

// JobQueries returns the SQLite-backed jobs.QueryRepository — the Job/Task
// read lane (#441), the capability layer's seam for it.
func (s *Store) JobQueries() jobs.QueryRepository {
	return &sqliteJobQueries{db: s.db}
}

// Freeze returns the SQLite-backed freeze.Repository — the persisted
// Relay-wide emergency stop (ADR-0013).
func (s *Store) Freeze() freeze.Repository {
	return &sqliteFreeze{db: s.db}
}

// Approvals returns the SQLite-backed approval.Repository — parked dispatches
// awaiting a human (ADR-0027). Persisted for the same reason the Freeze is: an
// approval queue a restart forgets would silently drop every pending request,
// and an auditor could no longer answer what was asked or what became of it.
func (s *Store) Approvals() approval.Repository {
	return &sqliteApprovals{db: s.db}
}

// Grants returns the SQLite-backed approval.GrantRepository — batch/window
// approvals (ADR-0027 decision 12).
//
// Separate from Approvals() because the two have different risks: a Request is
// decided once, while a Grant is CONSUMED repeatedly under concurrency, and its
// use counter is a bound a human was shown. Keeping the accessors apart keeps
// the claim path from being reached by anything looking for a decision path.
func (s *Store) Grants() approval.GrantRepository {
	return &sqliteGrants{db: s.db}
}

// MCPTasks returns the SQLite-backed mcptask.Repository — MCP task handles
// (#373, ADR-0028, SEP-2663).
//
// Durable rather than an in-process map because the MCP handler runs stateless
// (#267): a handle minted by one Relay instance must be resolvable by whichever
// instance the client's next poll happens to reach. An in-memory map would work
// perfectly on one process and fail silently on two, which is the failure mode
// HA (#139) would inherit.
func (s *Store) MCPTasks() mcptask.Repository {
	return &sqliteMCPTasks{db: s.db}
}

// Accounts returns the SQLite-backed accounts.Repository — the control
// plane's identity substrate (ADR-0010). Persisted rather than in-memory
// because an Account is a durable identity: a disabled Account must stay
// disabled across a Relay restart, and audit attribution must stay resolvable
// long after the process that wrote it exited.
func (s *Store) Accounts() accounts.Repository {
	return &sqliteAccounts{db: s.db}
}

// Passwords returns the SQLite-backed accounts.PasswordRepository — local
// Console sign-in credentials for human Accounts (#418).
//
// A distinct accessor from Accounts() rather than a wider Repository, so that
// the set of components able to read a password hash is exactly the set that
// asked this method for one. Everything else in the process holds an
// accounts.Repository and structurally cannot reach a hash.
func (s *Store) Passwords() accounts.PasswordRepository {
	return &sqlitePasswords{db: s.db, now: time.Now}
}

// APITokens returns the SQLite-backed accounts.TokenRepository — the control
// plane's credentials (ADR-0010). Distinct from Tokens() below, which is the
// Enrollment Token store: an Enrollment Token joins a Node to the fleet and
// can never call the control plane, and an API Token is the exact reverse.
func (s *Store) APITokens() accounts.TokenRepository {
	return &sqliteAPITokens{db: s.db}
}

// Tokens returns the SQLite-backed enroll.Repository — the persisted
// Enrollment Token store (ADR-0006), authoritative across a Relay restart so a
// revoked token can never mint a new identity after the process restarts
// (issue #133).
func (s *Store) Tokens() enroll.Repository {
	return &sqliteTokens{db: s.db}
}
