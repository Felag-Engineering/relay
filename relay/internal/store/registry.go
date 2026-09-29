package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// labelNamespace closes the two stored label namespaces getNode's read-back
// filter governs. Unexported and local to store: capability.Namespace exists
// but store must not import capability (a layering inversion the composition
// root's dependency graph forbids), and internal/metrics must not import
// store (its package doc pins its dependencies to capability + jobs, see
// LabelsDeclined below) — so neither existing enum can stand in for this one.
type labelNamespace int

const (
	nsNode labelNamespace = iota
	nsRelay
)

// nLabelNamespaces is the number of labelNamespace values.
const nLabelNamespaces = 2

// table returns the SQLite table ns is stored in, so the two string literals
// fetchLabels/replaceLabels used to take as bare arguments stop being
// free-floating and a namespace/table mismatch becomes a compile error at
// every new call site instead of a typo a reviewer has to catch by eye.
func (ns labelNamespace) table() string {
	if ns == nsRelay {
		return "relay_labels"
	}
	return "node_labels"
}

// sqliteRegistry implements registry.Repository against the nodes/node_labels/
// relay_labels tables, mirroring internal/registry.InMemory's semantics
// exactly (this is the security-relevant part: the two label namespaces are
// never confused, and Upsert's insert-vs-update distinction is preserved).
type sqliteRegistry struct {
	db               *sql.DB
	maxNodes         int    // 0 = unlimited
	minDaemonVersion string // ADR-0014 gate; empty = off

	// connected is the live Tunnel set. In memory and never written to SQLite:
	// a Relay restart means nothing is connected, and a persisted flag that
	// outlived the process would be a lie every read repeated.
	connMu    sync.RWMutex
	connected map[string]struct{}

	// declined counts read-back EVENTS, by labelNamespace: one increment per
	// stored pair wellFormedLabels declines to serve, once per Get, once per
	// Node per List, once per Hello via Upsert's internal read-back (#565).
	// NOT behind connMu: the read path must not take a lock just to count,
	// and atomic.Int64 is already internal/metrics' pattern for exactly this
	// shape of counter. Read out through Store.LabelsDeclined.
	declined [nLabelNamespaces]atomic.Int64
}

var _ registry.Repository = (*sqliteRegistry)(nil)

// queryer is satisfied by both *sql.DB and *sql.Tx, letting the label/lookup
// helpers below run against either a bare connection or an in-flight
// transaction.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Upsert registers or updates a Node from a daemon's report. See
// registry.Repository.Upsert for the field-by-field contract; this
// implementation preserves it exactly.
func (r *sqliteRegistry) Upsert(rep registry.Report) (registry.Node, error) {
	if rep.NodeID == "" {
		return registry.Node{}, registry.ErrEmptyNodeID
	}

	ctx := context.Background()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return registry.Node{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	exists, err := nodeExists(ctx, tx, rep.NodeID)
	if err != nil {
		return registry.Node{}, err
	}

	ipJSON, err := encodeIPAddresses(rep.Facts.IPAddresses)
	if err != nil {
		return registry.Node{}, err
	}
	now := roundTripTime(time.Now().UTC())

	if !exists {
		if r.maxNodes > 0 {
			count, err := countNodes(ctx, tx)
			if err != nil {
				return registry.Node{}, err
			}
			if count >= r.maxNodes {
				return registry.Node{}, registry.ErrAtCapacity
			}
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO nodes (node_id, cert_fingerprint, hostname, os, kernel, arch,
				ip_addresses, enrolling_token_id, policy_fingerprint, daemon_version,
				template_set_fingerprint, last_seen, revoked_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
			rep.NodeID, rep.CertFingerprint, rep.Facts.Hostname, rep.Facts.OS, rep.Facts.Kernel, rep.Facts.Arch,
			ipJSON, rep.EnrollingTokenID, rep.PolicyFingerprint, rep.DaemonVersion,
			rep.TemplateSetFingerprint, formatTime(now),
		); err != nil {
			return registry.Node{}, fmt.Errorf("insert node: %w", err)
		}
		if err := replaceLabels(ctx, tx, nsNode.table(), rep.NodeID, rep.NodeLabels()); err != nil {
			return registry.Node{}, err
		}
	} else {
		if _, err := tx.ExecContext(ctx, `
			UPDATE nodes SET cert_fingerprint = ?, hostname = ?, os = ?, kernel = ?, arch = ?,
				ip_addresses = ?, policy_fingerprint = ?, daemon_version = ?,
				template_set_fingerprint = ?, last_seen = ?
			WHERE node_id = ?`,
			rep.CertFingerprint, rep.Facts.Hostname, rep.Facts.OS, rep.Facts.Kernel, rep.Facts.Arch,
			ipJSON, rep.PolicyFingerprint, rep.DaemonVersion, rep.TemplateSetFingerprint,
			formatTime(now), rep.NodeID,
		); err != nil {
			return registry.Node{}, fmt.Errorf("update node: %w", err)
		}
		// enrolling_token_id and revoked_at are never touched here — provenance
		// and revocation state are Relay-set/first-write-wins, exactly as
		// registry.InMemory.Upsert preserves them on the update path.
		if err := replaceLabels(ctx, tx, nsNode.table(), rep.NodeID, rep.NodeLabels()); err != nil {
			return registry.Node{}, err
		}
	}

	n, ok, err := getNode(ctx, tx, rep.NodeID, &r.declined)
	if err != nil {
		return registry.Node{}, err
	}
	if !ok {
		return registry.Node{}, fmt.Errorf("node %q vanished within its own upsert tx", rep.NodeID)
	}

	if err := tx.Commit(); err != nil {
		return registry.Node{}, fmt.Errorf("commit tx: %w", err)
	}
	return r.withOutdated(n), nil
}

// UpdateLastSeen records the most recent contact time for nodeID. Returns
// registry.ErrNotFound if the Node is not in the registry.
func (r *sqliteRegistry) UpdateLastSeen(nodeID string, at time.Time) error {
	ctx := context.Background()
	res, err := r.db.ExecContext(ctx, `UPDATE nodes SET last_seen = ? WHERE node_id = ?`,
		formatTime(roundTripTime(at)), nodeID)
	if err != nil {
		return fmt.Errorf("update last_seen: %w", err)
	}
	return rowsAffectedOr(res, registry.ErrNotFound, "rows affected")
}

// SetRelayLabels replaces the relay-space label set for nodeID. Returns
// registry.ErrNotFound if the Node is not in the registry.
func (r *sqliteRegistry) SetRelayLabels(nodeID string, labels map[string]string) error {
	ctx := context.Background()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	exists, err := nodeExists(ctx, tx, nodeID)
	if err != nil {
		return err
	}
	if !exists {
		return registry.ErrNotFound
	}
	if err := replaceLabels(ctx, tx, nsRelay.table(), nodeID, labels); err != nil {
		return err
	}
	return tx.Commit()
}

// SetRevoked records that nodeID is revoked as of at. Returns
// registry.ErrNotFound if the Node is not in the registry.
// RecordEnrollment persists first-enrollment certificate provenance.
//
// enrolled_at is written only when NULL: re-enrolling an existing node_id must
// not rewrite the join date, because a daemon reinstall is not the Node joining
// the fleet a second time and the provenance chain is the whole point.
func (r *sqliteRegistry) RecordEnrollment(nodeID string, cert registry.Certificate, at time.Time) error {
	ctx := context.Background()
	res, err := r.db.ExecContext(ctx, `
		UPDATE nodes
		   SET cert_not_after = ?,
		       enrolled_at    = COALESCE(enrolled_at, ?)
		 WHERE node_id = ?`,
		formatTime(roundTripTime(cert.NotAfter)), formatTime(roundTripTime(at)), nodeID)
	if err != nil {
		return fmt.Errorf("record enrollment: %w", err)
	}
	return rowsAffectedOr(res, registry.ErrNotFound, "rows affected")
}

// RecordRenewal persists a reissued certificate.
//
// There is deliberately no enrolled_at in this statement. "Provenance survives
// renewal" is therefore enforced by the SQL, not by a caller remembering to pass
// the right flag.
func (r *sqliteRegistry) RecordRenewal(nodeID string, cert registry.Certificate, at time.Time) error {
	ctx := context.Background()
	res, err := r.db.ExecContext(ctx, `
		UPDATE nodes
		   SET cert_not_after  = ?,
		       renewal_count   = renewal_count + 1,
		       last_renewed_at = ?
		 WHERE node_id = ?`,
		formatTime(roundTripTime(cert.NotAfter)), formatTime(roundTripTime(at)), nodeID)
	if err != nil {
		return fmt.Errorf("record renewal: %w", err)
	}
	return rowsAffectedOr(res, registry.ErrNotFound, "rows affected")
}

// SetConnected records a Tunnel opening or closing.
//
// In memory, never in SQLite — see registry.Node.Connected. A persisted
// connected flag surviving a crash would render as a green dot for a Node
// nothing can reach.
func (r *sqliteRegistry) SetConnected(nodeID string, connected bool) {
	r.connMu.Lock()
	defer r.connMu.Unlock()

	if connected {
		r.connected[nodeID] = struct{}{}
		return
	}
	delete(r.connected, nodeID)
}

// isConnected reports whether nodeID currently holds a Tunnel.
func (r *sqliteRegistry) isConnected(nodeID string) bool {
	r.connMu.RLock()
	defer r.connMu.RUnlock()
	_, ok := r.connected[nodeID]
	return ok
}

// updateRevokedSQL is the one UPDATE text shared by SetRevoked and
// SetRevokedAll, so the single-Node and batch paths provably write the same
// column with the same statement.
const updateRevokedSQL = `UPDATE nodes SET revoked_at = ? WHERE node_id = ?`

func (r *sqliteRegistry) SetRevoked(nodeID string, at time.Time) error {
	ctx := context.Background()
	res, err := r.db.ExecContext(ctx, updateRevokedSQL, formatTime(roundTripTime(at)), nodeID)
	if err != nil {
		return fmt.Errorf("update revoked_at: %w", err)
	}
	return rowsAffectedOr(res, registry.ErrNotFound, "rows affected")
}

// SetRevokedAll is SetRevoked's chunked twin: it marks every id in nodeIDs
// revoked as of at, all inside ONE transaction (see
// registry.Repository.SetRevokedAll for the all-or-nothing contract). A
// missing row is not an error: it is appended to missing and does not abort
// the rest of the batch.
//
// One commit for the whole batch instead of one per id — and, under WAL at
// SQLite's default synchronous, one fsync instead of len(nodeIDs) — which is
// where a large cascade's wall-clock, and everyone else's queuing behind it,
// actually goes. In exchange this holds the Store's single connection (Open
// sets SetMaxOpenConns(1), which serialises STATEMENTS, not transactions —
// see accounts.go) for the whole batch, where the per-id autocommits it
// replaces released it between every UPDATE. A concurrent store call
// arriving mid-batch therefore waits for the batch, not for one statement.
// Deliberate, and the same trade AppendAll already makes for the cascade's
// audit records (#601). Keep the batch bounded by
// revocation.cascadeRecordChunk.
//
// On a non-nil error the transaction rolled back and nothing was written;
// missing rows are returned, never an error, and never abort the batch.
//
// Per-id UPDATEs inside one transaction, rather than one
// "WHERE node_id IN (...)" statement, deliberately: an IN-list can only
// report a row COUNT, and the cascade's existing per-Node "no registry row"
// Info log needs the ids. The cost that matters on SQLite is the commit, not
// the statement count.
func (r *sqliteRegistry) SetRevokedAll(nodeIDs []string, at time.Time) ([]string, error) {
	if len(nodeIDs) == 0 {
		return nil, nil
	}

	ctx := context.Background()
	ts := formatTime(roundTripTime(at))

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin set revoked: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.PrepareContext(ctx, updateRevokedSQL)
	if err != nil {
		return nil, fmt.Errorf("prepare set revoked: %w", err)
	}
	defer stmt.Close() //nolint:errcheck

	var missing []string
	for i, id := range nodeIDs {
		res, err := stmt.ExecContext(ctx, ts, id)
		if err != nil {
			return nil, fmt.Errorf("set revoked %d of %d: %w", i+1, len(nodeIDs), err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, fmt.Errorf("rows affected %d of %d: %w", i+1, len(nodeIDs), err)
		}
		if n == 0 {
			missing = append(missing, id)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit set revoked: %w", err)
	}
	return missing, nil
}

// RevokedNodeIDs returns the IDs of every Node with a non-NULL revoked_at.
func (r *sqliteRegistry) RevokedNodeIDs() ([]string, error) {
	ctx := context.Background()
	rows, err := r.db.QueryContext(ctx, `SELECT node_id FROM nodes WHERE revoked_at IS NOT NULL ORDER BY node_id`)
	if err != nil {
		return nil, fmt.Errorf("query revoked node ids: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan revoked node id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// Count returns the total number of enrolled Nodes and the subset currently
// revoked, via COUNT(*) rather than a full List() deep-copy (cheap at fleet
// scale — /metrics scraping must not be O(N)).
func (r *sqliteRegistry) Count() (int, int, error) {
	ctx := context.Background()
	var total, revoked int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(revoked_at) FROM nodes`).Scan(&total, &revoked)
	if err != nil {
		return 0, 0, fmt.Errorf("count nodes: %w", err)
	}
	return total, revoked, nil
}

// Get returns the stored Node record, or (Node{}, false) if the Node is not
// in the registry.
func (r *sqliteRegistry) Get(nodeID string) (registry.Node, bool) {
	ctx := context.Background()
	n, ok, err := getNode(ctx, r.db, nodeID, &r.declined)
	if err != nil {
		// registry.Repository.Get has no error return; a query failure here
		// is treated as "not found" rather than panicking the caller.
		return registry.Node{}, false
	}
	if !ok {
		return registry.Node{}, false
	}
	return r.withOutdated(n), true
}

// List returns all stored Node records, sorted by NodeID.
func (r *sqliteRegistry) List() []registry.Node {
	ctx := context.Background()
	ids, err := allNodeIDs(ctx, r.db)
	if err != nil {
		return nil
	}
	out := make([]registry.Node, 0, len(ids))
	for _, id := range ids {
		n, ok, err := getNode(ctx, r.db, id, &r.declined)
		if err != nil || !ok {
			continue
		}
		out = append(out, r.withOutdated(n))
	}
	return out
}

// withOutdated computes n.Outdated (ADR-0014) against this registry's
// configured minDaemonVersion. Outdated is derived on every read, never
// stored — getNode itself stays free of this computation so it can be
// reused from within an in-flight Upsert tx before minDaemonVersion is known
// to matter there.
func (r *sqliteRegistry) withOutdated(n registry.Node) registry.Node {
	n.Outdated = registry.Outdated(n.DaemonVersion, r.minDaemonVersion)
	// Connected is derived on the same read, for the same reason: it is a fact
	// about right now, and a stored one would go stale the instant a stream
	// closed.
	n.Connected = r.isConnected(n.NodeID)
	return n
}

func allNodeIDs(ctx context.Context, q queryer) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT node_id FROM nodes ORDER BY node_id`)
	if err != nil {
		return nil, fmt.Errorf("query node ids: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan node id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func nodeExists(ctx context.Context, q queryer, nodeID string) (bool, error) {
	var one int
	err := q.QueryRowContext(ctx, `SELECT 1 FROM nodes WHERE node_id = ?`, nodeID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check node exists: %w", err)
	}
	return true, nil
}

func countNodes(ctx context.Context, q queryer) (int, error) {
	var count int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count nodes: %w", err)
	}
	return count, nil
}

// getNode loads one Node record (nodes row + both label tables). Returns
// (Node{}, false, nil) if nodeID does not exist.
//
// declined is threaded as an explicit parameter rather than read off a
// receiver — getNode stays a free function taking its queryer as a
// parameter, exactly as before this counter existed, because Upsert (below)
// calls it while holding the transaction that is store.Open's single SQLite
// connection (SetMaxOpenConns(1)). A method that ever reached for a *Store's
// own r.db instead of the q it was given would block forever waiting for a
// connection its own caller is holding open — a hang on every Hello, not a
// data bug — so the counter travels as a pointer instead of a receiver,
// making that hazard structurally unreachable rather than merely documented.
// Asserted by TestUpsert_ReadBackIsNeverRoutedThroughTheSharedHandle, which
// reads this file's AST rather than probing the hazard — see that test's doc
// for why a behavioural probe cannot report this particular failure — and by
// TestUpsert_ReadBackDeclinesAndCountsInsideItsOwnTransaction for the
// behaviour that CAN be observed.
func getNode(ctx context.Context, q queryer, nodeID string, declined *[nLabelNamespaces]atomic.Int64) (registry.Node, bool, error) {
	var (
		certFingerprint, hostname, osName, kernel, arch string
		ipAddresses                                     sql.NullString
		enrollingTokenID, policyFingerprint             string
		daemonVersion, templateSetFingerprint           string
		lastSeen                                        string
		revokedAt                                       sql.NullString
		certNotAfter, enrolledAt, lastRenewedAt         sql.NullString
		renewalCount                                    int
	)
	err := q.QueryRowContext(ctx, `
		SELECT cert_fingerprint, hostname, os, kernel, arch, ip_addresses,
			enrolling_token_id, policy_fingerprint, daemon_version,
			template_set_fingerprint, last_seen, revoked_at,
			cert_not_after, enrolled_at, renewal_count, last_renewed_at
		FROM nodes WHERE node_id = ?`, nodeID,
	).Scan(&certFingerprint, &hostname, &osName, &kernel, &arch, &ipAddresses,
		&enrollingTokenID, &policyFingerprint, &daemonVersion, &templateSetFingerprint,
		&lastSeen, &revokedAt,
		&certNotAfter, &enrolledAt, &renewalCount, &lastRenewedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return registry.Node{}, false, nil
	}
	if err != nil {
		return registry.Node{}, false, fmt.Errorf("query node %q: %w", nodeID, err)
	}

	ips, err := decodeIPAddresses(ipAddresses)
	if err != nil {
		return registry.Node{}, false, err
	}

	nodeLabels, err := fetchLabels(ctx, q, nsNode.table(), nodeID)
	if err != nil {
		return registry.Node{}, false, err
	}
	nodeLabels = wellFormedLabels(nsNode, nodeLabels, declined)
	relayLabels, err := fetchLabels(ctx, q, nsRelay.table(), nodeID)
	if err != nil {
		return registry.Node{}, false, err
	}
	relayLabels = wellFormedLabels(nsRelay, relayLabels, declined)

	lastSeenTime, err := parseTime(sql.NullString{String: lastSeen, Valid: true})
	if err != nil {
		return registry.Node{}, false, fmt.Errorf("parse last_seen for node %q: %w", nodeID, err)
	}
	revokedAtTime, err := parseTime(revokedAt)
	if err != nil {
		return registry.Node{}, false, fmt.Errorf("parse revoked_at for node %q: %w", nodeID, err)
	}
	// NULL parses to the zero time, which the domain defines as "not recorded"
	// (Node.CertProvenanceKnown). Nodes that enrolled before migration 0020
	// carry NULL here until their next renewal.
	certNotAfterTime, err := parseTime(certNotAfter)
	if err != nil {
		return registry.Node{}, false, fmt.Errorf("parse cert_not_after for node %q: %w", nodeID, err)
	}
	enrolledAtTime, err := parseTime(enrolledAt)
	if err != nil {
		return registry.Node{}, false, fmt.Errorf("parse enrolled_at for node %q: %w", nodeID, err)
	}
	lastRenewedAtTime, err := parseTime(lastRenewedAt)
	if err != nil {
		return registry.Node{}, false, fmt.Errorf("parse last_renewed_at for node %q: %w", nodeID, err)
	}

	return registry.Node{
		NodeID:          nodeID,
		CertFingerprint: certFingerprint,
		Facts: registry.Facts{
			Hostname:    hostname,
			OS:          osName,
			Kernel:      kernel,
			Arch:        arch,
			IPAddresses: ips,
		},
		NodeLabels:             nodeLabels,
		RelayLabels:            relayLabels,
		LastSeen:               lastSeenTime,
		CertNotAfter:           certNotAfterTime,
		EnrolledAt:             enrolledAtTime,
		RenewalCount:           renewalCount,
		LastRenewedAt:          lastRenewedAtTime,
		EnrollingTokenID:       enrollingTokenID,
		PolicyFingerprint:      policyFingerprint,
		DaemonVersion:          daemonVersion,
		RevokedAt:              revokedAtTime,
		TemplateSetFingerprint: templateSetFingerprint,
	}, true, nil
}

// wellFormedLabels returns a copy of labels containing only the pairs
// registry.WellFormedLabel accepts. It governs BOTH stored namespaces:
//
//   - node_labels (#504): rows written BEFORE the ingress gate existed
//     (protoconv.ParseNodeLabel) can carry a value that was never validated.
//   - relay_labels (#555): rows stamped by an enrollment that ran BEFORE the
//     ingress gate existed (enroll.validateScope) can carry a value that was
//     never validated either. The ingress fix alone leaves these rows serving
//     forever — the Console renders every relay_labels entry as a `relay:`
//     chip (console/fleet.go's declaredChips), lock glyph and security hue,
//     for a label this Relay's own ingress gate would now refuse.
//
// WHAT IT DROPS IS WIDER THAN WHAT IS UNMATCHABLE, and that difference is a
// residual, not a rounding error. WellFormedLabel is deliberately narrower
// than capability.ParseSelector: the parser needs only a non-empty key and
// cuts on the first `=`, so `relay:tier=pci/1`, `relay:owner=team@sec` and
// `relay:dc=dc1:rack2` each parse to exactly ONE predicate and match a Node
// today. The allowlist refuses them anyway, because the hazard it exists for
// is RENDERING (a term concatenated back together by a Console href or an
// AI-agent), not parsing. So on upgrade this filter removes some labels that
// were genuinely matchable, permanently and with no self-heal — relay-space
// has no equivalent of the Node's next Hello. The direction is always
// UNDER-inclusion (a filter can only remove matches; the Selector grammar has
// no negation) and a quarantine specifically cannot be lost, per the note
// below — but a security-lane Selector CAN come to resolve to fewer Nodes
// than it did before the upgrade, silently. That is an accepted residual
// (threat model R13), not a claim that nothing was lost, and it is why
// docs/operations/enrollment.md tells operators to re-mint before upgrading.
//
// #565 adds a bounded signal at this seam, for BOTH namespaces, as two
// separate things: declined below counts read-back EVENTS, not distinct
// Labels — one increment per declined pair, per Get, per Node per List, per
// Hello via Upsert's own read-back — so it is live but says nothing about
// WHICH Nodes are affected. The authoritative "which Nodes" answer is the
// one-shot startup scan (labelscan.go), which deliberately does NOT call
// this function or go through getNode: reusing this filter at boot would
// inflate the same read-back counter and destroy the distinction between the
// two signals the design deliberately keeps separate.
//
// getNode is the single load path behind both Get and List, so this one
// function, called once per namespace, covers every reader — the Control
// API, MCP, and the Console all read a stored label through here, never
// around it.
//
// This does NOT delete or rewrite the stored row: node-space storage is the
// Node's own self-description, and relay-space storage is the Relay's own
// stamp from a token scope (both invariant 7, ADR-0006) — the Relay declining
// to SERVE a value is not the same act as the Relay MODIFYING one. For
// node_labels the legitimate way for the row to heal is the Node's own next
// Hello, which replaces the whole set via replaceLabels. For relay_labels
// there is no equivalent self-heal: the only production writer is
// SetRelayLabels, whose only caller is enrollment, which builds its map from
// a token scope and never from a read — Upsert's internal getNode (line 358)
// is read-only, so there is no read-modify-write path that could turn this
// filter into a delete. STANDING OBLIGATION: a future admin relay-label
// writer (ADR-0020's incident ladder) must preserve that — it must never
// read-modify-write over this filtered view, or "decline to serve" silently
// becomes "delete". "Never write, decline to serve" keeps this fix
// unambiguously clear of the Relay-immutability half of invariant 7. A Node
// whose relay_labels predate this gate, and that never gets a fresh
// enrollment, keeps serving a filtered view forever — accepted for the same
// reason as node-space: the Relay is not in the business of rewriting a
// stored label out from under whichever side owns it.
//
// The filter can never lift a quarantine: registry.QuarantineKey/
// QuarantineOn are "quarantine"/"on", both inside the allowlist.
//
// declined is threaded as an explicit parameter for the same reason getNode's
// is: this stays a free function so no future call site can reach a
// receiver's r.db and deadlock inside an in-flight transaction (see getNode's
// doc). Every reject increments declined[ns] by one — per PAIR declined, not
// per Node and not per call — which is what makes the counter's HELP text
// honest about counting events rather than distinct Labels.
func wellFormedLabels(ns labelNamespace, labels map[string]string, declined *[nLabelNamespaces]atomic.Int64) map[string]string {
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		if registry.WellFormedLabel(k, v) {
			out[k] = v
			continue
		}
		declined[ns].Add(1)
	}
	return out
}

func fetchLabels(ctx context.Context, q queryer, table, nodeID string) (map[string]string, error) {
	rows, err := q.QueryContext(ctx, fmt.Sprintf(`SELECT key, value FROM %s WHERE node_id = ?`, table), nodeID) //nolint:gosec // table is one of two fixed literals, never user input
	if err != nil {
		return nil, fmt.Errorf("query %s: %w", table, err)
	}
	defer rows.Close()

	labels := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("scan %s row: %w", table, err)
		}
		labels[k] = v
	}
	return labels, rows.Err()
}

func replaceLabels(ctx context.Context, tx *sql.Tx, table, nodeID string, labels map[string]string) error {
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE node_id = ?`, table), nodeID); err != nil { //nolint:gosec // table is one of two fixed literals, never user input
		return fmt.Errorf("clear %s: %w", table, err)
	}
	for k, v := range labels {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s (node_id, key, value) VALUES (?, ?, ?)`, table), //nolint:gosec // table is one of two fixed literals, never user input
			nodeID, k, v); err != nil {
			return fmt.Errorf("insert %s row: %w", table, err)
		}
	}
	return nil
}

// rowsAffectedOr maps a single-row write's result onto the caller's contract:
// a RowsAffected failure is wrapped as "<what>: <err>", and a write that
// matched no row returns notFound, so an update against a missing row is
// reported rather than passing silently.
func rowsAffectedOr(res sql.Result, notFound error, what string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if n == 0 {
		return notFound
	}
	return nil
}

// encodeIPAddresses returns the value to store in ip_addresses: NULL when ips
// is nil, or its JSON encoding otherwise (including "[]" for a non-nil empty
// slice). This preserves Facts.IPAddresses' nil-vs-empty distinction across a
// restart, matching registry.InMemory's cloneFacts behavior.
func encodeIPAddresses(ips []string) (any, error) {
	if ips == nil {
		return nil, nil
	}
	b, err := json.Marshal(ips)
	if err != nil {
		return nil, fmt.Errorf("encode ip_addresses: %w", err)
	}
	return string(b), nil
}

func decodeIPAddresses(s sql.NullString) ([]string, error) {
	if !s.Valid {
		return nil, nil
	}
	var ips []string
	if err := json.Unmarshal([]byte(s.String), &ips); err != nil {
		return nil, fmt.Errorf("decode ip_addresses: %w", err)
	}
	return ips, nil
}

// timeLayout is used for every persisted timestamp. RFC3339Nano is lossless
// to nanosecond precision and unambiguous (always UTC "Z", never a wall-clock
// offset from a non-UTC location).
const timeLayout = time.RFC3339Nano

// roundTripTime strips monotonic-clock state and normalizes t to UTC via a
// format/parse round trip, so the value returned to a caller is byte-identical
// (via reflect.DeepEqual) to the value that will be read back after a store
// reopen. Calling this once, and reusing the result for both the write and
// the in-memory return value, is what makes that guarantee hold.
func roundTripTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	parsed, err := time.Parse(timeLayout, t.UTC().Format(timeLayout))
	if err != nil {
		// Format always produces a value Parse can read back; this is
		// unreachable in practice.
		return t.UTC()
	}
	return parsed
}

// formatTime returns the value to store in a TIMESTAMP column: NULL for the
// zero value, else the RFC3339Nano text.
func formatTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(timeLayout)
}

// parseTime is the inverse of formatTime.
func parseTime(s sql.NullString) (time.Time, error) {
	if !s.Valid || s.String == "" {
		return time.Time{}, nil
	}
	return time.Parse(timeLayout, s.String)
}
