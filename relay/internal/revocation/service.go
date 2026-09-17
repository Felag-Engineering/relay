package revocation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	// registry is imported for the Registry return type (registry.Node) and its
	// ErrNotFound sentinel.
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"

	// enroll is imported for the ErrNotFound sentinel only. No import cycle:
	// revocation → enroll → registry; revocation → registry.
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll"
)

// Registry is the fleet Node registry as the revocation Service needs it: to
// list Nodes (for the token cascade) and to persist a Node's revocation so it
// survives a Relay restart. Both *registry.InMemory and the store-backed
// registry satisfy it.
type Registry interface {
	List() []registry.Node
	SetRevoked(nodeID string, at time.Time) error
}

// TokenRevoker marks an Enrollment Token as revoked in the token store.
// *enroll.Service satisfies this interface.
type TokenRevoker interface {
	Revoke(ctx context.Context, id string) error
}

// RevocationRecorder records the trail's entries for a chunk of Nodes the
// cascade is about to revoke, and reports whether that chunk was written.
//
// The contract is ALL-OR-NOTHING per call: a nil error means every ID in
// nodeIDs was recorded, a non-nil error means none of them were. The cascade
// below counts len(nodeIDs) as unrecorded on error, and that count is the
// number threat-model R12 rests on being honest — a recorder that recorded
// some of a chunk and still returned an error, or vice versa, would corrupt
// it. nodeIDs is a READ-ONLY BORROW: the recorder must not modify it — in
// place, by index, or by appending within its spare capacity — and must not
// retain it, or any alias of its backing array, after the call returns. The
// cascade still needs every one of those IDs to revoke the chunk once record
// returns, so it hands the recorder a defensive copy rather than trusting
// this contract alone: a recorder that mutated the slice it was given could
// otherwise make the cascade revoke the wrong set of Nodes, which is exactly
// the authentication hole R12 exists to prevent.
//
// WHY A CALLBACK AND NOT A SINK FIELD: package revocation imports neither
// internal/audit nor internal/capability (imports_test.go enforces this), so
// the record's CONTENT — the acting Principal, its asserted lane, and the
// derived reason naming the token — must be authored by the surface that
// authenticated the operator, while the SET of Nodes to record is decided
// HERE, inside RevokeToken's re-scan, which is the only place that set is
// first knowable (a Node can appear on a later pass than the caller's own
// snapshot). A callback is what lets those two facts stay split along the
// line that already exists between this package and its caller.
//
// WHY IT TAKES NO context.Context: the caller already chose the context its
// audit write runs under before constructing this closure — that is what lets
// the Control API detach the write from the client connection (see
// context.WithoutCancel in tokens.go) so an irreversible cascade is not
// aborted by a client that hangs up mid-revoke.
type RevocationRecorder func(nodeIDs []string) error

// cascadeRecordChunk bounds how many Nodes one RevocationRecorder call covers.
//
// It bounds how long one recorder call holds the store's only connection
// (SetMaxOpenConns(1)), so other requests can run between chunks. It bounds
// how long a Node waits between being found and being revoked. And a chunk
// that commits before the Control API's audit budget runs out stays
// committed. It does NOT bound N: the pass loop below still walks every
// matching Node in the registry, in chunks, however many there are.
const cascadeRecordChunk = 500

// ErrRecorderRequired is returned by RevokeToken when called with a nil
// recorder, before the token store or the registry is touched.
//
// A nil recorder must not be read as "skip recording": a cascade that CAN run
// unattributed is the bug #557 exists to close, so making that state
// unreachable IS the fix. This mirrors api.authorizeControl's nil-Authz
// posture (#397) — loud and closed, never quiet and open.
var ErrRecorderRequired = errors.New("revocation: RevokeToken requires a recorder; refusing to run an unattributed cascade")

// CascadeShortfall reports how much of a cascade went unrecorded. It wraps
// ErrCascadeNotRecorded, so errors.Is keeps working for callers that only need
// to know THAT the trail is incomplete.
//
// The counts are a typed field rather than text inside an error string because
// they are the number an on-call operator reads to size the audit gap -- the
// threat model's R12 entry rests on "notes any failure" being an honest count.
// Baked into a format string, that number is unassertable without parsing prose,
// and a corruption of it (double-counting, or setting it to the cascade length
// on the first failure) reddens nothing. A code review found exactly that: the
// entire suite stayed green with unrecorded incremented by two.
type CascadeShortfall struct {
	Unrecorded int
	Total      int
}

func (e *CascadeShortfall) Error() string {
	return fmt.Sprintf("revocation: %d of %d cascaded Node revocations were not recorded",
		e.Unrecorded, e.Total)
}

// Unwrap lets errors.Is(err, ErrCascadeNotRecorded) hold, which is what the
// Control API route keys on to tell a completed-but-unrecorded cascade from an
// outright failure.
func (e *CascadeShortfall) Unwrap() error { return ErrCascadeNotRecorded }

// ErrCascadeNotRecorded is returned by RevokeToken when every cascaded Node
// was revoked but one or more of their revocation records could not be
// written. See RevokeToken's cascade loop for why the revoke proceeds anyway.
var ErrCascadeNotRecorded = errors.New("revocation: one or more cascaded Node revocations were not recorded")

// Service coordinates the denylist and live-connection teardown for Node and
// Enrollment Token revocation.
type Service struct {
	denylist *Denylist
	conns    *Connections
	reg      Registry
	tokens   TokenRevoker
}

// NewService creates a Service.
func NewService(d *Denylist, c *Connections, reg Registry, tokens TokenRevoker) *Service {
	return &Service{denylist: d, conns: c, reg: reg, tokens: tokens}
}

// RevokeNode adds nodeID to the denylist, persists the revocation to the
// registry (the authority), and tears down any live Tunnel stream. The registry
// is now the source of truth: at startup the denylist is rehydrated from
// registry.RevokedNodeIDs(), so a revoked Node stays revoked across a Relay
// restart (issue #133, ADR-0006). The denylist is a derived in-memory cache.
//
// node_id is the verified client-cert CN (ADR-0006) and is not a secret; it is
// safe to log.
func (s *Service) RevokeNode(nodeID string) {
	// Add to the denylist FIRST so the in-process barrier is instant even if the
	// persist below fails — over-denying beats under-denying on this surface.
	s.denylist.Add(nodeID)

	// Persist to the authority. registry.ErrNotFound is expected when the Node
	// has no registry row (e.g. it never connected): the in-memory denylist still
	// holds for this process, so log and continue rather than fail.
	if err := s.reg.SetRevoked(nodeID, time.Now().UTC()); err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			slog.Info("node revocation not persisted: no registry row",
				"node_id", nodeID)
		} else {
			slog.Warn("persist node revocation failed",
				"node_id", nodeID, "error", err)
		}
	}

	s.conns.Disconnect(nodeID)
	slog.Info("node revoked", "node_id", nodeID)
}

// RevokeToken revokes the Enrollment Token (so it can no longer enroll new
// Nodes) and cascade-revokes every Node whose provenance matches tokenID.
//
// Security rationale: re-enrollment assigns a NEW random node_id
// (enroll.randomNodeID), so denylisting existing node_ids alone would not stop
// a leaked token from minting a fresh, un-denylisted identity. Revoking the
// token in the store closes that hole; both steps are required for a coherent
// cascade.
//
// token_id is the public, non-secret half of the Enrollment Token credential —
// safe to log (see enroll/token.go).
//
// record is REQUIRED (#557): every cascaded Node's revocation must be
// recorded through it, one call per chunk of at most cascadeRecordChunk
// Nodes, from inside the pass loop below — see RevocationRecorder's doc for
// why a callback rather than a sink field, and why it takes no context.
func (s *Service) RevokeToken(ctx context.Context, tokenID string, record RevocationRecorder) error {
	// A nil recorder is refused before the token store is touched, so a nil
	// recorder revokes NOTHING — see ErrRecorderRequired.
	if record == nil {
		return ErrRecorderRequired
	}

	// Step 1: Revoke the token FIRST — this is the barrier. After this returns,
	// any subsequent Enroll Validate call for tokenID returns ErrRevoked, so no
	// new node_id can be minted under this token.
	if err := s.tokens.Revoke(ctx, tokenID); err != nil {
		if errors.Is(err, enroll.ErrNotFound) {
			// Unknown token: log and continue. The cascade is still valid — Nodes
			// that recorded this tokenID in their provenance must still be revoked.
			slog.Info("token not found during revocation, continuing cascade",
				"token_id", tokenID)
		} else {
			return err
		}
	}

	// Step 2 + 3: Scan the registry, denylist + Disconnect every matching Node,
	// then re-scan to catch Nodes whose Upsert landed AFTER the first snapshot.
	//
	// WHY re-scan: the enroll handler's Validate→Upsert sequence is not atomic.
	// A daemon can pass Validate just before the token-revoke barrier above and
	// then write its registry entry after our first List() snapshot. The re-scan
	// catches those late arrivals. We always do the initial scan plus at least
	// one re-scan; we break early once a pass adds no new nodes (the registry
	// has settled), or stop at the cap. RevokeNode/denylist.Add is idempotent,
	// so re-visiting an already-revoked Node (detected via IsRevoked) is a
	// harmless no-op and avoids redundant Disconnect churn.
	const maxRescanPasses = 2 // initial scan + up to 2 re-scans = 3 passes total
	var total, unrecorded int
	for pass := 0; pass <= maxRescanPasses; pass++ {
		var newThisPass int
		chunk := make([]string, 0, cascadeRecordChunk)
		pending := make(map[string]struct{}, cascadeRecordChunk)

		// flush records and revokes the accumulated chunk, then resets both
		// chunk and pending to FRESH values (never re-sliced to zero length),
		// so that this pass's next chunk gets its own backing array rather
		// than one that might still be aliased by an earlier flush's local
		// variables.
		flush := func() {
			if len(chunk) == 0 {
				return
			}

			// Re-check IsRevoked immediately before recording, dropping any id
			// that was revoked by something else (e.g. a concurrent single-Node
			// revoke) while it sat in this unflushed chunk. Without this, that
			// Node would get a second node_revoke record here, against the
			// causative-record rule the IsRevoked skip below already enforces
			// across passes. This can only trigger under a concurrent revoke
			// racing this pass's List loop — nothing in this package runs
			// between an id being appended to chunk and the flush that follows
			// it — so no deterministic test drives this branch; it exists for
			// that concurrent case, not for anything the sequential tests can
			// observe. Filtered in place: chunk's backing array is not shared
			// with any earlier flush's chunk (each got a fresh make).
			live := 0
			for _, id := range chunk {
				if !s.denylist.IsRevoked(id) {
					chunk[live] = id
					live++
				}
			}
			chunk = chunk[:live]
			if len(chunk) == 0 {
				chunk = make([]string, 0, cascadeRecordChunk)
				pending = make(map[string]struct{}, cascadeRecordChunk)
				return
			}

			// Record the chunk BEFORE revoking any Node in it, but — unlike
			// handleRevokeNode's #487 ordering — revoke EVERY Node in the chunk
			// EITHER WAY, deliberately inverting that posture. #487's fail-closed
			// order was licensed by two facts that do not hold here: nothing had
			// happened yet, and RevokeNode has no error return to strand. Here the
			// token is already revoked (Step 1 above) and any earlier Node in this
			// same cascade already is too; refusing to revoke a Node because its
			// chunk's record failed would leave a Node whose enrolling token is
			// already dead still holding a live Tunnel and a cert-authenticated
			// Renew path — a permanent security hole traded for an audit gap,
			// against this file's own stated direction (see the over-denying
			// comment in RevokeNode). Aborting the loop entirely would be worse
			// still: it would un-revoke nothing already done and under-revoke
			// everything still to come. So: record the chunk, note the failure,
			// revoke every Node in the chunk anyway, and report the shortfall to
			// the caller afterward via ErrCascadeNotRecorded rather than papering
			// over it.
			//
			// This still leaves a wider crash window than the old one-Node-at-a-
			// time cascade did: a process crash between this chunk's commit and
			// the end of the RevokeNode loop below can leave up to
			// cascadeRecordChunk records for Nodes not yet revoked (the
			// per-Node cascade before #563: at most 1). That is the same
			// failure direction #557 chose — a record with no matching revoke
			// is an audit-trail overstatement, never an unattributed revoke —
			// just wider now that recording and revoking happen per chunk
			// instead of per Node. Accepted; do not reorder.
			//
			// record is handed a defensive copy, never chunk itself: chunk is
			// what the revoke loop below (and the error log above it) reads
			// once record returns, and RevocationRecorder's contract only asks
			// the recorder not to mutate or retain what it was given — it does
			// not enforce that. A recorder that broke the contract and mutated
			// or reordered chunk in place could otherwise make the cascade
			// revoke the wrong Nodes; copying first means a misbehaving
			// recorder can corrupt only its own copy, and every Node in this
			// chunk still gets revoked.
			recordIDs := append([]string(nil), chunk...)
			if err := record(recordIDs); err != nil {
				for _, id := range chunk {
					slog.Error("cascaded node revocation not recorded",
						"node_id", id, "token_id", tokenID, "error", err)
				}
				unrecorded += len(chunk)
			}
			for _, id := range chunk {
				s.RevokeNode(id)
			}
			newThisPass += len(chunk)

			chunk = make([]string, 0, cascadeRecordChunk)
			pending = make(map[string]struct{}, cascadeRecordChunk)
		}

		for _, n := range s.reg.List() {
			if n.EnrollingTokenID != tokenID {
				continue
			}
			if s.denylist.IsRevoked(n.NodeID) {
				// Already handled in a prior pass; skip to avoid redundant Disconnect.
				// This also means an already-revoked Node gets no second record,
				// preserving the Console's causative-record rule (console/node.go,
				// #545/#487): the record that already exists for it stays the one
				// that answers "who did it".
				continue
			}
			if _, ok := pending[n.NodeID]; ok {
				// Already queued in THIS pass's unflushed chunk. The old per-Node
				// revoke relied on a duplicate List() entry hitting the IsRevoked
				// skip above; inside an unflushed chunk it would not yet, and
				// would get a second record against the causative-record rule.
				// This guard restores that dedup explicitly.
				continue
			}
			chunk = append(chunk, n.NodeID)
			pending[n.NodeID] = struct{}{}
			if len(chunk) >= cascadeRecordChunk {
				flush()
			}
		}
		flush()

		total += newThisPass
		// After the initial scan (pass > 0), stop early if this pass found no new
		// nodes: the registry has settled and no further late Upserts are expected.
		if pass > 0 && newThisPass == 0 {
			break
		}
	}
	slog.Info("token revoked", "token_id", tokenID, "nodes_revoked", total, "nodes_unrecorded", unrecorded)
	if unrecorded > 0 {
		return &CascadeShortfall{Unrecorded: unrecorded, Total: total}
	}
	return nil
}
