package revocation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/logctx"

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
//
// The cascade lists through ListChecked, never List: List cannot report a
// store read failure, so a cascade over it would revoke nothing on an
// unreadable registry and still report success (see ErrCascadeIncomplete).
type Registry interface {
	ListChecked() ([]registry.Node, error)
	SetRevoked(nodeID string, at time.Time) error

	// SetRevokedAll is the cascade's persistence path (revokeAll): one
	// registry write per chunk instead of one per Node. See
	// registry.Repository.SetRevokedAll for the all-or-nothing contract.
	SetRevokedAll(nodeIDs []string, at time.Time) (missing []string, err error)
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
// internal/audit nor internal/capability (.golangci.yml's revocation-imports rule), so
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
//
// The recorder MUST NEVER CALL BACK INTO Service: it runs while Service is
// holding the node locks for the chunk it covers, so any re-entrant call —
// directly or through something the recorder itself calls — self-deadlocks.
// It MUST ALSO RETURN IN BOUNDED TIME: it is invoked while holding up to
// cascadeRecordChunk node locks and the token lock, so a recorder that stalls
// blocks every single-Node revoke of those Nodes as well as the cascade's own
// forward progress. The Control API's cascade recorder satisfies the
// bounded-time half via cascadeAuditBudget (tokens.go).
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

// ErrRecorderRequired is returned by RevokeToken and RevokeNodeRecorded when
// called with a nil recorder, before the token store, the registry, or the
// Node's lock is touched.
//
// A nil recorder must not be read as "skip recording": a cascade or a
// single-Node revoke that CAN run unattributed is the bug, so making that state unreachable IS the fix. This mirrors
// api.authorizeControl's nil-Authz posture — loud and closed, never
// quiet and open.
var ErrRecorderRequired = errors.New("revocation: a Node revocation requires a recorder; refusing to run an unattributed revoke")

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

// ErrCascadeIncomplete is wrapped by the *IncompleteCascade RevokeToken
// returns when the token was revoked but the registry could not be read
// completely, so Nodes enrolled under it may still be trusted. It
// deliberately does NOT wrap ErrCascadeNotRecorded: that error means "every
// Node was revoked", which is exactly what cannot be claimed here.
//
// A retry is safe — token revocation is idempotent and the cascade skips
// Nodes already revoked — and fixes a TRANSIENT store fault. It does not fix
// a Node whose row stays unreadable: every retry fails the same way, and that
// Node must be revoked individually by the ID IncompleteCascade names (the
// single-Node revoke never reads the row).
var ErrCascadeIncomplete = errors.New("revocation: the registry could not be read completely; Nodes enrolled under the token may not all be revoked")

// maxNamedUnreadable bounds how many unreadable Node IDs an IncompleteCascade
// carries, so one bad store cannot turn an error string or a log line into
// an unbounded list; UnreadableCount still gives the full number.
const maxNamedUnreadable = 10

// IncompleteCascade reports a cascade that stopped because the registry could
// not be read completely. It wraps ErrCascadeIncomplete and the registry's
// read error, and never ErrCascadeNotRecorded. The counts are typed fields for
// the reason CascadeShortfall's are: they are what an operator acts on, and
// they must stay assertable when an unreadable registry and a recording
// shortfall coincide.
type IncompleteCascade struct {
	// Pass is the 0-based cascade pass whose registry read failed.
	Pass int
	// Revoked and Unrecorded count what the cascade did before it stopped:
	// Nodes revoked, and how many of those went unrecorded.
	Revoked    int
	Unrecorded int
	// UnreadableNodeIDs names at most maxNamedUnreadable of the Nodes the
	// registry listed but could not read; UnreadableCount is how many there
	// were in all. Both are zero when the ID scan itself failed — then no
	// Node can be named, and every Node the token enrolled may still be
	// trusted.
	UnreadableNodeIDs []string
	UnreadableCount   int
	// Err is the registry's read error.
	Err error
}

func (e *IncompleteCascade) Error() string {
	unseen := "every Node enrolled under the token may still be trusted"
	if e.UnreadableCount > 0 {
		unseen = fmt.Sprintf("%d unreadable Node(s) may still be trusted %v", e.UnreadableCount, e.UnreadableNodeIDs)
		if more := e.UnreadableCount - len(e.UnreadableNodeIDs); more > 0 {
			unseen += fmt.Sprintf(" and %d more", more)
		}
	}
	return fmt.Sprintf("revocation: the registry could not be read completely on pass %d "+
		"(%d Nodes revoked, %d unrecorded); %s: %v", e.Pass, e.Revoked, e.Unrecorded, unseen, e.Err)
}

// Unwrap lets errors.Is(err, ErrCascadeIncomplete) hold, and keeps the
// registry's own error reachable.
func (e *IncompleteCascade) Unwrap() []error { return []error{ErrCascadeIncomplete, e.Err} }

// newIncompleteCascade builds the IncompleteCascade for listErr, naming the
// unreadable Nodes when the registry reported them.
func newIncompleteCascade(pass, revoked, unrecorded int, listErr error) *IncompleteCascade {
	ic := &IncompleteCascade{Pass: pass, Revoked: revoked, Unrecorded: unrecorded, Err: listErr}
	var unreadable *registry.UnreadableNodesError
	if errors.As(listErr, &unreadable) {
		ic.UnreadableCount = len(unreadable.NodeIDs)
		ic.UnreadableNodeIDs = append([]string(nil), unreadable.NodeIDs[:min(len(unreadable.NodeIDs), maxNamedUnreadable)]...)
	}
	return ic
}

// Service coordinates the denylist and live-connection teardown for Node and
// Enrollment Token revocation.
type Service struct {
	denylist *Denylist
	conns    *Connections
	reg      Registry
	tokens   TokenRevoker

	// log is where revocations are reported; nil means slog.Default().
	log *slog.Logger

	// tokenLocks and nodeLocks serialise RevokeToken per token id and the
	// decide-record-revoke critical section per Node id: a cascade
	// holds tokenLocks for the whole of one token's cascade and nodeLocks for
	// each chunk it records and revokes, RevokeNodeRecorded holds nodeLocks
	// for the one Node it records and revokes. Keyed, never global, so
	// different tokens and different Nodes still revoke concurrently — see
	// RevokeToken and RevokeNodeRecorded for the lock order (token, then
	// node) and keyedMutex's doc for why that order is deadlock-free.
	tokenLocks *keyedMutex
	nodeLocks  *keyedMutex

	// recorded is the in-process record of which Nodes this cascade has
	// already recorded a revocation for, consulted by RevokeNodeRecorded to
	// avoid writing a second node_revoke record for a Node whose cascade
	// revocation this process already recorded. See recordedSet's doc
	// for why this is not the denylist.
	recorded *recordedSet
}

// NewService creates a Service.
func NewService(d *Denylist, c *Connections, reg Registry, tokens TokenRevoker, opts ...Option) *Service {
	s := &Service{
		denylist:   d,
		conns:      c,
		reg:        reg,
		tokens:     tokens,
		tokenLocks: newKeyedMutex(),
		nodeLocks:  newKeyedMutex(),
		recorded:   newRecordedSet(),
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Option configures a Service at construction.
type Option func(*Service)

// WithLogger sets the logger the Service reports revocations to. Without it
// the Service logs through slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(s *Service) { s.log = l }
}

func (s *Service) logger() *slog.Logger { return logctx.Or(s.log) }

// RevokeNode adds nodeID to the denylist, persists the revocation to the
// registry (the authority), and tears down any live Tunnel stream. The registry
// is now the source of truth: at startup the denylist is rehydrated from
// registry.RevokedNodeIDs(), so a revoked Node stays revoked across a Relay
// restart (ADR-0006). The denylist is a derived in-memory cache.
//
// node_id is the verified client-cert CN (ADR-0006) and is not a secret; it is
// safe to log.
//
// MUST STAY LOCK-FREE: revokeChunk and RevokeNodeRecorded both call
// this while already holding the Node's nodeLocks entry, and
// enroll.Service's post-enrollment cleanup (handler.go:540, through
// NodeDenylister) calls it with no lock held at all — it has no Principal and
// nothing to serialise against. Adding a nodeLocks acquisition here would
// self-deadlock the first two callers and is the one change to this method a
// future author is most likely to reach for; don't.
//
// revokeAll is this method's chunked twin, used only by revokeChunk for the
// token cascade: it keeps this method's three-phase order (denylist,
// persist, teardown) but persists a whole chunk in one registry call instead
// of one per Node. A future change to the order in one of these two methods
// should check the other.
func (s *Service) RevokeNode(nodeID string) {
	// Add to the denylist FIRST so the in-process barrier is instant even if the
	// persist below fails — over-denying beats under-denying on this surface.
	s.denylist.Add(nodeID)

	// Persist to the authority. registry.ErrNotFound is expected when the Node
	// has no registry row (e.g. it never connected): the in-memory denylist still
	// holds for this process, so log and continue rather than fail.
	if err := s.reg.SetRevoked(nodeID, time.Now().UTC()); err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			s.logger().Info("node revocation not persisted: no registry row",
				"node_id", nodeID)
		} else {
			s.logger().Warn("persist node revocation failed",
				"node_id", nodeID, "error", err)
		}
	}

	s.conns.Disconnect(nodeID)
	s.logger().Info("node revoked", "node_id", nodeID)
}

// revokeAll is RevokeNode's chunked twin, called only by revokeChunk for the
// token cascade. It keeps RevokeNode's per-Node relative order — denylist,
// then persist, then teardown — for every id in the chunk, but persists the
// whole chunk in ONE registry call instead of one per Node.
//
// THE PERSISTENCE TRADE, stated both ways: one transaction per chunk
// instead of one autocommit UPDATE per Node. SetMaxOpenConns(1) serialises
// statements, not transactions, so the autocommits this replaces already let
// other store callers interleave between every pair of them; what they cost
// was one commit per Node, and that total is what a large cascade made
// everyone else queue behind. The chunk cuts that by the chunk factor and,
// in exchange, holds the single connection for one chunk's transaction
// rather than releasing it between every Node. Same trade as this cascade's
// audit records.
//
// Phase (1) — denylist.Add for every id — runs regardless of what phase (2)
// returns, and phase (2)'s error is logged and never returned: over-denying
// beats under-denying, the same posture RevokeNode and revokeChunk state. A
// caller that could refuse to revoke on a store failure would leave a Node
// whose enrolling token is already dead holding a live Tunnel. Phase (3) —
// the live-Tunnel teardown — runs for every id regardless of (2) too; it is
// not conditional on persistence.
//
// WHY THE WHOLE CHUNK IS DENYLISTED BEFORE ANY STORE I/O rather than
// interleaved per Node: it makes every Node's in-memory barrier land EARLIER
// than it does today (today the 500th Node in a chunk waits behind 499
// autocommits), and it is what lets phase (2) be one call.
//
// THE ONE DIRECTIONAL COST: the chunk's FIRST Node keeps an
// already-authenticated, live Tunnel for up to one chunk transaction LONGER
// than it does today — phase (3) does not run for it until the chunk's
// store write returns, and neither dispatch nor Selector resolution filters
// on the denylist or on RevokedAt, so during that window the Node can still
// send and receive on that stream AND receive and execute a newly
// dispatched Task. Bounded by one chunk's transaction; its denylist barrier
// lands no later than today (phase (1) is first), so it cannot reconnect.
// Net across a chunk this is still an improvement: Nodes 2..N disconnect
// far earlier than they did under the per-Node loop, so only the chunk's
// first Node is marginally worse off. Accepted.
//
// THE FALLBACK ON A BATCH FAILURE. SetRevokedAll is all-or-nothing
// (registry.Repository.SetRevokedAll): one store fault partway through the
// chunk — SQLITE_FULL, an IOERR, a BUSY or failed COMMIT — rolls back every
// row in the chunk, not only the one that faulted. Because the in-memory
// denylist is rehydrated from RevokedNodeIDs() at every start (ADR-0006), an unrecovered batch failure would leave up to
// cascadeRecordChunk Nodes denylisted in memory only, and a restart would
// let every one of them back in. Falling back to a per-Node
// SetRevoked loop on error degrades exactly to that loop's behaviour instead
// of losing the chunk: whichever ids the fallback still manages to persist
// survive a restart, and the per-id log lines below (the same message and
// key RevokeNode uses) make every id in the chunk recoverable by an operator
// even where the fallback itself fails. One batch attempt only, no retry,
// then the fallback loop, then stop.
//
// ids is handed to SetRevokedAll WITHOUT a defensive copy, unlike the record
// call above it in revokeChunk: RevocationRecorder is a caller-supplied
// closure from outside this package, whereas every Registry implementation
// is in-repo and bound by the read-only-borrow contract documented on
// registry.Repository.SetRevokedAll — a review contract, not one the
// compiler can check, which is why the doubles in this package's tests copy
// what they retain.
func (s *Service) revokeAll(ids []string) {
	for _, id := range ids {
		s.denylist.Add(id)
	}

	now := time.Now().UTC()
	missing, err := s.reg.SetRevokedAll(ids, now)
	for _, id := range missing {
		s.logger().Info("node revocation not persisted: no registry row",
			"node_id", id)
	}
	if err != nil {
		// The batch is all-or-nothing, so this chunk's ids are the
		// recoverable set — see the fallback below and the doc above.
		s.logger().Warn("persist node revocations failed; falling back to per-Node writes",
			"chunk_size", len(ids), "error", err)
		for _, id := range ids {
			if ferr := s.reg.SetRevoked(id, now); ferr != nil {
				if errors.Is(ferr, registry.ErrNotFound) {
					s.logger().Info("node revocation not persisted: no registry row",
						"node_id", id)
				} else {
					s.logger().Warn("persist node revocation failed",
						"node_id", id, "error", ferr)
				}
			}
		}
	}

	for _, id := range ids {
		s.conns.Disconnect(id)
		s.logger().Info("node revoked", "node_id", id)
	}
}

// RevokeNodeRecorded is the operator-ordered single-Node revoke: it records
// nodeID's revocation through record and then revokes it, holding the Node's
// lock across both so a token cascade cannot write a second node_revoke
// record for the same Node.
//
// record is REQUIRED, refused with ErrRecorderRequired before the Node's
// lock is even acquired — the same posture RevokeToken takes, for the same
// reason: a revoke that CAN run unattributed is the bug to close.
//
// WHY THIS MAY INVERT THE ORDINARY BEST-EFFORT AUDIT POSTURE: nothing has
// happened yet at the moment record is called, and RevokeNode has no error
// return to strand — so record is called BEFORE RevokeNode, and a record
// failure returns the error and revokes nothing (FAIL CLOSED). This is
// record-before-act ordering, held inside the Node's lock — the only place it
// can be atomic against a concurrent cascade for the same Node.
//
// THE HONEST LIMIT: RevokeNode's DURABLE half can
// still fail quietly. It adds to the in-process denylist first and
// disconnects reliably, but reg.SetRevoked is best-effort and only logged
// (see RevokeNode), so a persist failure leaves a permanent, attributed
// node_revoke record beside a registry that did not record the revocation,
// and a later restart — which rehydrates the denylist from the registry
// — could let the Node reconnect. What this ordering guarantees is
// narrower and still worth having: no revocation is ATTEMPTED without a
// durable record of who ordered it and why.
//
// THE ONE SUPPRESSION AND ITS EXACT SCOPE: a second record is withheld only
// when THIS PROCESS already recorded a cascade revocation for nodeID
// (recordedSet, set by revokeChunk). A Node that is merely denylisted — by
// enroll.Service's self-denylist, by a cascade chunk whose record failed, or
// by denylist rehydration at startup — still gets a record here, because
// this route is the backstop that supplies attribution none of those paths
// can. See recordedSet's doc for why this is keyed on a written record and
// never on denylist membership.
func (s *Service) RevokeNodeRecorded(ctx context.Context, nodeID string, record RevocationRecorder) error {
	if record == nil {
		return ErrRecorderRequired
	}

	unlock, err := s.nodeLocks.lock(ctx, nodeID)
	if err != nil {
		// Nothing has happened yet: the wait was cancelled before the Node
		// was touched.
		return err
	}
	defer unlock()

	if s.recorded.has(nodeID) {
		s.logger().InfoContext(ctx, "node revocation already recorded by this relay; no second record written",
			"node_id", nodeID)
		// RevokeNode is idempotent and is called anyway: over-denying beats
		// under-denying is this surface's own stated posture, and a repeat
		// call here is exactly that — re-applying the denylist add and the
		// live-Tunnel teardown, never re-attributing them.
		s.RevokeNode(nodeID)
		return nil
	}

	if err := record([]string{nodeID}); err != nil {
		return err
	}
	s.RevokeNode(nodeID)
	return nil
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
// record is REQUIRED: every cascaded Node's revocation must be
// recorded through it, one call per chunk of at most cascadeRecordChunk
// Nodes, from inside the pass loop below — see RevocationRecorder's doc for
// why a callback rather than a sink field, and why it takes no context.
//
// SERIALISED PER TOKEN ID: RevokeToken takes tokenID's lock before
// Step 1 and holds it for the whole cascade, every pass included. Three
// consequences worth knowing: (a) the lock is taken BEFORE s.tokens.Revoke,
// so a caller whose wait is cancelled has caused nothing at all — the token
// and every Node it enrolled are untouched; (b) a second concurrent
// RevokeToken call for the same tokenID waits for the first to finish and
// then re-runs its own cascade, which is a no-op: enroll.Service.Revoke is
// idempotent (token.go:326) and every Node is already denylisted, so the
// pass loop's IsRevoked skip drops all of them and nothing is recorded
// twice; (c) the lock is keyed on tokenID, so a cascade for a different
// token is never delayed by this one.
//
// FAILS LOUDLY ON AN UNREADABLE REGISTRY: if any pass cannot read the whole
// registry, the Nodes it did read are still revoked, and RevokeToken then
// returns an *IncompleteCascade (wrapping ErrCascadeIncomplete) naming what
// it could not see, instead of reporting success. The token itself stays
// revoked (Step 1 already ran). See ErrCascadeIncomplete for what a retry
// does and does not fix.
func (s *Service) RevokeToken(ctx context.Context, tokenID string, record RevocationRecorder) error {
	// A nil recorder is refused before the token store or the token lock is
	// touched, so a nil recorder revokes NOTHING — see ErrRecorderRequired.
	if record == nil {
		return ErrRecorderRequired
	}

	unlockToken, err := s.tokenLocks.lock(ctx, tokenID)
	if err != nil {
		// Nothing has happened yet: the wait was cancelled before the token
		// was touched.
		return err
	}
	defer unlockToken()

	// Step 1: Revoke the token FIRST — this is the barrier. After this returns,
	// any subsequent Enroll Validate call for tokenID returns ErrRevoked, so no
	// new node_id can be minted under this token.
	if err := s.tokens.Revoke(ctx, tokenID); err != nil {
		if errors.Is(err, enroll.ErrNotFound) {
			// Unknown token: log and continue. The cascade is still valid — Nodes
			// that recorded this tokenID in their provenance must still be revoked.
			s.logger().InfoContext(ctx, "token not found during revocation, continuing cascade",
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
			n, u := s.revokeChunk(chunk, record, tokenID)
			newThisPass += n
			unrecorded += u

			chunk = make([]string, 0, cascadeRecordChunk)
			pending = make(map[string]struct{}, cascadeRecordChunk)
		}

		// A failed or partial read must never pass for a settled registry:
		// otherwise a store error would revoke zero Nodes and report
		// success, leaving every Node a leaked token enrolled still trusted.
		// The Nodes that WERE read are still revoked below — over-denying
		// beats under-denying — and the cascade then stops and fails loudly
		// after this pass rather than claiming completion.
		nodes, listErr := s.reg.ListChecked()
		for _, n := range nodes {
			if n.EnrollingTokenID != tokenID {
				continue
			}
			if s.denylist.IsRevoked(n.NodeID) {
				// Already handled in a prior pass; skip to avoid redundant Disconnect.
				// This also means an already-revoked Node gets no second record,
				// preserving the Console's causative-record rule (console/node.go):
				// the record that already exists for it stays the one
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
		if listErr != nil {
			ic := newIncompleteCascade(pass, total, unrecorded, listErr)
			s.logger().ErrorContext(ctx, "token revocation cascade incomplete: registry read failed",
				"token_id", tokenID, "pass", pass, "nodes_revoked", total,
				"nodes_unrecorded", unrecorded, "nodes_unreadable", ic.UnreadableCount,
				"unreadable_node_ids", ic.UnreadableNodeIDs, "error", listErr)
			return ic
		}
		// After the initial scan (pass > 0), stop early if this pass found no new
		// nodes: the registry has settled and no further late Upserts are expected.
		if pass > 0 && newThisPass == 0 {
			break
		}
	}
	s.logger().InfoContext(ctx, "token revoked", "token_id", tokenID, "nodes_revoked", total, "nodes_unrecorded", unrecorded)
	if unrecorded > 0 {
		return &CascadeShortfall{Unrecorded: unrecorded, Total: total}
	}
	return nil
}

// revokeChunk locks every id in ids, drops the ids something else already
// revoked, records the survivors through record, marks them recorded, and
// revokes them regardless of a record failure; it returns how many were
// revoked and how many of those went unrecorded.
//
// LOCKING EVERY id IN THE CHUNK FIRST is what prevents a duplicate record: no
// other revoke path — a concurrent RevokeNodeRecorded, or another cascade
// pass, though a Node belongs to exactly one enrolling token so that second
// case cannot actually contend — can observe one of these Nodes in the
// window between this chunk's record committing and its revokeAll call
// below, because reaching that Node at all requires this same lock.
func (s *Service) revokeChunk(ids []string, record RevocationRecorder, tokenID string) (revoked, unrecorded int) {
	unlockNodes := s.nodeLocks.lockAll(ids)
	defer unlockNodes()

	// Re-check IsRevoked now that every id in ids is locked, dropping any id
	// that was revoked by something else (e.g. a concurrent single-Node
	// revoke) while it sat in this unflushed chunk. Without this, that Node
	// would get a second node_revoke record here, against the
	// causative-record rule the IsRevoked skip in RevokeToken's pass loop
	// already enforces across passes. Evaluated under the locks acquired
	// above, this is not a best-effort narrowing: it is the actual
	// dedup for a single-Node revoke that reached and revoked this Node
	// first, while it sat unflushed in this chunk. The predicate stays
	// IsRevoked, deliberately not the recorded set below: the cascade's
	// "skip what is already revoked" rule is deliberately not widened —
	// keying it on the recorded set instead would make the cascade record
	// Nodes it skips (a Node self-denylisted by enroll.Service with no
	// record).
	live := ids[:0]
	for _, id := range ids {
		if !s.denylist.IsRevoked(id) {
			live = append(live, id)
		}
	}
	ids = live
	if len(ids) == 0 {
		return 0, 0
	}

	// Record the chunk BEFORE revoking any Node in it, but — unlike
	// RevokeNodeRecorded's record-before-act ordering — revoke EVERY Node in
	// the chunk EITHER WAY, deliberately inverting that posture. That
	// fail-closed order is licensed by two facts that do not hold here:
	// nothing has happened yet, and RevokeNode has no error return to strand. Here the
	// token is already revoked (RevokeToken's Step 1) and any earlier Node in
	// this same cascade already is too; refusing to revoke a Node because its
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
	// This leaves a crash window: a process crash between this chunk's
	// commit and the end of the revokeAll call below can leave up to
	// cascadeRecordChunk records for Nodes not yet revoked. That is the
	// chosen failure direction — a record with no matching revoke is an
	// audit-trail overstatement, never an unattributed revoke — widened by
	// recording and revoking per chunk instead of per Node. Accepted; do not
	// reorder.
	//
	// The revoke half below is one store transaction per chunk rather than
	// len(ids) autocommits — see revokeAll's doc for that trade. So the
	// window does not decay across the chunk as Nodes are revoked; it is a
	// step function — the full chunk is exposed for the entire
	// transaction, then zero the instant it commits; on a batch failure the
	// fallback below closes the window per Node as each autocommit lands,
	// not in one step.
	//
	// record is handed a defensive copy, never ids itself: ids is what the
	// revoke loop below (and the error log above it) reads once record
	// returns, and RevocationRecorder's contract only asks the recorder not
	// to mutate or retain what it was given — it does not enforce that. A
	// recorder that broke the contract and mutated or reordered ids in
	// place could otherwise make the cascade revoke the wrong Nodes;
	// copying first means a misbehaving recorder can corrupt only its own
	// copy, and every Node in this chunk still gets revoked.
	recordIDs := append([]string(nil), ids...)
	if err := record(recordIDs); err != nil {
		for _, id := range ids {
			s.logger().Error("cascaded node revocation not recorded",
				"node_id", id, "token_id", tokenID, "error", err)
		}
		unrecorded = len(ids)
	} else {
		// Marked BEFORE the revoke loop, and only on a nil error: "recorded"
		// must imply "about to be revoked under this same lock" so that a
		// RevokeNodeRecorded call for one of these Nodes, blocked on its
		// lock right now, sees the mark the instant it acquires it. On a
		// non-nil error, do NOT mark: this chunk is then one of the
		// record-free denylist paths recordedSet's doc names, and the
		// operator route must still be able to supply its attribution.
		s.recorded.markAll(ids)
	}
	s.revokeAll(ids)
	return len(ids), unrecorded
}
