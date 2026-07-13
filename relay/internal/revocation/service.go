package revocation

import (
	"context"
	"errors"
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
func (s *Service) RevokeToken(ctx context.Context, tokenID string) error {
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
	var total int
	for pass := 0; pass <= maxRescanPasses; pass++ {
		var newThisPass int
		for _, n := range s.reg.List() {
			if n.EnrollingTokenID != tokenID {
				continue
			}
			if s.denylist.IsRevoked(n.NodeID) {
				// Already handled in a prior pass; skip to avoid redundant Disconnect.
				continue
			}
			s.RevokeNode(n.NodeID)
			newThisPass++
		}
		total += newThisPass
		// After the initial scan (pass > 0), stop early if this pass found no new
		// nodes: the registry has settled and no further late Upserts are expected.
		if pass > 0 && newThisPass == 0 {
			break
		}
	}
	slog.Info("token revoked", "token_id", tokenID, "nodes_revoked", total)
	return nil
}
