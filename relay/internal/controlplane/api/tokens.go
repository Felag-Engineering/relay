package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/revocation"
)

// maxTTLSeconds bounds ttl_seconds: it guards against
// time.Duration(req.TTLSeconds)*time.Second overflowing on an absurd input,
// and there is no legitimate need for an Enrollment Token to outlive a year.
const maxTTLSeconds = 365 * 24 * 60 * 60

// mintTokenRequest is the POST /api/v1/enrollment-tokens request body.
// Scope must be non-empty and every entry relay:-prefixed with a non-empty
// bare key and a (possibly empty) value whose every byte is in
// [A-Za-z0-9._-] (enforced by enroll.Service.Create -> enroll.validateScope,
// registry.WellFormedLabel, ADR-0006, #555) — this handler never
// re-implements or loosens that check. MaxUses <= 0 means unlimited
// (enroll.WithMaxUses's own convention).
type mintTokenRequest struct {
	Scope      []string `json:"scope"`
	TTLSeconds int64    `json:"ttl_seconds"`
	MaxUses    int      `json:"max_uses"`
}

// mintTokenResponse is the POST /api/v1/enrollment-tokens response body.
// Token carries the plaintext Enrollment Token credential — this is the only
// response in which it ever appears; it is never persisted, logged, or
// audited (recordLifecycle below records only the token's non-secret id).
type mintTokenResponse struct {
	ID        string   `json:"id"`
	Token     string   `json:"token"`
	Scope     []string `json:"scope"`
	ExpiresAt string   `json:"expires_at"`
	MaxUses   int      `json:"max_uses"`
}

// handleMintToken implements POST /api/v1/enrollment-tokens: mint a scoped
// Enrollment Token via TokenMinter.Create, audit the mint (KindTokenMint),
// and return the plaintext credential exactly once (201).
//
// **Requires `admin`** (ADR-0032 §5, #397), checked before the body is even
// decoded. A token's scope becomes the enrolling Node's relay: labels, and
// relay: is the namespace the security-sensitive lane targets (invariant 7,
// ADR-0020) — so minting manufactures Nodes that quarantine, remediation, and
// secret distribution will treat as authoritative. Until #397 this route
// checked no role at all: a viewer could stamp `relay:env=prod` onto anything
// that presented the token.
func handleMintToken(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
			return
		}
		if !authorizeControl(w, r, d, p, capability.ControlMintEnrollmentToken) {
			return
		}

		var req mintTokenRequest
		if err := decodeJSON(w, r, &req); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
			return
		}

		if req.TTLSeconds <= 0 || req.TTLSeconds > maxTTLSeconds {
			writeProblem(w, http.StatusBadRequest, "invalid enrollment token request",
				fmt.Sprintf("ttl_seconds must be > 0 and <= %d", maxTTLSeconds))
			return
		}

		opts := []enroll.Option{enroll.WithCreatedBy(p.Attribution())}
		if req.MaxUses > 0 {
			opts = append(opts, enroll.WithMaxUses(req.MaxUses))
		}

		tok, plaintext, err := d.Tokens.Create(r.Context(), req.Scope, time.Duration(req.TTLSeconds)*time.Second, opts...)
		if err != nil {
			if errors.Is(err, enroll.ErrInvalidScope) || errors.Is(err, enroll.ErrInvalidTTL) {
				writeProblem(w, http.StatusBadRequest, "invalid enrollment token request", err.Error())
				return
			}
			writeProblem(w, http.StatusInternalServerError, "mint enrollment token failed", "")
			return
		}

		recordLifecycle(r.Context(), d, p, audit.KindTokenMint, "", "token_id="+tok.ID)

		writeJSON(w, http.StatusCreated, mintTokenResponse{
			ID:        tok.ID,
			Token:     plaintext,
			Scope:     tok.Scope,
			ExpiresAt: tok.ExpiresAt.UTC().Format(time.RFC3339),
			MaxUses:   tok.MaxUses,
		})
	}
}

// cascadeAuditBudget bounds the wall-clock time the cascade's chunked record
// writes may take in total, once detached from the request context.
//
// Generous rather than tight: it exists to stop an unbounded stall on the
// Relay's single store connection, not to police a slow disk. A cascade that
// exceeds it stops recording and reports the shortfall like any other
// unrecorded cascade — the Nodes are still revoked, which is the direction
// revocation/service.go settles.
const cascadeAuditBudget = 2 * time.Minute

// handleRevokeToken implements DELETE /api/v1/enrollment-tokens/{id}:
// revoke the token (and, via TokenRevoker.RevokeToken, cascade-revoke every
// Node it enrolled), audit the revoke (KindTokenRevoke) plus one
// KindNodeRevoke per cascaded Node (#557), and return 204. Idempotent:
// revoking an unknown or already-revoked id still returns 204
// (revocation.Service.RevokeToken swallows enroll.ErrNotFound).
//
// **Requires `admin`** (#397). #397's table named the mint and the Node
// revoke; this route was the same hole, found by the structural guard that
// issue asked for. It cascades to every Node the token enrolled, tearing down
// live Tunnels — the same availability blast radius as revoking those Nodes
// one at a time, which ADR-0020's incident ladder puts at admin.
//
// Can now also answer 400 (the token id cannot be rendered into a revocation
// reason) and a completed-but-unrecorded 500 (the token and its Nodes were
// revoked, but one or more per-Node records could not be written).
func handleRevokeToken(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
			return
		}
		if !authorizeControl(w, r, d, p, capability.ControlRevokeEnrollmentToken) {
			return
		}

		id := r.PathValue("id")
		if id == "" {
			writeProblem(w, http.StatusBadRequest, "missing token id", "path parameter id must not be empty")
			return
		}

		// id is raw r.PathValue input, not a store-validated value — RevokeToken
		// deliberately tolerates an unknown id and still cascades (it may name a
		// token that was already deleted) — so this is NOT ceremony: without it, a
		// control character or bidi override in the path would be persisted
		// verbatim into every cascade record and rendered on Node detail. A
		// genuine 32-hex id passes this trivially.
		reason, err := capability.ValidateRevokeReason(capability.CascadeRevokeReason(id))
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid token id",
				"the token id cannot be rendered into a revocation reason: "+err.Error())
			return
		}

		// WithoutCancel: the cascade performs N irreversible acts (denylist +
		// live-Tunnel teardown per Node); if the client hangs up midway the
		// revocations continue, so the audit records describing them must too.
		// Values — and so capability.AssertionsFromContext's asserted lane —
		// survive WithoutCancel; only the cancellation signal is dropped.
		//
		// BUT NOT WITHOUT A DEADLINE. Detaching from the request would otherwise
		// leave these writes unbounded, and they are not cheap: the store runs
		// on a single connection (SetMaxOpenConns(1)). The records are now
		// written in chunked transactions (revocation.cascadeRecordChunk), one
		// commit per chunk rather than one per Node, so a token covering a
		// large fleet no longer makes every other store-backed request —
		// registry reads, Job persistence, the fail-closed read-audit path —
		// queue behind one commit per Node; the connection is instead held
		// for one chunk's transaction at a time. The deadline still bounds
		// the total: a chunk that is in flight or not yet started when the
		// budget expires fails whole and is counted whole by the cascade,
		// while earlier committed chunks stay. N must still stay unbounded:
		// capping the cascade would leave Nodes either unrevoked (an
		// authentication hole) or unrecorded (the bug this closes).
		//
		// The registry writes are now chunked the same way (#607): on the
		// happy path the cascade marks each chunk's Nodes revoked in ONE
		// transaction per revocation.cascadeRecordChunk, not one autocommit
		// UPDATE per Node; a batch failure falls back to exactly that
		// per-Node autocommit loop for the chunk (revocation.Service).
		// Both halves are the same two-sided trade, and it is worth stating
		// precisely. SetMaxOpenConns(1) serialises STATEMENTS, not
		// transactions (store/accounts.go), so the per-Node autocommits
		// already let other store callers interleave between every pair of
		// them; what they cost was one commit — one WAL fsync — per Node,
		// and that total is what made a large cascade's run, and everyone
		// else's queuing behind it, scale with N. Chunking divides that by
		// the chunk size. In exchange the single connection is now held for
		// a whole chunk transaction, so a dispatch write or a read-audit
		// write arriving mid-chunk waits for the chunk rather than for one
		// statement. Accepted deliberately, in both halves.
		//
		// The registry half is deliberately NOT bound by this budget. A
		// budget expiry that stopped persisting revocations would leave
		// Nodes denylisted in memory only, and a restart rehydrates the
		// denylist from the registry (#133, ADR-0006) — it would silently
		// un-revoke them. That is under-denying, which this cascade's stated
		// posture forbids; the chunk SIZE, not a deadline, is what bounds
		// the registry write.
		//
		// The budget starts here, BEFORE RevokeToken — so if a second
		// concurrent revoke of this same token (#605) is already waiting on
		// tokenLocks, this cascade's cascadeAuditBudget clock is already
		// running for the whole of that wait too. Bounded harm: the wait
		// itself is bounded by the first cascade's own run, and a budget that
		// expires mid-wait is reported the same way as one that expires
		// mid-cascade — a shortfall, not a silent success.
		auditCtx, cancelAudit := context.WithTimeout(
			context.WithoutCancel(r.Context()), cascadeAuditBudget)
		defer cancelAudit()
		record := func(nodeIDs []string) error {
			return recordLifecycleAllErr(auditCtx, d, p, audit.KindNodeRevoke, nodeIDs, reason)
		}

		err = d.TokenRevoker.RevokeToken(r.Context(), id, record)
		if err != nil && !errors.Is(err, revocation.ErrCascadeNotRecorded) {
			writeProblem(w, http.StatusInternalServerError, "revoke enrollment token failed", "")
			return
		}

		// KindTokenRevoke stays AFTER the act and best-effort (recordLifecycle) —
		// unlike handleRevokeNode's record-before-act ordering, deliberately:
		// RevokeToken CAN return an error, so recording first would risk a
		// permanent record asserting a revoke that never happened.
		// revocation.Service.RevokeNodeRecorded's doc explains #487 was allowed
		// to invert this ordering only because RevokeNode has no error return
		// to strand; RevokeToken does, so this route keeps recordLifecycle's
		// ordinary best-effort contract instead.
		recordLifecycle(r.Context(), d, p, audit.KindTokenRevoke, "", "token_id="+id)

		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "revoke not fully recorded",
				"the Enrollment Token and its Nodes were revoked, but one or more per-Node "+
					"revocation records could not be written; retrying will not restore them")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
