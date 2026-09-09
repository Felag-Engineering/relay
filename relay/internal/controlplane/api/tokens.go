package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll"
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

// handleRevokeToken implements DELETE /api/v1/enrollment-tokens/{id}:
// revoke the token (and, via TokenRevoker.RevokeToken, cascade-revoke every
// Node it enrolled), audit the revoke (KindTokenRevoke), and return 204.
// Idempotent: revoking an unknown or already-revoked id still returns 204
// (revocation.Service.RevokeToken swallows enroll.ErrNotFound).
//
// **Requires `admin`** (#397). #397's table named the mint and the Node
// revoke; this route was the same hole, found by the structural guard that
// issue asked for. It cascades to every Node the token enrolled, tearing down
// live Tunnels — the same availability blast radius as revoking those Nodes
// one at a time, which ADR-0020's incident ladder puts at admin.
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

		if err := d.TokenRevoker.RevokeToken(r.Context(), id); err != nil {
			writeProblem(w, http.StatusInternalServerError, "revoke enrollment token failed", "")
			return
		}

		recordLifecycle(r.Context(), d, p, audit.KindTokenRevoke, "", "token_id="+id)
		w.WriteHeader(http.StatusNoContent)
	}
}
