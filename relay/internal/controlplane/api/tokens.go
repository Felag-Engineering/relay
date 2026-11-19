package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

// maxTTLSeconds bounds ttl_seconds: it guards against
// time.Duration(req.TTLSeconds)*time.Second overflowing on an absurd input,
// and there is no legitimate need for an Enrollment Token to outlive a year.
const maxTTLSeconds = int64(capability.MaxEnrollmentTokenTTL / time.Second)

// mintTokenRequest is the POST /api/v1/enrollment-tokens request body.
// InitialTags is optional: each entry is a tag in written form, tag:key=value,
// checked by enroll behind the capability layer through
// registry.ParseInitialTags (EN-40, EN-42) — this handler never re-implements or
// loosens that check, and the rule that only a human Account names a tag (EN-44)
// is enroll's too. The use limit is required and decided by the capability
// layer's mint action (EN-31); this handler passes MaxUses and Unlimited
// through unchanged.
type mintTokenRequest struct {
	InitialTags []string `json:"initial_tags"`
	TTLSeconds  int64    `json:"ttl_seconds"`
	MaxUses     int      `json:"max_uses"`
	Unlimited   bool     `json:"unlimited"`
}

// mintTokenResponse is the POST /api/v1/enrollment-tokens response body.
// Token carries the plaintext Enrollment Token credential and JoinString the
// join string that embeds it — this is the only response in which the plaintext
// ever appears, once in "token" and once inside "join_string"; it is never
// persisted, logged, or audited (the capability layer's record names only the
// token's non-secret id).
type mintTokenResponse struct {
	ID          string   `json:"id"`
	Token       string   `json:"token"`
	JoinString  string   `json:"join_string"`
	InitialTags []string `json:"initial_tags"`
	ExpiresAt   string   `json:"expires_at"`
	MaxUses     int      `json:"max_uses"`
	Unlimited   bool     `json:"unlimited"`
}

// handleMintToken implements POST /api/v1/enrollment-tokens: mint an
// Enrollment Token naming initial tags via TokenMinter, and return the plaintext
// credential exactly once (201). The mint names its use limit, a positive
// max_uses or unlimited (EN-31); an invalid one is a 400. The token_mint record
// is the capability layer's and is fail-closed: a mint that cannot be recorded is
// withdrawn and answers 500, with no credential in the response.
//
// **Requires `admin`** (ADR-0032 §5), checked in the capability layer (Gate)
// before the body is decoded (EN-1). Minting makes every Node that presents the
// token join the fleet carrying its initial tags, which a Selector then targets
// (ADR-0050), so the act is an admin's. A machine Account is refused when it
// names any initial tag (EN-44), and any relay: label is refused naming it,
// whoever mints (EN-35).
func handleMintToken(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
			return
		}
		if !gateControl(w, r, d, func(g ControlGate) error { return g.AuthorizeEnrollmentTokenMint(r.Context(), p) }) {
			return
		}

		var req mintTokenRequest
		if !readJSONBody(w, r, &req) {
			return
		}

		if req.TTLSeconds <= 0 || req.TTLSeconds > maxTTLSeconds {
			writeProblem(w, http.StatusBadRequest, "invalid enrollment token request",
				fmt.Sprintf("ttl_seconds must be > 0 and <= %d", maxTTLSeconds))
			return
		}

		if d.Tokens == nil {
			writeProblem(w, http.StatusInternalServerError, "enrollment token minting unavailable",
				"enrollment token minting is not configured on this Relay")
			return
		}

		minted, err := d.Tokens.MintEnrollmentToken(r.Context(), p, capability.EnrollmentMint{
			MaxUses:     req.MaxUses,
			Unlimited:   req.Unlimited,
			TTL:         time.Duration(req.TTLSeconds) * time.Second,
			InitialTags: req.InitialTags,
		})
		if err != nil {
			writeMintTokenError(w, r, d, err)
			return
		}

		// InitialTags is nil for an empty set; the response renders [], not null.
		tags := minted.InitialTags()
		if tags == nil {
			tags = []string{}
		}
		writeJSON(w, http.StatusCreated, mintTokenResponse{
			ID:          minted.ID(),
			Token:       minted.Credential(),
			JoinString:  minted.JoinString(),
			InitialTags: tags,
			ExpiresAt:   minted.ExpiresAt().UTC().Format(time.RFC3339),
			MaxUses:     minted.MaxUses(),
			Unlimited:   minted.Unlimited(),
		})
	}
}

// logUnrecordedMintRefusal logs an audited refusal the capability layer could
// not record: it arrives joined with the record failure, which the response
// never shows. Only the two audited refusals (unauthorized, initial tags needing
// a human) are recorded, so only they can carry such a failure; every other
// error, including an invalid initial tag whose error names the submitted entry,
// logs nothing here. Only the error is logged, never the request.
func logUnrecordedMintRefusal(r *http.Request, d Deps, err error) {
	if !errors.Is(err, authz.ErrUnauthorized) && !errors.Is(err, capability.ErrEnrollmentInitialTagsNeedHuman) {
		return
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok || len(joined.Unwrap()) < 2 {
		return
	}
	d.logger().ErrorContext(r.Context(), "control api: enrollment token mint refusal not recorded",
		"route", "POST /api/v1/enrollment-tokens", "error", err)
}

// writeMintTokenError renders a refused or failed mint. Details are constant or
// the capability layer's own sentinel text, never the credential or join string.
func writeMintTokenError(w http.ResponseWriter, r *http.Request, d Deps, err error) {
	logUnrecordedMintRefusal(r, d, err)
	switch {
	case errors.Is(err, capability.ErrEnrollmentTokenMayBeLive):
		var live *capability.EnrollmentTokenLiveError
		tokenID := ""
		if errors.As(err, &live) {
			tokenID = live.TokenID
		}
		d.logger().ErrorContext(r.Context(), "control api: enrollment token mint not recorded and not withdrawn",
			"route", "POST /api/v1/enrollment-tokens", "token_id", tokenID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "mint not recorded",
			"the mint could not be recorded or withdrawn; token "+tokenID+" may still be live; revoke it with DELETE /api/v1/enrollment-tokens/"+tokenID)
	case errors.Is(err, capability.ErrEnrollmentMintNotRecorded):
		d.logger().ErrorContext(r.Context(), "control api: enrollment token mint not recorded",
			"route", "POST /api/v1/enrollment-tokens", "error", err)
		writeProblem(w, http.StatusInternalServerError, "mint not recorded",
			"the token was withdrawn and admits no Node; mint again")
	case errors.Is(err, capability.ErrEnrollmentInitialTagsNeedHuman):
		// The sentinel, never err.Error(): the refusal may be joined with a record failure.
		writeProblem(w, http.StatusForbidden, "forbidden", capability.ErrEnrollmentInitialTagsNeedHuman.Error())
	case errors.Is(err, capability.ErrEnrollmentInitialTags) || errors.Is(err, capability.ErrEnrollmentTTL) ||
		errors.Is(err, capability.ErrEnrollmentUseLimit):
		writeProblem(w, http.StatusBadRequest, "invalid enrollment token request", err.Error())
	case errors.Is(err, authz.ErrUnauthorized):
		writeProblem(w, http.StatusForbidden, "forbidden", "minting an Enrollment Token requires the admin role")
	case errors.Is(err, capability.ErrEnrollmentTokensUnavailable):
		writeProblem(w, http.StatusInternalServerError, "enrollment token minting unavailable",
			"enrollment token minting is not configured on this Relay")
	default:
		d.logger().ErrorContext(r.Context(), "control api: enrollment token mint failed",
			"route", "POST /api/v1/enrollment-tokens", "error", err)
		writeProblem(w, http.StatusInternalServerError, "mint enrollment token failed", "")
	}
}

// handleRevokeToken implements DELETE /api/v1/enrollment-tokens/{id}: revoke
// the token, cascade-revoke every Node it enrolled, and return 204.
// Idempotent: revoking an unknown or already-revoked id still returns 204.
//
// **Requires `admin`**: it cascades to every Node the token enrolled, tearing
// down live Tunnels, the same availability blast radius as revoking those Nodes
// one at a time, which ADR-0020's incident ladder puts at admin. The floor is
// asked inside capability.Revocations, before the id is rendered into the
// cascade's reason, so this route holds no gate of its own. The act and its
// records are the layer's too.
//
// Can also answer 400 (the token id cannot be rendered into a revocation
// reason), a completed-but-unrecorded 500 (the token and its Nodes were
// revoked, but one or more per-Node records could not be written), and a
// token-revoked-cascade-incomplete 500 (the registry could not be read
// completely, so some of its Nodes may still be trusted).
func handleRevokeToken(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
			return
		}
		id, ok := requirePathValue(w, r, "id", "missing token id", "path parameter id must not be empty")
		if !ok {
			return
		}
		if d.Revocations == nil {
			writeRevocationsUnavailable(w)
			return
		}

		err := d.Revocations.RevokeEnrollmentToken(r.Context(), p, id)
		switch {
		case err == nil:
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, authz.ErrUnauthorized):
			writeControlRefusal(w, r, d, err)
		case isRevokeReasonError(err):
			writeProblem(w, http.StatusBadRequest, "invalid token id",
				"the token id cannot be rendered into a revocation reason: "+err.Error())
		case errors.Is(err, capability.ErrRevokeCascadeIncomplete):
			writeProblem(w, http.StatusInternalServerError, "token revoked, cascade incomplete",
				"the Enrollment Token was revoked, but the registry could not be read completely, "+
					"so Nodes enrolled under it may still be trusted; retry the revoke, and if it "+
					"fails again revoke the Nodes named in the Relay's log individually")
		case errors.Is(err, capability.ErrRevokeCascadeNotRecorded):
			writeProblem(w, http.StatusInternalServerError, "revoke not fully recorded",
				"the Enrollment Token and its Nodes were revoked, but one or more per-Node "+
					"revocation records could not be written; retrying will not restore them")
		default:
			writeProblem(w, http.StatusInternalServerError, "revoke enrollment token failed", "")
		}
	}
}

// isRevokeReasonError reports whether err is the capability layer's refusal of
// an unusable revocation reason.
func isRevokeReasonError(err error) bool {
	return errors.Is(err, capability.ErrRevokeReasonRequired) ||
		errors.Is(err, capability.ErrRevokeReasonTooLong) ||
		errors.Is(err, capability.ErrRevokeReasonMalformed)
}

// writeRevocationsUnavailable answers a revoke route when no Revocations is
// wired: loud and closed rather than quiet and open.
func writeRevocationsUnavailable(w http.ResponseWriter) {
	writeProblem(w, http.StatusInternalServerError, "revocation unavailable",
		"no revocation service is wired; refusing rather than proceeding ungated")
}
