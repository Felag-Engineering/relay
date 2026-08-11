package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
)

// -----------------------------------------------------------------------
// Wire shapes
// -----------------------------------------------------------------------

// accountResponse is the rendered form of an Account. Every field here is
// non-secret by construction — an Account holds no credential material at all
// (that lives on its tokens, hashed), so there is nothing to redact.
type accountResponse struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Role       string `json:"role"`
	Enabled    bool   `json:"enabled"`
	CreatedAt  string `json:"created_at"`
	LastSeenAt string `json:"last_seen_at,omitempty"`
}

func renderAccount(a accounts.Account) accountResponse {
	return accountResponse{
		ID:         a.ID,
		Name:       a.Name,
		Kind:       string(a.Kind),
		Role:       string(a.Role),
		Enabled:    a.Enabled,
		CreatedAt:  rfc3339(a.CreatedAt),
		LastSeenAt: rfc3339(a.LastSeenAt),
	}
}

type createAccountRequest struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Role string `json:"role"`
}

type setRoleRequest struct {
	Role string `json:"role"`
}

type listAccountsResponse struct {
	Accounts []accountResponse `json:"accounts"`
}

// apiTokenResponse is the **redacted** view of a stored API Token: the stored
// form carries a SecretHash, and this shape deliberately has no field it could
// land in. Listing an Account's tokens must never hand back anything a caller
// could authenticate with, nor anything worth offline cracking.
type apiTokenResponse struct {
	ID         string `json:"id"`
	AccountID  string `json:"account_id"`
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	RevokedAt  string `json:"revoked_at,omitempty"`
	Revoked    bool   `json:"revoked"`
}

func renderAPIToken(t accounts.APIToken) apiTokenResponse {
	return apiTokenResponse{
		ID:         t.ID,
		AccountID:  t.AccountID,
		Name:       t.Name,
		CreatedAt:  rfc3339(t.CreatedAt),
		ExpiresAt:  rfc3339(t.ExpiresAt),
		LastUsedAt: rfc3339(t.LastUsedAt),
		RevokedAt:  rfc3339(t.RevokedAt),
		Revoked:    t.Revoked(),
	}
}

type listAPITokensResponse struct {
	Tokens []apiTokenResponse `json:"tokens"`
}

// mintAPITokenRequest is the POST .../tokens body.
//
// TTLSeconds is a *pointer* so "absent" and "0" are distinguishable. 0 is
// legitimate — it means a token that never expires, which is what a long-lived
// CI credential wants — but it must be *asked for*. A plain int64 would make a
// forgotten field silently mint an immortal credential; requiring the field
// turns that into a deliberate, auditable choice.
type mintAPITokenRequest struct {
	Name       string `json:"name"`
	TTLSeconds *int64 `json:"ttl_seconds"`
}

// mintAPITokenResponse carries the plaintext credential in Token — the only
// response in which it ever appears, and the only place in the codebase that
// calls Plaintext.Reveal(). It is never persisted, logged, or audited; the
// audit record below stores the token's non-secret id.
type mintAPITokenResponse struct {
	APIToken apiTokenResponse `json:"api_token"`
	Token    string           `json:"token"`
}

// maxAPITokenNameLen bounds the operator-facing label. Names are echoed into
// audit reasons and (later) the Console; an unbounded one lets a caller size
// an audit record.
const maxAPITokenNameLen = 128

// rfc3339 renders t, or "" for the zero time so an "never happened" timestamp
// is omitted from the response rather than rendered as year 1.
func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// -----------------------------------------------------------------------
// Authorization
// -----------------------------------------------------------------------

// requireAdmin resolves the acting Principal and refuses anyone below admin.
//
// Identity management is admin-only in full (#297): an operator who could mint
// themselves an admin Account, or re-role their own, would make every other
// role advisory. The comparison goes through accounts.Role.AtLeast rather than
// a string equality check, so it inherits that function's fail-closed
// behaviour in both directions — an unknown or corrupted role satisfies
// nothing.
//
// This is a surface-level gate, not a second authorization engine: it decides
// who may call the control plane's *administrative* endpoints, and it never
// touches execution, which stays with the capability layer's Authorizer
// (invariant 10) and, on the Node, with Policy.
func requireAdmin(w http.ResponseWriter, r *http.Request) (capability.Principal, bool) {
	p, ok := principal(w, r)
	if !ok {
		return capability.Principal{}, false
	}
	if !accounts.Role(p.Role).AtLeast(accounts.RoleAdmin) {
		writeProblem(w, http.StatusForbidden, "forbidden",
			"identity management requires the admin role")
		return capability.Principal{}, false
	}
	return p, true
}

// refuseSelfTarget blocks an Account from disabling or re-roling itself.
//
// A guard against lockout, not a security boundary: the last admin demoting or
// switching off their own Account leaves a control plane nobody can administer
// and no in-band way back. Any *other* admin can still do either — this only
// removes the one-keystroke path to locking yourself out. It is deliberately
// not applied to token revocation: revoking your own token is a normal,
// sometimes urgent act.
func refuseSelfTarget(w http.ResponseWriter, p capability.Principal, targetID, action string) bool {
	if p.AccountID == "" || p.AccountID != targetID {
		return false
	}
	writeProblem(w, http.StatusConflict, "cannot "+action+" your own account",
		"another admin must do this; a control plane whose last admin can switch itself off has no way back in")
	return true
}

// -----------------------------------------------------------------------
// Error mapping
// -----------------------------------------------------------------------

// writeAccountError maps a domain error from the Account store onto an HTTP
// problem response. Unrecognized errors become a bare 500 with no detail: an
// unexpected failure must not spill store internals onto the wire.
func writeAccountError(w http.ResponseWriter, err error, title string) {
	switch {
	case errors.Is(err, accounts.ErrNotFound):
		writeProblem(w, http.StatusNotFound, "account not found", "")
	case errors.Is(err, accounts.ErrNameTaken):
		writeProblem(w, http.StatusConflict, "account name already in use",
			"names are unique so audit attribution is never ambiguous")
	case errors.Is(err, accounts.ErrReservedName):
		writeProblem(w, http.StatusBadRequest, "reserved account name",
			"the founding admin is created by seeding, never through the API")
	case errors.Is(err, accounts.ErrInvalidName),
		errors.Is(err, accounts.ErrInvalidKind),
		errors.Is(err, accounts.ErrInvalidRole):
		writeProblem(w, http.StatusBadRequest, "invalid account", err.Error())
	default:
		writeProblem(w, http.StatusInternalServerError, title, "")
	}
}

// -----------------------------------------------------------------------
// Account handlers
// -----------------------------------------------------------------------

// handleCreateAccount implements POST /api/v1/accounts.
//
// Validation is not repeated here: accounts.Repository.Create is the single
// write path every surface funnels through and is where name/kind/role rules
// live. This handler's job is to pass the request through and map the domain
// error onto a status code.
func handleCreateAccount(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := requireAdmin(w, r)
		if !ok {
			return
		}

		var req createAccountRequest
		if err := decodeJSON(w, r, &req); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
			return
		}

		created, err := d.Accounts.Create(r.Context(), accounts.Account{
			Name:    req.Name,
			Kind:    accounts.Kind(req.Kind),
			Role:    accounts.Role(req.Role),
			Enabled: true,
		})
		if err != nil {
			writeAccountError(w, err, "create account failed")
			return
		}

		recordLifecycle(r.Context(), d, p, audit.KindAccountCreate, "",
			fmt.Sprintf("account_id=%s name=%s kind=%s role=%s",
				created.ID, created.Name, created.Kind, created.Role))

		writeJSON(w, http.StatusCreated, renderAccount(created))
	}
}

// handleListAccounts implements GET /api/v1/accounts.
func handleListAccounts(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdmin(w, r); !ok {
			return
		}

		list, err := d.Accounts.List(r.Context())
		if err != nil {
			writeAccountError(w, err, "list accounts failed")
			return
		}

		out := make([]accountResponse, 0, len(list))
		for _, a := range list {
			out = append(out, renderAccount(a))
		}
		writeJSON(w, http.StatusOK, listAccountsResponse{Accounts: out})
	}
}

// handleGetAccount implements GET /api/v1/accounts/{id}.
func handleGetAccount(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdmin(w, r); !ok {
			return
		}
		id, ok := pathID(w, r, "id", "account id")
		if !ok {
			return
		}

		acct, err := d.Accounts.Get(r.Context(), id)
		if err != nil {
			writeAccountError(w, err, "get account failed")
			return
		}
		writeJSON(w, http.StatusOK, renderAccount(acct))
	}
}

// handleSetAccountRole implements POST /api/v1/accounts/{id}/role.
//
// A separate endpoint rather than a partial update of the Account: a role
// change is the single most security-relevant edit on this surface, and giving
// it its own route means it has its own audit kind and cannot be smuggled in
// beside an innocuous field.
func handleSetAccountRole(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := requireAdmin(w, r)
		if !ok {
			return
		}
		id, ok := pathID(w, r, "id", "account id")
		if !ok {
			return
		}
		if refuseSelfTarget(w, p, id, "re-role") {
			return
		}

		var req setRoleRequest
		if err := decodeJSON(w, r, &req); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
			return
		}

		if err := d.Accounts.SetRole(r.Context(), id, accounts.Role(req.Role)); err != nil {
			writeAccountError(w, err, "set account role failed")
			return
		}

		recordLifecycle(r.Context(), d, p, audit.KindAccountRole, "",
			fmt.Sprintf("account_id=%s role=%s", id, req.Role))

		writeUpdatedAccount(w, r, d, id)
	}
}

// handleSetAccountEnabled implements POST /api/v1/accounts/{id}/enable and
// .../disable — one handler, parameterized, so the two can never drift in how
// they authorize, audit, or render.
func handleSetAccountEnabled(d Deps, enabled bool) http.HandlerFunc {
	kind, verb := audit.KindAccountEnable, "enable"
	if !enabled {
		kind, verb = audit.KindAccountDisable, "disable"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := requireAdmin(w, r)
		if !ok {
			return
		}
		id, ok := pathID(w, r, "id", "account id")
		if !ok {
			return
		}
		if !enabled && refuseSelfTarget(w, p, id, "disable") {
			return
		}

		if err := d.Accounts.SetEnabled(r.Context(), id, enabled); err != nil {
			writeAccountError(w, err, verb+" account failed")
			return
		}

		recordLifecycle(r.Context(), d, p, kind, "", "account_id="+id)

		writeUpdatedAccount(w, r, d, id)
	}
}

// writeUpdatedAccount re-reads and renders an Account after a mutation, so the
// caller sees the stored state rather than an echo of what they asked for.
//
// The mutation has already succeeded and is already audited by the time this
// runs; a read-back failure therefore reports 200 with no body rather than an
// error status that would wrongly suggest the change did not happen.
func writeUpdatedAccount(w http.ResponseWriter, r *http.Request, d Deps, id string) {
	acct, err := d.Accounts.Get(r.Context(), id)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSON(w, http.StatusOK, renderAccount(acct))
}

// -----------------------------------------------------------------------
// API Token handlers
// -----------------------------------------------------------------------

// handleMintAPIToken implements POST /api/v1/accounts/{id}/tokens: mint a
// credential for an Account and return its plaintext exactly once (201).
func handleMintAPIToken(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := requireAdmin(w, r)
		if !ok {
			return
		}
		accountID, ok := pathID(w, r, "id", "account id")
		if !ok {
			return
		}

		var req mintAPITokenRequest
		if err := decodeJSON(w, r, &req); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
			return
		}
		if req.TTLSeconds == nil {
			writeProblem(w, http.StatusBadRequest, "invalid api token request",
				"ttl_seconds is required; pass 0 for a token that never expires")
			return
		}
		if *req.TTLSeconds < 0 || *req.TTLSeconds > maxTTLSeconds {
			writeProblem(w, http.StatusBadRequest, "invalid api token request",
				fmt.Sprintf("ttl_seconds must be >= 0 and <= %d", maxTTLSeconds))
			return
		}
		if len(req.Name) > maxAPITokenNameLen {
			writeProblem(w, http.StatusBadRequest, "invalid api token request",
				fmt.Sprintf("name must be at most %d characters", maxAPITokenNameLen))
			return
		}

		tok, plaintext, err := d.APITokens.Mint(r.Context(), accountID, req.Name,
			time.Duration(*req.TTLSeconds)*time.Second)
		if err != nil {
			switch {
			case errors.Is(err, accounts.ErrNotFound):
				writeProblem(w, http.StatusNotFound, "account not found", "")
			case errors.Is(err, accounts.ErrInvalidTTL):
				writeProblem(w, http.StatusBadRequest, "invalid api token request", err.Error())
			case accounts.IsInvalidToken(err):
				// Minting for a disabled Account. Safe to state plainly: the
				// caller is an authenticated admin who can list Accounts and
				// read that state directly — it is not an unauthenticated
				// oracle.
				writeProblem(w, http.StatusConflict, "account is disabled",
					"enable the account before minting a credential for it")
			default:
				writeProblem(w, http.StatusInternalServerError, "mint api token failed", "")
			}
			return
		}

		recordLifecycle(r.Context(), d, p, audit.KindAPITokenMint, "",
			fmt.Sprintf("account_id=%s api_token_id=%s", accountID, tok.ID))

		// The single Reveal() in the codebase: the mint response is the one
		// moment the plaintext is allowed to exist outside the minting call.
		writeJSON(w, http.StatusCreated, mintAPITokenResponse{
			APIToken: renderAPIToken(tok),
			Token:    plaintext.Reveal(),
		})
	}
}

// handleListAPITokens implements GET /api/v1/accounts/{id}/tokens, rendering
// the redacted view. This is the operator's honest window into token state —
// which tokens exist, which are revoked or expired, which are unused — the
// view that verification itself deliberately refuses to give a caller
// presenting a bad credential.
func handleListAPITokens(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdmin(w, r); !ok {
			return
		}
		accountID, ok := pathID(w, r, "id", "account id")
		if !ok {
			return
		}

		list, err := d.APITokens.List(r.Context(), accountID)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "list api tokens failed", "")
			return
		}

		out := make([]apiTokenResponse, 0, len(list))
		for _, t := range list {
			out = append(out, renderAPIToken(t))
		}
		writeJSON(w, http.StatusOK, listAPITokensResponse{Tokens: out})
	}
}

// handleRevokeAPIToken implements DELETE /api/v1/api-tokens/{token_id}.
//
// Revoking an already-revoked token returns 204 (the end state is what was
// asserted, and an operator racing themselves mid-incident should not see a
// failure); an unknown id returns 404, because that is a typo they need to
// hear about while they still believe they revoked something.
func handleRevokeAPIToken(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := requireAdmin(w, r)
		if !ok {
			return
		}
		id, ok := pathID(w, r, "token_id", "api token id")
		if !ok {
			return
		}

		if err := d.APITokens.Revoke(r.Context(), id); err != nil {
			if errors.Is(err, accounts.ErrTokenNotFound) {
				writeProblem(w, http.StatusNotFound, "api token not found", "")
				return
			}
			writeProblem(w, http.StatusInternalServerError, "revoke api token failed", "")
			return
		}

		recordLifecycle(r.Context(), d, p, audit.KindAPITokenRevoke, "", "api_token_id="+id)
		w.WriteHeader(http.StatusNoContent)
	}
}

// pathID reads a required path parameter, rendering a 400 when it is empty.
func pathID(w http.ResponseWriter, r *http.Request, param, label string) (string, bool) {
	v := r.PathValue(param)
	if v == "" {
		writeProblem(w, http.StatusBadRequest, "missing "+label,
			"path parameter "+param+" must not be empty")
		return "", false
	}
	return v, true
}
