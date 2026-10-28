package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
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
		CreatedAt:  controlplane.RFC3339(a.CreatedAt),
		LastSeenAt: controlplane.RFC3339(a.LastSeenAt),
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
		CreatedAt:  controlplane.RFC3339(t.CreatedAt),
		ExpiresAt:  controlplane.RFC3339(t.ExpiresAt),
		LastUsedAt: controlplane.RFC3339(t.LastUsedAt),
		RevokedAt:  controlplane.RFC3339(t.RevokedAt),
		Revoked:    t.Revoked(),
	}
}

type listAPITokensResponse struct {
	Tokens []apiTokenResponse `json:"tokens"`
}

// mintAPITokenRequest is the POST .../tokens body.
//
// TTLSeconds is a *pointer* so "absent" and "0" are distinguishable. Absent
// means the capability layer's default: seven days for a human Account, and a
// refusal for a machine Account. 0 is legitimate — it means a token that never
// expires, which is what a long-lived CI credential wants — but it must be
// *asked for*. A plain int64 would make a forgotten field silently mint an
// immortal credential.
type mintAPITokenRequest struct {
	Name       string `json:"name"`
	TTLSeconds *int64 `json:"ttl_seconds"`
}

// mintAPITokenResponse carries the plaintext credential in Token and again
// inside each HarnessSetup block that embeds it. This one response is the only
// place it ever appears. It is never persisted, logged, or audited; the audit
// record below stores the token's non-secret id.
type mintAPITokenResponse struct {
	APIToken     apiTokenResponse      `json:"api_token"`
	Token        string                `json:"token"`
	HarnessSetup *harnessSetupResponse `json:"harness_setup,omitempty"`
}

// harnessSetupResponse is the rendered Harness setup. Every field but the MCP
// URL and the CA certificate embeds the plaintext credential. Gleipnir is set
// for a machine Account only.
type harnessSetupResponse struct {
	MCPURL            string `json:"mcp_url"`
	CACertificate     string `json:"ca_certificate"`
	ClaudeCode        string `json:"claude_code"`
	ClaudeCodeMCPJSON string `json:"claude_code_mcp_json"`
	Gleipnir          string `json:"gleipnir,omitempty"`
	Check             string `json:"check"`
}

// LogValue keeps the credential-bearing blocks out of any log line.
func (harnessSetupResponse) LogValue() slog.Value { return slog.GroupValue() }

// maxAPITokenNameLen bounds the operator-facing label. Names are echoed into
// audit reasons and (later) the Console; an unbounded one lets a caller size
// an audit record.
const maxAPITokenNameLen = 128

// -----------------------------------------------------------------------
// Nil-seam guard
// -----------------------------------------------------------------------

// requireAccountAdmin resolves the acting Principal and refuses with a bare
// 500 if d.AccountAdmin is unwired — the same unwired-gate posture
// TestAdministrativeRoutes_RefuseWithoutAGate pins for the enrollment/
// revocation routes: an unwired administration surface must be loud and
// closed, never quietly ungated.
//
// This does NOT decide role. The floor — admin, in full — and the
// self-targeting and last-enabled-admin refusals all live inside the
// capability layer (capability.AccountAdmin.Accounts/CreateAccount/
// SetAccountRole/...), reached through d.AccountAdmin below; this surface
// renders whatever it answers and re-derives nothing
// (role_floor_test.go's TestCapabilityFlooredRoutesDoNotReachASurfaceGate
// pins that as a mechanical fact).
func requireAccountAdmin(w http.ResponseWriter, r *http.Request, d Deps) (capability.Principal, bool) {
	p, ok := principal(w, r)
	if !ok {
		return capability.Principal{}, false
	}
	if d.AccountAdmin == nil {
		writeProblem(w, http.StatusInternalServerError, "identity administration is not wired", "")
		return capability.Principal{}, false
	}
	return p, true
}

// requireAccountAdminAndID is requireAccountAdmin followed by pathID, the
// prelude of every route that names one Account or API Token: the caller is
// checked before the path is read.
func requireAccountAdminAndID(w http.ResponseWriter, r *http.Request, d Deps, param, label string) (capability.Principal, string, bool) {
	p, ok := requireAccountAdmin(w, r, d)
	if !ok {
		return capability.Principal{}, "", false
	}
	id, ok := pathID(w, r, param, label)
	if !ok {
		return capability.Principal{}, "", false
	}
	return p, id, true
}

// -----------------------------------------------------------------------
// Error mapping
// -----------------------------------------------------------------------

// writeAccountError maps a domain or capability-layer error onto an HTTP
// problem response. Unrecognized errors become a bare 500 with no detail: an
// unexpected failure must not spill store internals onto the wire.
//
// selfTargetVerb names the act being refused ("re-role", "disable") for the
// ErrSelfTargeted title, so the two callers that can actually produce it
// (handleSetAccountRole, handleSetAccountEnabled) render a specific title
// ("cannot re-role your own account" / "cannot disable your own account")
// rather than a generic one.
// Every other caller passes "" — they cannot reach this branch, since
// SetAccountRole/SetAccountEnabled are the only two capability methods that
// return ErrSelfTargeted — and "" would only ever render if that stopped
// being true, which is itself worth noticing.
func writeAccountError(w http.ResponseWriter, err error, title, selfTargetVerb string) {
	switch {
	case errors.Is(err, authz.ErrUnauthorized):
		writeProblem(w, http.StatusForbidden, "forbidden",
			"identity management requires the admin role")
	case errors.Is(err, capability.ErrSelfTargeted):
		verb := selfTargetVerb
		if verb == "" {
			verb = "target"
		}
		writeProblem(w, http.StatusConflict, "cannot "+verb+" your own account",
			"another admin must do this; a control plane whose last admin can switch itself off has no way back in")
	case errors.Is(err, accounts.ErrLastAdmin):
		writeProblem(w, http.StatusConflict, "the last enabled admin cannot be demoted or disabled",
			"another admin must exist before this account can be changed; a control plane with zero enabled admins has no way back in")
	case errors.Is(err, accounts.ErrRoleChanged):
		writeProblem(w, http.StatusConflict, "account changed concurrently",
			"the account's role changed while this request was applied; read it and retry")
	case errors.Is(err, accounts.ErrNotFound):
		writeProblem(w, http.StatusNotFound, "account not found", "")
	case errors.Is(err, accounts.ErrNameTaken):
		writeProblem(w, http.StatusConflict, "account name already in use",
			"names are unique so audit attribution is never ambiguous")
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
// Validation is not repeated here: accounts.Repository.Create (reached
// through the capability layer) is the single write path every surface
// funnels through and is where name/kind/role rules live. This handler's job
// is to pass the request through and map the resulting error onto a status
// code.
func handleCreateAccount(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := requireAccountAdmin(w, r, d)
		if !ok {
			return
		}

		var req createAccountRequest
		if !readJSONBody(w, r, &req) {
			return
		}

		created, err := d.AccountAdmin.CreateAccount(r.Context(), p, accounts.Account{
			Name:    req.Name,
			Kind:    accounts.Kind(req.Kind),
			Role:    accounts.Role(req.Role),
			Enabled: true,
		})
		if err != nil {
			writeAccountError(w, err, "create account failed", "")
			return
		}

		writeJSON(w, http.StatusCreated, renderAccount(created))
	}
}

// handleListAccounts implements GET /api/v1/accounts.
func handleListAccounts(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := requireAccountAdmin(w, r, d)
		if !ok {
			return
		}

		list, err := d.AccountAdmin.Accounts(r.Context(), p)
		if err != nil {
			writeAccountError(w, err, "list accounts failed", "")
			return
		}

		writeJSON(w, http.StatusOK, listAccountsResponse{Accounts: controlplane.MapSlice(list, renderAccount)})
	}
}

// handleGetAccount implements GET /api/v1/accounts/{id}.
func handleGetAccount(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, id, ok := requireAccountAdminAndID(w, r, d, "id", "account id")
		if !ok {
			return
		}

		acct, err := d.AccountAdmin.Account(r.Context(), p, id)
		if err != nil {
			writeAccountError(w, err, "get account failed", "")
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
		p, id, ok := requireAccountAdminAndID(w, r, d, "id", "account id")
		if !ok {
			return
		}

		var req setRoleRequest
		if !readJSONBody(w, r, &req) {
			return
		}

		if err := d.AccountAdmin.SetAccountRole(r.Context(), p, id, accounts.Role(req.Role)); err != nil {
			writeAccountError(w, err, "set account role failed", "re-role")
			return
		}

		writeUpdatedAccount(w, r, d, p, id)
	}
}

// handleSetAccountEnabled implements POST /api/v1/accounts/{id}/enable and
// .../disable — one handler, parameterized, so the two can never drift in how
// they authorize or render.
func handleSetAccountEnabled(d Deps, enabled bool) http.HandlerFunc {
	verb := "enable"
	if !enabled {
		verb = "disable"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p, id, ok := requireAccountAdminAndID(w, r, d, "id", "account id")
		if !ok {
			return
		}

		if err := d.AccountAdmin.SetAccountEnabled(r.Context(), p, id, enabled); err != nil {
			writeAccountError(w, err, verb+" account failed", verb)
			return
		}

		writeUpdatedAccount(w, r, d, p, id)
	}
}

// writeUpdatedAccount re-reads and renders an Account after a mutation, so the
// caller sees the stored state rather than an echo of what they asked for.
//
// The mutation has already succeeded and is already audited (by the
// capability layer) by the time this runs; a read-back failure therefore
// reports 200 with no body rather than an error status that would wrongly
// suggest the change did not happen.
func writeUpdatedAccount(w http.ResponseWriter, r *http.Request, d Deps, p capability.Principal, id string) {
	acct, err := d.AccountAdmin.Account(r.Context(), p, id)
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
//
// Request validation (decodeJSON, the ttl_seconds bounds, the name length)
// runs BEFORE the capability call, and so before AuthorizeControl inside it
// — see TestIdentityAPI_AuthorizationIsCheckedAfterRequestValidation. Every
// check here validates only the CALLER'S OWN INPUT and touches no store, so
// a caller refused at the floor learns nothing about any Account: they get
// exactly the same 400 a caller who would have been PERMITTED gets for the
// same malformed body.
func handleMintAPIToken(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, accountID, ok := requireAccountAdminAndID(w, r, d, "id", "account id")
		if !ok {
			return
		}

		var req mintAPITokenRequest
		if !readJSONBody(w, r, &req) {
			return
		}
		lifetime := capability.DefaultAPITokenLifetime()
		if req.TTLSeconds != nil {
			if *req.TTLSeconds < 0 || *req.TTLSeconds > maxTTLSeconds {
				writeProblem(w, http.StatusBadRequest, "invalid api token request",
					fmt.Sprintf("ttl_seconds must be >= 0 and <= %d", maxTTLSeconds))
				return
			}
			lifetime = capability.ExplicitAPITokenLifetime(time.Duration(*req.TTLSeconds) * time.Second)
		}
		if len(req.Name) > maxAPITokenNameLen {
			writeProblem(w, http.StatusBadRequest, "invalid api token request",
				fmt.Sprintf("name must be at most %d characters", maxAPITokenNameLen))
			return
		}

		tok, plaintext, err := d.AccountAdmin.MintAPIToken(r.Context(), p, accountID, req.Name, lifetime)
		if err != nil {
			switch {
			case errors.Is(err, authz.ErrUnauthorized):
				writeAccountError(w, err, "mint api token failed", "")
			case errors.Is(err, accounts.ErrNotFound):
				writeProblem(w, http.StatusNotFound, "account not found", "")
			case errors.Is(err, accounts.ErrInvalidTTL):
				writeProblem(w, http.StatusBadRequest, "invalid api token request", err.Error())
			case errors.Is(err, capability.ErrAPITokenTTLRequired):
				writeProblem(w, http.StatusBadRequest, "invalid api token request",
					"ttl_seconds is required for a machine Account's token; pass 0 for a token that never expires")
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

		// One of the two permitted Reveal() call sites (accounts.Plaintext's
		// own doc comment enumerates both): the mint response is the one
		// moment the plaintext is allowed to exist outside the minting call.
		credential := plaintext.Reveal()
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusCreated, mintAPITokenResponse{
			APIToken:     renderAPIToken(tok),
			Token:        credential,
			HarnessSetup: renderHarnessSetup(r, d, p, accountID, credential),
		})
	}
}

// renderHarnessSetup renders the Harness setup for a freshly minted credential,
// or nil when there is none to render. The Account's kind decides whether the
// Gleipnir block is included; a failed read leaves the kind empty, which drops
// that block and nothing else. A render error never fails the mint: the token
// is already minted and is returned either way.
func renderHarnessSetup(r *http.Request, d Deps, p capability.Principal, accountID, credential string) *harnessSetupResponse {
	var kind accounts.Kind
	if acct, err := d.AccountAdmin.Account(r.Context(), p, accountID); err == nil {
		kind = acct.Kind
	}
	rendering, err := d.HarnessSetup.Render(credential, kind)
	if err != nil {
		return nil
	}
	return &harnessSetupResponse{
		MCPURL:            rendering.MCPURL(),
		CACertificate:     rendering.CACertificate(),
		ClaudeCode:        rendering.ClaudeCode(),
		ClaudeCodeMCPJSON: rendering.ClaudeCodeMCPJSON(),
		Gleipnir:          rendering.Gleipnir(),
		Check:             rendering.Check(),
	}
}

// handleListAPITokens implements GET /api/v1/accounts/{id}/tokens, rendering
// the redacted view. This is the operator's honest window into token state —
// which tokens exist, which are revoked or expired, which are unused — the
// view that verification itself deliberately refuses to give a caller
// presenting a bad credential.
func handleListAPITokens(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, accountID, ok := requireAccountAdminAndID(w, r, d, "id", "account id")
		if !ok {
			return
		}

		list, err := d.AccountAdmin.APITokens(r.Context(), p, accountID)
		if err != nil {
			if errors.Is(err, authz.ErrUnauthorized) {
				writeAccountError(w, err, "list api tokens failed", "")
				return
			}
			writeProblem(w, http.StatusInternalServerError, "list api tokens failed", "")
			return
		}

		writeJSON(w, http.StatusOK, listAPITokensResponse{Tokens: controlplane.MapSlice(list, renderAPIToken)})
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
		p, id, ok := requireAccountAdminAndID(w, r, d, "token_id", "api token id")
		if !ok {
			return
		}

		if err := d.AccountAdmin.RevokeAPIToken(r.Context(), p, id); err != nil {
			switch {
			case errors.Is(err, authz.ErrUnauthorized):
				writeAccountError(w, err, "revoke api token failed", "")
			case errors.Is(err, accounts.ErrTokenNotFound):
				writeProblem(w, http.StatusNotFound, "api token not found", "")
			default:
				writeProblem(w, http.StatusInternalServerError, "revoke api token failed", "")
			}
			return
		}

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
