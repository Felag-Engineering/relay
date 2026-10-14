package mcp

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp/requeststate"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/logctx"
)

// elicit.go renders an askable park as an MRTR input-required
// CallToolResult — one elicitation/create form question — instead of the
// opaque `pending_approval` result (ADR-0029 decision 6; ADR-0028 as amended
// 2026-09-24).
//
// It is an EXEC file (no_dispatch_test.go's relaxed partition, tools_execution.go's
// header): it spells capability.Principal and capability.ParkedError, needed
// to read what the capability layer already decided, and nothing more.
//
// # What this file is not
//
// It NEVER records or accepts a decision. That is tools_approval.go's alone
// (ADR-0029 decision 5) — the ONE file in this package permitted to name a
// decision path. This file must therefore never name any of
// no_decision_test.go's forbiddenDecisionIdents (DecideApproval,
// ApprovalDecision, RecordDecision, ChannelInBand, ChannelOutOfBand) nor the
// literal "tasks/update": doing either would fail the build, by design.
//
// It also never sends elicitation/create itself. The question below travels
// as an ORDINARY tool result (InputRequests on a CallToolResult); the SDK's
// own client-side multi-round-trip middleware is what turns that into an
// elicitation/create round trip when the CLIENT supports it. A
// server-initiated elicitation/create — the SDK's fallback for a client that
// does NOT — is exactly what ADR-0029 rejected, and clientCanBeAsked below
// exists to keep that path from ever being reached (see its doc comment on
// why condition 2 must never be skipped).
const (
	// mrtrProtocolVersion mirrors the SDK's own unexported
	// protocolVersion20260728 — the version clientSupportsMultiRoundTrip
	// (go-sdk mcp/mrtr.go) compares against. The SDK does not export its
	// constant, so this package declares its own rather than importing an
	// internal one that does not exist.
	mrtrProtocolVersion = "2026-07-28"

	// metaKeyRequestID and metaKeyPlanHash are the question result's `_meta`
	// keys, named after approve_request's own argument names (tools_approval.go)
	// so the rescue path — approve_request, or POST
	// /api/v1/approvals/{id}/decision — is a mechanical copy rather than a
	// second vocabulary to learn.
	metaKeyRequestID = "relay/request_id"
	metaKeyPlanHash  = "relay/plan_hash"

	// clientNameGleipnir and clientNameClaudeCode are the declared client
	// names (io.modelcontextprotocol/clientInfo.name) Relay recognises for
	// AP-78: gleipnir is asked wherever the emission predicate otherwise
	// allows; claude-code is asked only on a session that authenticated by
	// OAuth with a human Account (clientCanBeAsked calls
	// tools_approval.go's oauthHumanSession to check that). The declared name
	// decides only whether to ask (AP-78). How an answer is accepted turns on
	// the session, never on the name (tools_approval.go, acceptElicitedAnswer).
	// These identifiers name an external consumer's wire value, exactly as
	// responderMetaKey already does, so they do not conflict with ADR-0016.
	clientNameGleipnir   = "gleipnir"
	clientNameClaudeCode = "claude-code"
)

// WithApprovalElicitation turns on the in-band MRTR question path for an
// askable park (ADR-0029 decision 6; ADR-0028 amendment 2026-09-24).
//
// Off by default, and effective only together with WithApprovalDecider: Relay
// never asks a question it cannot accept an answer to. The answer leg is
// tools_execution.go's answered retry (ADR-0029 decision 6), and the
// composition root (cmd/relay/control_surfaces.go) passes both options.
//
// The seal key this enables is minted inside mcp.New itself, from
// crypto/rand, never from an Option, a config key, a flag, an environment
// variable or a file (invariant 11 by construction).
func WithApprovalElicitation() Option {
	return func(o *serverOptions) { o.elicitApprovals = true }
}

// questioner renders an askable park as a question. It is process-lifetime:
// the Sealer it holds lives inside newQuestioner's one call to
// requeststate.Mint. A nil *questioner means "never ask" — the emission path
// is absent, not a disabled branch — and every method on it is nil-receiver
// safe for exactly that reason.
//
// The key itself lives only inside the Sealer's own closure (requeststate's
// own redaction, see that package's Sealer doc); nothing here ever holds it
// as a byte-shaped value.
type questioner struct {
	sealer *requeststate.Sealer
	log    *slog.Logger // nil means slog.Default() (logger)
}

func (q *questioner) logger() *slog.Logger { return logctx.Or(q.log) }

// newQuestioner mints a process-lifetime Sealer via requeststate.Mint —
// crypto/rand, never configuration. A Mint failure disables asking (fail
// closed: every park then renders today's pending_approval) rather than
// panicking or refusing to start over an operationally recoverable
// condition; only the fact that minting failed is logged, never key
// material.
func newQuestioner(log *slog.Logger) *questioner {
	sealer, err := requeststate.Mint()
	if err != nil {
		logctx.Or(log).Error("mcp: approval elicitation disabled: request-state key could not be minted", "error", err)
		return nil
	}
	return &questioner{sealer: sealer, log: log}
}

// stateOpener is the ONLY way a sealed request state is opened outside this
// file: a narrow, binding-checked capability over the questioner's Sealer.
// It runs requeststate's OpenFor — the seal check AND the binding to the
// caller, request, tool and argument digest, in one call — and nothing else.
// The unbound Open, Seal, and the Sealer itself are unreachable through it:
// the Sealer lives only in this closure, so tools_approval.go (the one file
// permitted to accept a decision) can verify an answer without ever holding
// or passing the key's custodian (TestElicit_SealKeyIsPerProcessAndNotConfiguration).
type stateOpener func(state string, now time.Time, call requeststate.Call) (requeststate.State, error)

// opener returns q's binding-checked stateOpener, or nil when q (or its
// sealer) is absent — "never ask" also means "never accept an answer", and
// the answer path refuses a nil opener rather than calling it. Nil-receiver
// safe, like every method on questioner.
func (q *questioner) opener() stateOpener {
	if q == nil || q.sealer == nil {
		return nil
	}
	sealer := q.sealer
	return func(state string, now time.Time, call requeststate.Call) (requeststate.State, error) {
		return sealer.OpenFor(state, now, call)
	}
}

// declaredClientName reads the client's declared name from meta's raw
// io.modelcontextprotocol/clientInfo entry — AP-78's input.
//
// It reads the RAW value rather than req.ClientInfo(): a wire request always
// decodes clientInfo into the map[string]any shape below, and only the exact
// lowercase key "name", asserted with .(string), counts — an object keyed
// "Name" is unrecognised, not merely differently cased, for the same
// case-insensitive-remarshal reason recognisedResponder documents
// (tools_approval.go). An in-process caller (this package's own tests) may
// instead place the typed *sdkmcp.Implementation or Implementation value
// directly in meta, which is also read. Anything else — clientInfo absent,
// nil, not a string-keyed name, or some other type — reports ("", false); no
// trimming and no case folding are applied either way.
func declaredClientName(meta sdkmcp.Meta) (string, bool) {
	v, present := meta[sdkmcp.MetaKeyClientInfo]
	if !present || v == nil {
		return "", false
	}
	switch info := v.(type) {
	case map[string]any:
		name, ok := info["name"].(string)
		return name, ok
	case *sdkmcp.Implementation:
		if info == nil {
			return "", false
		}
		return info.Name, true
	case sdkmcp.Implementation:
		return info.Name, true
	default:
		return "", false
	}
}

// clientCanBeAsked implements the emission predicate's conditions 2 (the
// SDK's own MRTR judgment), 3 (the per-request `_meta` agrees) and 5 (the
// declared client name is recognised for THIS session, AP-78) — conditions 1
// (a questioner is wired) and 4 (the park is Askable) are the caller's,
// question below. It also gates the answered retry (isAnsweredRetry,
// tools_execution.go): a client that cannot be asked never has its retry
// fields — requestState, inputResponses — read at all, so an unrecognised
// name's (or an ineligible session's) stray answer fields are ignored exactly
// as AP-70 already ignores them for any other client that cannot be asked.
//
// p is the authenticated caller: gleipnir is asked on any session, but
// claude-code is asked only where oauthHumanSession (tools_approval.go)
// reports the session authenticated by OAuth with a human Account — checked
// here, never inferred from anything about the request itself, since the
// declared name is self-reported and only the session's own verified facts
// can be trusted to gate an ask that must be acceptable once answered
// (AP-61).
//
// A nil req or a nil req.Session/req.Params fails closed.
func clientCanBeAsked(req *sdkmcp.CallToolRequest, p capability.Principal) bool {
	if req == nil || req.Session == nil || req.Params == nil {
		return false
	}

	// Condition 2 — the SDK's own judgment of MRTR capability, read EXACTLY
	// as clientSupportsMultiRoundTrip reads it: the SESSION's initialize
	// params, never the per-request `_meta`. This must never be skipped or
	// merged with condition 3: a client can negotiate a legacy protocol
	// version at the session level (an old MCP-Protocol-Version header, or
	// none at all) while sending a modern-looking `_meta` on a single call —
	// that combination still yields a legacy SESSION, and the SDK's
	// unconditionally-installed serverMultiRoundTripMiddleware treats any
	// non-MRTR session by fulfilling an input-required result itself with a
	// SERVER-INITIATED elicitation/create, straight to the client — exactly
	// the pattern ADR-0029 rejected, on a stateless handler that cannot serve
	// it anyway. Trusting condition 3 alone would ask on precisely that path.
	pv := mrtrProtocolVersion
	if ip := req.Session.InitializeParams(); ip != nil {
		pv = ip.ProtocolVersion
	}
	if pv < mrtrProtocolVersion {
		return false
	}

	// Condition 3 — the per-request `_meta` must agree, and must do so on
	// its OWN say-so: ServerRequest.ProtocolVersion()/ClientCapabilities()
	// fall back to the session's InitializeParams when `_meta` omits the
	// protocol-version or clientCapabilities key, which would let an absent
	// `_meta` silently inherit a modern session's version or capabilities
	// rather than stating its own. That fallback is exactly right for the
	// SDK's own general-purpose accessors, but "the per-request _meta
	// agrees" is a narrower claim than "the accessor returns a modern
	// value" — so this checks the raw `_meta` map for BOTH keys' presence
	// before trusting either accessor's answer.
	meta := req.Params.GetMeta()
	if _, present := meta[sdkmcp.MetaKeyProtocolVersion]; !present {
		return false
	}
	if _, present := meta[sdkmcp.MetaKeyClientCapabilities]; !present {
		return false
	}
	if req.ProtocolVersion() < mrtrProtocolVersion {
		return false
	}

	caps := req.ClientCapabilities()
	if caps == nil || caps.Elicitation == nil {
		return false
	}
	// Form-capable: Form set, or neither Form nor URL set — the SDK's own
	// documented default ("If neither Form nor URL is set, the 'Form'
	// capability is assumed", ElicitationCapabilities). The question below is
	// always a form elicitation, so a client that advertises URL-only
	// elicitation is treated as unable to be asked rather than sent a prompt
	// it cannot render. This only narrows who gets asked.
	if caps.Elicitation.Form == nil && caps.Elicitation.URL != nil {
		return false
	}

	// Condition 5 (AP-78) — the declared client name, read from the SAME raw
	// `_meta` map condition 3 already reads, so the first call and a retry are
	// each judged by their OWN request's declared name. This narrows who gets
	// asked; it decides only whether to ask.
	name, ok := declaredClientName(meta)
	if !ok {
		return false
	}
	switch name {
	case clientNameGleipnir:
		return true
	case clientNameClaudeCode:
		return oauthHumanSession(p)
	default:
		return false
	}
}

// callArgsDigest digests the TYPED, re-marshalled tool input (runOperationInput
// or rawExecInput), per requeststate.DigestArgs' own guidance: the answer leg
// must digest the same typed value the same way, or every answer refuses at
// the binding check (fail closed, never a silent mismatch).
func callArgsDigest(in any) (requeststate.Digest, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return requeststate.Digest{}, fmt.Errorf("mcp: marshal call arguments for digest: %w", err)
	}
	return requeststate.DigestArgs(b)
}

// elicitRequestedSchema returns the consent-shaped, protocol-generic schema
// every question carries: an object with no properties. The client renders a
// plain confirm/decline against the message alone — never a vendor
// "elicitation-kind" hint, and never the approver's identity folded into the
// schema. Built fresh on every call rather than shared as a package-level
// value: the returned map is placed directly into a CallToolResult, and a
// package-level map would let one caller's mutation of it (however
// unlikely) leak into every other question rendered by this process.
func elicitRequestedSchema() map[string]any {
	return map[string]any{"type": "object", "properties": map[string]any{}}
}

// question renders parked as an input-required CallToolResult if and only if
// ALL of: q (and its sealer) is wired, parked is Askable, and req's client can
// be asked (clientCanBeAsked — MRTR-capable, elicitation-capable, and
// declaring a client name recognised for p's own session, AP-78). Any other
// outcome — including a sealing failure — returns (nil, false), telling the
// caller to fall back to rendering today's pending_approval.
//
// tool is the literal registered tool name (toolRunOperation/toolRawExec) and
// in is the handler's own typed input value, so the sealed tool/args-digest
// pair can never drift from what was actually called.
func (q *questioner) question(req *sdkmcp.CallToolRequest, p capability.Principal, parked *capability.ParkedError, tool string, in any) (*sdkmcp.CallToolResult, bool) {
	if q == nil || q.sealer == nil {
		return nil, false
	}
	if parked == nil || !parked.Askable {
		return nil, false
	}
	if !clientCanBeAsked(req, p) {
		return nil, false
	}

	digest, err := callArgsDigest(in)
	if err != nil {
		q.logger().Warn("mcp: approval elicitation: could not digest call arguments; rendering pending_approval instead",
			"request_id", parked.RequestID, "error", err)
		return nil, false
	}

	state, err := q.sealer.Seal(requeststate.State{
		AccountID:  p.AccountID,
		RequestID:  parked.RequestID,
		PlanHash:   parked.PlanHash,
		Tool:       tool,
		ArgsDigest: digest,
		ExpiresAt:  parked.ExpiresAt,
	})
	if err != nil {
		// Seal also enforces the 256-byte input-request-ID bound (it refuses a
		// RequestID over requeststate.MaxFieldBytes) and refuses an empty
		// AccountID — both render pending_approval here, fail closed, rather
		// than a question this package could not actually seal.
		q.logger().Warn("mcp: approval elicitation: could not seal request state; rendering pending_approval instead",
			"request_id", parked.RequestID, "error", err)
		return nil, false
	}

	// NO Content, NO StructuredContent, NO ElicitParams.Meta (no vendor
	// elicitation-kind hint): the SDK's typed handler wrapper suppresses
	// structured content whenever InputRequests is set and rejects a result
	// that carries both — see server.go's typed-handler result assembly.
	return &sdkmcp.CallToolResult{
		Meta: sdkmcp.Meta{
			metaKeyRequestID: parked.RequestID,
			metaKeyPlanHash:  parked.PlanHash,
		},
		InputRequests: sdkmcp.InputRequestMap{
			parked.RequestID: &sdkmcp.ElicitParams{
				Mode:            "form",
				Message:         parked.Summary,
				RequestedSchema: elicitRequestedSchema(),
			},
		},
		RequestState: state,
	}, true
}
