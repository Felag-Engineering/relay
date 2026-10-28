package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp/requeststate"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// tools_approval_test.go is #726's proof: acceptElicitedAnswer and
// classifyElicitedDecision (both unexported — hence package mcp, not
// mcp_test) are tested at the handler seam, exactly the way approve_request
// is: real fixtures, a real requeststate.Sealer, and a decider double that
// records exactly what it was handed.
//
// Nothing here wires acceptElicitedAnswer into a tool handler — every test
// calls it directly. See tools_execution_retry_test.go for that wiring
// (#727, S4a-2): run_operation and raw_exec's answered-retry path.

// -----------------------------------------------------------------------
// Fixtures shared by every test below
// -----------------------------------------------------------------------

var fixedNow = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

const (
	answerTool       = "run_operation"
	answerRequestID  = "apr-1"
	answerPlanHash   = "hash-1"
	answerAccountID  = "acct-caller"
	answerCallerCred = accounts.TokenPrefix + "0123456789abcdef.tools-approval-test" // test fixture, not a real credential
)

// answerArgsJSON is the canonical arguments the answer-path fixtures seal
// and digest — a run_operation call's arguments, operation service.restart
// against unit=nginx.
const answerArgsJSON = `{"operation":"service.restart","args":{"unit":"nginx"}}`

// digestOf digests raw with requeststate.DigestArgs, failing the test on a
// malformed fixture.
func digestOf(t *testing.T, raw string) requeststate.Digest {
	t.Helper()
	d, err := requeststate.DigestArgs([]byte(raw))
	if err != nil {
		t.Fatalf("DigestArgs(%s): %v", raw, err)
	}
	return d
}

// mustCallArgsDigest is elicit.go's production callArgsDigest — the one
// digest source emission seals with (#727) — failing the test on an error.
// It is not a copy: the tests pin the production pairing.
func mustCallArgsDigest(t *testing.T, in any) requeststate.Digest {
	t.Helper()
	d, err := callArgsDigest(in)
	if err != nil {
		t.Fatalf("callArgsDigest(%#v): %v", in, err)
	}
	return d
}

// openerOf builds the answer path's binding-checked stateOpener from a test
// Sealer through the SAME constructor production uses (questioner.opener in
// elicit.go), so the tests drive exactly the capability tools_approval.go is
// handed and never a hand-rolled one. A nil sealer yields a nil opener.
func openerOf(sealer *requeststate.Sealer) stateOpener {
	return (&questioner{sealer: sealer}).opener()
}

// sealState returns the baseline requeststate.State the answer-path tests
// share, sealed for accountID: RequestID answerRequestID, Tool answerTool,
// the canonical digest of answerArgsJSON, PlanHash answerPlanHash, expiring
// an hour after fixedNow. Callers mutate a copy to test a specific mismatch.
func sealState(t *testing.T, accountID string) requeststate.State {
	t.Helper()
	return requeststate.State{
		AccountID:  accountID,
		RequestID:  answerRequestID,
		PlanHash:   answerPlanHash,
		Tool:       answerTool,
		ArgsDigest: digestOf(t, answerArgsJSON),
		ExpiresAt:  fixedNow.Add(time.Hour),
	}
}

// sealWith seals base (or base mutated by fn, when fn is non-nil) under
// sealer, failing the test on a Seal error.
func sealWith(t *testing.T, sealer *requeststate.Sealer, base requeststate.State, fn func(*requeststate.State)) string {
	t.Helper()
	st := base
	if fn != nil {
		fn(&st)
	}
	out, err := sealer.Seal(st)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return out
}

// flipMiddleChar flips a single character in the middle of s, so the result
// still decodes structurally (it is not the LAST character, whose
// strict-base64 trailing bits would instead yield ErrMalformed) but fails
// the MAC comparison — ErrTampered, not ErrMalformed.
func flipMiddleChar(s string) string {
	b := []byte(s)
	i := len(b) / 2
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

// elicit builds a single-entry InputResponseMap keyed by the sealed request
// ID, holding one ElicitResult.
func elicit(action string, meta sdkmcp.Meta) sdkmcp.InputResponseMap {
	return sdkmcp.InputResponseMap{
		answerRequestID: &sdkmcp.ElicitResult{Action: action, Meta: meta},
	}
}

// permissionResponder is a recognised io.gleipnir/responder assertion
// naming username with gate "permission".
func permissionResponder(username string) sdkmcp.Meta {
	return sdkmcp.Meta{
		responderMetaKey: map[string]any{"gate": responderGatePermission, "username": username},
	}
}

// recordedDecision is one call a recordingDecider captured.
type recordedDecision struct {
	Principal  capability.Principal
	Decision   capability.ApprovalDecision
	Assertions capability.Assertions
}

// recordingDecider is an ApprovalDecider that records every call it
// receives — including the context's asserted attribution — and returns a
// scripted (approval.Request, error) pair. Mutex-guarded because
// approve_request's tool handler runs on the SDK server's own goroutine,
// never the test goroutine.
type recordingDecider struct {
	mu   sync.Mutex
	got  []recordedDecision
	resp approval.Request
	err  error
}

func (d *recordingDecider) DecideApproval(ctx context.Context, p capability.Principal, in capability.ApprovalDecision) (approval.Request, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.got = append(d.got, recordedDecision{Principal: p, Decision: in, Assertions: capability.AssertionsFromContext(ctx)})
	return d.resp, d.err
}

func (d *recordingDecider) calls() []recordedDecision {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]recordedDecision, len(d.got))
	copy(out, d.got)
	return out
}

// scriptedDecider is a stateless ApprovalDecider that always returns the
// same (approval.Request, error) pair — the fixture
// TestElicitedAnswer_ClassifiesEveryOutcome needs, where only the SCRIPTED
// RETURN varies from row to row.
type scriptedDecider struct {
	resp approval.Request
	err  error
}

func (d scriptedDecider) DecideApproval(context.Context, capability.Principal, capability.ApprovalDecision) (approval.Request, error) {
	return d.resp, d.err
}

// answerTestVerifier authenticates exactly one credential, as the human
// operator the answer-path tests act as.
type answerTestVerifier struct{}

func (answerTestVerifier) Verify(_ context.Context, credential string) (accounts.Account, accounts.APIToken, error) {
	if credential != answerCallerCred {
		return accounts.Account{}, accounts.APIToken{}, accounts.ErrTokenInvalid
	}
	return accounts.Account{
		ID: answerAccountID, Name: "caller", Role: accounts.RoleOperator, Kind: accounts.KindHuman, Enabled: true,
	}, accounts.APIToken{ID: "tok-caller"}, nil
}

// approveRequestServer mounts the real MCP handler — with decider wired via
// WithApprovalDecider — at /mcp behind the real Authenticator.Middleware,
// served over plain HTTP by httptest (mirrors golden_test.go's
// goldenServer; that file is package mcp_test, so the verifier is
// redeclared here rather than shared).
func approveRequestServer(t *testing.T, decider ApprovalDecider) *httptest.Server {
	t.Helper()
	handler := New(nil, stubOpsLister{}, noopExecutor{}, nil, nil, WithApprovalDecider(decider))
	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	srv := httptest.NewServer(controlplane.NewAuthenticator(answerTestVerifier{}).Middleware(mux))
	t.Cleanup(srv.Close)
	return srv
}

// answerClient is an authenticated *http.Client against approveRequestServer.
func answerClient() *http.Client {
	return &http.Client{Transport: relaytest.BearerRoundTripper{Base: http.DefaultTransport, Token: answerCallerCred}}
}

// callApproveRequest calls approve_request through a real server wired to
// decider, with the given approver.
func callApproveRequest(t *testing.T, decider ApprovalDecider, approver string) *sdkmcp.CallToolResult {
	t.Helper()
	srv := approveRequestServer(t, decider)
	session := relaytest.Connect(t, srv.URL, answerClient())
	return relaytest.CallTool(t, session, "approve_request", map[string]any{
		"request_id": answerRequestID,
		"plan_hash":  answerPlanHash,
		"approve":    true,
		"approver":   approver,
	})
}

// capturedPrincipal drives one approve_request call through the real server
// and returns the Principal the decider actually saw — exactly what
// production authentication produces, rather than a hand-built value that
// could quietly drift from it.
func capturedPrincipal(t *testing.T) capability.Principal {
	t.Helper()
	rec := &recordingDecider{resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash}}
	res := callApproveRequest(t, rec, "capture-principal")
	if res.IsError {
		t.Fatalf("approve_request (capturing the principal): IsError, content=%+v", res.Content)
	}
	calls := rec.calls()
	if len(calls) != 1 {
		t.Fatalf("recordingDecider recorded %d calls capturing the principal, want 1", len(calls))
	}
	return calls[0].Principal
}

// oauthHumanPrincipal is capturedPrincipal with the session shape AP-79
// admits for the verified form, whatever the client name: an OAuth session
// of a human Account. It keeps the real AccountID capturedPrincipal captured
// (so sealing still works exactly as it does for every other answer-path
// test) and only overrides the two fields oauthHumanSession reads.
func oauthHumanPrincipal(t *testing.T) capability.Principal {
	t.Helper()
	return principalAs(capturedPrincipal(t), capability.AuthMethodOAuth, capability.PrincipalKindHuman)
}

// principalAs returns p with AuthMethod and kind overridden — the negative
// rows' way of asking "what if the SAME Account had authenticated some other
// way", without hand-building a Principal that could drift from a real one.
func principalAs(p capability.Principal, method capability.AuthMethod, kind string) capability.Principal {
	p.AuthMethod = method
	p.Kind = kind
	return p
}

// machineSelfDecisionErrorText fetches approve_request's exact no-approver
// message through the real server, so AP-64's "identical message" claim is
// checked against the live text rather than a copy that could drift from it.
func machineSelfDecisionErrorText(t *testing.T) string {
	t.Helper()
	res := callApproveRequest(t, &recordingDecider{}, "")
	return relaytest.ToolErrorText(t, res)
}

// -----------------------------------------------------------------------
// AP-63: an accepted answer records the same Decision approve_request would
// -----------------------------------------------------------------------

func TestElicitedAnswer_RecordsTheSameDecisionAsApproveRequest(t *testing.T) {
	// capability.Approvals.DecideApproval builds a Decision solely from
	// (Principal, ApprovalDecision, the context's asserted attribution) —
	// see internal/capability/approval_decide.go — so identical inputs
	// produce the identical Decision. This test proves the INPUTS are
	// identical; the audit-trail proof itself is S5's (#730).
	recA := &recordingDecider{resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash}}
	res := callApproveRequest(t, recA, "alice")
	if res.IsError {
		t.Fatalf("approve_request: IsError, content=%+v", res.Content)
	}
	callsA := recA.calls()
	if len(callsA) != 1 {
		t.Fatalf("recordingDecider A recorded %d calls, want 1", len(callsA))
	}
	principal := callsA[0].Principal

	sealer, err := requeststate.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	base := sealState(t, principal.AccountID)
	sealed := sealWith(t, sealer, base, nil)

	recB := &recordingDecider{resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash}}
	ctx := capability.WithAssertions(context.Background(), capability.Assertions{Traceparent: "tp-1", SessionRef: "sess-1"})
	result := acceptElicitedAnswer(ctx, recB, openerOf(sealer), fixedNow, principal, elicitedAnswer{
		RequestState:   sealed,
		InputResponses: elicit("accept", permissionResponder("alice")),
		Tool:           answerTool,
		ArgsDigest:     base.ArgsDigest,
	})
	if result.Err != nil {
		t.Fatalf("acceptElicitedAnswer: Err = %v, want nil", result.Err)
	}
	callsB := recB.calls()
	if len(callsB) != 1 {
		t.Fatalf("recordingDecider B recorded %d calls, want 1", len(callsB))
	}

	if !reflect.DeepEqual(callsA[0].Principal, callsB[0].Principal) {
		t.Errorf("Principal differs:\n A = %+v\n B = %+v", callsA[0].Principal, callsB[0].Principal)
	}
	if !reflect.DeepEqual(callsA[0].Decision, callsB[0].Decision) {
		t.Errorf("ApprovalDecision differs:\n A = %+v\n B = %+v", callsA[0].Decision, callsB[0].Decision)
	}
	if callsA[0].Assertions.OnBehalfOf != "alice" || callsB[0].Assertions.OnBehalfOf != "alice" {
		t.Errorf("OnBehalfOf = %q / %q, want alice/alice", callsA[0].Assertions.OnBehalfOf, callsB[0].Assertions.OnBehalfOf)
	}
	// "alice" must appear in the asserted lane only, never in the Principal.
	if strings.Contains(fmt.Sprintf("%+v", callsB[0].Principal), "alice") {
		t.Errorf("the asserted approver leaked into the verified Principal: %+v", callsB[0].Principal)
	}
	// A traceparent and session_ref already on the helper's ctx survive
	// withAssertedApprover's rewrite of OnBehalfOf.
	if callsB[0].Assertions.Traceparent != "tp-1" || callsB[0].Assertions.SessionRef != "sess-1" {
		t.Errorf("Assertions = %+v, want Traceparent \"tp-1\" and SessionRef \"sess-1\" preserved", callsB[0].Assertions)
	}
}

func TestElicitedAnswer_DeclineRecordsADenial(t *testing.T) {
	p := capturedPrincipal(t)
	sealer, err := requeststate.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	base := sealState(t, p.AccountID)
	sealed := sealWith(t, sealer, base, nil)

	rec := &recordingDecider{resp: approval.Request{ID: answerRequestID, State: approval.StateDenied, PlanHash: answerPlanHash}}
	result := acceptElicitedAnswer(context.Background(), rec, openerOf(sealer), fixedNow, p, elicitedAnswer{
		RequestState:   sealed,
		InputResponses: elicit("decline", permissionResponder("bob")),
		Tool:           answerTool,
		ArgsDigest:     base.ArgsDigest,
	})
	if result.Err != nil {
		t.Fatalf("Err = %v, want nil", result.Err)
	}
	if result.Outcome != elicitedDenied {
		t.Errorf("Outcome = %v, want elicitedDenied", result.Outcome)
	}
	calls := rec.calls()
	if len(calls) != 1 {
		t.Fatalf("decider called %d times, want 1", len(calls))
	}
	if calls[0].Decision.Approve {
		t.Error("Decision.Approve = true, want false (this was a decline)")
	}
	if calls[0].Decision.Channel != approval.ChannelInBand {
		t.Errorf("Decision.Channel = %v, want ChannelInBand", calls[0].Decision.Channel)
	}
	if calls[0].Assertions.OnBehalfOf != "bob" {
		t.Errorf("OnBehalfOf = %q, want bob", calls[0].Assertions.OnBehalfOf)
	}
}

// -----------------------------------------------------------------------
// AP-65: an unbound, tampered or stale state is refused; nothing recorded
// -----------------------------------------------------------------------

func TestElicitedAnswer_RefusesAnUnboundOrTamperedState(t *testing.T) {
	p := capturedPrincipal(t)
	sealer, err := requeststate.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	otherSealer, err := requeststate.Mint()
	if err != nil {
		t.Fatalf("Mint (other): %v", err)
	}
	base := sealState(t, p.AccountID)

	otherArgsDigest := digestOf(t, `{"operation":"service.restart","args":{"unit":"php-fpm"}}`)
	reorderedDigest := digestOf(t, `{ "args": { "unit": "nginx" }, "operation": "service.restart" }`)
	if reorderedDigest != base.ArgsDigest {
		t.Fatal("reordered/whitespace-changed JSON did not digest identically to the baseline — the positive control below is broken")
	}

	cases := []struct {
		name         string
		build        func(t *testing.T) (state string, sealer *requeststate.Sealer, tool string, digest requeststate.Digest, now time.Time)
		wantSentinel error
		wantAccepted bool
	}{
		{
			name: "tampered: a byte flipped in the middle of the encoded state",
			build: func(t *testing.T) (string, *requeststate.Sealer, string, requeststate.Digest, time.Time) {
				return flipMiddleChar(sealWith(t, sealer, base, nil)), sealer, answerTool, base.ArgsDigest, fixedNow
			},
			wantSentinel: requeststate.ErrTampered,
		},
		{
			name: "sealed under a different Sealer",
			build: func(t *testing.T) (string, *requeststate.Sealer, string, requeststate.Digest, time.Time) {
				return sealWith(t, otherSealer, base, nil), sealer, answerTool, base.ArgsDigest, fixedNow
			},
			wantSentinel: requeststate.ErrTampered,
		},
		{
			name: "validly sealed for a different request",
			build: func(t *testing.T) (string, *requeststate.Sealer, string, requeststate.Digest, time.Time) {
				st := sealWith(t, sealer, base, func(s *requeststate.State) { s.RequestID = "apr-2" })
				return st, sealer, answerTool, base.ArgsDigest, fixedNow
			},
			wantSentinel: requeststate.ErrBindingMismatch,
		},
		{
			name: "sealed for another Account, response keyed by its own sealed request id",
			build: func(t *testing.T) (string, *requeststate.Sealer, string, requeststate.Digest, time.Time) {
				st := sealWith(t, sealer, base, func(s *requeststate.State) { s.AccountID = "acct-other" })
				return st, sealer, answerTool, base.ArgsDigest, fixedNow
			},
			wantSentinel: requeststate.ErrBindingMismatch,
		},
		{
			name: "sealed for another tool",
			build: func(t *testing.T) (string, *requeststate.Sealer, string, requeststate.Digest, time.Time) {
				st := sealWith(t, sealer, base, func(s *requeststate.State) { s.Tool = "raw_exec" })
				return st, sealer, answerTool, base.ArgsDigest, fixedNow
			},
			wantSentinel: requeststate.ErrBindingMismatch,
		},
		{
			name: "sealed for other arguments",
			build: func(t *testing.T) (string, *requeststate.Sealer, string, requeststate.Digest, time.Time) {
				st := sealWith(t, sealer, base, func(s *requeststate.State) { s.ArgsDigest = otherArgsDigest })
				return st, sealer, answerTool, base.ArgsDigest, fixedNow
			},
			wantSentinel: requeststate.ErrBindingMismatch,
		},
		{
			name: "past its expiry",
			build: func(t *testing.T) (string, *requeststate.Sealer, string, requeststate.Digest, time.Time) {
				return sealWith(t, sealer, base, nil), sealer, answerTool, base.ArgsDigest, base.ExpiresAt.Add(time.Second)
			},
			wantSentinel: requeststate.ErrExpired,
		},
		{
			name: "an empty state",
			build: func(t *testing.T) (string, *requeststate.Sealer, string, requeststate.Digest, time.Time) {
				return "", sealer, answerTool, base.ArgsDigest, fixedNow
			},
			wantSentinel: requeststate.ErrUnknownVersion,
		},
		{
			name: "a nil sealer (no opener)",
			build: func(t *testing.T) (string, *requeststate.Sealer, string, requeststate.Digest, time.Time) {
				return sealWith(t, sealer, base, nil), nil, answerTool, base.ArgsDigest, fixedNow
			},
			wantSentinel: requeststate.ErrInvalidKey,
		},
		{
			name: "a zero ArgsDigest",
			build: func(t *testing.T) (string, *requeststate.Sealer, string, requeststate.Digest, time.Time) {
				return sealWith(t, sealer, base, nil), sealer, answerTool, requeststate.Digest{}, fixedNow
			},
			// No requeststate sentinel: refused before OpenFor is even called.
		},
		{
			name: "positive control: reordered, whitespace-changed arguments digest identically",
			build: func(t *testing.T) (string, *requeststate.Sealer, string, requeststate.Digest, time.Time) {
				return sealWith(t, sealer, base, nil), sealer, answerTool, reorderedDigest, fixedNow
			},
			wantAccepted: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, useSealer, tool, digest, now := tc.build(t)
			rec := &recordingDecider{resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash}}
			result := acceptElicitedAnswer(context.Background(), rec, openerOf(useSealer), now, p, elicitedAnswer{
				RequestState:   state,
				InputResponses: elicit("accept", permissionResponder("alice")),
				Tool:           tool,
				ArgsDigest:     digest,
			})

			if tc.wantAccepted {
				if result.Err != nil {
					t.Fatalf("Err = %v, want nil (positive control)", result.Err)
				}
				if calls := rec.calls(); len(calls) != 1 {
					t.Fatalf("decider called %d times, want 1 (positive control)", len(calls))
				}
				return
			}

			if result.Outcome != elicitedRefused {
				t.Errorf("Outcome = %v, want elicitedRefused", result.Outcome)
			}
			if !errors.Is(result.Err, errAnswerStateRefused) {
				t.Errorf("Err = %v, want errors.Is(_, errAnswerStateRefused)", result.Err)
			}
			if tc.wantSentinel != nil && !errors.Is(result.Err, tc.wantSentinel) {
				t.Errorf("Err = %v, want errors.Is(_, %v)", result.Err, tc.wantSentinel)
			}
			if calls := rec.calls(); len(calls) != 0 {
				t.Errorf("decider called %d times, want 0", len(calls))
			}
		})
	}
}

func TestElicitedAnswer_RequiresExactlyOneResponseForTheSealedRequest(t *testing.T) {
	p := capturedPrincipal(t)
	sealer, err := requeststate.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	base := sealState(t, p.AccountID)
	sealed := sealWith(t, sealer, base, nil)

	cases := []struct {
		name        string
		responses   sdkmcp.InputResponseMap
		wantWrapped error // nil for a plain errAnswerShape row
	}{
		{name: "nil map", responses: nil},
		{name: "empty map", responses: sdkmcp.InputResponseMap{}},
		{
			name: "two entries",
			responses: sdkmcp.InputResponseMap{
				answerRequestID: &sdkmcp.ElicitResult{Action: "accept", Meta: permissionResponder("alice")},
				"apr-other":     &sdkmcp.ElicitResult{Action: "accept", Meta: permissionResponder("alice")},
			},
		},
		{
			name: "one entry keyed apr-other",
			responses: sdkmcp.InputResponseMap{
				"apr-other": &sdkmcp.ElicitResult{Action: "accept", Meta: permissionResponder("alice")},
			},
			wantWrapped: requeststate.ErrBindingMismatch,
		},
		{
			name: "one entry keyed the empty string",
			responses: sdkmcp.InputResponseMap{
				"": &sdkmcp.ElicitResult{Action: "accept", Meta: permissionResponder("alice")},
			},
			wantWrapped: requeststate.ErrBindingMismatch,
		},
		{
			name: "a non-elicitation InputResponse keyed by the sealed id",
			responses: sdkmcp.InputResponseMap{
				// ListRootsResult is deprecated SDK vocabulary (SEP-2577); it
				// is used here only as a non-ElicitResult InputResponse, to
				// prove acceptElicitedAnswer refuses one rather than assuming
				// every entry is an elicitation answer.
				answerRequestID: &sdkmcp.ListRootsResult{}, //nolint:staticcheck // deprecated SDK type, used only as a non-elicitation fixture
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recordingDecider{}
			result := acceptElicitedAnswer(context.Background(), rec, openerOf(sealer), fixedNow, p, elicitedAnswer{
				RequestState:   sealed,
				InputResponses: tc.responses,
				Tool:           answerTool,
				ArgsDigest:     base.ArgsDigest,
			})
			if result.Outcome != elicitedRefused {
				t.Errorf("Outcome = %v, want elicitedRefused", result.Outcome)
			}
			switch {
			case tc.wantWrapped != nil:
				if !errors.Is(result.Err, errAnswerStateRefused) || !errors.Is(result.Err, tc.wantWrapped) {
					t.Errorf("Err = %v, want errAnswerStateRefused wrapping %v", result.Err, tc.wantWrapped)
				}
			default:
				if !errors.Is(result.Err, errAnswerShape) {
					t.Errorf("Err = %v, want errAnswerShape", result.Err)
				}
			}
			if calls := rec.calls(); len(calls) != 0 {
				t.Errorf("decider called %d times, want 0", len(calls))
			}
		})
	}
}

// -----------------------------------------------------------------------
// Coordinator course correction (after #725 -> PR #736): the answer path's
// ArgsDigest must be computed the same way emission computes it -- over
// json.Marshal of the handler's TYPED input, never the raw wire bytes.
// -----------------------------------------------------------------------

func TestElicitedAnswer_ArgsDigestMatchesEmissionOverTheTypedInput(t *testing.T) {
	p := capturedPrincipal(t)

	t.Run("run_operation", func(t *testing.T) {
		typedIn := runOperationInput{Operation: "service.restart", Args: map[string]string{"unit": "nginx"}}
		sealer, err := requeststate.Mint()
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		base := requeststate.State{
			AccountID:  p.AccountID,
			RequestID:  answerRequestID,
			PlanHash:   answerPlanHash,
			Tool:       answerTool,
			ArgsDigest: mustCallArgsDigest(t, typedIn),
			ExpiresAt:  fixedNow.Add(time.Hour),
		}
		sealed := sealWith(t, sealer, base, nil)

		t.Run("accepted: the retried call's raw JSON reorders keys and adds whitespace, decoded into the same typed struct then digested the way emission does", func(t *testing.T) {
			retriedRaw := []byte(`{ "args": { "unit": "nginx" }, "operation":  "service.restart" }`)
			var retried runOperationInput
			if err := json.Unmarshal(retriedRaw, &retried); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			digest := mustCallArgsDigest(t, retried)

			rec := &recordingDecider{resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash}}
			result := acceptElicitedAnswer(context.Background(), rec, openerOf(sealer), fixedNow, p, elicitedAnswer{
				RequestState:   sealed,
				InputResponses: elicit("accept", permissionResponder("alice")),
				Tool:           answerTool,
				ArgsDigest:     digest,
			})
			if result.Err != nil {
				t.Fatalf("Err = %v, want nil", result.Err)
			}
			if calls := rec.calls(); len(calls) != 1 {
				t.Errorf("decider called %d times, want 1", len(calls))
			}
		})

		t.Run("refused: a digest computed over the raw wire bytes carrying an extra unknown field diverges from the typed re-marshal", func(t *testing.T) {
			retriedRaw := `{"operation":"service.restart","args":{"unit":"nginx"},"unexpected":"field"}`
			digest := digestOf(t, retriedRaw) // over the raw bytes, NOT decoded/re-marshalled through the typed struct

			rec := &recordingDecider{}
			result := acceptElicitedAnswer(context.Background(), rec, openerOf(sealer), fixedNow, p, elicitedAnswer{
				RequestState:   sealed,
				InputResponses: elicit("accept", permissionResponder("alice")),
				Tool:           answerTool,
				ArgsDigest:     digest,
			})
			if result.Outcome != elicitedRefused {
				t.Errorf("Outcome = %v, want elicitedRefused", result.Outcome)
			}
			if !errors.Is(result.Err, requeststate.ErrBindingMismatch) {
				t.Errorf("Err = %v, want errors.Is(_, requeststate.ErrBindingMismatch)", result.Err)
			}
			if calls := rec.calls(); len(calls) != 0 {
				t.Errorf("decider called %d times, want 0", len(calls))
			}
		})
	})

	t.Run("raw_exec: an omitted-vs-zero field diverges from the typed re-marshal", func(t *testing.T) {
		const rawExecTool = "raw_exec"
		typedIn := rawExecInput{Argv: []string{"systemctl", "restart", "nginx"}}
		sealer, err := requeststate.Mint()
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		base := requeststate.State{
			AccountID:  p.AccountID,
			RequestID:  answerRequestID,
			PlanHash:   answerPlanHash,
			Tool:       rawExecTool,
			ArgsDigest: mustCallArgsDigest(t, typedIn),
			ExpiresAt:  fixedNow.Add(time.Hour),
		}
		sealed := sealWith(t, sealer, base, nil)

		// json.Marshal(typedIn) omits Plan (its `omitempty` tag drops the zero
		// value -- see rawExecInput in tools_execution.go), but the raw wire
		// bytes below spell it out as "plan":false. Digesting the raw bytes
		// therefore diverges from digesting the typed re-marshal, even though
		// both describe the identical call.
		retriedRaw := `{"argv":["systemctl","restart","nginx"],"plan":false}`
		digest := digestOf(t, retriedRaw)

		rec := &recordingDecider{}
		result := acceptElicitedAnswer(context.Background(), rec, openerOf(sealer), fixedNow, p, elicitedAnswer{
			RequestState:   sealed,
			InputResponses: elicit("accept", permissionResponder("alice")),
			Tool:           rawExecTool,
			ArgsDigest:     digest,
		})
		if result.Outcome != elicitedRefused {
			t.Errorf("Outcome = %v, want elicitedRefused", result.Outcome)
		}
		if !errors.Is(result.Err, requeststate.ErrBindingMismatch) {
			t.Errorf("Err = %v, want errors.Is(_, requeststate.ErrBindingMismatch)", result.Err)
		}
		if calls := rec.calls(); len(calls) != 0 {
			t.Errorf("decider called %d times, want 0", len(calls))
		}
	})
}

// -----------------------------------------------------------------------
// Step 0: refused up front, before any seal is even opened
// -----------------------------------------------------------------------

func TestElicitedAnswer_RefusesUpFrontWithoutADeciderOrAStoredAccount(t *testing.T) {
	p := capturedPrincipal(t)
	sealer, err := requeststate.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	base := sealState(t, p.AccountID)
	sealed := sealWith(t, sealer, base, nil)

	t.Run("nil decider", func(t *testing.T) {
		result := acceptElicitedAnswer(context.Background(), nil, openerOf(sealer), fixedNow, p, elicitedAnswer{
			RequestState:   sealed,
			InputResponses: elicit("accept", permissionResponder("alice")),
			Tool:           answerTool,
			ArgsDigest:     base.ArgsDigest,
		})
		if result.Outcome != elicitedRefused {
			t.Errorf("Outcome = %v, want elicitedRefused", result.Outcome)
		}
		if !errors.Is(result.Err, capability.ErrApprovalUnavailable) {
			t.Errorf("Err = %v, want errors.Is(_, capability.ErrApprovalUnavailable)", result.Err)
		}
	})

	t.Run("empty AccountID", func(t *testing.T) {
		// A Principal with no stored Account never has a state sealed for it
		// (requeststate.Sealer.Seal refuses an empty AccountID), so this is
		// refused before OpenFor is even called — same as a zero ArgsDigest.
		noAccount := p
		noAccount.AccountID = ""
		rec := &recordingDecider{}
		result := acceptElicitedAnswer(context.Background(), rec, openerOf(sealer), fixedNow, noAccount, elicitedAnswer{
			RequestState:   sealed,
			InputResponses: elicit("accept", permissionResponder("alice")),
			Tool:           answerTool,
			ArgsDigest:     base.ArgsDigest,
		})
		if result.Outcome != elicitedRefused {
			t.Errorf("Outcome = %v, want elicitedRefused", result.Outcome)
		}
		if !errors.Is(result.Err, errAnswerStateRefused) {
			t.Errorf("Err = %v, want errors.Is(_, errAnswerStateRefused)", result.Err)
		}
		if calls := rec.calls(); len(calls) != 0 {
			t.Errorf("decider called %d times, want 0", len(calls))
		}
	})
}

// -----------------------------------------------------------------------
// AP-64: no permission responder is a machine self-decision
// -----------------------------------------------------------------------

func TestElicitedAnswer_WithoutAPermissionResponderIsAMachineSelfDecision(t *testing.T) {
	p := capturedPrincipal(t)
	sealer, err := requeststate.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	base := sealState(t, p.AccountID)
	sealed := sealWith(t, sealer, base, nil)
	wantText := machineSelfDecisionErrorText(t)

	cases := []struct {
		name   string
		action string
		meta   sdkmcp.Meta
	}{
		{name: "no responder at all", action: "accept", meta: nil},
		{name: `gate "information"`, action: "accept", meta: sdkmcp.Meta{responderMetaKey: map[string]any{"gate": "information", "username": "alice"}}},
		{name: "gate missing", action: "accept", meta: sdkmcp.Meta{responderMetaKey: map[string]any{"username": "alice"}}},
		{name: "gate a non-string", action: "accept", meta: sdkmcp.Meta{responderMetaKey: map[string]any{"gate": true, "username": "alice"}}},
		{name: "responder not an object", action: "accept", meta: sdkmcp.Meta{responderMetaKey: "alice"}},
		{name: "case-variant keys only", action: "accept", meta: sdkmcp.Meta{responderMetaKey: map[string]any{"Gate": "permission", "Username": "alice"}}},
		{
			name:   "a valid permission responder plus replayed-from in the response's own Meta",
			action: "accept",
			meta: func() sdkmcp.Meta {
				m := permissionResponder("alice")
				m[replayedFromMetaKey] = "req-earlier"
				return m
			}(),
		},
		{name: `action "cancel" with a valid responder`, action: "cancel", meta: permissionResponder("alice")},
		{name: `action ""`, action: "", meta: permissionResponder("alice")},
		{name: `username ""`, action: "accept", meta: permissionResponder("")},
		{name: "username of spaces only", action: "accept", meta: permissionResponder("   ")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recordingDecider{}
			result := acceptElicitedAnswer(context.Background(), rec, openerOf(sealer), fixedNow, p, elicitedAnswer{
				RequestState:   sealed,
				InputResponses: elicit(tc.action, tc.meta),
				Tool:           answerTool,
				ArgsDigest:     base.ArgsDigest,
			})
			if result.Outcome != elicitedRefused {
				t.Errorf("Outcome = %v, want elicitedRefused", result.Outcome)
			}
			if !errors.Is(result.Err, approval.ErrMachineSelfDecision) {
				t.Errorf("Err = %v, want errors.Is(_, approval.ErrMachineSelfDecision)", result.Err)
			}
			if result.Err == nil || result.Err.Error() != wantText {
				t.Errorf("Err.Error() = %q, want %q (AP-64: identical to approve_request's no-approver message)", result.Err, wantText)
			}
			if calls := rec.calls(); len(calls) != 0 {
				t.Errorf("decider called %d times, want 0", len(calls))
			}
		})
	}

	t.Run("a valid permission responder with replayed-from in CallMeta only", func(t *testing.T) {
		rec := &recordingDecider{}
		result := acceptElicitedAnswer(context.Background(), rec, openerOf(sealer), fixedNow, p, elicitedAnswer{
			RequestState:   sealed,
			InputResponses: elicit("accept", permissionResponder("alice")),
			CallMeta:       sdkmcp.Meta{replayedFromMetaKey: "req-earlier"},
			Tool:           answerTool,
			ArgsDigest:     base.ArgsDigest,
		})
		if result.Outcome != elicitedRefused {
			t.Errorf("Outcome = %v, want elicitedRefused", result.Outcome)
		}
		if !errors.Is(result.Err, approval.ErrMachineSelfDecision) {
			t.Errorf("Err = %v, want errors.Is(_, approval.ErrMachineSelfDecision)", result.Err)
		}
		if calls := rec.calls(); len(calls) != 0 {
			t.Errorf("decider called %d times, want 0", len(calls))
		}
	})
}

func TestElicitedAnswer_RefusesRatherThanTruncatesAMalformedResponder(t *testing.T) {
	p := capturedPrincipal(t)
	sealer, err := requeststate.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	base := sealState(t, p.AccountID)
	sealed := sealWith(t, sealer, base, nil)

	call := func(t *testing.T, username string) (elicitedAnswerResult, *recordingDecider) {
		t.Helper()
		rec := &recordingDecider{resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash}}
		result := acceptElicitedAnswer(context.Background(), rec, openerOf(sealer), fixedNow, p, elicitedAnswer{
			RequestState:   sealed,
			InputResponses: elicit("accept", permissionResponder(username)),
			Tool:           answerTool,
			ArgsDigest:     base.ArgsDigest,
		})
		return result, rec
	}

	refused := []struct {
		name         string
		username     string
		wantSentinel error
	}{
		{name: "a 257-byte ASCII username", username: strings.Repeat("a", 257), wantSentinel: audit.ErrAssertedFieldTooLong},
		{name: `"alice" + LF + "FAKE"`, username: "alice\nFAKE", wantSentinel: audit.ErrAssertedFieldInvalid},
		{name: `"alice" + ESC + "[31m"`, username: "alice\x1b[31m", wantSentinel: audit.ErrAssertedFieldInvalid},
		{name: `"alice" + U+0085 + "x"`, username: "alice\u0085x", wantSentinel: audit.ErrAssertedFieldInvalid},
		{name: `"alice" + CR LF`, username: "alice\r\n", wantSentinel: audit.ErrAssertedFieldInvalid},
		{name: `"alice" + U+0085`, username: "alice\u0085", wantSentinel: audit.ErrAssertedFieldInvalid},
		{name: `tab + "alice"`, username: "\talice", wantSentinel: audit.ErrAssertedFieldInvalid},
		{
			name:         "one leading space + 256 'a' (257 raw bytes, 256 after trim)",
			username:     " " + strings.Repeat("a", 256),
			wantSentinel: audit.ErrAssertedFieldTooLong,
		},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			result, rec := call(t, tc.username)
			if result.Outcome != elicitedRefused {
				t.Errorf("Outcome = %v, want elicitedRefused", result.Outcome)
			}
			if !errors.Is(result.Err, tc.wantSentinel) {
				t.Errorf("Err = %v, want errors.Is(_, %v)", result.Err, tc.wantSentinel)
			}
			if calls := rec.calls(); len(calls) != 0 {
				t.Errorf("decider called %d times, want 0", len(calls))
			}
		})
	}

	t.Run("boundary: a 256-byte username is accepted and recorded verbatim", func(t *testing.T) {
		username := strings.Repeat("a", 256)
		result, rec := call(t, username)
		if result.Err != nil {
			t.Fatalf("Err = %v, want nil", result.Err)
		}
		if result.OnBehalfOf != username || len(result.OnBehalfOf) != 256 {
			t.Errorf("OnBehalfOf = %q (len %d), want the 256-byte username verbatim", result.OnBehalfOf, len(result.OnBehalfOf))
		}
		calls := rec.calls()
		if len(calls) != 1 {
			t.Fatalf("decider called %d times, want 1", len(calls))
		}
		if calls[0].Assertions.OnBehalfOf != username {
			t.Errorf("Assertions.OnBehalfOf = %q, want the 256-byte username", calls[0].Assertions.OnBehalfOf)
		}
	})

	t.Run(`boundary: " alice " (ASCII spaces) is accepted and recorded as "alice"`, func(t *testing.T) {
		result, rec := call(t, " alice ")
		if result.Err != nil {
			t.Fatalf("Err = %v, want nil", result.Err)
		}
		if result.OnBehalfOf != "alice" {
			t.Errorf("OnBehalfOf = %q, want %q", result.OnBehalfOf, "alice")
		}
		calls := rec.calls()
		if len(calls) != 1 || calls[0].Assertions.OnBehalfOf != "alice" {
			t.Errorf("recorded calls = %+v, want one call asserting alice", calls)
		}
	})
}

// -----------------------------------------------------------------------
// AP-79: on a signed-in human session, an answered retry is that human's
// own verified decision, whatever the declared client name
// -----------------------------------------------------------------------

// claudeCodeCallMeta is a retried call's `_meta` declaring the recognised
// client name "claude-code" (AP-78), shaped after the probe evidence (spec
// Known limits): clientInfo, clientCapabilities, and the vendor keys Claude
// Code's own retry actually carries. acceptElicitedAnswer never reads the
// declared name at all (AP-78); the rest is here to prove the name and the
// extra keys are simply ignored.
func claudeCodeCallMeta() sdkmcp.Meta {
	return sdkmcp.Meta{
		sdkmcp.MetaKeyClientInfo: map[string]any{
			"name": "claude-code", "title": "Claude Code", "version": "2.1.283",
		},
		sdkmcp.MetaKeyClientCapabilities: map[string]any{
			"roots":       map[string]any{"listChanged": true},
			"elicitation": map[string]any{"form": map[string]any{}, "url": map[string]any{}},
		},
		"claudecode/toolUseId": "toolu_01abc",
		"progressToken":        2,
	}
}

// gleipnirCallMeta is a retried call's `_meta` declaring the recognised
// client name "gleipnir" — used alongside claudeCodeCallMeta to prove that
// acceptance turns on the session (oauthHumanSession), never on which
// recognised name the retry declares (AP-78).
func gleipnirCallMeta() sdkmcp.Meta {
	return callMetaNamed(clientNameGleipnir)
}

// callMetaNamed builds a retried call's `_meta` declaring an arbitrary
// client name, varying nothing else — the shape
// TestElicitedAnswer_VerifiedFormIgnoresTheDeclaredName and
// TestElicitedAnswer_OffAnOAuthHumanSessionOnlyTheNamedFormCounts use to vary
// only the name.
func callMetaNamed(name string) sdkmcp.Meta {
	return sdkmcp.Meta{sdkmcp.MetaKeyClientInfo: map[string]any{"name": name, "version": "1"}}
}

// TestElicitedAnswer_OAuthHumanSessionAnswerIsTheHumansVerifiedDecision is
// AP-79's headline proof: an accept with no asserted lane entry, on a
// session that authenticated by OAuth with a human Account, is recorded as
// that human's own decision — the verified Principal, nothing written to the
// asserted lane, and any OTHER assertion already on ctx (a stray
// X-Relay-On-Behalf-Of, a traceparent) is handled exactly as AP-79 requires:
// the asserted approver is explicitly cleared, everything else survives. Run
// once per recognised client name (claude-code, gleipnir): the session,
// never the name, decides this (AP-78).
func TestElicitedAnswer_OAuthHumanSessionAnswerIsTheHumansVerifiedDecision(t *testing.T) {
	p := oauthHumanPrincipal(t)
	sealer, err := requeststate.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	cases := []struct {
		name     string
		callMeta sdkmcp.Meta
	}{
		{"claude-code session", claudeCodeCallMeta()},
		{"gleipnir session", gleipnirCallMeta()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := sealState(t, p.AccountID)
			sealed := sealWith(t, sealer, base, nil)

			const traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
			ctx := capability.WithAssertions(context.Background(), capability.Assertions{
				OnBehalfOf:  "mallory",
				Traceparent: traceparent,
			})

			rec := &recordingDecider{resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash, JobID: "job-verified-1"}}
			result := acceptElicitedAnswer(ctx, rec, openerOf(sealer), fixedNow, p, elicitedAnswer{
				RequestState:   sealed,
				InputResponses: elicit("accept", nil),
				CallMeta:       tc.callMeta,
				Tool:           answerTool,
				ArgsDigest:     base.ArgsDigest,
			})
			if result.Err != nil {
				t.Fatalf("Err = %v, want nil", result.Err)
			}
			if result.OnBehalfOf != "" {
				t.Errorf("OnBehalfOf = %q, want empty — AP-79 writes nothing to the asserted lane", result.OnBehalfOf)
			}
			if !result.deciderReached {
				t.Error("deciderReached = false, want true")
			}

			calls := rec.calls()
			if len(calls) != 1 {
				t.Fatalf("decider called %d times, want 1", len(calls))
			}
			if !calls[0].Decision.Approve {
				t.Error("Decision.Approve = false, want true (this was an accept)")
			}
			if calls[0].Decision.Channel != approval.ChannelInBand {
				t.Errorf("Decision.Channel = %v, want ChannelInBand", calls[0].Decision.Channel)
			}
			if !reflect.DeepEqual(calls[0].Principal, p) {
				t.Errorf("Principal = %+v, want the verified caller %+v", calls[0].Principal, p)
			}
			if calls[0].Assertions.OnBehalfOf != "" {
				t.Errorf("Assertions.OnBehalfOf = %q, want empty — the explicit clear", calls[0].Assertions.OnBehalfOf)
			}
			if calls[0].Assertions.Traceparent != traceparent {
				t.Errorf("Assertions.Traceparent = %q, want %q preserved", calls[0].Assertions.Traceparent, traceparent)
			}

			out := result.decisionOutput(RunOrPlanOutput{JobID: "job-verified-1"})
			if out.Channel != approval.ChannelInBand.String() {
				t.Errorf("decisionOutput.Channel = %q, want %q", out.Channel, approval.ChannelInBand.String())
			}
			if out.OnBehalfOf != "" {
				t.Errorf("decisionOutput.OnBehalfOf = %q, want empty", out.OnBehalfOf)
			}
		})
	}
}

// TestElicitedAnswer_OAuthHumanSessionDeclineIsADenial is AP-79's decline
// half: a human's "no", recorded exactly as their "yes" would be attributed,
// still terminal and still empty in the asserted lane — whatever the
// declared client name.
func TestElicitedAnswer_OAuthHumanSessionDeclineIsADenial(t *testing.T) {
	p := oauthHumanPrincipal(t)
	sealer, err := requeststate.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	cases := []struct {
		name     string
		callMeta sdkmcp.Meta
	}{
		{"claude-code session", claudeCodeCallMeta()},
		{"gleipnir session", gleipnirCallMeta()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := sealState(t, p.AccountID)
			sealed := sealWith(t, sealer, base, nil)

			rec := &recordingDecider{resp: approval.Request{ID: answerRequestID, State: approval.StateDenied, PlanHash: answerPlanHash}}
			result := acceptElicitedAnswer(context.Background(), rec, openerOf(sealer), fixedNow, p, elicitedAnswer{
				RequestState:   sealed,
				InputResponses: elicit("decline", nil),
				CallMeta:       tc.callMeta,
				Tool:           answerTool,
				ArgsDigest:     base.ArgsDigest,
			})
			if result.Err != nil {
				t.Fatalf("Err = %v, want nil", result.Err)
			}
			if result.Outcome != elicitedDenied {
				t.Errorf("Outcome = %v, want elicitedDenied", result.Outcome)
			}
			calls := rec.calls()
			if len(calls) != 1 {
				t.Fatalf("decider called %d times, want 1", len(calls))
			}
			if calls[0].Decision.Approve {
				t.Error("Decision.Approve = true, want false (this was a decline)")
			}
			if calls[0].Assertions.OnBehalfOf != "" {
				t.Errorf("Assertions.OnBehalfOf = %q, want empty", calls[0].Assertions.OnBehalfOf)
			}
		})
	}
}

// TestElicitedAnswer_OAuthHumanSessionCancelIsRefusedAsToday: the action
// check comes BEFORE the verified-form choice, so a "cancel" (or any action
// but accept/decline) keeps today's refusal untouched — nothing is recorded,
// even on a qualifying OAuth human session.
func TestElicitedAnswer_OAuthHumanSessionCancelIsRefusedAsToday(t *testing.T) {
	p := oauthHumanPrincipal(t)
	sealer, err := requeststate.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	base := sealState(t, p.AccountID)
	sealed := sealWith(t, sealer, base, nil)

	rec := &recordingDecider{}
	result := acceptElicitedAnswer(context.Background(), rec, openerOf(sealer), fixedNow, p, elicitedAnswer{
		RequestState:   sealed,
		InputResponses: elicit("cancel", nil),
		CallMeta:       claudeCodeCallMeta(),
		Tool:           answerTool,
		ArgsDigest:     base.ArgsDigest,
	})
	if result.Outcome != elicitedRefused {
		t.Errorf("Outcome = %v, want elicitedRefused", result.Outcome)
	}
	if !errors.Is(result.Err, approval.ErrMachineSelfDecision) {
		t.Errorf("Err = %v, want errors.Is(_, approval.ErrMachineSelfDecision)", result.Err)
	}
	if calls := rec.calls(); len(calls) != 0 {
		t.Errorf("decider called %d times, want 0", len(calls))
	}
}

// TestElicitedAnswer_ResponderOnAnOAuthHumanSessionIsIgnored: on a
// signed-in human session, a present io.gleipnir/responder — well-formed or
// not — is ignored completely (AP-79): it is never parsed, and the answer is
// still recorded as the human's own verified decision. Run against both
// recognised client names, because acceptance never reads the name (AP-78).
func TestElicitedAnswer_ResponderOnAnOAuthHumanSessionIsIgnored(t *testing.T) {
	p := oauthHumanPrincipal(t)
	sealer, err := requeststate.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	responderShapes := []struct {
		name string
		meta sdkmcp.Meta
	}{
		{name: "a valid permission responder", meta: permissionResponder("alice")},
		{name: `gate "information"`, meta: sdkmcp.Meta{responderMetaKey: map[string]any{"gate": "information", "username": "alice"}}},
		{name: "responder not an object", meta: sdkmcp.Meta{responderMetaKey: "alice"}},
		{name: "case-variant inner keys", meta: sdkmcp.Meta{responderMetaKey: map[string]any{"Gate": "permission", "Username": "alice"}}},
		{name: "wrong-case outer key", meta: sdkmcp.Meta{"IO.Gleipnir/Responder": map[string]any{"gate": "permission", "username": "alice"}}},
	}
	callMetas := []struct {
		name     string
		callMeta sdkmcp.Meta
	}{
		{"claude-code session", claudeCodeCallMeta()},
		{"gleipnir session", gleipnirCallMeta()},
	}

	for _, cm := range callMetas {
		t.Run(cm.name, func(t *testing.T) {
			for _, rs := range responderShapes {
				t.Run(rs.name, func(t *testing.T) {
					base := sealState(t, p.AccountID)
					sealed := sealWith(t, sealer, base, nil)

					rec := &recordingDecider{resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash}}
					result := acceptElicitedAnswer(context.Background(), rec, openerOf(sealer), fixedNow, p, elicitedAnswer{
						RequestState:   sealed,
						InputResponses: elicit("accept", rs.meta),
						CallMeta:       cm.callMeta,
						Tool:           answerTool,
						ArgsDigest:     base.ArgsDigest,
					})
					if result.Err != nil {
						t.Fatalf("Err = %v, want nil", result.Err)
					}
					calls := rec.calls()
					if len(calls) != 1 {
						t.Fatalf("decider called %d times, want 1", len(calls))
					}
					if calls[0].Assertions.OnBehalfOf != "" {
						t.Errorf("Assertions.OnBehalfOf = %q, want empty — \"alice\" must never reach the decider's assertions", calls[0].Assertions.OnBehalfOf)
					}
					if result.OnBehalfOf != "" {
						t.Errorf("OnBehalfOf = %q, want empty", result.OnBehalfOf)
					}
					out := result.decisionOutput(RunOrPlanOutput{})
					if out.OnBehalfOf != "" {
						t.Errorf("decisionOutput().OnBehalfOf = %q, want empty", out.OnBehalfOf)
					}
				})
			}
		})
	}
}

// TestElicitedAnswer_VerifiedFormIgnoresTheDeclaredName pins that AP-79's
// verified form never reads the declared client name (AP-78): on a
// signed-in human session, an answer is that human's own verified decision
// whatever the retried call's CallMeta says — absent, a near-miss name, or a
// name present only in the ElicitResult's own `_meta`. The Principal is an
// OAuth human throughout, so the declared name is the only thing that
// varies.
func TestElicitedAnswer_VerifiedFormIgnoresTheDeclaredName(t *testing.T) {
	p := oauthHumanPrincipal(t)
	sealer, err := requeststate.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	cases := []struct {
		name     string
		callMeta sdkmcp.Meta
	}{
		{name: "CallMeta absent", callMeta: nil},
		{name: "gleipnir", callMeta: callMetaNamed("gleipnir")},
		{name: "Claude-Code (wrong case)", callMeta: callMetaNamed("Claude-Code")},
		{name: `"claude-code " (trailing space)`, callMeta: callMetaNamed("claude-code ")},
		{name: "some-other-client", callMeta: callMetaNamed("some-other-client")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := sealState(t, p.AccountID)
			sealed := sealWith(t, sealer, base, nil)

			rec := &recordingDecider{resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash}}
			result := acceptElicitedAnswer(context.Background(), rec, openerOf(sealer), fixedNow, p, elicitedAnswer{
				RequestState:   sealed,
				InputResponses: elicit("accept", nil),
				CallMeta:       tc.callMeta,
				Tool:           answerTool,
				ArgsDigest:     base.ArgsDigest,
			})
			if result.Err != nil {
				t.Fatalf("Err = %v, want nil", result.Err)
			}
			calls := rec.calls()
			if len(calls) != 1 {
				t.Fatalf("decider called %d times, want 1", len(calls))
			}
			if !reflect.DeepEqual(calls[0].Principal, p) {
				t.Errorf("Principal = %+v, want the verified caller %+v", calls[0].Principal, p)
			}
			if calls[0].Assertions.OnBehalfOf != "" {
				t.Errorf("Assertions.OnBehalfOf = %q, want empty", calls[0].Assertions.OnBehalfOf)
			}
			if result.OnBehalfOf != "" {
				t.Errorf("OnBehalfOf = %q, want empty", result.OnBehalfOf)
			}
		})
	}

	t.Run(`"claude-code" present only in the ElicitResult's own _meta is still verified`, func(t *testing.T) {
		base := sealState(t, p.AccountID)
		sealed := sealWith(t, sealer, base, nil)

		rec := &recordingDecider{resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash}}
		resultMeta := sdkmcp.Meta{sdkmcp.MetaKeyClientInfo: map[string]any{"name": "claude-code", "version": "1"}}
		result := acceptElicitedAnswer(context.Background(), rec, openerOf(sealer), fixedNow, p, elicitedAnswer{
			RequestState:   sealed,
			InputResponses: elicit("accept", resultMeta),
			CallMeta:       nil,
			Tool:           answerTool,
			ArgsDigest:     base.ArgsDigest,
		})
		if result.Err != nil {
			t.Fatalf("Err = %v, want nil", result.Err)
		}
		calls := rec.calls()
		if len(calls) != 1 {
			t.Fatalf("decider called %d times, want 1", len(calls))
		}
		if result.OnBehalfOf != "" {
			t.Errorf("OnBehalfOf = %q, want empty", result.OnBehalfOf)
		}
	})

	t.Run("a replay marker is refused", func(t *testing.T) {
		base := sealState(t, p.AccountID)
		sealed := sealWith(t, sealer, base, nil)

		cases := []struct {
			name     string
			callMeta sdkmcp.Meta
		}{
			{"claude-code CallMeta", claudeCodeCallMeta()},
			{"gleipnir CallMeta", gleipnirCallMeta()},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				rec := &recordingDecider{}
				callMeta := tc.callMeta
				callMeta[replayedFromMetaKey] = "req-earlier"
				result := acceptElicitedAnswer(context.Background(), rec, openerOf(sealer), fixedNow, p, elicitedAnswer{
					RequestState:   sealed,
					InputResponses: elicit("accept", nil),
					CallMeta:       callMeta,
					Tool:           answerTool,
					ArgsDigest:     base.ArgsDigest,
				})
				if result.Outcome != elicitedRefused {
					t.Errorf("Outcome = %v, want elicitedRefused", result.Outcome)
				}
				if !errors.Is(result.Err, approval.ErrMachineSelfDecision) {
					t.Errorf("Err = %v, want errors.Is(_, approval.ErrMachineSelfDecision)", result.Err)
				}
				if calls := rec.calls(); len(calls) != 0 {
					t.Errorf("decider called %d times, want 0", len(calls))
				}
			})
		}
	})
}

// TestElicitedAnswer_OffAnOAuthHumanSessionOnlyTheNamedFormCounts is
// AP-79/AP-64's acceptance-seam proof that off a signed-in human session
// only the named form counts, whatever the CallMeta says; the acceptor no
// longer reads the declared name at all. The name gate that keeps a
// claude-code retry off an OAuth human session from ever reaching
// acceptElicitedAnswer lives in isAnsweredRetry (via clientCanBeAsked), and
// its proof is TestElicit_ClaudeCodeRetryOnAnAPITokenSessionIsAnOrdinaryCall
// (elicit_test.go, the handler seam, stubDecider fails if called) — with
// TestMCPElicitation_SpoofedClaudeCodeOnANonOAuthSessionEarnsNothing as its
// e2e counterpart. This test deliberately calls acceptElicitedAnswer
// directly, bypassing that gate.
func TestElicitedAnswer_OffAnOAuthHumanSessionOnlyTheNamedFormCounts(t *testing.T) {
	base0 := capturedPrincipal(t)
	sealer, err := requeststate.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	principalCases := []struct {
		name string
		p    capability.Principal
	}{
		{"API Token + human", principalAs(base0, capability.AuthMethodAPIToken, capability.PrincipalKindHuman)},
		{"API Token + machine", principalAs(base0, capability.AuthMethodAPIToken, "machine")},
		{"OAuth + machine", principalAs(base0, capability.AuthMethodOAuth, "machine")},
		{`OAuth + "" (unset kind)`, principalAs(base0, capability.AuthMethodOAuth, "")},
		{`OAuth + "Human" (wrong case)`, principalAs(base0, capability.AuthMethodOAuth, "Human")},
		{"Console session + human", principalAs(base0, capability.AuthMethodConsoleSession, capability.PrincipalKindHuman)},
		{"Unspecified + human", principalAs(base0, capability.AuthMethodUnspecified, capability.PrincipalKindHuman)},
	}
	callMetaCases := []struct {
		name     string
		callMeta sdkmcp.Meta
	}{
		{"claude-code CallMeta", claudeCodeCallMeta()},
		{"gleipnir CallMeta", gleipnirCallMeta()},
		{"no CallMeta", nil},
	}

	for _, pc := range principalCases {
		for _, cm := range callMetaCases {
			t.Run(pc.name+", "+cm.name+", no responder", func(t *testing.T) {
				base := sealState(t, base0.AccountID)
				sealed := sealWith(t, sealer, base, nil)

				rec := &recordingDecider{}
				result := acceptElicitedAnswer(context.Background(), rec, openerOf(sealer), fixedNow, pc.p, elicitedAnswer{
					RequestState:   sealed,
					InputResponses: elicit("accept", nil),
					CallMeta:       cm.callMeta,
					Tool:           answerTool,
					ArgsDigest:     base.ArgsDigest,
				})
				if result.Outcome != elicitedRefused {
					t.Errorf("Outcome = %v, want elicitedRefused", result.Outcome)
				}
				if !errors.Is(result.Err, approval.ErrMachineSelfDecision) {
					t.Errorf("Err = %v, want errors.Is(_, approval.ErrMachineSelfDecision)", result.Err)
				}
				if calls := rec.calls(); len(calls) != 0 {
					t.Errorf("decider called %d times, want 0", len(calls))
				}
				if result.deciderReached {
					t.Error("deciderReached = true, want false")
				}
				wantReason := errNoNamedApprover.Error()
				if got := result.refusalOutput().Reason; got != wantReason {
					t.Errorf("refusalOutput().Reason = %q, want %q", got, wantReason)
				}
			})

			// The named path still counts on a disqualified session (AP-64):
			// this inverts the old fold-in row, because AP-78 says acceptance
			// never turns on the name.
			t.Run(pc.name+", "+cm.name+", with a valid responder", func(t *testing.T) {
				base := sealState(t, base0.AccountID)
				sealed := sealWith(t, sealer, base, nil)

				rec := &recordingDecider{resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash}}
				result := acceptElicitedAnswer(context.Background(), rec, openerOf(sealer), fixedNow, pc.p, elicitedAnswer{
					RequestState:   sealed,
					InputResponses: elicit("accept", permissionResponder("alice")),
					CallMeta:       cm.callMeta,
					Tool:           answerTool,
					ArgsDigest:     base.ArgsDigest,
				})
				if result.Err != nil {
					t.Fatalf("Err = %v, want nil", result.Err)
				}
				calls := rec.calls()
				if len(calls) != 1 {
					t.Fatalf("decider called %d times, want 1", len(calls))
				}
				if calls[0].Assertions.OnBehalfOf != "alice" {
					t.Errorf("Assertions.OnBehalfOf = %q, want %q — the named path (AP-64)", calls[0].Assertions.OnBehalfOf, "alice")
				}
				if result.OnBehalfOf != "alice" {
					t.Errorf("OnBehalfOf = %q, want %q", result.OnBehalfOf, "alice")
				}
			})
		}
	}
}

// TestElicitedAnswer_VerifiedFormMeetsTheSameRefusals is AP-79's "same
// refusals" claim, at the ADAPTER seam: acceptElicitedAnswer classifies a
// verified answer's domain refusal identically to how it classifies a named
// one — run against both recognised client names, because acceptance never
// reads the name (AP-78). recordingDecider is scripted here, so this proves
// the adapter's classification only; the real domain's side (requester
// exclusion, machine self-decision) is item 7's capability-seam proof
// (TestDecideApproval_InBandHumanWithNoAssertedApproverIsVerified). Its
// ErrRequesterExcluded row is "requester exclusion still refuses" at this
// seam; requester exclusion is UNREACHABLE end to end at all (AP-61 never
// asks where the rule excludes the requester, and the seal binds an answer
// to the asking Account) — see
// TestMCPElicitation_ClaudeCodeHumanAnswerMeetsTheSameRefusals's doc.
func TestElicitedAnswer_VerifiedFormMeetsTheSameRefusals(t *testing.T) {
	p := oauthHumanPrincipal(t)
	sealer, err := requeststate.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	cases := []struct {
		name         string
		action       string
		resp         approval.Request
		err          error
		wantOutcome  elicitedOutcome
		wantNextStep string
	}{
		{name: "ErrRequesterExcluded", action: "accept", err: approval.ErrRequesterExcluded, wantOutcome: elicitedRefused, wantNextStep: answerRefusalNextStepRequesterExcluded},
		{name: "ErrWeakChannel", action: "accept", err: approval.ErrWeakChannel, wantOutcome: elicitedRefused, wantNextStep: answerRefusalNextStepCannotAnswerHere},
		{name: "ErrNotInAudience", action: "accept", err: approval.ErrNotInAudience, wantOutcome: elicitedRefused, wantNextStep: answerRefusalNextStepIneligibleAccount},
		{name: "ErrPlanChanged", action: "accept", err: approval.ErrPlanChanged, wantOutcome: elicitedRefused, wantNextStep: answerRefusalNextStepUnchanged},
		{
			// A decline that lost the race to an out-of-band approval: the
			// SAME shape TestElicitedAnswer_ClassifiesEveryOutcome exercises
			// for the named path ("DECLINE, ErrNotPending, approved, no Job,
			// not past deadline"), so ErrDuplicateDecider is proven here
			// against the identical resp/action combination that row uses.
			name:         "ErrDuplicateDecider, a decline that lost the race",
			action:       "decline",
			resp:         approval.Request{ID: answerRequestID, PlanHash: answerPlanHash, State: approval.StateApproved},
			err:          approval.ErrDuplicateDecider,
			wantOutcome:  elicitedRefused,
			wantNextStep: answerRefusalNextStepDeclineNotRecorded,
		},
		{
			name:         "ErrNotPending, a decline that lost the race",
			action:       "decline",
			resp:         approval.Request{ID: answerRequestID, PlanHash: answerPlanHash, State: approval.StateApproved},
			err:          approval.ErrNotPending,
			wantOutcome:  elicitedRefused,
			wantNextStep: answerRefusalNextStepDeclineNotRecorded,
		},
	}

	callMetaCases := []struct {
		name     string
		callMeta sdkmcp.Meta
	}{
		{"claude-code session", claudeCodeCallMeta()},
		{"gleipnir session", gleipnirCallMeta()},
	}

	for _, cm := range callMetaCases {
		t.Run(cm.name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					base := sealState(t, p.AccountID)
					sealed := sealWith(t, sealer, base, nil)

					rec := &recordingDecider{resp: tc.resp, err: tc.err}
					result := acceptElicitedAnswer(context.Background(), rec, openerOf(sealer), fixedNow, p, elicitedAnswer{
						RequestState:   sealed,
						InputResponses: elicit(tc.action, nil),
						CallMeta:       cm.callMeta,
						Tool:           answerTool,
						ArgsDigest:     base.ArgsDigest,
					})
					if result.Outcome != tc.wantOutcome {
						t.Errorf("Outcome = %v, want %v", result.Outcome, tc.wantOutcome)
					}
					if !errors.Is(result.Err, tc.err) {
						t.Errorf("Err = %v, want errors.Is(_, %v)", result.Err, tc.err)
					}
					if calls := rec.calls(); len(calls) != 1 {
						t.Fatalf("decider called %d times, want 1", len(calls))
					}
					if got := result.refusalOutput().NextStep; got != tc.wantNextStep {
						t.Errorf("refusalOutput().NextStep = %q, want %q", got, tc.wantNextStep)
					}
				})
			}
		})
	}
}

// TestElicitedAnswer_FailureAfterAVerifiedDecisionMayHaveBeenRecorded guards
// deciderReached (which replaces "OnBehalfOf is empty" as the
// was-the-decider-called signal): a plain, non-domain error after a VERIFIED
// decision's decider call must render as "may already reflect this answer",
// never as "this call left the request unchanged" — the false-safe reading
// security review #727 finding 1 forbade, now reachable on an empty
// OnBehalfOf for the first time under AP-79.
func TestElicitedAnswer_FailureAfterAVerifiedDecisionMayHaveBeenRecorded(t *testing.T) {
	p := oauthHumanPrincipal(t)
	sealer, err := requeststate.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	base := sealState(t, p.AccountID)
	sealed := sealWith(t, sealer, base, nil)

	rec := &recordingDecider{err: errors.New("audit write failed")}
	result := acceptElicitedAnswer(context.Background(), rec, openerOf(sealer), fixedNow, p, elicitedAnswer{
		RequestState:   sealed,
		InputResponses: elicit("accept", nil),
		CallMeta:       gleipnirCallMeta(),
		Tool:           answerTool,
		ArgsDigest:     base.ArgsDigest,
	})
	if !result.deciderReached {
		t.Fatal("deciderReached = false, want true — the decider WAS called")
	}
	out := result.refusalOutput()
	if out.NextStep != answerRefusalNextStepMayAlreadyReflectAnswer {
		t.Errorf("NextStep = %q, want %q", out.NextStep, answerRefusalNextStepMayAlreadyReflectAnswer)
	}
	if !strings.HasPrefix(out.Reason, "the answer may have been recorded") {
		t.Errorf("Reason = %q, want it to start with %q", out.Reason, "the answer may have been recorded")
	}
}

// TestOAuthHumanSession_ChecksTheAccountKindNotTheAuthMethod is a direct
// table on oauthHumanSession, using the same principal rows
// TestElicit_WhoIsAskedByNameAndSession's session table uses: only an OAuth
// session of a human Account returns true. The check is on the Account's
// stored Kind, never inferred from AuthMethod alone.
func TestOAuthHumanSession_ChecksTheAccountKindNotTheAuthMethod(t *testing.T) {
	cases := []struct {
		name string
		p    capability.Principal
		want bool
	}{
		{"OAuth + human", capability.Principal{AuthMethod: capability.AuthMethodOAuth, Kind: capability.PrincipalKindHuman}, true},
		{"API Token + human", capability.Principal{AuthMethod: capability.AuthMethodAPIToken, Kind: capability.PrincipalKindHuman}, false},
		{"API Token + machine", capability.Principal{AuthMethod: capability.AuthMethodAPIToken, Kind: "machine"}, false},
		{"OAuth + machine", capability.Principal{AuthMethod: capability.AuthMethodOAuth, Kind: "machine"}, false},
		{"OAuth + unset kind", capability.Principal{AuthMethod: capability.AuthMethodOAuth}, false},
		{"Console session + human", capability.Principal{AuthMethod: capability.AuthMethodConsoleSession, Kind: capability.PrincipalKindHuman}, false},
		{"Unspecified + human", capability.Principal{Kind: capability.PrincipalKindHuman}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := oauthHumanSession(tc.p); got != tc.want {
				t.Errorf("oauthHumanSession(%+v) = %v, want %v", tc.p, got, tc.want)
			}
		})
	}
}

// -----------------------------------------------------------------------
// approve_request's approver is bound the same way
// -----------------------------------------------------------------------

func TestApproveRequest_RefusesRatherThanTruncatesAMalformedApprover(t *testing.T) {
	call := func(t *testing.T, approver string) (*sdkmcp.CallToolResult, *recordingDecider) {
		t.Helper()
		rec := &recordingDecider{resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash}}
		res := callApproveRequest(t, rec, approver)
		return res, rec
	}

	refused := []struct {
		name     string
		approver string
	}{
		{name: "a 257-byte approver", approver: strings.Repeat("a", 257)},
		{name: `"bob" + CR LF + "FAKE RECORD"`, approver: "bob\r\nFAKE RECORD"},
		{name: `"alice" + CR LF`, approver: "alice\r\n"},
		{name: `"alice" + U+0085`, approver: "alice\u0085"},
		{name: `tab + "alice"`, approver: "\talice"},
		{name: "one space + 256 'a'", approver: " " + strings.Repeat("a", 256)},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			res, rec := call(t, tc.approver)
			if !res.IsError {
				t.Fatalf("approve_request(%q): IsError = false, want true", tc.approver)
			}
			text := relaytest.ToolErrorText(t, res)
			if !strings.Contains(text, "256 bytes") || !strings.Contains(text, "control character") {
				t.Errorf("error text = %q, does not name the bound (at most 256 bytes, no control characters)", text)
			}
			if calls := rec.calls(); len(calls) != 0 {
				t.Errorf("decider called %d times, want 0", len(calls))
			}
		})
	}

	t.Run("a 256-byte approver reaches the decider verbatim", func(t *testing.T) {
		approver := strings.Repeat("a", 256)
		res, rec := call(t, approver)
		if res.IsError {
			t.Fatalf("approve_request: IsError, content=%+v", res.Content)
		}
		calls := rec.calls()
		if len(calls) != 1 {
			t.Fatalf("decider called %d times, want 1", len(calls))
		}
		if calls[0].Assertions.OnBehalfOf != approver {
			t.Errorf("OnBehalfOf = %q, want the 256-byte approver verbatim", calls[0].Assertions.OnBehalfOf)
		}
	})

	t.Run(`approver "" still returns the unchanged message`, func(t *testing.T) {
		res, rec := call(t, "")
		if !res.IsError {
			t.Fatal(`approve_request(""): IsError = false, want true`)
		}
		text := relaytest.ToolErrorText(t, res)
		if text != errNoNamedApprover.Error() {
			t.Errorf("error text = %q, want the unchanged no-approver message %q", text, errNoNamedApprover.Error())
		}
		if calls := rec.calls(); len(calls) != 0 {
			t.Errorf("decider called %d times, want 0", len(calls))
		}
	})

	t.Run(`"  alice  " still records "alice" (existing space-trimming unchanged)`, func(t *testing.T) {
		res, rec := call(t, "  alice  ")
		if res.IsError {
			t.Fatalf("approve_request: IsError, content=%+v", res.Content)
		}
		calls := rec.calls()
		if len(calls) != 1 || calls[0].Assertions.OnBehalfOf != "alice" {
			t.Errorf("recorded calls = %+v, want one call asserting alice", calls)
		}
	})
}

// -----------------------------------------------------------------------
// Classification: every domain outcome maps to exactly one elicitedOutcome
// -----------------------------------------------------------------------

func TestElicitedAnswer_ClassifiesEveryOutcome(t *testing.T) {
	p := capturedPrincipal(t)
	sealer, err := requeststate.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	base := sealState(t, p.AccountID)
	sealed := sealWith(t, sealer, base, nil)

	future := fixedNow.Add(time.Hour)
	past := fixedNow.Add(-time.Hour)

	// otherReq deliberately carries a DIFFERENT RequestID/PlanHash than the
	// sealed state, so every row below also proves acceptElicitedAnswer
	// reports the SEALED RequestID/PlanHash, never the scripted Request's.
	otherReq := func(state approval.State, jobID string, expiresAt time.Time) approval.Request {
		return approval.Request{
			ID:        "some-other-id",
			PlanHash:  "some-other-hash",
			State:     state,
			JobID:     jobID,
			ExpiresAt: expiresAt,
			Require:   approval.Requirement{Count: 2},
			Decisions: []approval.Decision{{Approve: true}},
		}
	}

	cases := []struct {
		name         string
		decline      bool
		resp         approval.Request
		err          error
		wantOutcome  elicitedOutcome
		wantErrIs    error
		wantProgress string
		checkState   bool
	}{
		{
			name:         "nil err, approved, no Job",
			resp:         otherReq(approval.StateApproved, "", future),
			wantOutcome:  elicitedApproved,
			wantProgress: "1 of 2",
			checkState:   true,
		},
		{
			name:        "nil err, approved, JobID bound",
			resp:        otherReq(approval.StateApproved, "job-1", future),
			wantOutcome: elicitedApprovedJobBound,
			checkState:  true,
		},
		{
			name:        "nil err, denied",
			resp:        otherReq(approval.StateDenied, "", future),
			wantOutcome: elicitedDenied,
			checkState:  true,
		},
		{
			name:         "nil err, still pending, 1 of 2",
			resp:         otherReq(approval.StatePending, "", future),
			wantOutcome:  elicitedStillPending,
			wantProgress: "1 of 2",
			checkState:   true,
		},
		{
			name:        "nil err, unrecognised State (fail closed default)",
			resp:        otherReq(approval.State(99), "", future),
			wantOutcome: elicitedRefused,
			wantErrIs:   errUnknownRequestState,
			checkState:  true,
		},
		{
			name:        "ErrNotPending, approved, JobID bound",
			resp:        otherReq(approval.StateApproved, "job-1", future),
			err:         approval.ErrNotPending,
			wantOutcome: elicitedApprovedJobBound,
			wantErrIs:   approval.ErrNotPending,
			checkState:  true,
		},
		{
			name:        "ErrNotPending, approved, no Job, not past deadline",
			resp:        otherReq(approval.StateApproved, "", future),
			err:         approval.ErrNotPending,
			wantOutcome: elicitedApproved,
			wantErrIs:   approval.ErrNotPending,
			checkState:  true,
		},
		{
			name:        "ErrNotPending, approved, no Job, PAST its deadline",
			resp:        otherReq(approval.StateApproved, "", past),
			err:         approval.ErrNotPending,
			wantOutcome: elicitedLapsed,
			wantErrIs:   approval.ErrNotPending,
			checkState:  true,
		},
		{
			name:        "DECLINE, ErrNotPending, approved, no Job, not past deadline",
			decline:     true,
			resp:        otherReq(approval.StateApproved, "", future),
			err:         approval.ErrNotPending,
			wantOutcome: elicitedRefused,
			wantErrIs:   approval.ErrNotPending,
			checkState:  true,
		},
		{
			name:        "DECLINE, ErrNotPending, approved, JobID bound",
			decline:     true,
			resp:        otherReq(approval.StateApproved, "job-1", future),
			err:         approval.ErrNotPending,
			wantOutcome: elicitedApprovedJobBound,
			wantErrIs:   approval.ErrNotPending,
			checkState:  true,
		},
		{
			name:        "DECLINE, nil err, approved, no Job",
			decline:     true,
			resp:        otherReq(approval.StateApproved, "", future),
			wantOutcome: elicitedRefused,
			wantErrIs:   errDeclineNotHonoured,
			checkState:  true,
		},
		{
			name:        "ErrNotPending, denied",
			resp:        otherReq(approval.StateDenied, "", future),
			err:         approval.ErrNotPending,
			wantOutcome: elicitedDenied,
			wantErrIs:   approval.ErrNotPending,
			checkState:  true,
		},
		{
			name:        "ErrNotPending, expired",
			resp:        otherReq(approval.StateExpired, "", future),
			err:         approval.ErrNotPending,
			wantOutcome: elicitedLapsed,
			wantErrIs:   approval.ErrNotPending,
			checkState:  true,
		},
		{
			name:        "a wrapped ErrNotPending, pending, past its deadline",
			resp:        otherReq(approval.StatePending, "", past),
			err:         fmt.Errorf("wrapped: %w", approval.ErrNotPending),
			wantOutcome: elicitedLapsed,
			wantErrIs:   approval.ErrNotPending,
			checkState:  true,
		},
		{
			name:        "ErrDuplicateDecider, pending, not past deadline",
			resp:        otherReq(approval.StatePending, "", future),
			err:         approval.ErrDuplicateDecider,
			wantOutcome: elicitedStillPending,
			wantErrIs:   approval.ErrDuplicateDecider,
			checkState:  true,
		},
		{
			name:        "ErrDuplicateDecider, pending, past its deadline",
			resp:        otherReq(approval.StatePending, "", past),
			err:         approval.ErrDuplicateDecider,
			wantOutcome: elicitedLapsed,
			wantErrIs:   approval.ErrDuplicateDecider,
			checkState:  true,
		},
		{
			name:        "ErrNotPending with a zero Request",
			resp:        approval.Request{},
			err:         approval.ErrNotPending,
			wantOutcome: elicitedRefused,
			wantErrIs:   approval.ErrNotPending,
		},
		{
			name:        "ErrNotPending, pending, NOT past its deadline by the helper's own now (clock skew)",
			resp:        otherReq(approval.StatePending, "", future),
			err:         approval.ErrNotPending,
			wantOutcome: elicitedLapsed,
			wantErrIs:   approval.ErrNotPending,
			checkState:  true,
		},
		{
			name:        "ErrRequesterExcluded with an approved Request",
			resp:        otherReq(approval.StateApproved, "job-1", future),
			err:         approval.ErrRequesterExcluded,
			wantOutcome: elicitedRefused,
			wantErrIs:   approval.ErrRequesterExcluded,
		},
		{
			name:        "ErrNotInAudience with an approved Request",
			resp:        otherReq(approval.StateApproved, "", future),
			err:         approval.ErrNotInAudience,
			wantOutcome: elicitedRefused,
			wantErrIs:   approval.ErrNotInAudience,
		},
		{
			name:        "ErrMachineSelfDecision with an approved Request",
			resp:        otherReq(approval.StateApproved, "", future),
			err:         approval.ErrMachineSelfDecision,
			wantOutcome: elicitedRefused,
			wantErrIs:   approval.ErrMachineSelfDecision,
		},
		{
			name:        "ErrWeakChannel with an approved Request",
			resp:        otherReq(approval.StateApproved, "", future),
			err:         approval.ErrWeakChannel,
			wantOutcome: elicitedRefused,
			wantErrIs:   approval.ErrWeakChannel,
		},
		{
			name:        "ErrPlanChanged with an approved Request",
			resp:        otherReq(approval.StateApproved, "", future),
			err:         approval.ErrPlanChanged,
			wantOutcome: elicitedRefused,
			wantErrIs:   approval.ErrPlanChanged,
		},
		{
			name:        "ErrNotFound with an approved Request",
			resp:        otherReq(approval.StateApproved, "", future),
			err:         approval.ErrNotFound,
			wantOutcome: elicitedRefused,
			wantErrIs:   approval.ErrNotFound,
		},
		{
			name:        "capability.ErrApprovalUnavailable with an approved Request",
			resp:        otherReq(approval.StateApproved, "", future),
			err:         capability.ErrApprovalUnavailable,
			wantOutcome: elicitedRefused,
			wantErrIs:   capability.ErrApprovalUnavailable,
		},
		{
			name:        `a non-domain error ("store down") with an approved Request — the audit-write shape`,
			resp:        otherReq(approval.StateApproved, "", future),
			err:         errors.New("store down"),
			wantOutcome: elicitedRefused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := scriptedDecider{resp: tc.resp, err: tc.err}
			action := "accept"
			if tc.decline {
				action = "decline"
			}
			result := acceptElicitedAnswer(context.Background(), rec, openerOf(sealer), fixedNow, p, elicitedAnswer{
				RequestState:   sealed,
				InputResponses: elicit(action, permissionResponder("alice")),
				Tool:           answerTool,
				ArgsDigest:     base.ArgsDigest,
			})

			if result.Outcome != tc.wantOutcome {
				t.Errorf("Outcome = %v, want %v (Err = %v)", result.Outcome, tc.wantOutcome, result.Err)
			}
			if tc.wantErrIs != nil && !errors.Is(result.Err, tc.wantErrIs) {
				t.Errorf("Err = %v, want errors.Is(_, %v)", result.Err, tc.wantErrIs)
			}
			if tc.wantProgress != "" && result.Progress != tc.wantProgress {
				t.Errorf("Progress = %q, want %q", result.Progress, tc.wantProgress)
			}
			if tc.wantOutcome == elicitedRefused && result.Progress != "" {
				t.Errorf("Progress = %q, want empty on a refusal", result.Progress)
			}
			// stateReported must agree with checkState exactly: it is the flag
			// a caller's refusalOutput uses to decide whether State/JobID/
			// ExpiresAt are safe to copy (issue #727 comment 2, point 2 and
			// plan review's decisionOutput/refusalOutput split).
			if result.stateReported != tc.checkState {
				t.Errorf("stateReported = %v, want %v", result.stateReported, tc.checkState)
			}
			if tc.checkState {
				if result.State != tc.resp.State || result.JobID != tc.resp.JobID || !result.ExpiresAt.Equal(tc.resp.ExpiresAt) {
					t.Errorf("State/JobID/ExpiresAt = %v/%q/%v, want %v/%q/%v",
						result.State, result.JobID, result.ExpiresAt, tc.resp.State, tc.resp.JobID, tc.resp.ExpiresAt)
				}
			} else {
				var zeroState approval.State
				if result.State != zeroState || result.JobID != "" || !result.ExpiresAt.IsZero() {
					t.Errorf("State/JobID/ExpiresAt = %v/%q/%v, want zero (this refusal must not carry the Request's state)",
						result.State, result.JobID, result.ExpiresAt)
				}
			}
			// RequestID and PlanHash always come from the SEAL, never from
			// the (deliberately different) Request the scripted decider
			// returned.
			if result.RequestID != answerRequestID || result.PlanHash != answerPlanHash {
				t.Errorf("RequestID/PlanHash = %q/%q, want the sealed %q/%q",
					result.RequestID, result.PlanHash, answerRequestID, answerPlanHash)
			}
		})
	}
}

// -----------------------------------------------------------------------
// #735 review: a refused decision exposes only State, JobID and the deadline
// -----------------------------------------------------------------------

func TestElicitedAnswer_ARefusedDecisionExposesOnlyStateJobAndDeadline(t *testing.T) {
	t.Run("structural: the result type can never reach approval.Request or approval.Decision", func(t *testing.T) {
		reqType := reflect.TypeOf(approval.Request{})
		decType := reflect.TypeOf(approval.Decision{})
		visited := map[reflect.Type]bool{}

		var walk func(typ reflect.Type)
		walk = func(typ reflect.Type) {
			if typ == nil || visited[typ] {
				return
			}
			visited[typ] = true
			if typ == reqType || typ == decType {
				t.Errorf("elicitedAnswerResult can reach %v — it must never carry the raw Request or a Decision (#735 review)", typ)
				return
			}
			switch typ.Kind() { // only the recursive shapes need walking
			case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Chan:
				walk(typ.Elem())
			case reflect.Map:
				walk(typ.Key())
				walk(typ.Elem())
			case reflect.Struct:
				for i := 0; i < typ.NumField(); i++ {
					walk(typ.Field(i).Type)
				}
			}
		}
		walk(reflect.TypeOf(elicitedAnswerResult{}))
	})

	t.Run("behavioural: another approver's detail never renders", func(t *testing.T) {
		p := capturedPrincipal(t)
		sealer, err := requeststate.Mint()
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		base := sealState(t, p.AccountID)
		sealed := sealWith(t, sealer, base, nil)

		expiresAt := fixedNow.Add(time.Hour)
		leaky := approval.Request{
			ID:          "apr-1",
			PlanHash:    answerPlanHash,
			State:       approval.StateApproved,
			ExpiresAt:   expiresAt,
			RequestedBy: "dana",
			Summary:     "secret-summary",
			Decisions: []approval.Decision{
				{Account: "carol", OnBehalfOf: "Carol Private", Reason: "private note", Approve: true},
			},
		}
		rec := scriptedDecider{resp: leaky, err: approval.ErrNotPending}

		result := acceptElicitedAnswer(context.Background(), rec, openerOf(sealer), fixedNow, p, elicitedAnswer{
			RequestState:   sealed,
			InputResponses: elicit("decline", permissionResponder("alice")),
			Tool:           answerTool,
			ArgsDigest:     base.ArgsDigest,
		})

		rendered := fmt.Sprintf("%+v", result)
		for _, secret := range []string{"carol", "Carol Private", "private note", "dana", "secret-summary"} {
			if strings.Contains(rendered, secret) {
				t.Errorf("rendered result contains %q, which came from another approver's Decision — it must never leak: %s", secret, rendered)
			}
		}
		if result.Progress != "" {
			t.Errorf("Progress = %q, want empty on a refusal", result.Progress)
		}
		if result.State != leaky.State || result.JobID != leaky.JobID || !result.ExpiresAt.Equal(leaky.ExpiresAt) {
			t.Errorf("State/JobID/ExpiresAt = %v/%q/%v, want %v/%q/%v",
				result.State, result.JobID, result.ExpiresAt, leaky.State, leaky.JobID, leaky.ExpiresAt)
		}
	})
}

// -----------------------------------------------------------------------
// #727: decisionOutput's NextStep is chosen from Outcome AND what dispatch
// actually returned, never Outcome alone; refusalOutput's Reason is chosen
// by r.Err, in the fixed arm order AP-64 requires.
// -----------------------------------------------------------------------

func TestDecisionOutput_ChoosesNextStepFromOutcomeAndDispatchResult(t *testing.T) {
	future := fixedNow.Add(time.Hour)

	cases := []struct {
		name           string
		result         elicitedAnswerResult
		after          RunOrPlanOutput
		wantChannel    string
		wantOnBehalfOf string
		wantNextStep   string
	}{
		{
			name:           "approved, recorded, dispatch ran and minted a Job",
			result:         elicitedAnswerResult{Outcome: elicitedApproved, State: approval.StateApproved, OnBehalfOf: "alice"},
			after:          RunOrPlanOutput{JobID: "job-1"},
			wantChannel:    approval.ChannelInBand.String(),
			wantOnBehalfOf: "alice",
			wantNextStep:   nextStepRanThePipeline + " " + nextStepAnswerRecorded,
		},
		{
			name:         "approved but ErrNotPending (already decided by someone else), dispatch still ran",
			result:       elicitedAnswerResult{Outcome: elicitedApproved, State: approval.StateApproved, Err: approval.ErrNotPending},
			after:        RunOrPlanOutput{JobID: "job-1"},
			wantNextStep: nextStepRanThePipeline + " " + nextStepAnswerNotRecordedAlreadyDecided,
		},
		{
			name:         "still pending, ErrDuplicateDecider, dispatch re-parked (observed, non-askable)",
			result:       elicitedAnswerResult{Outcome: elicitedStillPending, State: approval.StatePending, Err: approval.ErrDuplicateDecider},
			after:        RunOrPlanOutput{PendingApproval: &PendingApprovalOutput{}},
			wantNextStep: nextStepReParkedOnApproval + " " + nextStepAnswerNotRecordedDuplicateDecider,
		},
		{
			name:           "Job-bound re-attach, recorded",
			result:         elicitedAnswerResult{Outcome: elicitedApprovedJobBound, State: approval.StateApproved, JobID: "job-1", OnBehalfOf: "alice"},
			after:          RunOrPlanOutput{JobID: "job-1"},
			wantChannel:    approval.ChannelInBand.String(),
			wantOnBehalfOf: "alice",
			wantNextStep:   nextStepReattachedExistingJob + " " + nextStepAnswerRecorded,
		},
		{
			name:         "Job-bound re-attach, NOT recorded (this decline lost the race to an existing approval)",
			result:       elicitedAnswerResult{Outcome: elicitedApprovedJobBound, State: approval.StateApproved, JobID: "job-1", Err: approval.ErrNotPending},
			after:        RunOrPlanOutput{JobID: "job-1"},
			wantNextStep: nextStepReattachedExistingJob + " " + nextStepAnswerNotRecordedAlreadyDecided,
		},
		{
			name:           "denied, terminal",
			result:         elicitedAnswerResult{Outcome: elicitedDenied, State: approval.StateDenied, OnBehalfOf: "bob"},
			after:          RunOrPlanOutput{},
			wantChannel:    approval.ChannelInBand.String(),
			wantOnBehalfOf: "bob",
			wantNextStep:   nextStepDenialIsTerminal + " " + nextStepAnswerRecorded,
		},
		{
			name:           "lapsed, recorded, nothing dispatched",
			result:         elicitedAnswerResult{Outcome: elicitedLapsed, State: approval.StateExpired, ExpiresAt: future, OnBehalfOf: "alice"},
			after:          RunOrPlanOutput{},
			wantChannel:    approval.ChannelInBand.String(),
			wantOnBehalfOf: "alice",
			wantNextStep:   nextStepNothingWasDispatched + " " + nextStepAnswerRecorded,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := tc.result.decisionOutput(tc.after)
			if out.Channel != tc.wantChannel {
				t.Errorf("Channel = %q, want %q", out.Channel, tc.wantChannel)
			}
			if out.OnBehalfOf != tc.wantOnBehalfOf {
				t.Errorf("OnBehalfOf = %q, want %q", out.OnBehalfOf, tc.wantOnBehalfOf)
			}
			if out.NextStep != tc.wantNextStep {
				t.Errorf("NextStep = %q, want %q", out.NextStep, tc.wantNextStep)
			}
			if out.RequestID != tc.result.RequestID {
				t.Errorf("RequestID = %q, want %q", out.RequestID, tc.result.RequestID)
			}
			if out.State != tc.result.State.String() {
				t.Errorf("State = %q, want %q", out.State, tc.result.State.String())
			}
		})
	}
}

func TestRefusalOutput_ReasonArmsAndOrdering(t *testing.T) {
	wantMachineText := machineSelfDecisionErrorText(t)

	cases := []struct {
		name         string
		result       elicitedAnswerResult
		wantReason   string
		wantNextStep string
	}{
		{
			name:         "arm 1: ErrMachineSelfDecision renders AP-64's text, never renderApprovalError's",
			result:       elicitedAnswerResult{Err: approval.ErrMachineSelfDecision, OnBehalfOf: "someone"},
			wantReason:   wantMachineText,
			wantNextStep: answerRefusalNextStepUnchanged,
		},
		{
			name:         "arm 1 ordering: ErrMachineSelfDecision wins even though it is also in isKnownApprovalRefusal's list",
			result:       elicitedAnswerResult{Err: fmt.Errorf("wrapped: %w", approval.ErrMachineSelfDecision), OnBehalfOf: "someone"},
			wantReason:   wantMachineText,
			wantNextStep: answerRefusalNextStepUnchanged,
		},
		{
			name:         "arm 2: errAnswerStateRefused",
			result:       elicitedAnswerResult{Err: errAnswerStateRefused},
			wantReason:   errAnswerStateRefused.Error(),
			wantNextStep: answerRefusalNextStepUnchanged,
		},
		{
			name:         "arm 2: errAnswerShape",
			result:       elicitedAnswerResult{Err: errAnswerShape},
			wantReason:   errAnswerShape.Error(),
			wantNextStep: answerRefusalNextStepUnchanged,
		},
		{
			name:         "arm 3: a malformed responder (too long) is never truncated silently",
			result:       elicitedAnswerResult{Err: fmt.Errorf("bound: %w", audit.ErrAssertedFieldTooLong), OnBehalfOf: ""},
			wantReason:   fmt.Errorf("bound: %w", audit.ErrAssertedFieldTooLong).Error(),
			wantNextStep: answerRefusalNextStepUnchanged,
		},
		{
			name:         "arm 4: errDeclineNotHonoured gets its own non-contradictory NextStep",
			result:       elicitedAnswerResult{Err: errDeclineNotHonoured, OnBehalfOf: "alice", stateReported: true, State: approval.StateApproved},
			wantReason:   errDeclineNotHonoured.Error(),
			wantNextStep: answerRefusalNextStepDeclineRecordedButNotHonoured,
		},
		{
			name: "arm 5: ErrNotPending on a decline-after-approval renders the decline-not-recorded NextStep",
			result: elicitedAnswerResult{
				Err: approval.ErrNotPending, OnBehalfOf: "alice", stateReported: true, State: approval.StateApproved, JobID: "",
			},
			wantReason:   renderApprovalError(approval.ErrNotPending).Error(),
			wantNextStep: answerRefusalNextStepDeclineNotRecorded,
		},
		{
			name: "arm 5: ErrNotPending on any other state says the request is closed, not that it can still be answered",
			result: elicitedAnswerResult{
				Err: approval.ErrNotPending, OnBehalfOf: "alice", stateReported: true, State: approval.StateDenied,
			},
			wantReason:   renderApprovalError(approval.ErrNotPending).Error(),
			wantNextStep: answerRefusalNextStepRequestClosed,
		},
		{
			name:         "arm 5: ErrRequesterExcluded says a different human must decide out-of-band, not that it can still be answered",
			result:       elicitedAnswerResult{Err: approval.ErrRequesterExcluded, OnBehalfOf: "alice"},
			wantReason:   renderApprovalError(approval.ErrRequesterExcluded).Error(),
			wantNextStep: answerRefusalNextStepRequesterExcluded,
		},
		{
			name:         "arm 5: capability.ErrApprovalUnavailable (decider never wired) says no endpoint can decide it",
			result:       elicitedAnswerResult{Err: capability.ErrApprovalUnavailable},
			wantReason:   renderApprovalError(capability.ErrApprovalUnavailable).Error(),
			wantNextStep: answerRefusalNextStepApprovalsUnavailable,
		},
		{
			name:         "the deciderReached-false catch-all: the decider was never reached, so nothing to say was recorded",
			result:       elicitedAnswerResult{Err: errors.New("some new sentinel")},
			wantNextStep: answerRefusalNextStepUnchanged,
		},
		{
			name:         "the default catch-all: a non-domain failure AFTER the decider ran must never claim the request is unchanged",
			result:       elicitedAnswerResult{Err: errors.New("capability: record audit entry: disk full"), OnBehalfOf: "alice", deciderReached: true},
			wantNextStep: answerRefusalNextStepMayAlreadyReflectAnswer,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := tc.result.refusalOutput()
			if tc.wantReason != "" && out.Reason != tc.wantReason {
				t.Errorf("Reason = %q, want %q", out.Reason, tc.wantReason)
			}
			if out.NextStep != tc.wantNextStep {
				t.Errorf("NextStep = %q, want %q", out.NextStep, tc.wantNextStep)
			}
		})
	}

	t.Run("the deciderReached-false catch-all never claims the answer was recorded", func(t *testing.T) {
		out := elicitedAnswerResult{Err: errors.New("boom")}.refusalOutput()
		if strings.Contains(out.Reason, "may have been recorded") {
			t.Errorf("Reason = %q, must not say the answer may have been recorded when the decider was never reached", out.Reason)
		}
	})

	t.Run("the default catch-all never claims nothing was recorded, or that the request is unchanged", func(t *testing.T) {
		out := elicitedAnswerResult{Err: errors.New("boom"), OnBehalfOf: "alice", deciderReached: true}.refusalOutput()
		if !strings.Contains(out.Reason, "may have been recorded") {
			t.Errorf("Reason = %q, must say the answer may have been recorded", out.Reason)
		}
		if out.NextStep != answerRefusalNextStepMayAlreadyReflectAnswer {
			t.Errorf("NextStep = %q, want %q", out.NextStep, answerRefusalNextStepMayAlreadyReflectAnswer)
		}
		if strings.Contains(out.NextStep, "unchanged") {
			t.Errorf("NextStep = %q, must not claim the request is unchanged: the decider ran and the audit write may still have landed "+
				"(security review #727 finding 1)", out.NextStep)
		}
	})

	t.Run("the default catch-all points the caller at the Control API's approval READ, never at approve_request", func(t *testing.T) {
		// approve_request records a NEW decision; it is not a way to read the
		// request's current state back (PR #738 follow-up review, finding 2).
		out := elicitedAnswerResult{Err: errors.New("boom"), OnBehalfOf: "alice", deciderReached: true}.refusalOutput()
		if !strings.Contains(out.Reason, "GET /api/v1/approvals/{id}") {
			t.Errorf("Reason = %q, want it to name the Control API's approval-read route", out.Reason)
		}
		if strings.Contains(out.Reason, "Confirm the request's state with approve_request") {
			t.Errorf("Reason = %q, must not suggest approve_request as a way to confirm state — it records a decision, not a read", out.Reason)
		}
	})

	t.Run("refusalOutput copies State/JobID/ExpiresAt only when stateReported", func(t *testing.T) {
		unreported := elicitedAnswerResult{Err: errAnswerStateRefused, State: approval.StateApproved, JobID: "job-leak", stateReported: false}.refusalOutput()
		if unreported.State != "" || unreported.JobID != "" || unreported.ExpiresAt != "" {
			t.Errorf("refusalOutput copied State/JobID/ExpiresAt with stateReported false: %+v", unreported)
		}

		expiresAt := fixedNow.Add(time.Hour)
		reported := elicitedAnswerResult{
			Err: errDeclineNotHonoured, State: approval.StateApproved, JobID: "job-1", ExpiresAt: expiresAt, stateReported: true,
		}.refusalOutput()
		if reported.State != approval.StateApproved.String() || reported.JobID != "job-1" || reported.ExpiresAt != expiresAt.UTC().Format(time.RFC3339) {
			t.Errorf("refusalOutput = %+v, want State/JobID/ExpiresAt copied verbatim", reported)
		}
	})
}

// TestRefusalOutput_NextStepNeverContradictsReason is a table over EVERY
// refusal shape refusalOutput can render (acceptElicitedAnswer's own
// refusals and classifyElicitedDecision's Outcome == elicitedRefused
// branches), asserting the NextStep never contradicts its own Reason (PR #738
// follow-up review, finding 1): a single "it can still be answered with
// approve_request or on the Control API endpoint" text used to be given to
// every known refusal alike, which was true of exactly one of them
// (ErrPlanChanged) and false of the rest, in different ways.
func TestRefusalOutput_NextStepNeverContradictsReason(t *testing.T) {
	const stillAnswerable = "It can still be answered with approve_request or on the Control API endpoint."

	cases := []struct {
		name    string
		result  elicitedAnswerResult
		forbid  []string // substrings the NextStep must NOT contain
		require []string // substrings the NextStep MUST contain
	}{
		{
			name:   "ErrNotFound: there is no request to answer at all",
			result: elicitedAnswerResult{Err: approval.ErrNotFound, OnBehalfOf: "alice"},
			forbid: []string{stillAnswerable, "can still be answered"},
		},
		{
			name:    "ErrWeakChannel: no in-band tool, approve_request included, can ever satisfy this rule",
			result:  elicitedAnswerResult{Err: approval.ErrWeakChannel, OnBehalfOf: "alice"},
			forbid:  []string{stillAnswerable, "can still be answered"},
			require: []string{"Control API's decision endpoint"},
		},
		{
			name:    "ErrRequesterExcluded: this call runs in the requesting Account's own session, so no in-band answer can ever decide it",
			result:  elicitedAnswerResult{Err: approval.ErrRequesterExcluded, OnBehalfOf: "alice"},
			forbid:  []string{stillAnswerable, "approve_request"},
			require: []string{"out-of-band"},
		},
		{
			name:    "ErrNotInAudience: this Account is not in the named audience",
			result:  elicitedAnswerResult{Err: approval.ErrNotInAudience, OnBehalfOf: "alice"},
			forbid:  []string{stillAnswerable, "can still be answered"},
			require: []string{"not in the request's audience"},
		},
		{
			name:   "ErrNotPending, no Request read at all (stateReported false)",
			result: elicitedAnswerResult{Err: approval.ErrNotPending, OnBehalfOf: "alice"},
			forbid: []string{stillAnswerable, "can still be answered"},
		},
		{
			name:   "ErrDuplicateDecider, no Request read at all (stateReported false)",
			result: elicitedAnswerResult{Err: approval.ErrDuplicateDecider, OnBehalfOf: "alice"},
			forbid: []string{stillAnswerable},
		},
		{
			// classifyElicitedDecision never produces ErrNotPending with a
			// terminal (denied) Request read back — Decide's denial is
			// terminal, so a denied Request is never re-decided into
			// ErrNotPending by this path. This row is a unit check of
			// refusalOutput's own branching, not a reachable outcome.
			name:   "ErrNotPending, Request read back terminal (denied): closed to everyone",
			result: elicitedAnswerResult{Err: approval.ErrNotPending, OnBehalfOf: "alice", stateReported: true, State: approval.StateDenied},
			forbid: []string{stillAnswerable, "can still be answered"},
		},
		{
			// Likewise unreachable from classifyElicitedDecision (a
			// duplicate decider on an already-denied Request is classified
			// elicitedDenied there, never routed through this refusal
			// shape) — a unit check of refusalOutput alone.
			name:   "ErrDuplicateDecider, Request read back terminal (denied): this Account's say is spent, not necessarily the request",
			result: elicitedAnswerResult{Err: approval.ErrDuplicateDecider, OnBehalfOf: "alice", stateReported: true, State: approval.StateDenied},
			forbid: []string{stillAnswerable},
		},
		{
			name: "ErrNotPending, approved with no Job bound: a decline that lost the race, not recorded",
			result: elicitedAnswerResult{
				Err: approval.ErrNotPending, OnBehalfOf: "alice", stateReported: true, State: approval.StateApproved, JobID: "",
			},
			require: []string{"decline was not recorded"},
			forbid:  []string{stillAnswerable},
		},
		{
			name: "ErrDuplicateDecider, approved with no Job bound: a decline that lost the race, not recorded",
			result: elicitedAnswerResult{
				Err: approval.ErrDuplicateDecider, OnBehalfOf: "alice", stateReported: true, State: approval.StateApproved, JobID: "",
			},
			require: []string{"decline was not recorded"},
			forbid:  []string{stillAnswerable},
		},
		{
			name:    "ErrPlanChanged: re-reading the current plan_hash and answering it IS what this Reason asks for",
			result:  elicitedAnswerResult{Err: approval.ErrPlanChanged, OnBehalfOf: "alice"},
			require: []string{"can still be answered"},
		},
		{
			name:   "capability.ErrApprovalUnavailable: no decider is configured, so no endpoint exists at all",
			result: elicitedAnswerResult{Err: capability.ErrApprovalUnavailable},
			forbid: []string{stillAnswerable, "can still be answered"},
		},
		{
			name:   "ErrMachineSelfDecision: AP-64's own text, not renderApprovalError's — a later call CAN still name an approver",
			result: elicitedAnswerResult{Err: approval.ErrMachineSelfDecision, OnBehalfOf: "someone"},
			// This one legitimately keeps the generic text: nothing about
			// this Account or channel is refused, only THIS call named no
			// human.
			require: []string{"can still be answered"},
		},
		{
			name:   "errDeclineNotHonoured: the decline WAS recorded, so must never say it was not",
			result: elicitedAnswerResult{Err: errDeclineNotHonoured, OnBehalfOf: "alice", stateReported: true, State: approval.StateApproved},
			forbid: []string{"was not recorded", stillAnswerable},
		},
		{
			// classifyElicitedDecision's own fail-closed backstop: err is nil
			// but req.State is unrecognised, so the decision WAS recorded —
			// "unchanged" or "can still be answered" would contradict that.
			name:    "errUnknownRequestState: the decision was recorded, only the resulting state is unrecognised",
			result:  elicitedAnswerResult{Err: errUnknownRequestState, OnBehalfOf: "alice", stateReported: true},
			forbid:  []string{"unchanged", "can still be answered"},
			require: []string{"Control API"},
		},
		{
			// The bare form: acceptElicitedAnswer's own refusal before the
			// decider is ever reached (OnBehalfOf empty, no decision made).
			name:    "errAnswerStateRefused: the requestState never opened",
			result:  elicitedAnswerResult{Err: errAnswerStateRefused},
			require: []string{"can still be answered"},
		},
		{
			// The wrapped form acceptElicitedAnswer actually returns when the
			// seal opens but its binding to this call fails — errors.Is must
			// still recognise it through the %w wrapping.
			name:    "errAnswerStateRefused: wrapped, as acceptElicitedAnswer's binding-mismatch path returns it",
			result:  elicitedAnswerResult{Err: fmt.Errorf("%w: %w", errAnswerStateRefused, requeststate.ErrBindingMismatch)},
			require: []string{"can still be answered"},
		},
		{
			// The retry did not carry exactly one elicitation response keyed
			// by the sealed request ID — nothing was recorded.
			name:    "errAnswerShape: the retry's InputResponses do not match the sealed request",
			result:  elicitedAnswerResult{Err: errAnswerShape},
			require: []string{"can still be answered"},
		},
		{
			// assertedApprover's malformed-responder refusal (too long):
			// refused before the decider is ever called, so nothing was
			// recorded and re-answering is still on the table.
			name:    "audit.ErrAssertedFieldTooLong: the responder assertion is malformed",
			result:  elicitedAnswerResult{Err: fmt.Errorf("the asserted approver is refused: %w", audit.ErrAssertedFieldTooLong)},
			require: []string{"can still be answered"},
		},
		{
			// assertedApprover's malformed-responder refusal (control
			// characters): same as above, different sentinel.
			name:    "audit.ErrAssertedFieldInvalid: the responder assertion is malformed",
			result:  elicitedAnswerResult{Err: fmt.Errorf("the asserted approver is refused: %w", audit.ErrAssertedFieldInvalid)},
			require: []string{"can still be answered"},
		},
		{
			name:    "the deciderReached-false catch-all: the decider was never reached, approve_request itself is still untried",
			result:  elicitedAnswerResult{Err: errors.New("some new sentinel")},
			require: []string{"can still be answered"},
		},
		{
			name:   "the default catch-all: a non-domain failure after the decider ran must never claim the request is unchanged",
			result: elicitedAnswerResult{Err: errors.New("capability: record audit entry: disk full"), OnBehalfOf: "alice", deciderReached: true},
			forbid: []string{"unchanged", stillAnswerable},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := tc.result.refusalOutput()
			for _, s := range tc.forbid {
				if strings.Contains(out.NextStep, s) {
					t.Errorf("NextStep = %q, must not contain %q — contradicts Reason %q", out.NextStep, s, out.Reason)
				}
			}
			for _, s := range tc.require {
				if !strings.Contains(out.NextStep, s) {
					t.Errorf("NextStep = %q, want it to contain %q", out.NextStep, s)
				}
			}
		})
	}
}

// TestNextStepConstants_CarryNoReviewerReferences guards every model-facing
// NextStep constant against the class of leak a prior follow-up pass fixed:
// a PR or code-review citation belongs in a Go comment, never in text an
// AI-agent reads back as instructions.
func TestNextStepConstants_CarryNoReviewerReferences(t *testing.T) {
	nextSteps := map[string]string{
		"nextStepAnswerRecorded":                             nextStepAnswerRecorded,
		"nextStepAnswerNotRecordedAlreadyDecided":            nextStepAnswerNotRecordedAlreadyDecided,
		"nextStepAnswerNotRecordedDuplicateDecider":          nextStepAnswerNotRecordedDuplicateDecider,
		"approveRequestNextStep":                             approveRequestNextStep,
		"answerRefusalNextStepUnchanged":                     answerRefusalNextStepUnchanged,
		"answerRefusalNextStepCannotAnswerHere":              answerRefusalNextStepCannotAnswerHere,
		"answerRefusalNextStepIneligibleAccount":             answerRefusalNextStepIneligibleAccount,
		"answerRefusalNextStepRequesterExcluded":             answerRefusalNextStepRequesterExcluded,
		"answerRefusalNextStepNoSuchRequest":                 answerRefusalNextStepNoSuchRequest,
		"answerRefusalNextStepRequestClosed":                 answerRefusalNextStepRequestClosed,
		"answerRefusalNextStepAlreadyDecidedByThisAccount":   answerRefusalNextStepAlreadyDecidedByThisAccount,
		"answerRefusalNextStepApprovalsUnavailable":          answerRefusalNextStepApprovalsUnavailable,
		"answerRefusalNextStepDeclineNotRecorded":            answerRefusalNextStepDeclineNotRecorded,
		"answerRefusalNextStepDeclineRecordedButNotHonoured": answerRefusalNextStepDeclineRecordedButNotHonoured,
		"answerRefusalNextStepMayAlreadyReflectAnswer":       answerRefusalNextStepMayAlreadyReflectAnswer,
	}

	for name, text := range nextSteps {
		if strings.Contains(text, "PR #") {
			t.Errorf("%s = %q, must not carry a PR reference — an AI-agent reads this back as instructions", name, text)
		}
		lower := strings.ToLower(text)
		if strings.Contains(lower, "review") || strings.Contains(lower, "finding") {
			t.Errorf("%s = %q, must not carry a reviewer reference — an AI-agent reads this back as instructions", name, text)
		}
	}
}
