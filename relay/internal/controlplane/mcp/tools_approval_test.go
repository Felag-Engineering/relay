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

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp/requeststate"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

// tools_approval_test.go is #726's proof: acceptElicitedAnswer and
// classifyElicitedDecision (both unexported — hence package mcp, not
// mcp_test) are tested at the handler seam, exactly the way approve_request
// is: real fixtures, a real requeststate.Sealer, and a decider double that
// records exactly what it was handed.
//
// Nothing here wires acceptElicitedAnswer into a tool handler — that is
// S4a-2 (#725's follow-on). Every test calls it directly.

// -----------------------------------------------------------------------
// Fixtures shared by every test below
// -----------------------------------------------------------------------

var fixedNow = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

const (
	answerTool       = "run_operation"
	answerRequestID  = "apr-1"
	answerPlanHash   = "hash-1"
	answerAccountID  = "acct-caller"
	answerCallerCred = accounts.TokenPrefix + "0123456789abcdef.tools-approval-test" //nolint:gosec // test fixture, not a real credential
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

// emissionArgsDigest mirrors elicit.go's callArgsDigest (#725, PR #736,
// unmerged): both digest requeststate.DigestArgs over json.Marshal of the
// handler's TYPED input value (runOperationInput or rawExecInput), never the
// raw wire bytes of params.arguments. This is a test-local copy that exists
// only to pin the contract from this side of the seam — see
// elicitedAnswer.ArgsDigest's doc — not a production helper; production
// emission is #725's, and this file must not create one.
func emissionArgsDigest(t *testing.T, in any) requeststate.Digest {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("json.Marshal(%#v): %v", in, err)
	}
	d, err := requeststate.DigestArgs(raw)
	if err != nil {
		t.Fatalf("DigestArgs(%s): %v", raw, err)
	}
	return d
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
// served over plain HTTP by httptest (mirrors taskgolden_test.go's
// goldenServer; that file is package mcp_test, so the verifier is
// redeclared here rather than shared).
func approveRequestServer(t *testing.T, decider ApprovalDecider) *httptest.Server {
	t.Helper()
	handler := New(nil, stubOpsLister{}, noopExecutor{}, nil, nil, nil, WithApprovalDecider(decider))
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
	// capability.Service.DecideApproval builds a Decision solely from
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
	result := acceptElicitedAnswer(ctx, recB, sealer, fixedNow, principal, elicitedAnswer{
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
	result := acceptElicitedAnswer(context.Background(), rec, sealer, fixedNow, p, elicitedAnswer{
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
			name: "a nil sealer",
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
			result := acceptElicitedAnswer(context.Background(), rec, useSealer, now, p, elicitedAnswer{
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
			result := acceptElicitedAnswer(context.Background(), rec, sealer, fixedNow, p, elicitedAnswer{
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
			ArgsDigest: emissionArgsDigest(t, typedIn),
			ExpiresAt:  fixedNow.Add(time.Hour),
		}
		sealed := sealWith(t, sealer, base, nil)

		t.Run("accepted: the retried call's raw JSON reorders keys and adds whitespace, decoded into the same typed struct then digested the way emission does", func(t *testing.T) {
			retriedRaw := []byte(`{ "args": { "unit": "nginx" }, "operation":  "service.restart" }`)
			var retried runOperationInput
			if err := json.Unmarshal(retriedRaw, &retried); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			digest := emissionArgsDigest(t, retried)

			rec := &recordingDecider{resp: approval.Request{ID: answerRequestID, State: approval.StateApproved, PlanHash: answerPlanHash}}
			result := acceptElicitedAnswer(context.Background(), rec, sealer, fixedNow, p, elicitedAnswer{
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
			result := acceptElicitedAnswer(context.Background(), rec, sealer, fixedNow, p, elicitedAnswer{
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
			ArgsDigest: emissionArgsDigest(t, typedIn),
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
		result := acceptElicitedAnswer(context.Background(), rec, sealer, fixedNow, p, elicitedAnswer{
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
		result := acceptElicitedAnswer(context.Background(), nil, sealer, fixedNow, p, elicitedAnswer{
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
		result := acceptElicitedAnswer(context.Background(), rec, sealer, fixedNow, noAccount, elicitedAnswer{
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
			result := acceptElicitedAnswer(context.Background(), rec, sealer, fixedNow, p, elicitedAnswer{
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
		result := acceptElicitedAnswer(context.Background(), rec, sealer, fixedNow, p, elicitedAnswer{
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
		result := acceptElicitedAnswer(context.Background(), rec, sealer, fixedNow, p, elicitedAnswer{
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
// AP-70 (as amended): approve_request's approver is bound the same way
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
			result := acceptElicitedAnswer(context.Background(), rec, sealer, fixedNow, p, elicitedAnswer{
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
			switch typ.Kind() { //nolint:exhaustive // only the recursive shapes need walking
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

		result := acceptElicitedAnswer(context.Background(), rec, sealer, fixedNow, p, elicitedAnswer{
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
