package capability

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// revokeSink is a spyAuditSink that is also a RevokeRecorder.
type revokeSink struct {
	*spyAuditSink
	nodeEvents   []NodeRevokeEvent
	nodeCtxErrs  []error
	nodeDeadline []time.Time
	tokenEvents  []EnrollmentTokenRevokeEvent
	nodeErr      error
	tokenErr     error
}

func (s *revokeSink) RecordNodeRevokes(ctx context.Context, e NodeRevokeEvent) error {
	if s.nodeErr != nil {
		return s.nodeErr
	}
	e.NodeIDs = append([]string(nil), e.NodeIDs...)
	s.nodeEvents = append(s.nodeEvents, e)
	s.nodeCtxErrs = append(s.nodeCtxErrs, ctx.Err())
	dl, _ := ctx.Deadline()
	s.nodeDeadline = append(s.nodeDeadline, dl)
	return nil
}

func (s *revokeSink) RecordEnrollmentTokenRevoke(_ context.Context, e EnrollmentTokenRevokeEvent) error {
	if s.tokenErr != nil {
		return s.tokenErr
	}
	s.tokenEvents = append(s.tokenEvents, e)
	return nil
}

// fakeRevoker records its calls, hands record the configured cascade and
// returns the configured error. beforeRecord runs just before record, where a
// test cancels the request.
type fakeRevoker struct {
	nodeCalls    []string
	tokenCalls   []string
	cascade      []string
	err          error
	beforeRecord func()
}

func (f *fakeRevoker) run(record func([]string) error) error {
	if f.beforeRecord != nil {
		f.beforeRecord()
	}
	if err := record(f.cascade); err != nil {
		return err
	}
	return f.err
}

func (f *fakeRevoker) RevokeNodeRecorded(_ context.Context, nodeID string, record func([]string) error) error {
	f.nodeCalls = append(f.nodeCalls, nodeID)
	return f.run(record)
}

func (f *fakeRevoker) RevokeToken(_ context.Context, tokenID string, record func([]string) error) error {
	f.tokenCalls = append(f.tokenCalls, tokenID)
	return f.run(record)
}

type revocationsFix struct {
	revs    *Revocations
	authz   *spyAuthorizer
	sink    *revokeSink
	revoker *fakeRevoker
	logs    *bytes.Buffer
}

func newRevocationsFix() *revocationsFix {
	f := &revocationsFix{
		authz:   &spyAuthorizer{},
		sink:    &revokeSink{spyAuditSink: &spyAuditSink{}},
		revoker: &fakeRevoker{cascade: []string{"node-1"}},
		logs:    &bytes.Buffer{},
	}
	log := slog.New(slog.NewTextHandler(f.logs, nil))
	control := newControl(NewRecorder(f.sink, nil, log), f.authz, noopFreezeStore{})
	f.revs = newRevocations(control, f.revoker, f.sink)
	return f
}

var revokeAdmin = Principal{AccountID: "acct-admin", Account: "mike", Role: "admin", Kind: PrincipalKindHuman, Source: "203.0.113.9"}

func TestRevocations_EachEntryAuthorizesAtItsOwnControlAction(t *testing.T) {
	f := newRevocationsFix()
	if err := f.revs.RevokeNodeWithReason(context.Background(), revokeAdmin, "node-1", "stolen"); err != nil {
		t.Fatalf("node revoke: %v", err)
	}
	if len(f.authz.controlCalls) != 1 || f.authz.controlCalls[0] != ControlRevokeNode {
		t.Errorf("node controlCalls = %v, want exactly [%s]", f.authz.controlCalls, ControlRevokeNode)
	}

	f = newRevocationsFix()
	if err := f.revs.RevokeEnrollmentToken(context.Background(), revokeAdmin, "tok-1"); err != nil {
		t.Fatalf("token revoke: %v", err)
	}
	if len(f.authz.controlCalls) != 1 || f.authz.controlCalls[0] != ControlRevokeEnrollmentToken {
		t.Errorf("token controlCalls = %v, want exactly [%s]", f.authz.controlCalls, ControlRevokeEnrollmentToken)
	}
}

func TestRevocations_ARefusalIsOneRefusalRecordAndNothingIsRevoked(t *testing.T) {
	asserted := Assertions{OnBehalfOf: "ops-team", SessionRef: "conv_1"}
	ctx := WithAssertions(context.Background(), asserted)
	entries := map[string]func(f *revocationsFix) error{
		// An unusable reason or id must not change the answer: the caller is
		// refused first.
		"node":  func(f *revocationsFix) error { return f.revs.RevokeNodeWithReason(ctx, revokeAdmin, "node-1", "") },
		"token": func(f *revocationsFix) error { return f.revs.RevokeEnrollmentToken(ctx, revokeAdmin, "tok\nbad") },
	}
	for name, call := range entries {
		t.Run(name, func(t *testing.T) {
			f := newRevocationsFix()
			f.authz.controlErr = errRefused

			err := call(f)
			if !errors.Is(err, errRefused) {
				t.Fatalf("error = %v, want the refusal", err)
			}
			if len(f.revoker.nodeCalls)+len(f.revoker.tokenCalls) != 0 {
				t.Error("a refused caller reached the revoker")
			}
			if len(f.sink.entries) != 1 || f.sink.entries[0].Kind != AuditKindRefusal {
				t.Fatalf("entries = %+v, want exactly one refusal", f.sink.entries)
			}
			got := f.sink.entries[0]
			if got.Principal != revokeAdmin || got.Asserted != asserted {
				t.Errorf("refusal Principal/Asserted = %+v / %+v, want the caller's", got.Principal, got.Asserted)
			}
			if len(f.sink.nodeEvents)+len(f.sink.tokenEvents) != 0 {
				t.Error("a refused revoke wrote a revoke record")
			}
		})
	}
}

// Proves EX-7.
func TestRevocations_AuthorizeWithoutAssertions(t *testing.T) {
	asserted := Assertions{OnBehalfOf: "ops-team", ChangeRef: "CHG-1"}
	ctx := WithAssertions(context.Background(), asserted)
	spy := &assertionSpyAuthorizer{}
	sink := &revokeSink{spyAuditSink: &spyAuditSink{}}
	revoker := &fakeRevoker{cascade: []string{"node-1"}}
	revs := newRevocations(newControl(NewRecorder(sink, nil, nil), spy, noopFreezeStore{}), revoker, sink)

	if err := revs.RevokeNodeWithReason(ctx, revokeAdmin, "node-1", "stolen"); err != nil {
		t.Fatalf("node revoke: %v", err)
	}
	if err := revs.RevokeEnrollmentToken(ctx, revokeAdmin, "tok-1"); err != nil {
		t.Fatalf("token revoke: %v", err)
	}
	if !spy.called {
		t.Fatal("the Authorizer was never asked")
	}
	if !spy.sawAssertions.IsZero() {
		t.Errorf("the Authorizer saw %+v, want none: a decision never rests on caller-asserted attribution", spy.sawAssertions)
	}
	for _, e := range sink.nodeEvents {
		if e.Asserted != asserted {
			t.Errorf("NodeRevokeEvent.Asserted = %+v, want %+v", e.Asserted, asserted)
		}
	}
	if len(sink.tokenEvents) != 1 || sink.tokenEvents[0].Asserted != asserted {
		t.Errorf("token events = %+v, want one carrying %+v", sink.tokenEvents, asserted)
	}
}

func TestRevocations_NodeRevokeRefusesAnUnusableReasonBeforeTheAct(t *testing.T) {
	cases := map[string]struct {
		reason string
		want   error
	}{
		"empty":     {"  ", ErrRevokeReasonRequired},
		"too long":  {strings.Repeat("x", MaxRevokeReasonBytes+1), ErrRevokeReasonTooLong},
		"malformed": {"bad\x07reason", ErrRevokeReasonMalformed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRevocationsFix()
			err := f.revs.RevokeNodeWithReason(context.Background(), revokeAdmin, "node-1", tc.reason)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if len(f.revoker.nodeCalls) != 0 || len(f.sink.nodeEvents) != 0 || len(f.sink.entries) != 0 {
				t.Error("an unusable reason reached the revoker or the trail")
			}
		})
	}
}

func TestRevocations_NodeRevokeRecordsOneAttributedRecordForThatNode(t *testing.T) {
	asserted := Assertions{OnBehalfOf: "ops-team"}
	f := newRevocationsFix()
	f.revoker.cascade = []string{"node-7"}

	if err := f.revs.RevokeNodeWithReason(WithAssertions(context.Background(), asserted), revokeAdmin, "node-7", "  stolen laptop  "); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if len(f.sink.nodeEvents) != 1 {
		t.Fatalf("node events = %d, want 1", len(f.sink.nodeEvents))
	}
	e := f.sink.nodeEvents[0]
	if len(e.NodeIDs) != 1 || e.NodeIDs[0] != "node-7" {
		t.Errorf("NodeIDs = %v, want [node-7]", e.NodeIDs)
	}
	if e.Reason != "stolen laptop" {
		t.Errorf("Reason = %q, want the trimmed reason", e.Reason)
	}
	if e.Principal != revokeAdmin || e.Asserted != asserted {
		t.Errorf("Principal/Asserted = %+v / %+v, want the caller's", e.Principal, e.Asserted)
	}
	if len(f.revoker.nodeCalls) != 1 || f.revoker.nodeCalls[0] != "node-7" {
		t.Errorf("nodeCalls = %v, want [node-7]", f.revoker.nodeCalls)
	}
}

func TestRevocations_AnUnrecordedNodeRevokeIsReturned(t *testing.T) {
	f := newRevocationsFix()
	f.sink.nodeErr = errors.New("test: audit store down")

	err := f.revs.RevokeNodeWithReason(context.Background(), revokeAdmin, "node-1", "stolen")
	if !errors.Is(err, f.sink.nodeErr) {
		t.Fatalf("error = %v, want the record failure", err)
	}
}

func TestRevocations_TokenRevokeRecordsTheCascadeThenTheTokenRevoke(t *testing.T) {
	f := newRevocationsFix()
	f.revoker.cascade = []string{"node-1", "node-2"}

	if err := f.revs.RevokeEnrollmentToken(context.Background(), revokeAdmin, "tok-1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if len(f.sink.nodeEvents) != 1 {
		t.Fatalf("node events = %d, want 1", len(f.sink.nodeEvents))
	}
	n := f.sink.nodeEvents[0]
	if n.Reason != CascadeRevokeReason("tok-1") || len(n.NodeIDs) != 2 || n.Principal != revokeAdmin {
		t.Errorf("cascade event = %+v, want both Nodes, the cascade reason and the caller", n)
	}
	if len(f.sink.tokenEvents) != 1 {
		t.Fatalf("token events = %d, want 1", len(f.sink.tokenEvents))
	}
	if e := f.sink.tokenEvents[0]; e.TokenID != "tok-1" || e.CascadeIncomplete || e.Principal != revokeAdmin {
		t.Errorf("token event = %+v, want tok-1, complete, the caller", e)
	}
}

func TestRevocations_TokenRevokeCascadeRecordsOutliveTheRequest(t *testing.T) {
	f := newRevocationsFix()
	ctx, cancel := context.WithCancel(context.Background())
	f.revoker.beforeRecord = cancel
	before := time.Now()

	if err := f.revs.RevokeEnrollmentToken(ctx, revokeAdmin, "tok-1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if len(f.sink.nodeCtxErrs) != 1 {
		t.Fatalf("cascade writes = %d, want 1", len(f.sink.nodeCtxErrs))
	}
	if err := f.sink.nodeCtxErrs[0]; err != nil {
		t.Errorf("the cascade record's context ended with the request: %v", err)
	}
	deadline := f.sink.nodeDeadline[0]
	if deadline.IsZero() || deadline.After(before.Add(cascadeAuditBudget).Add(time.Second)) {
		t.Errorf("deadline = %v, want one within cascadeAuditBudget", deadline)
	}
}

func TestRevocations_IncompleteCascadeRecordsTheTokenRevokeMarkedIncomplete(t *testing.T) {
	f := newRevocationsFix()
	f.revoker.err = ErrRevokeCascadeIncomplete

	err := f.revs.RevokeEnrollmentToken(context.Background(), revokeAdmin, "tok-1")
	if !errors.Is(err, ErrRevokeCascadeIncomplete) {
		t.Fatalf("error = %v, want ErrRevokeCascadeIncomplete", err)
	}
	if len(f.sink.tokenEvents) != 1 || !f.sink.tokenEvents[0].CascadeIncomplete {
		t.Errorf("token events = %+v, want one marked incomplete", f.sink.tokenEvents)
	}
}

func TestRevocations_UnrecordedCascadeStillRecordsTheTokenRevoke(t *testing.T) {
	f := newRevocationsFix()
	f.revoker.err = ErrRevokeCascadeNotRecorded

	err := f.revs.RevokeEnrollmentToken(context.Background(), revokeAdmin, "tok-1")
	if !errors.Is(err, ErrRevokeCascadeNotRecorded) {
		t.Fatalf("error = %v, want ErrRevokeCascadeNotRecorded", err)
	}
	if len(f.sink.tokenEvents) != 1 || f.sink.tokenEvents[0].CascadeIncomplete {
		t.Errorf("token events = %+v, want one, not marked incomplete", f.sink.tokenEvents)
	}
}

func TestRevocations_AFailedTokenRevokeRecordsNoTokenRevoke(t *testing.T) {
	f := newRevocationsFix()
	f.revoker.err = errors.New("test: token store down")

	err := f.revs.RevokeEnrollmentToken(context.Background(), revokeAdmin, "tok-1")
	if !errors.Is(err, f.revoker.err) {
		t.Fatalf("error = %v, want the revoker's", err)
	}
	if len(f.sink.tokenEvents) != 0 {
		t.Errorf("token events = %+v, want none for a revoke that failed", f.sink.tokenEvents)
	}
}

func TestRevocations_AnUnrecordedTokenRevokeIsLoggedAndTheRevokeStands(t *testing.T) {
	f := newRevocationsFix()
	f.sink.tokenErr = errors.New("test: audit store down")

	if err := f.revs.RevokeEnrollmentToken(context.Background(), revokeAdmin, "tok-1"); err != nil {
		t.Fatalf("error = %v, want nil: the revoke took effect", err)
	}
	if got := f.logs.String(); !strings.Contains(got, "tok-1") || !strings.Contains(got, "not recorded") {
		t.Errorf("log = %q, want a line naming the token id", got)
	}
}

func TestNewRevocations_PanicsOnAnUnsafeComposition(t *testing.T) {
	real := &spyAuthorizer{}
	sink := &revokeSink{spyAuditSink: &spyAuditSink{}}
	revoker := &fakeRevoker{}
	good := func(authz Authorizer, s AuditSink) *Control {
		return newControl(NewRecorder(s, nil, nil), authz, noopFreezeStore{})
	}
	cases := map[string]func(){
		"nil control":    func() { NewRevocations(nil, revoker) },
		"nil revoker":    func() { NewRevocations(good(real, sink), nil) },
		"allow-all":      func() { NewRevocations(good(allowAllAuthorizer{}, sink), revoker) },
		"no-op sink":     func() { NewRevocations(good(real, noopAuditSink{}), revoker) },
		"not a recorder": func() { NewRevocations(good(real, plainTagSink{&spyAuditSink{}}), revoker) },
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("did not panic")
				}
			}()
			f()
		})
	}
	if NewRevocations(good(real, sink), revoker) == nil {
		t.Error("a safe composition returned nil")
	}
}
