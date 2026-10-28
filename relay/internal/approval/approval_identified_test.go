package approval

import (
	"errors"
	"testing"
	"time"
)

// TestDecide_MachineAPITokenAnswerIsInBandSelfConfirmation: a machine's own
// API-token-session answer to its own request is accepted in-band only.
//
// Proves AP-87, AP-48.
func TestDecide_MachineAPITokenAnswerIsInBandSelfConfirmation(t *testing.T) {
	cases := []struct {
		name    string
		channel Channel
		by      IdentifiedBy
		wantErr error
	}{
		{"api token session, in-band", ChannelInBand, IdentifiedByAPITokenSession, nil},
		{"api token session, out-of-band", ChannelOutOfBand, IdentifiedByAPITokenSession, ErrMachineSelfDecision},
		{"unrecorded, in-band, no assertion", ChannelInBand, IdentifiedByUnrecorded, ErrMachineSelfDecision},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := req(1, true)
			rule.Channel = ChannelInBand
			r := newTestRequest(t, rule)
			d := Decision{
				AccountID: "acct-mike", Account: "mike", Approve: true,
				Channel: tc.channel, PlanHash: "hash-abc", DeciderHuman: false,
				IdentifiedBy: tc.by, At: t0.Add(time.Minute),
			}
			_, err := r.Decide(d, t0.Add(time.Minute))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestIdentifiedBy_StringAndParseRoundTrip(t *testing.T) {
	for _, id := range []IdentifiedBy{
		IdentifiedByUnrecorded, IdentifiedByOAuthSession,
		IdentifiedByAPITokenSession, IdentifiedByResponderAssertion,
	} {
		got, err := ParseIdentifiedBy(id.String())
		if err != nil || got != id {
			t.Errorf("ParseIdentifiedBy(%q) = %v, %v; want %v", id.String(), got, err, id)
		}
	}
	if IdentifiedByUnrecorded.String() != "" {
		t.Errorf("Unrecorded renders %q, want empty", IdentifiedByUnrecorded.String())
	}
	if _, err := ParseIdentifiedBy("oauth"); !errors.Is(err, ErrUnknownIdentifiedBy) {
		t.Errorf("err = %v, want ErrUnknownIdentifiedBy", err)
	}
}
