package main

import (
	"context"
	"errors"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/revocation"
)

func TestRevocationActs_MapsTheCascadeErrorsOntoTheCapabilitySentinels(t *testing.T) {
	cause := errors.New("test: store unavailable")
	cases := []struct {
		name           string
		in             error
		wantIncomplete bool
		wantNotRecord  bool
		wantSame       bool // the error passes through unchanged
	}{
		{name: "nil", in: nil},
		{name: "shortfall", in: &revocation.CascadeShortfall{Unrecorded: 1, Total: 2}, wantNotRecord: true},
		{name: "incomplete", in: &revocation.IncompleteCascade{Err: cause}, wantIncomplete: true},
		{name: "cancelled", in: context.Canceled, wantSame: true},
		{name: "other", in: cause, wantSame: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := capabilityRevokeError(tc.in)
			if tc.in == nil {
				if got != nil {
					t.Fatalf("got %v, want nil", got)
				}
				return
			}
			if errors.Is(got, capability.ErrRevokeCascadeIncomplete) != tc.wantIncomplete {
				t.Errorf("Is ErrRevokeCascadeIncomplete = %v, want %v", !tc.wantIncomplete, tc.wantIncomplete)
			}
			if errors.Is(got, capability.ErrRevokeCascadeNotRecorded) != tc.wantNotRecord {
				t.Errorf("Is ErrRevokeCascadeNotRecorded = %v, want %v", !tc.wantNotRecord, tc.wantNotRecord)
			}
			if tc.wantSame && got != tc.in {
				t.Errorf("got %v, want the error unchanged", got)
			}
			if !errors.Is(got, tc.in) {
				t.Errorf("got %v, want the original error still matchable", got)
			}
		})
	}
}
