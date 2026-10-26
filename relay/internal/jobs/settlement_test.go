package jobs

import (
	"context"
	"testing"
)

func TestSettlement_SettleReleasesEachHoldOnce(t *testing.T) {
	ctx, s := WithSettlement(context.Background())
	if SettlementFrom(ctx) != s {
		t.Fatal("SettlementFrom did not return the Settlement in ctx")
	}
	var released int
	release := func() { released++ }
	for range 2 {
		if !s.Hold(release) {
			t.Fatal("Hold refused before Settle")
		}
	}
	s.Settle()
	s.Settle()
	if released != 2 {
		t.Fatalf("released %d times, want 2", released)
	}
	if s.Hold(func() { released++ }) {
		t.Fatal("Hold accepted after Settle")
	}
	if released != 2 {
		t.Fatalf("a refused Hold ran its release")
	}
}

func TestSettlement_AbsentAndNil(t *testing.T) {
	if SettlementFrom(context.Background()) != nil {
		t.Fatal("SettlementFrom found a Settlement in a bare context")
	}
	var s *Settlement
	s.Settle()
}
