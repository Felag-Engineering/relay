package controlplane

import (
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

func TestRenderClockSkew_MeasuredZeroIsNotNotMeasured(t *testing.T) {
	at := time.Date(2026, 7, 10, 11, 59, 0, 0, time.UTC)

	unmeasured := RenderClockSkew(registry.Node{})
	if unmeasured.Measured || unmeasured.SkewMs != nil || unmeasured.MeasuredAt != "" {
		t.Errorf("zero Node = %+v, want not measured with no value", unmeasured)
	}

	measured := RenderClockSkew(registry.Node{ClockSkew: 0, ClockSkewMeasuredAt: at})
	if !measured.Measured || measured.SkewMs == nil || *measured.SkewMs != 0 {
		t.Fatalf("measured zero = %+v, want Measured with SkewMs pointing at 0", measured)
	}
	if measured.MeasuredAt != "2026-07-10T11:59:00Z" {
		t.Errorf("MeasuredAt = %q, want 2026-07-10T11:59:00Z", measured.MeasuredAt)
	}

	behind := RenderClockSkew(registry.Node{ClockSkew: -2500 * time.Millisecond, ClockSkewMeasuredAt: at})
	if behind.SkewMs == nil || *behind.SkewMs != -2500 {
		t.Errorf("behind SkewMs = %v, want -2500", behind.SkewMs)
	}
}

func TestRenderFirstConnect_NeverConnectedHasNoTime(t *testing.T) {
	if got := RenderFirstConnect(registry.Node{}); got.EverConnected || got.At != "" {
		t.Errorf("zero Node = %+v, want never connected with no time", got)
	}
	at := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	got := RenderFirstConnect(registry.Node{FirstConnectedAt: at})
	if !got.EverConnected || got.At != "2026-07-10T09:00:00Z" {
		t.Errorf("connected = %+v, want EverConnected at 2026-07-10T09:00:00Z", got)
	}
}
