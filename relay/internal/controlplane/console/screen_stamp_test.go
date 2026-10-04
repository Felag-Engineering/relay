package console

import (
	"testing"
	"time"
)

func TestUTCStampConvertsToUTCAndKeepsSeconds(t *testing.T) {
	zone := time.FixedZone("UTC+2", 2*60*60)
	at := time.Date(2026, 10, 4, 14, 5, 9, 0, zone)
	if got, want := utcStamp(at), "2026-10-04 12:05:09Z"; got != want {
		t.Fatalf("utcStamp = %q, want %q", got, want)
	}
}
