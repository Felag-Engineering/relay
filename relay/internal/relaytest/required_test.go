package relaytest

import (
	"fmt"
	"strings"
	"testing"
)

// recordingTB records which of Skip and Fatalf SkipMissingBin called, without ending the
// real test.
type recordingTB struct {
	skipped, fataled bool
	msg              string
}

func (r *recordingTB) Helper() {}
func (r *recordingTB) Skip(args ...any) {
	r.skipped = true
	r.msg = fmt.Sprint(args...)
}
func (r *recordingTB) Fatalf(format string, args ...any) {
	r.fataled = true
	r.msg = fmt.Sprintf(format, args...)
}

func TestSkipMissingBin_SkipsWhenNotRequired(t *testing.T) {
	for _, v := range []string{"", "0", "true"} {
		t.Run("RELAY_E2E_REQUIRED="+v, func(t *testing.T) {
			t.Setenv(E2ERequiredEnv, v)
			r := &recordingTB{}
			SkipMissingBin(r, "RELAY_DAEMON_BIN not set")
			if !r.skipped || r.fataled {
				t.Fatalf("skipped=%v fataled=%v, want a skip only", r.skipped, r.fataled)
			}
		})
	}
}

func TestSkipMissingBin_FailsWhenRequired(t *testing.T) {
	t.Setenv(E2ERequiredEnv, "1")
	r := &recordingTB{}
	SkipMissingBin(r, "RELAY_DAEMON_BIN not set")
	if !r.fataled || r.skipped {
		t.Fatalf("skipped=%v fataled=%v, want a failure only", r.skipped, r.fataled)
	}
	if !strings.Contains(r.msg, "RELAY_DAEMON_BIN not set") || !strings.Contains(r.msg, E2ERequiredEnv) {
		t.Fatalf("failure message %q should name the missing binary and the switch", r.msg)
	}
}
