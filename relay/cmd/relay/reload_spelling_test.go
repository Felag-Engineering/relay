package main

import (
	"context"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
)

// A reload whose file spells a key in another case is refused, naming each key as
// written and never a value, and nothing is swapped.
//
// Proves RC-54.
func TestReloader_CaseVariantKeyRefusedNamingKey(t *testing.T) {
	f := newReloadFixture(t)
	liveBefore, gateBefore := f.deps.live.cur.Load(), f.deps.gate.cur.Load()
	f.body = f.toml("[Reach]\nmutate_blast_cap = 7\n[log]\nLevel = \"CANARY\"\n")

	if _, err := f.r.reload(context.Background()); err == nil {
		t.Fatal("a reload naming a variant-case key succeeded")
	}
	if f.deps.live.cur.Load() != liveBefore || f.deps.gate.cur.Load() != gateBefore {
		t.Error("a refused reload replaced the snapshot or the gate")
	}
	got := f.logBuf.String()
	for _, want := range []string{"it is written Reach", "it is written log.Level"} {
		if !strings.Contains(got, want) {
			t.Errorf("log = %q, want it to contain %q", got, want)
		}
	}
	if strings.Contains(got, "CANARY") {
		t.Errorf("log = %q, must not echo the value", got)
	}
	if len(f.records(audit.KindConfigReload)) != 0 {
		t.Error("a refused reload wrote a config_reload record")
	}
	if n := len(f.records(audit.KindConfigReloadRefused)); n != 1 {
		t.Fatalf("config_reload_refused records = %d, want 1", n)
	}
}
