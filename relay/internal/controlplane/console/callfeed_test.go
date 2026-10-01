package console

// callfeed_test.go proves Activity's call-feed code
// (callfeed.go): run folding, the collapse sentence and the
// Console-read rule. Each screen's own behaviour over it is proved beside that
// screen.

import (
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
)

// TestConsoleRead_ARowThatCannotTellIsNotARead: both halves come from the
// row, and a row that does not say it was a read stays listed.
func TestConsoleRead_ARowThatCannotTellIsNotARead(t *testing.T) {
	for name, row := range map[string]capability.AuditRow{
		"no kind":             {Verified: consoleActor},
		"unknown kind":        {Kind: "something_new", Verified: consoleActor},
		"read kind, raw argv": {Kind: audit.KindRead, RawExecArgv: []string{"/bin/true"}, Verified: consoleActor},
		"read, not console": {Kind: audit.KindRead, OperationName: "list_nodes",
			Verified: capability.VerifiedIdentity{AccountName: "x", Method: string(capability.AuthMethodAPIToken)}},
		"read, no method": {Kind: audit.KindRead, OperationName: "list_nodes"},
	} {
		if consoleRead(row) {
			t.Errorf("%s: treated as a Console-session read", name)
		}
	}
	if !consoleRead(capability.AuditRow{Kind: audit.KindRead, OperationName: "list_nodes", Verified: consoleActor}) {
		t.Error("a Console-session read is not recognised")
	}
}

// TestCollapseNote_SpeaksWhenThereIsSomethingToSay: "" when nothing folded,
// otherwise the counts of calls and the rows they fold into.
func TestCollapseNote_SpeaksWhenThereIsSomethingToSay(t *testing.T) {
	if got := collapseNote(0, 0); got != "" {
		t.Errorf("collapseNote with nothing folded = %q, want empty", got)
	}
	got := collapseNote(7, 2)
	want := "7 calls on this page are collapsed into 2 rows, each saying how many calls it stands for."
	if got != want {
		t.Errorf("collapseNote = %q, want %q", got, want)
	}
}

// TestFoldRuns_ConsecutiveOnly: A, A, B, A folds to A(2), B, A — a match is
// only ever sought against the last row already kept — and a row whose key
// says it may not fold never does.
func TestFoldRuns_ConsecutiveOnly(t *testing.T) {
	type row struct {
		key   string
		calls int
	}
	key := func(r row) (string, bool) { return r.key, r.key != "never" }
	fold := func(run *row, older row) { run.calls += older.calls }
	got := foldRuns([]row{{"A", 1}, {"A", 1}, {"B", 1}, {"A", 1}}, key, fold)
	if len(got) != 3 || got[0] != (row{"A", 2}) || got[1] != (row{"B", 1}) || got[2] != (row{"A", 1}) {
		t.Errorf("foldRuns = %+v, want A(2), B, A", got)
	}
	got = foldRuns([]row{{"never", 1}, {"never", 1}}, key, fold)
	if len(got) != 2 {
		t.Errorf("rows whose key says they may not fold were folded: %+v", got)
	}
	if got := foldRuns([]row(nil), key, fold); len(got) != 0 {
		t.Errorf("foldRuns over nothing = %+v", got)
	}
}

func TestFoldedSummary_CountsOnlyRowsThatFoldedSomething(t *testing.T) {
	calls := func(n int) int { return n }
	fc, fr := foldedSummary([]int{1, 4, 1, 3}, calls)
	if fc != 7 || fr != 2 {
		t.Errorf("foldedSummary = (%d, %d), want (7, 2)", fc, fr)
	}
	if fc, fr := foldedSummary([]int{1, 1}, calls); fc != 0 || fr != 0 {
		t.Errorf("foldedSummary over unfolded rows = (%d, %d), want (0, 0)", fc, fr)
	}
}
