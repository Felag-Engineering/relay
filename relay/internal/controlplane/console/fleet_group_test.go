package console

import "testing"

func TestDeviationTable_DeviatingFirstThenRarityThenID(t *testing.T) {
	nodes := []fleetNode{
		{ID: "n1", signature: ""},
		{ID: "n2", signature: "offline"},
		{ID: "n3", signature: "offline"},
		{ID: "n4", signature: "revoked"},
	}
	var g fleetGroup
	tallyGroup(&g, nodes)

	got := deviationTable(nodes, true)
	want := []string{"n4", "n2", "n3", "n1"}
	for i, id := range want {
		if got[i].ID != id {
			t.Fatalf("row %d = %s, want %s (rows %v)", i, got[i].ID, id, got)
		}
	}

	if only := deviationTable(nodes, false); len(only) != 3 {
		t.Fatalf("deviating-only table has %d rows, want 3", len(only))
	}
}

func TestGroupModeLine_EmptyWhenNothingDeviates(t *testing.T) {
	if got := groupModeLine(0, 5, 2); got != "" {
		t.Fatalf("mode line = %q, want empty", got)
	}
}
