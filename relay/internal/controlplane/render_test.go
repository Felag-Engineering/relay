package controlplane

import (
	"slices"
	"testing"
)

func TestMapSlice(t *testing.T) {
	double := func(n int) int { return n * 2 }

	if got := MapSlice([]int{1, 2, 3}, double); !slices.Equal(got, []int{2, 4, 6}) {
		t.Errorf("MapSlice = %v, want [2 4 6]", got)
	}
	for name, in := range map[string][]int{"nil": nil, "empty": {}} {
		got := MapSlice(in, double)
		if got == nil || len(got) != 0 {
			t.Errorf("MapSlice(%s) = %#v, want a non-nil empty slice", name, got)
		}
	}
}
