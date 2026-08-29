package approval

import (
	"bytes"
	"testing"
)

// TestEncodingFormatIsPinned is a FORMAT golden, not a digest golden: it pins
// the exact bytes writeField and writeCount produce, rather than the output of
// any hash function built on top of them.
//
// writeField and writeCount are shared by three live stored bindings —
// HashPlan and HashScope in approval_requests.plan_hash, and the shape keys in
// approval_requests.shape_key — so "someone tidies the shared primitive" would
// otherwise be a silent re-point of every one of those stored values. This
// test turns that into a failing test whose message names the consequence,
// instead of leaving it to be discovered as a run of approvals that
// mysteriously stop matching.
func TestEncodingFormatIsPinned(t *testing.T) {
	fieldCases := []struct {
		name  string
		field string
		value string
		want  string
	}{
		{name: "empty value", field: "f", value: "", want: "f=0:\n"},
		{name: "plain value", field: "f", value: "hello", want: "f=5:hello\n"},
		{
			name:  "value containing the format's own separators",
			field: "f",
			value: "a=b:c\nd",
			want:  "f=7:a=b:c\nd\n",
		},
	}
	for _, c := range fieldCases {
		t.Run("writeField/"+c.name, func(t *testing.T) {
			var buf bytes.Buffer
			writeField(&buf, c.field, c.value)
			if got := buf.String(); got != c.want {
				t.Errorf("writeField(%q, %q) = %q, want %q — this format is shared by every "+
					"live plan_hash and shape_key on disk", c.field, c.value, got, c.want)
			}
		})
	}

	countCases := []struct {
		name  string
		field string
		n     int
		want  string
	}{
		{name: "zero", field: "n", n: 0, want: "n=0\n"},
		{name: "multi-digit count", field: "n", n: 12345, want: "n=12345\n"},
	}
	for _, c := range countCases {
		t.Run("writeCount/"+c.name, func(t *testing.T) {
			var buf bytes.Buffer
			writeCount(&buf, c.field, c.n)
			if got := buf.String(); got != c.want {
				t.Errorf("writeCount(%q, %d) = %q, want %q — this format is shared by every "+
					"live plan_hash and shape_key on disk", c.field, c.n, got, c.want)
			}
		})
	}
}
