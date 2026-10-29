package textbound

import "testing"

func TestTruncate(t *testing.T) {
	const euro = "€" // three bytes
	cases := []struct {
		name      string
		in        string
		n         int
		want      string
		truncated bool
	}{
		{"within budget", "abc", 3, "abc", false},
		{"ascii cut", "abcdef", 3, "abc", true},
		{"cut on a rune boundary", "a" + euro, 4, "a" + euro, false},
		{"cut inside a rune backs up", "a" + euro, 3, "a", true},
		{"budget smaller than first rune", euro, 2, "", true},
		{"zero budget", "abc", 0, "", true},
		{"empty", "", 0, "", false},
	}
	for _, c := range cases {
		got, truncated := Truncate(c.in, c.n)
		if got != c.want || truncated != c.truncated {
			t.Errorf("%s: Truncate(%q, %d) = (%q, %v), want (%q, %v)", c.name, c.in, c.n, got, truncated, c.want, c.truncated)
		}
	}
}
