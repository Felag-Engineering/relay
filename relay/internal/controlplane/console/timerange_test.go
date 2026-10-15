package console

import (
	"net/url"
	"testing"
	"time"
)

func TestTimeRangeParamsRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	cases := []url.Values{
		{},
		{"window": {"1h"}},
		{"since": {"2026-10-01T00:00:00Z"}, "until": {"2026-10-02T00:00:00Z"}},
	}
	for _, in := range cases {
		tr, notes := parseTimeRange(in, now)
		if len(notes) != 0 {
			t.Fatalf("%v: unexpected notes %v", in, notes)
		}
		out := url.Values{}
		tr.setParams(out)
		if out.Encode() != in.Encode() {
			t.Errorf("round trip of %v produced %v", in, out)
		}
	}
}
