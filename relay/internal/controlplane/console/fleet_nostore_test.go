package console

import (
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

// TestFleet_IsNeverShownFromTheHTTPCache: the page states its age relative to
// when it was rendered, so a cached copy would claim "rendered just now" about
// an old read, with scripts on or off.
func TestFleet_IsNeverShownFromTheHTTPCache(t *testing.T) {
	rec := get(t, newTestHandler(fleetFixture(), accounts.RoleAdmin), "/console/")
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}
