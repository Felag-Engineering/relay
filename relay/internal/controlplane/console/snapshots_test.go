package console

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

// TestConsole_WriteScreenSnapshots renders every reachable GET screen for the
// admin role against sweepFixture and writes the HTML to the directory named by
// RELAY_CONSOLE_SNAPSHOT_DIR. It is a producer, not an assertion: the files are
// what `make console-snapshots` hands to a design canvas so the UI can be edited
// from the real rendered pages rather than from a redrawing of them. Unset, it
// skips, so the ordinary suite never writes outside the test tree.
//
// Derived from the route table through walkableScreens for the same reason the
// exhaustive sweeps are: a screen added later is snapshotted without anyone
// remembering to list it.
func TestConsole_WriteScreenSnapshots(t *testing.T) {
	dir := os.Getenv("RELAY_CONSOLE_SNAPSHOT_DIR")
	if dir == "" {
		t.Skip("RELAY_CONSOLE_SNAPSHOT_DIR unset; snapshots are produced by `make console-snapshots`")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	d := withExecution(sweepFixture(), true)
	role := accounts.RoleAdmin
	h := newTestHandler(d, role)
	written := 0
	// The Account page is a walkable route and draws the danger buttons.
	paths := walkableScreens(routesFor(d, role), fixtureIDs)
	for _, path := range paths {
		rec := get(t, h, path)
		if rec.Code != 200 {
			t.Errorf("%s: status %d, not snapshotted", path, rec.Code)
			continue
		}
		name := snapshotName(path)
		if err := os.WriteFile(filepath.Join(dir, name+".html"), rec.Body.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		written++
	}
	if written == 0 {
		t.Fatal("wrote zero snapshots — the sweep is not running")
	}
	t.Logf("wrote %d screen snapshots to %s", written, dir)
}

// snapshotName turns a Console path into a stable file stem: "/console/" is
// "fleet", "/console/nodes/node-web-1" is "nodes-node-web-1".
func snapshotName(path string) string {
	p := strings.TrimPrefix(strings.TrimSuffix(path, "/"), "/console")
	p = strings.Trim(p, "/")
	if p == "" {
		return "fleet"
	}
	return strings.ReplaceAll(strings.ReplaceAll(p, "/", "-"), "?", "-")
}
