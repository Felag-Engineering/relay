package console

// enrollment_surface_test.go pins what the Console does with enrollment today:
// it shows where each Node came from, shows attempts from the in-memory event
// seam alone, and mints only through its one form, adding no Node.

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/events"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// Proves EN-47.
func TestConsole_ShowsEachNodesEnrollmentProvenance(t *testing.T) {
	enrolledAt := time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC)
	d := withFleet(fleetFixture(),
		registry.Node{NodeID: "node-with", Connected: true, EnrollingTokenID: "tok-provenance", EnrolledAt: enrolledAt,
			CertNotAfter: enrolledAt.Add(90 * 24 * time.Hour), Facts: registry.Facts{Hostname: "with"}},
		registry.Node{NodeID: "node-without", Connected: true, Facts: registry.Facts{Hostname: "without"}},
	)
	h := newTestHandler(d, accounts.RoleAdmin)

	with := contentOf(get(t, h, "/console/nodes/node-with").Body.String())
	for _, want := range []string{"enrolled via", "<code>tok-provenance</code>", utcStamp(enrolledAt)} {
		if !strings.Contains(with, want) {
			t.Errorf("a Node enrolled by a recorded token does not show %q", want)
		}
	}
	without := contentOf(get(t, h, "/console/nodes/node-without").Body.String())
	if !strings.Contains(without, "not recorded") {
		t.Error("a Node with no recorded token does not say so")
	}
}

// Proves EN-47.
func TestConsole_EnrollmentAttemptsReachItThroughTheEventSeamAlone(t *testing.T) {
	d := dayOneDeps()
	bus := d.Events.(*fakeEvents)
	bus.publish(events.EnrollmentEvent{Outcome: events.EnrollmentRejected, Reason: events.ReasonExhausted, TokenID: "tok-rejected"})
	bus.publish(events.EnrollmentEvent{Outcome: events.EnrollmentAccepted, TokenID: "tok-accepted"})

	body := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String())
	for _, want := range []string{"tok-rejected", "tok-accepted", enrollmentReasonText(events.ReasonExhausted)} {
		if !strings.Contains(body, want) {
			t.Errorf("day one does not show %q while the event seam holds it", want)
		}
	}

	// What a restart leaves: an empty event seam, and a durable trail that
	// names both tokens.
	d.Events = newFakeEvents()
	d.Audit = fakeAudit{records: []audit.Record{
		{Kind: audit.KindTokenMint, Reason: "token_id=tok-rejected", Timestamp: testNow},
		{Kind: audit.KindTokenMint, Reason: "token_id=tok-accepted", Timestamp: testNow},
	}}
	d.Queries = fakeQueriesWithRows(d, []capability.AuditRow{
		{Kind: audit.KindTokenMint, Reason: "token_id=tok-rejected", Timestamp: testNow},
		{Kind: audit.KindTokenMint, Reason: "token_id=tok-accepted", Timestamp: testNow},
	})
	after := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String())
	for _, gone := range []string{"tok-rejected", "tok-accepted"} {
		if strings.Contains(after, gone) {
			t.Errorf("day one shows %q from the durable trail; attempts come only from the event seam", gone)
		}
	}
}

func fakeQueriesWithRows(d Deps, rows []capability.AuditRow) *fakeQueries {
	cp := fakeQueriesCopy(d)
	cp.rows = rows
	return cp
}

// Proves EN-47.
func TestConsole_MintsOnlyThroughItsMintFormAndAddsNoNode(t *testing.T) {
	t.Run("structurally, one seam names a mint and it has one method", func(t *testing.T) {
		typ := reflect.TypeOf(Deps{})
		var minting []string
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if f.Type.Kind() != reflect.Interface {
				continue
			}
			for j := 0; j < f.Type.NumMethod(); j++ {
				name := f.Type.Method(j).Name
				if strings.Contains(name, "EnrollmentToken") {
					minting = append(minting, f.Name+"."+name)
				}
				if name == "Upsert" || strings.HasPrefix(name, "Enroll") {
					t.Errorf("Deps.%s declares %s, which adds or enrolls a Node", f.Name, name)
				}
			}
		}
		if len(minting) != 1 || minting[0] != "EnrollmentTokens.MintEnrollmentTokenFromForm" {
			t.Errorf("Deps fields declaring an Enrollment Token method = %v, want exactly EnrollmentTokens.MintEnrollmentTokenFromForm", minting)
		}
		if n := reflect.TypeOf((*EnrollmentTokenMinter)(nil)).Elem().NumMethod(); n != 1 {
			t.Errorf("EnrollmentTokenMinter declares %d methods, want 1", n)
		}
	})

	t.Run("behaviourally, only its own route mints", func(t *testing.T) {
		var posts []Route
		for _, r := range Routes(sweepFixture()) {
			if r.Method == http.MethodPost && r.Path != LoginPath && r.Path != LogoutPath {
				posts = append(posts, r)
			}
		}
		if len(posts) == 0 {
			t.Fatal("no POST routes were found to probe")
		}
		total := 0
		for _, r := range posts {
			tokens := &fakeEnrollmentTokens{}
			x := addNodesFix(t, tokens)
			path, ok := fixturePath(r, fixtureIDs)
			if !ok {
				continue
			}
			x.post(t, path, url.Values{"nodes": {"1"}, "ttl": {"2h"}, "password": {consolePassword}})
			n := len(tokens.calls())
			total += n
			if n > 0 && r.Path != mintEnrollmentTokenAction {
				t.Errorf("POST %s minted an Enrollment Token", r.Path)
			}
		}
		if total != 1 {
			t.Errorf("the POST routes minted %d tokens in total, want exactly 1 (the mint form)", total)
		}
	})
}
