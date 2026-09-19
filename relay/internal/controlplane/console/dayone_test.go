package console

// dayone_test.go asserts spec 10's five acceptance criteria, plus the
// properties of the live-read route day one needed built (#427).
//
// It has its own file rather than a corner of screens_test.go for the reason
// login_test.go and components_test.go do: this area needs a harness nothing
// else needs — a streaming request over a real connection, with a real
// *events.Bus published into mid-request — and that harness would be noise in
// the 2,500-line shared file.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/events"
)

// ---------------------------------------------------------------------------
// Criterion 1: with zero Nodes, no screen renders an empty table or a zeroed
// statistic.
// ---------------------------------------------------------------------------

// TestDayOne_NoScreenRendersAZeroedStatisticOnAFreshRelay walks every mounted
// screen with an empty registry and an empty audit trail.
//
// A row of zeros is a MEASUREMENT: "we measured your exposure and it is nil",
// said to someone who has not started yet. The distinction matters most on the
// screens that are least likely to be looked at on day one, which is exactly
// why this is a sweep and not a per-screen assertion.
func TestDayOne_NoScreenRendersAZeroedStatisticOnAFreshRelay(t *testing.T) {
	// Execution on, so the sweep covers every route this process can mount.
	d := withExecution(dayOneDeps(), true)
	h := newTestHandler(d, accounts.RoleAdmin)

	// No substitutions: a parameterised route names one object, and an empty
	// registry has none to name, so walkableScreens skips them.
	paths := walkableScreens(Routes(d), nil)
	if len(paths) == 0 {
		t.Fatal("the sweep walked zero screens — it is not running")
	}

	// ">0 events" and not "0 events", which also matches "10 events".
	zeroed := regexp.MustCompile(`<b>0</b>|>0 (events|Nodes|Jobs|reads)`)

	// Screens whose day-one shape is NOT "nothing has happened yet". A map
	// with a written reason rather than a bare continue, so the exclusion
	// argues for itself in the diff that adds it.
	dayOneExempt := map[string]string{
		"/console/accounts": "EnsureFoundingAdmin (relay/cmd/relay/main.go, in the same " +
			"ControlEnabled branch that mounts the Console) seeds an enabled human admin at " +
			"startup, so a Relay with zero Accounts is unreachable and the founding admin's " +
			"row IS the honest first-boot shape. This criterion is about measuring a fleet " +
			"that does not exist yet; an Account table is not a fleet, and hiding the one " +
			"row a fresh Relay really has would be the fiction, not the table. The real " +
			"day-one shape is pinned in TestAccounts_DayOneShowsTheFoundingAdmin.",
	}

	// An exemption that stops being reached is an unexecuted paragraph that
	// outlives its reason — the failure this package answers elsewhere with a
	// vacuity assert (no_dispatch_test.go). If /console/accounts ever leaves
	// walkableScreens, the reason above must be re-argued, not inherited.
	exemptHit := map[string]bool{}

	for _, path := range paths {
		if why, ok := dayOneExempt[path]; ok {
			exemptHit[path] = true
			t.Logf("skipping %s: %s", path, why)
			continue
		}
		rec := get(t, h, path)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s on a fresh Relay = %d, want 200", path, rec.Code)
			continue
		}

		body := contentOf(rec.Body.String())
		if strings.Contains(body, "<thead>") {
			t.Errorf("%s rendered a table with zero rows on a fresh Relay — column headings over "+
				"nothing is a confident statement about a fleet that does not exist yet", path)
		}
		if m := zeroed.FindString(body); m != "" {
			t.Errorf("%s rendered the zeroed statistic %q on a fresh Relay — say nothing has "+
				"happened, do not measure it", path, m)
		}
	}

	for path := range dayOneExempt {
		if !exemptHit[path] {
			t.Errorf("dayOneExempt names %s, which this sweep never reached — the exemption is "+
				"now an unexecuted paragraph. Delete it, or fix the sweep that stopped covering "+
				"the route it excuses", path)
		}
	}
}

// TestActivity_FreshRelaySaysNothingHappenedRatherThanNothingMatches is the
// other half of the same fix. "Nothing matches." is a statement about a filter,
// and on a fresh Relay nothing was filtered — the trail is simply empty.
func TestActivity_FreshRelaySaysNothingHappenedRatherThanNothingMatches(t *testing.T) {
	h := newTestHandler(dayOneDeps(), accounts.RoleAdmin)

	body := contentOf(get(t, h, "/console/activity").Body.String())
	if strings.Contains(body, "Nothing matches.") {
		t.Error("an unfiltered, empty trail says \"Nothing matches.\" — nothing was filtered out")
	}
	if !strings.Contains(body, "Nothing has been recorded yet") {
		t.Error("an empty trail does not say so")
	}

	// With a filter, the filter-shaped copy is the right copy.
	filtered := contentOf(get(t, h, "/console/activity?q=nosuchthing").Body.String())
	if !strings.Contains(filtered, "Nothing matches.") {
		t.Error("a filter that matches nothing no longer says so")
	}
}

// ---------------------------------------------------------------------------
// Criterion 2: both fingerprints are shown.
// ---------------------------------------------------------------------------

func TestDayOne_ShowsTheFingerprintsAMachineNeeds(t *testing.T) {
	body := contentOf(get(t, newTestHandler(dayOneDeps(), accounts.RoleAdmin), "/console/").Body.String())

	for _, want := range []string{
		// Shortened for the eye, full value in the title: the question a
		// fingerprint answers on a screen is "same or different".
		`title="` + testCAFingerprint + `">` + shortHash(testCAFingerprint),
		`title="` + testServerFingerprint + `">` + shortHash(testServerFingerprint),
	} {
		if !strings.Contains(body, want) {
			t.Errorf("day one does not render %q", want)
		}
	}
	if !strings.Contains(body, "the value to compare against") {
		t.Error("day one does not say which fingerprint is the one to check")
	}
	// The copy must not claim a mechanism the tree does not have: nothing
	// pins a CA fingerprint today (ADR-0031 decision 3 is decided, not
	// built), and there is no join string anywhere in relay/, daemon/ or
	// proto/. This screen's five criteria are all honesty; a confident
	// sentence about a check nobody performs is the same defect as a zeroed
	// statistic.
	for _, overclaim := range []string{"join string", "is the value to pin", "refuses any Relay"} {
		if strings.Contains(body, overclaim) {
			t.Errorf("day one claims %q — that mechanism is not built (ADR-0031 decision 3); "+
				"say what the value is for, in the tense the tree supports", overclaim)
		}
	}
}

// TestDayOne_ServerFingerprintIsNotPresentedAsAPin is ADR-0031's decision, on
// the screen. The leaf rotates about daily, so a comparison ritual against it
// teaches an operator a check that breaks by design — and a browser exception
// pinned to it breaks with it.
func TestDayOne_ServerFingerprintIsNotPresentedAsAPin(t *testing.T) {
	body := contentOf(get(t, newTestHandler(dayOneDeps(), accounts.RoleAdmin), "/console/").Body.String())

	leaf := strings.Index(body, testServerFingerprint)
	if leaf < 0 {
		t.Fatal("day one does not render the server certificate fingerprint at all")
	}
	if ca := strings.Index(body, testCAFingerprint); ca < 0 || ca > leaf {
		t.Error("the server leaf is rendered before the CA fingerprint — the CA is the value to pin " +
			"and belongs first")
	}
	if !strings.Contains(body, "re-issued") || !strings.Contains(body, "not what you pin") {
		t.Error("the server certificate is not labelled as rotating and not-for-pinning (ADR-0031)")
	}
}

func TestDayOne_UnwiredTrustSaysSoRatherThanRenderingBlank(t *testing.T) {
	d := dayOneDeps()
	d.Trust = nil
	body := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String())

	if !strings.Contains(body, "not wired into this Console") {
		t.Error("day one with no fingerprint seam renders blanks instead of admitting it is unwired")
	}
}

// ---------------------------------------------------------------------------
// Criterion 3: a Relay-side rejection appears with its reason, live; the screen
// never claims to see daemon-side rejections.
// ---------------------------------------------------------------------------

func TestDayOne_RejectedAttemptRendersWithItsReason(t *testing.T) {
	d := dayOneDeps()
	bus := d.Events.(*fakeEvents)
	bus.publish(events.EnrollmentEvent{
		Outcome: events.EnrollmentRejected,
		Reason:  events.ReasonExhausted,
		TokenID: "tok-public-half",
		Source:  "203.0.113.9",
	})

	body := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String())

	for _, want := range []string{
		enrollmentReasonText(events.ReasonExhausted),
		"tok-public-half",
		"203.0.113.9",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the rendered attempt is missing %q", want)
		}
	}
	if strings.Contains(body, "No enrollment attempts in the last") &&
		!strings.Contains(body, `id="dayone-empty" hidden`) {
		t.Error("the screen says there are no attempts while rendering one")
	}
}

// TestEnrollmentReasonText_InvalidScopeIsNotTheFallback pins #555's day-one
// text: a reason this Console DOES recognise must never render the "does not
// recognise" fallback enrollmentReasonText's default case returns for a
// reason it has NOT been taught about.
func TestEnrollmentReasonText_InvalidScopeIsNotTheFallback(t *testing.T) {
	got := enrollmentReasonText(events.ReasonInvalidScope)
	if got == enrollmentReasonText(events.EnrollmentReason("some-reason-this-console-does-not-recognise")) {
		t.Errorf("enrollmentReasonText(ReasonInvalidScope) = %q, want a dedicated case, not the fallback", got)
	}
}

// TestDayOne_NeverClaimsToSeeDaemonSideRejections is criterion 3's second half,
// and it must hold whether or not the watch is live. A daemon that refuses this
// Relay's certificate aborts the handshake before it sends anything (ADR-0031),
// so the Relay has a connection and no attempt — surfacing it needs #444.
func TestDayOne_NeverClaimsToSeeDaemonSideRejections(t *testing.T) {
	for _, tc := range []struct {
		name string
		deps Deps
	}{
		{"watching", dayOneDeps()},
		{"seam unwired", func() Deps { d := dayOneDeps(); d.Events = nil; return d }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := contentOf(get(t, newTestHandler(tc.deps, accounts.RoleAdmin), "/console/").Body.String())
			if !strings.Contains(body, "never appears here") {
				t.Error("day one does not name the failure class it cannot see")
			}
			for _, absent := range []string{"fingerprint mismatch", "handshake failed"} {
				if strings.Contains(body, absent) {
					t.Errorf("day one renders %q — it cannot see daemon-side refusals and must not "+
						"imply it does", absent)
				}
			}
		})
	}
}

func TestDayOne_LiveRejectionIsDeliveredOverTheStream(t *testing.T) {
	d := dayOneDeps()
	bus := d.Events.(*fakeEvents)

	s := openStream(t, d, "/console/events?kinds=enrollment")
	bus.publish(events.EnrollmentEvent{
		Outcome: events.EnrollmentRejected,
		Reason:  events.ReasonRevoked,
		TokenID: "tok-revoked",
		Source:  "198.51.100.4",
	})

	frame := s.frame(t)
	if !strings.Contains(frame, "event: enrollment") {
		t.Errorf("frame is not an enrollment event: %q", frame)
	}
	if !strings.HasPrefix(frame, "id: ") {
		t.Errorf("frame carries no id:, so a reconnect cannot resume: %q", frame)
	}

	got := decodeFrame(t, frame)
	if got.Outcome != "rejected" || got.Reason != enrollmentReasonText(events.ReasonRevoked) {
		t.Errorf("frame = %+v, want a rejection carrying the humanised reason", got)
	}
	if got.TokenID != "tok-revoked" || got.Source != "198.51.100.4" {
		t.Errorf("frame = %+v, want the attempt's public token id and source", got)
	}
}

// ---------------------------------------------------------------------------
// Criterion 4: the first successful enrollment moves the operator to the fleet
// view without a reload.
// ---------------------------------------------------------------------------

func TestDayOne_AcceptedEnrollmentIsAnnouncedOnTheStream(t *testing.T) {
	d := dayOneDeps()
	bus := d.Events.(*fakeEvents)

	s := openStream(t, d, "/console/events?kinds=enrollment")
	// Exactly as enroll.Server publishes a success: no Reason field at all.
	// eventsink's exhaustive switch maps that zero value to ReasonInternal, so
	// this is what the seam really delivers on the happy path.
	bus.publish(events.EnrollmentEvent{
		Outcome: events.EnrollmentAccepted,
		Reason:  events.ReasonInternal,
		TokenID: "tok-good",
		NodeID:  "node-first",
		Source:  "198.51.100.7",
	})

	frame := s.frame(t)
	if got := decodeFrame(t, frame); got.Outcome != "accepted" {
		t.Errorf("frame = %+v, want outcome accepted", got)
	}
	if strings.Contains(frame, "node-first") {
		t.Error("the stream carries the Node id — day one navigates away on acceptance and never " +
			"needs it, and a projection ships only what a screen renders")
	}
}

// TestDayOne_AnAcceptedEnrollmentCarriesNoReasonText is the one this whole
// screen would have got wrong.
//
// enroll.Server publishes its SUCCESS with no Reason, the zero value has no
// constant, and eventsink's switch maps it through its safe default to
// ReasonInternal. So every accepted attempt arrives on the seam labelled
// "internal". Rendered unconditionally, the first successful enrollment on a
// brand-new fleet reads "accepted — internal error", on the one screen whose
// entire job is that moment.
//
// Both paths are asserted, because both would have been wrong.
func TestDayOne_AnAcceptedEnrollmentCarriesNoReasonText(t *testing.T) {
	internal := enrollmentReasonText(events.ReasonInternal)

	t.Run("on the stream", func(t *testing.T) {
		d := dayOneDeps()
		bus := d.Events.(*fakeEvents)
		s := openStream(t, d, "/console/events?kinds=enrollment")
		bus.publish(events.EnrollmentEvent{
			Outcome: events.EnrollmentAccepted,
			Reason:  events.ReasonInternal,
			TokenID: "tok-good",
			Source:  "198.51.100.7",
		})

		frame := s.frame(t)
		if strings.Contains(frame, `"reason"`) || strings.Contains(frame, internal) {
			t.Errorf("an accepted attempt's frame carries a reason: %q", frame)
		}
		if got := decodeFrame(t, frame); got.Reason != "" {
			t.Errorf("an accepted attempt's reason = %q, want empty", got.Reason)
		}
	})

	t.Run("in the rendered rows", func(t *testing.T) {
		d := dayOneDeps()
		d.Events.(*fakeEvents).publish(events.EnrollmentEvent{
			Outcome: events.EnrollmentAccepted,
			Reason:  events.ReasonInternal,
			TokenID: "tok-good",
			Source:  "198.51.100.7",
		})

		body := contentOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String())
		if !strings.Contains(body, "tok-good") {
			t.Fatal("the accepted attempt was not rendered at all")
		}
		if strings.Contains(body, internal) {
			t.Errorf("an accepted enrollment is rendered with the reason %q — the seam labels every "+
				"success 'internal', and this screen must not repeat it", internal)
		}
	})
}

// TestDayOne_ClientNavigatesOnAcceptance asserts the script as an ARTIFACT:
// this repository has no JavaScript test runner and shipping one is out of
// scope, so the properties that matter are asserted against the file's text.
func TestDayOne_ClientNavigatesOnAcceptance(t *testing.T) {
	src := readAsset(t, "assets/dayone.js")

	for _, want := range []string{
		`attempt.outcome === "accepted"`,
		`window.location.assign("/console/")`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("dayone.js does not %s — the first enrollment must move the operator to the "+
				"fleet view without a reload", want)
		}
	}

	// The live path must not have weaker escaping than the server-rendered
	// one: a token id derives from caller-supplied input, and a source is a
	// remote address.
	for _, banned := range []string{".innerHTML", ".outerHTML", "insertAdjacentHTML", "document.write"} {
		if strings.Contains(src, banned) {
			t.Errorf("dayone.js uses %s — live rows must be built with textContent, or the live "+
				"path escapes less than the html/template-rendered one", banned)
		}
	}
	if !strings.Contains(src, "textContent") {
		t.Error("dayone.js never sets textContent — how is it building rows?")
	}
}

// TestDayOne_ScriptIsActuallyServed is the same guard the stylesheet needed
// (#439): the shell landed before anything mounted its assets, so every page
// rendered unstyled and no test noticed. A script tag pointing at a 404 fails
// exactly as quietly — the page renders, the watch simply never connects.
func TestDayOne_ScriptIsActuallyServed(t *testing.T) {
	h := newTestHandler(dayOneDeps(), accounts.RoleAdmin)

	body := get(t, h, "/console/").Body.String()
	// BOTH files, and stream.js FIRST: it defines window.RelayLive, which
	// dayone.js reads at load time. Deferred scripts run in document order, so
	// the order in this list is load-bearing rather than cosmetic.
	stream := `<script src="/console/assets/stream.js" defer></script>`
	screen := `<script src="/console/assets/dayone.js" defer></script>`
	if !strings.Contains(body, stream) || !strings.Contains(body, screen) {
		t.Fatal("day one does not load the shared transport and its own handler")
	}
	if strings.Index(body, stream) > strings.Index(body, screen) {
		t.Error("dayone.js is loaded before stream.js — it would run before window.RelayLive exists")
	}

	for _, asset := range []struct{ path, sentinel string }{
		// A 404 page is also a 200-shaped thing to a careless assertion, so
		// each check names something only that file contains.
		{"/console/assets/stream.js", "EventSource"},
		{"/console/assets/dayone.js", "addRejection"},
		// Activity's handler is fetched here too. It is mounted by a
		// different screen, but nothing else in the suite ever asks the asset
		// route for it — so a typo in Activity's p.Scripts would 404 in
		// production with every Go test green, which is the exact failure
		// this test was written for.
		{"/console/assets/activity.js", "data-jobstate"},
	} {
		rec := get(t, h, asset.path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", asset.path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), asset.sentinel) {
			t.Errorf("%s did not return the script", asset.path)
		}
	}

	// A screen with no live seam must not load a script that would sit there
	// failing to connect.
	d := dayOneDeps()
	d.Events = nil
	if body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String(); strings.Contains(body, "dayone.js") ||
		strings.Contains(body, "stream.js") {
		t.Error("day one loads a script with no event seam wired")
	}
}

// TestDayOne_ClientDegradesVisiblyAndGivesUp is the session-lifetime problem,
// made visible.
//
// An SSE response is ONE request and the session's idle timeout is refreshed
// per request, so a tab parked on this screen refreshes nothing: the session
// can expire while the operator is actively watching. The reconnect then
// follows a redirect to the sign-in page and fails like any other error, so an
// unbounded backoff would spin against a login page forever, silently.
func TestDayOne_ClientDegradesVisiblyAndGivesUp(t *testing.T) {
	// The transport moved to the shell (#422): one reconnect loop for every
	// live region, because two copies is two backoff policies and the second
	// one is the one nobody looks at again. The PROPERTY is unchanged, so the
	// assertion moved with it rather than being dropped.
	src := readAsset(t, "assets/stream.js")

	for _, want := range []string{"maxAttempts", `setState("down")`, `setState("ended")`} {
		if !strings.Contains(src, want) {
			t.Errorf("stream.js is missing %q — the reconnect must be bounded and end in a state "+
				"the screen can explain", want)
		}
	}
	// Jittered backoff: a fleet's worth of Consoles reconnecting in lockstep
	// after a Relay restart is a self-inflicted thundering herd (spec 11).
	if !strings.Contains(src, "Math.random()") {
		t.Error("stream.js reconnects without jitter")
	}

	// The terminal state's words live in Go, like every other word on the
	// screen.
	body := contentOf(get(t, newTestHandler(dayOneDeps(), accounts.RoleAdmin), "/console/").Body.String())
	for _, want := range []string{`data-when="down"`, `data-when="ended"`, "Your session may have ended"} {
		if !strings.Contains(body, want) {
			t.Errorf("day one does not render the %q state — a monitoring surface that silently "+
				"freezes is worse than one that admits it is blind", want)
		}
	}
}

// ---------------------------------------------------------------------------
// Criterion 5: nothing here exposes a token, a private key, or a Relay
// configuration value.
// ---------------------------------------------------------------------------

func TestDayOne_ExposesNoCredentialOrConfiguration(t *testing.T) {
	d := dayOneDeps()
	d.Events.(*fakeEvents).publish(events.EnrollmentEvent{
		Outcome: events.EnrollmentRejected,
		Reason:  events.ReasonMalformed,
		TokenID: "tok-public-half",
		Source:  "203.0.113.4",
	})

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String()

	for _, banned := range []string{
		accounts.TokenPrefix, // an API Token
		"BEGIN", "PRIVATE KEY",
		"RELAY_",  // any environment-supplied configuration name
		"0.0.0.0", // a listen address
		":8443",   // a port
		"blast",   // the blast-radius cap
		"session_max_age",
	} {
		if strings.Contains(body, banned) {
			t.Errorf("day one renders %q — the screen shows what a machine needs in order to join, "+
				"never an inventory of configuration (invariant 11)", banned)
		}
	}
}

// TestDayOne_SeamsDeclareNoConfigurationOrPublishMethod is the structural half
// of criterion 5, in no_dispatch_test.go's shape: a property of the TYPES, so
// it cannot be undone by a handler.
//
// TrustReader may only ever return digests, and EventReader may only ever READ.
// The Console watches history; it never authors it. This is the guard that
// matters when #422 extends the same seam.
func TestConsole_EventSeamCannotPublish(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "seams.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse seams.go: %v", err)
	}

	banned := []string{"publish", "addr", "address", "host", "port", "listen", "config", "secret", "key"}
	checked := map[string]int{}

	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		iface, ok := spec.Type.(*ast.InterfaceType)
		if !ok || (spec.Name.Name != "EventReader" && spec.Name.Name != "TrustReader") {
			return true
		}
		for _, m := range iface.Methods.List {
			for _, name := range m.Names {
				checked[spec.Name.Name]++
				lower := strings.ToLower(name.Name)
				for _, b := range banned {
					if strings.Contains(lower, b) {
						t.Errorf("%s declares %s — this seam is a read projection over runtime "+
							"objects, and must never carry a write or a Relay configuration value "+
							"(invariants 10 and 11)", spec.Name.Name, name.Name)
					}
				}
			}
		}
		return true
	})

	if checked["EventReader"] == 0 || checked["TrustReader"] == 0 {
		t.Fatalf("the seam guard inspected %v — it is not finding the interfaces", checked)
	}
}

// ---------------------------------------------------------------------------
// The live-read route.
// ---------------------------------------------------------------------------

// TestConsoleEvents_UnknownKindIsRefused keeps this route to the one kind this
// issue built. The seam itself can carry MCP tool calls, which is raw_exec's
// full argv; the closed allowlist in the handler is what keeps them off this
// stream, and it is a test rather than a type.
func TestConsoleEvents_UnknownKindIsRefused(t *testing.T) {
	h := newTestHandler(dayOneDeps(), accounts.RoleAdmin)

	for _, query := range []string{"", "?kinds=", "?kinds=tool_call", "?kinds=registry",
		"?kinds=enrollment,tool_call", "?kinds=job,registry", "?kinds=gap"} {
		rec := getBounded(t, h, "/console/events"+query)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("GET /console/events%s = %d, want 400 — this route serves enrollment and "+
				"job, and nothing else", query, rec.Code)
		}
	}
}

// TestConsoleEvents_EveryKindNamesTheRoleThatMaySeeIt is the successor to
// #427's TestConsoleEvents_HasNoRoleGateBecauseEnrollmentNeedsNone, which
// recorded the absence of a role check as deliberate and said the absence
// stops being right the moment a second kind is added. Activity (#422) adds
// one, so this asserts the gate instead of the absence.
//
// The EXACT SIZE assertion is the point. A test that merely checked
// "enrollment and job are present" would still pass after someone added
// tool_call — which carries raw_exec's full argv — and this route's closed
// allowlist is its only structural defence.
func TestConsoleEvents_EveryKindNamesTheRoleThatMaySeeIt(t *testing.T) {
	if len(consoleEventKinds) != 2 {
		t.Fatalf("consoleEventKinds has %d entries, want exactly 2 (%v). Widening this route means "+
			"adding a ROLE and a PROJECTION for the new kind and then updating this list, in the "+
			"same change: MinRole in the route table is presentation and gates nothing.",
			len(consoleEventKinds), consoleEventKinds)
	}
	if consoleEventKinds["enrollment"].Kind != events.KindEnrollment {
		t.Errorf("the enrollment entry maps to %v", consoleEventKinds["enrollment"].Kind)
	}
	if consoleEventKinds["job"].Kind != events.KindJob {
		t.Errorf("the job entry maps to %v", consoleEventKinds["job"].Kind)
	}
	for name, entry := range consoleEventKinds {
		if !entry.MinRole.Valid() {
			t.Errorf("kind %q names the role %q, which is not a role — Role.AtLeast refuses an "+
				"invalid want, so this kind would be unreachable rather than open, but the entry "+
				"is still a mistake", name, entry.MinRole)
		}
	}
	// Named explicitly, because these two are the ones whose admission would
	// be a disclosure decision rather than a widening: tool_call carries
	// raw_exec's full argv, and registry carries no attribution at all.
	for _, absent := range []string{"tool_call", "registry"} {
		if _, present := consoleEventKinds[absent]; present {
			t.Errorf("%q is admitted to the Console event stream — see events.go's disclosure table", absent)
		}
	}

	// A viewer reaches both streams today, deliberately.
	d := dayOneDeps()
	s := openStreamAs(t, d, "/console/events?kinds=enrollment,job", accounts.RoleViewer)
	d.Events.(*fakeEvents).publish(events.EnrollmentEvent{
		Outcome: events.EnrollmentRejected, Reason: events.ReasonUnknown, Source: "203.0.113.1",
	})
	if got := decodeFrame(t, s.frame(t)); got.Outcome != "rejected" {
		t.Errorf("a viewer did not receive the enrollment stream: %+v", got)
	}
}

// TestConsoleEvents_UnknownRoleIsRefused is the mutation-sensitive half of the
// gate. principalFromAccount copies an Account's role string into the
// Principal VERBATIM and validates nothing, so a role this Relay does not
// recognise — a corrupted store row, a role from a future version, an empty
// string — reaches the handler intact. accounts.Role.AtLeast ranks it at zero
// and refuses, which is why AtLeast is used here rather than a switch.
func TestConsoleEvents_UnknownRoleIsRefused(t *testing.T) {
	d := dayOneDeps()
	bus := d.Events.(*fakeEvents)

	for _, role := range []accounts.Role{"auditor", ""} {
		// getBounded, not openStreamAs: openStreamAs t.Fatalf's on any
		// non-200, so a test written through it would fail even when the gate
		// works.
		h := newTestHandler(d, role)
		rec := getBounded(t, h, "/console/events?kinds=job")
		if rec.Code != http.StatusForbidden {
			t.Errorf("GET /console/events?kinds=job as role %q = %d, want 403", role, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "job") {
			t.Errorf("the refusal for role %q does not name the kind: %q", role, rec.Body.String())
		}
	}

	// And no stream was opened for any of them: the gate sits before
	// Subscribe, so an unrecognised role never reaches the bus.
	if got := bus.subscriptions(); got != 0 {
		t.Errorf("%d Subscriptions were handed out to refused requests, want 0", got)
	}
}

// TestConsoleEvents_JobFrameCarriesOnlyIDTransitionAndTime is the single most
// valuable test on this route. events.JobEvent carries the Selector, the
// Operation, the Account and eight outcome counts; the projection carries
// three strings, and the route's disclosure is bounded by that STRUCT rather
// than by the role gate.
func TestConsoleEvents_JobFrameCarriesOnlyIDTransitionAndTime(t *testing.T) {
	d := dayOneDeps()
	s := openStream(t, d, "/console/events?kinds=job")

	d.Events.(*fakeEvents).publishJob(events.JobEvent{
		Transition: events.JobCompleted,
		JobID:      "job-1",
		Account:    "gleipnir",
		AccountID:  "acct-secret",
		Selector:   "role=web,env=prod",
		Operation:  "service.restart",
		RiskClass:  "mutate",
		Nodes:      4000,
		Succeeded:  3986,
		Denied:     14,
	})

	frame := s.frame(t)
	data := frame[strings.Index(frame, "data: ")+len("data: "):]
	data = strings.TrimSpace(data)

	var got map[string]any
	if err := json.Unmarshal([]byte(data), &got); err != nil {
		t.Fatalf("decode job frame %q: %v", data, err)
	}
	if len(got) != 3 {
		t.Errorf("the job frame carries %d keys (%v), want exactly job_id, transition and at", len(got), got)
	}
	for _, key := range []string{"job_id", "transition", "at"} {
		if _, ok := got[key]; !ok {
			t.Errorf("the job frame is missing %q: %v", key, got)
		}
	}
	if got["job_id"] != "job-1" || got["transition"] != "completed" {
		t.Errorf("job frame = %v, want job-1/completed", got)
	}
	// Substrings, not keys: a widened projection that renamed a field would
	// still leak the value.
	for _, forbidden := range []string{"gleipnir", "acct-secret", "role=web", "service.restart", "mutate", "3986", "4000"} {
		if strings.Contains(data, forbidden) {
			t.Errorf("the job frame contains %q — events.JobEvent carries it and sseJob must not: %s",
				forbidden, data)
		}
	}
	if !strings.HasPrefix(frame, "id: ") {
		t.Errorf("the job frame carries no id: line, so a reconnect cannot resume from it: %q", frame)
	}
}

func TestConsoleEvents_UnwiredSeamRefusesRatherThanStreamingNothing(t *testing.T) {
	d := dayOneDeps()
	d.Events = nil
	rec := getBounded(t, newTestHandler(d, accounts.RoleAdmin), "/console/events?kinds=enrollment")

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /console/events with no seam wired = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not a quiet fleet") {
		t.Error("the refusal does not distinguish a wiring problem from an absence of events")
	}
}

func TestConsoleEvents_RequiresAuthentication(t *testing.T) {
	h := newTestHandler(dayOneDeps(), accounts.RoleAdmin)
	ctx, cancel := context.WithTimeout(context.Background(), streamTestTimeout)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/console/events?kinds=enrollment", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Error("an unauthenticated request opened the Console's event stream")
	}
}

// TestConsoleEvents_ResumesFromLastEventID: the client does its own jittered
// reconnect rather than relying on EventSource's fixed retry, and a manual
// re-open cannot set a header — so the query parameter is the only way a
// resume can happen at all.
func TestConsoleEvents_ResumesFromLastEventID(t *testing.T) {
	d := dayOneDeps()
	bus := d.Events.(*fakeEvents)

	bus.publish(events.EnrollmentEvent{Outcome: events.EnrollmentRejected, Reason: events.ReasonExpired, TokenID: "first"})
	recent := bus.Recent([]events.Kind{events.KindEnrollment}, 10)
	if len(recent) != 1 {
		t.Fatalf("Recent returned %d events, want 1", len(recent))
	}
	bus.publish(events.EnrollmentEvent{Outcome: events.EnrollmentRejected, Reason: events.ReasonUnknown, TokenID: "second"})

	s := openStream(t, d, "/console/events?kinds=enrollment&last_event_id="+recent[0].ID)

	// The resume replays what happened after the rendered page, and nothing
	// before it.
	if got := decodeFrame(t, s.frame(t)); got.TokenID != "second" {
		t.Errorf("resumed stream delivered %q, want the event after the resume point", got.TokenID)
	}
}

// TestConsoleEvents_GapCarriesNoID guards a small, load-bearing piece of
// reasoning: a gap has no position on the sequence it reports a hole in, and an
// EMPTY id: resets a browser's own Last-Event-ID to "" — which would turn the
// next reconnect into a fresh session instead of a resume.
func TestConsoleEvents_GapCarriesNoID(t *testing.T) {
	d := dayOneDeps()

	// An ID from a foreign epoch is what a Relay restart looks like to a
	// reconnecting browser.
	s := openStream(t, d, "/console/events?kinds=enrollment&last_event_id=beefbeefbeefbeef-4")

	frame := s.frame(t)
	if !strings.Contains(frame, "event: gap") {
		t.Fatalf("a foreign epoch did not produce a gap frame: %q", frame)
	}
	if strings.Contains(frame, "id:") {
		t.Errorf("the gap frame carries an id: line (%q) — an empty or borrowed id resets the "+
			"browser's Last-Event-ID and turns the next reconnect into a fresh session", frame)
	}
	if !strings.Contains(frame, "restarted") {
		t.Errorf("the gap frame does not say what happened: %q", frame)
	}
}

// TestConsoleEvents_ClosesItsSubscriptionWhenTheRequestEnds guards the leak.
//
// Bus.Close is the ONLY thing that removes a Subscription from the bus, and
// every publish fans out to every registered one — so a handler that returns
// without closing leaves a permanent map entry and a 256-slot channel per
// abandoned request.
func TestConsoleEvents_ClosesItsSubscriptionWhenTheRequestEnds(t *testing.T) {
	d := dayOneDeps()
	bus := d.Events.(*fakeEvents)

	s := openStream(t, d, "/console/events?kinds=enrollment")
	bus.publish(events.EnrollmentEvent{Outcome: events.EnrollmentRejected, Reason: events.ReasonUnknown})
	s.frame(t) // the handler is definitely inside its loop now

	sub := bus.subscription(0)
	if sub == nil {
		t.Fatal("the handler never subscribed")
	}

	s.close()

	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, open := <-sub.C():
			if !open {
				return // closed: the handler released it
			}
		case <-deadline:
			t.Fatal("the Subscription was still open five seconds after the request ended — " +
				"every future publish fans out to it forever")
		}
	}
}

// TestConsoleEvents_ConcurrentStreamsAreBounded: Bus.publish walks the whole
// subscription set holding the bus's one global mutex, and it is called from
// enrollment, tunnel-connect and dispatch. An unbounded stream count therefore
// lets the lowest role add O(N) work to the lock that gates a Node enrolling.
func TestConsoleEvents_ConcurrentStreamsAreBounded(t *testing.T) {
	d := dayOneDeps()
	bus := d.Events.(*fakeEvents)
	srv := httptest.NewServer(newTestHandler(d, accounts.RoleViewer))
	defer srv.Close()

	open := func() (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/console/events?kinds=enrollment", nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+testCredential)
		return srv.Client().Do(req)
	}

	// Fill to the cap, then keep going: the extras must be refused.
	var held []*http.Response
	var refused int
	for i := 0; i < maxStreamsPerPrincipal+3; i++ {
		res, err := open()
		if err != nil {
			t.Fatalf("open stream %d: %v", i, err)
		}
		if res.StatusCode == http.StatusTooManyRequests {
			refused++
			res.Body.Close() //nolint:errcheck
			continue
		}
		held = append(held, res)
	}
	defer func() {
		for _, res := range held {
			res.Body.Close() //nolint:errcheck
		}
	}()

	if refused == 0 {
		t.Errorf("a single Account opened %d concurrent streams unrefused — the cap is %d",
			maxStreamsPerPrincipal+3, maxStreamsPerPrincipal)
	}
	if len(held) != maxStreamsPerPrincipal {
		t.Errorf("%d streams were admitted, want exactly the cap of %d", len(held), maxStreamsPerPrincipal)
	}

	// Subscriptions match slots, not requests: a refused stream must not
	// have subscribed on its way out.
	if got := bus.subscriptions(); got > maxStreamsPerPrincipal {
		t.Errorf("%d Subscriptions registered for %d permitted streams — a refusal subscribed anyway",
			got, maxStreamsPerPrincipal)
	}

	// RELEASE. A slot that is taken and never given back is permanent
	// capacity loss — the cap stops being a bound on concurrency and becomes
	// a lifetime budget, and the operator's live view goes dark for good
	// after four page loads. Close one and the next open must be admitted.
	held[0].Body.Close() //nolint:errcheck
	held = held[1:]

	deadline := time.Now().Add(5 * time.Second)
	for {
		res, err := open()
		if err != nil {
			t.Fatalf("reopen after closing a stream: %v", err)
		}
		if res.StatusCode == http.StatusOK {
			held = append(held, res)
			break
		}
		res.Body.Close() //nolint:errcheck
		if time.Now().After(deadline) {
			t.Fatal("a closed stream never released its slot — the cap is a lifetime budget, not a " +
				"bound on concurrency, and the live view goes dark permanently")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestConsoleEvents_LimiterBoundsBothWays exercises the limiter directly,
// because the global cap needs sixty-five concurrent sockets to reach over
// HTTP and the property is about the counter, not the transport. The test above
// is what proves the counter is actually wired to the route.
func TestConsoleEvents_LimiterBoundsBothWays(t *testing.T) {
	l := newStreamLimiter()

	// Per principal.
	for i := 0; i < maxStreamsPerPrincipal; i++ {
		if ok, why := l.acquire("acct-a"); !ok {
			t.Fatalf("acquire %d for one Account refused: %s", i, why)
		}
	}
	ok, why := l.acquire("acct-a")
	if ok {
		t.Error("one Account exceeded its own cap")
	}
	if !strings.Contains(why, "Account") {
		t.Errorf("the per-principal refusal says %q, which does not name what was exceeded", why)
	}

	// Release gives the slot back, and only one.
	l.release("acct-a")
	if ok, why := l.acquire("acct-a"); !ok {
		t.Errorf("a released slot was not reusable: %s", why)
	}
	if ok, _ := l.acquire("acct-a"); ok {
		t.Error("releasing one slot admitted two")
	}

	// Global. Distinct principals, each within its own cap, until the
	// process-wide bound refuses one that has no streams at all.
	l = newStreamLimiter()
	for i := 0; i < maxConcurrentStreams; i++ {
		key := fmt.Sprintf("acct-%d", i)
		if ok, why := l.acquire(key); !ok {
			t.Fatalf("acquire %d across distinct Accounts refused early: %s", i, why)
		}
	}
	ok, why = l.acquire("acct-fresh")
	if ok {
		t.Errorf("the process admitted %d concurrent streams — the global cap is %d",
			maxConcurrentStreams+1, maxConcurrentStreams)
	}
	if !strings.Contains(why, "Relay") {
		t.Errorf("the global refusal says %q, which reads as the Account's fault", why)
	}

	// And the global count releases too, or the Relay degrades to a one-shot.
	l.release("acct-0")
	if ok, why := l.acquire("acct-fresh"); !ok {
		t.Errorf("a released global slot was not reusable: %s", why)
	}
}

// TestConsoleEvents_SurvivesOverHTTP2 is the transport that ships.
//
// The control-plane listener sets no NextProtos and serves TLS, so h2 is on and
// every real browser negotiates it. Over h2 a write deadline is NOT a bound on
// a blocking write: it arms a per-stream timer whose expiry sends
// RST_STREAM(INTERNAL_ERROR) whether or not a write is pending. A deadline left
// armed therefore killed every stream on a fixed schedule — 10s deadline, 20s
// keepalive, dead at 30s — and the client reconnected successfully and died
// again, forever, which no bounded-reconnect count can catch because each
// reconnect SUCCEEDS.
//
// Everything else here runs over httptest.NewServer, which is HTTP/1.1
// cleartext, so nothing else in this file would ever have seen it.
func TestConsoleEvents_SurvivesOverHTTP2(t *testing.T) {
	// Compressed so the gate does not pay forty seconds to watch two
	// keepalives. The shape is what matters: the deadline is shorter than the
	// keepalive, which is what made the old code reset every idle stream at a
	// fixed interval.
	defer restoreStreamTimings(sseKeepalive, sseWriteTimeout)()
	sseKeepalive, sseWriteTimeout = 200*time.Millisecond, 100*time.Millisecond

	d := dayOneDeps()
	bus := d.Events.(*fakeEvents)

	srv := httptest.NewUnstartedServer(newTestHandler(d, accounts.RoleAdmin))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/console/events?kinds=enrollment", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testCredential)
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer res.Body.Close() //nolint:errcheck
	if res.ProtoMajor != 2 {
		t.Fatalf("stream negotiated %s, want HTTP/2 — this test is worthless on 1.1", res.Proto)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /console/events = %d, want 200", res.StatusCode)
	}

	s := &stream{res: res, rd: bufio.NewReader(res.Body), srv: srv}

	// Two keepalives and a live event past the point the armed deadline used
	// to reset the stream (sseWriteTimeout after the last write).
	for i := 1; i <= 4; i++ {
		frame := s.frameWithin(t, 5*time.Second)
		if !strings.HasPrefix(frame, ": keepalive") {
			t.Fatalf("frame %d = %q, want a keepalive — the stream was reset, which is the write "+
				"deadline left armed over h2 counting down to RST_STREAM", i, frame)
		}
	}

	bus.publish(events.EnrollmentEvent{
		Outcome: events.EnrollmentRejected, Reason: events.ReasonUnknown, Source: "203.0.113.2",
	})
	for {
		frame := s.frameWithin(t, 5*time.Second)
		if strings.HasPrefix(frame, ": keepalive") {
			continue // raced a keepalive; the event is behind it
		}
		if got := decodeFrame(t, frame); got.Outcome != "rejected" {
			t.Errorf("after four keepalives the stream delivered %+v, want the published rejection", got)
		}
		return
	}
}

// restoreStreamTimings puts the shipping values back. Deferred as a call so the
// arguments are evaluated before the test overwrites them.
func restoreStreamTimings(keepalive, write time.Duration) func() {
	return func() { sseKeepalive, sseWriteTimeout = keepalive, write }
}

// TestConsoleEvents_WriteDeadlinesSurviveTheMiddleware is the other half of the
// same control, and it guards the tolerance in write().
//
// handleEvents ignores ErrNotSupported so httptest.ResponseRecorder can be used
// at all. That tolerance is a real hole the day a ResponseWriter wrapper is
// added to this chain that implements Flush (passing the flusher gate) but not
// Unwrap: SetWriteDeadline would start returning ErrNotSupported on a REAL
// connection and the protection would vanish silently. So: over a real
// connection, on both transports, setting a deadline must return nil.
func TestConsoleEvents_WriteDeadlinesSurviveTheMiddleware(t *testing.T) {
	probe := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /console/probe", func(w http.ResponseWriter, _ *http.Request) {
		probe <- http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Minute))
	})
	// The Console's own middleware, in the order the composition root mounts
	// it — this is what a future wrapper would be added to.
	authn := controlplane.NewAuthenticator(roleVerifier{role: accounts.RoleAdmin})
	handler := authn.Middleware(Secure(mux))

	for _, tc := range []struct {
		name  string
		http2 bool
	}{{"http/1.1", false}, {"http/2", true}} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewUnstartedServer(handler)
			srv.EnableHTTP2 = tc.http2
			srv.StartTLS()
			defer srv.Close()

			req, err := http.NewRequest(http.MethodGet, srv.URL+"/console/probe", nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			req.Header.Set("Authorization", "Bearer "+testCredential)
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			res.Body.Close() //nolint:errcheck

			select {
			case err := <-probe:
				if err != nil {
					t.Fatalf("SetWriteDeadline through the Console's middleware = %v, want nil. "+
						"A ResponseWriter wrapper without Unwrap has silently disabled the SSE "+
						"route's only protection against a client that stops reading.", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the probe handler never ran")
			}
		})
	}
}

// TestConsoleEvents_AWriteErrorEndsTheStream: the deadline is only half the
// protection — the handler has to ACT on the error it produces. Without this,
// removing both the deadline and the write-error handling leaves every test in
// this file passing.
func TestConsoleEvents_AWriteErrorEndsTheStream(t *testing.T) {
	d := dayOneDeps()
	bus := d.Events.(*fakeEvents)

	// Through the real middleware chain, which passes the ResponseWriter
	// through untouched — so this is the shipping handler writing to a peer
	// that has gone away, not a hand-assembled one.
	h := newTestHandler(d, accounts.RoleAdmin)
	w := &brokenWriter{err: errors.New("connection reset by peer")}
	req := httptest.NewRequest(http.MethodGet, "/console/events?kinds=enrollment", nil)
	req.Header.Set("Authorization", "Bearer "+testCredential)

	returned := make(chan struct{})
	go func() {
		h.ServeHTTP(w, req)
		close(returned)
	}()

	// Give the handler time to subscribe, then hand it something to write.
	deadline := time.Now().Add(5 * time.Second)
	for bus.subscription(0) == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	sub := bus.subscription(0)
	if sub == nil {
		t.Fatal("the handler never subscribed")
	}
	bus.publish(events.EnrollmentEvent{Outcome: events.EnrollmentRejected, Reason: events.ReasonUnknown})

	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("a write error did not end the stream — the goroutine, the connection and a " +
			"256-slot Subscription are held until the OS reaps the socket")
	}

	select {
	case _, open := <-sub.C():
		if open {
			t.Error("the Subscription was not closed after the write error")
		}
	default:
		t.Error("the Subscription was not closed after the write error")
	}
}

// brokenWriter is a client that has stopped reading: it accepts the header and
// fails every body write.
type brokenWriter struct {
	hdr  http.Header
	code int
	err  error
}

func (b *brokenWriter) Header() http.Header {
	if b.hdr == nil {
		b.hdr = http.Header{}
	}
	return b.hdr
}
func (b *brokenWriter) Write(p []byte) (int, error) { return 0, b.err }
func (b *brokenWriter) WriteHeader(code int)        { b.code = code }
func (b *brokenWriter) Flush()                      {}

// ---------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------

// streamTestTimeout bounds a request to the streaming route made through an
// httptest.Recorder, which carries a context nothing ever cancels.
//
// Without it a refusal that stops being a refusal HANGS: adding a kind to
// consoleEventKinds turned TestConsoleEvents_UnknownKindIsRefused into a
// 20-second panic and a goroutine dump — killing the binary before the
// role-gate tripwire beside it could print what to do about it.
const streamTestTimeout = time.Second

// getBounded is get() with a context that expires, for requests to a route that
// may legitimately never return on its own.
func getBounded(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), streamTestTimeout)
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+testCredential)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// stream is one open SSE response over a REAL connection.
//
// A real server rather than an httptest.Recorder, because a recorder has no
// cancellable context and no write deadline: the two things this handler's
// lifecycle is built out of would both be untested.
type stream struct {
	res *http.Response
	rd  *bufio.Reader
	srv *httptest.Server
}

func openStream(t *testing.T, d Deps, path string) *stream {
	t.Helper()
	return openStreamAs(t, d, path, accounts.RoleAdmin)
}

func openStreamAs(t *testing.T, d Deps, path string, role accounts.Role) *stream {
	t.Helper()

	srv := httptest.NewServer(newTestHandler(d, role))
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		srv.Close()
		t.Fatalf("build stream request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testCredential)

	res, err := srv.Client().Do(req)
	if err != nil {
		srv.Close()
		t.Fatalf("open stream: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		srv.Close()
		t.Fatalf("GET %s = %d, want 200", path, res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}
	if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store — a cached event stream is a stale one", cc)
	}

	s := &stream{res: res, rd: bufio.NewReader(res.Body), srv: srv}
	t.Cleanup(s.close)
	return s
}

// close ends the request. Every test that opens a stream must, because
// http.Server.Shutdown does not cancel in-flight request contexts — an
// unclosed stream costs the whole shutdown grace period.
func (s *stream) close() {
	s.res.Body.Close()
	s.srv.Close()
}

// frame reads one SSE frame, failing rather than hanging.
func (s *stream) frame(t *testing.T) string {
	t.Helper()
	return s.frameWithin(t, 5*time.Second)
}

// frameWithin is frame with an explicit budget, for the keepalive tests.
func (s *stream) frameWithin(t *testing.T, budget time.Duration) string {
	t.Helper()

	type read struct {
		frame string
		err   error
	}
	done := make(chan read, 1)
	go func() {
		var b strings.Builder
		for {
			line, err := s.rd.ReadString('\n')
			if err != nil {
				done <- read{b.String(), err}
				return
			}
			if line == "\n" {
				done <- read{b.String(), nil}
				return
			}
			b.WriteString(line)
		}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("read SSE frame: %v (partial %q)", r.err, r.frame)
		}
		return r.frame
	case <-time.After(budget):
		t.Fatalf("timed out after %s waiting for an SSE frame", budget)
		return ""
	}
}

// decodeFrame parses a frame's data: line back into the projection the handler
// emitted.
func decodeFrame(t *testing.T, frame string) sseEnrollment {
	t.Helper()

	for _, line := range strings.Split(frame, "\n") {
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var got sseEnrollment
		if err := json.Unmarshal([]byte(data), &got); err != nil {
			t.Fatalf("decode %q: %v", data, err)
		}
		return got
	}
	t.Fatalf("frame carries no data: line: %q", frame)
	return sseEnrollment{}
}

// readAsset reads a file out of the embedded assets, which is what the Console
// actually serves — not the copy on disk beside it.
func readAsset(t *testing.T, name string) string {
	t.Helper()
	b, err := assetsFS.ReadFile(name)
	if err != nil {
		// Fall back to disk only to produce a better failure than "file does
		// not exist" if the embed directive ever stops matching.
		if _, statErr := os.Stat(name); statErr == nil {
			t.Fatalf("%s exists on disk but is not embedded: %v", name, err)
		}
		t.Fatalf("read embedded asset %s: %v", name, err)
	}
	return string(b)
}

// TestConsoleEvents_RequiredRoleIsTheMaximumRegardlessOfOrder.
//
// `needed` starts as the empty role, and Role.AtLeast is false whenever EITHER
// side is invalid — so an unconditional "raise on !AtLeast" OVERWRITES an
// invalid requirement with the next valid one, and the answer depends on the
// order the caller listed the kinds in. The table this package ships has two
// valid entries, so this is only reachable through an allowlist a test
// supplies: which is the point, because this gate's whole argument is that it
// makes the NEXT widening safe.
func TestConsoleEvents_RequiredRoleIsTheMaximumRegardlessOfOrder(t *testing.T) {
	table := map[string]consoleEventKind{
		"low":  {events.KindEnrollment, accounts.RoleViewer},
		"high": {events.KindJob, accounts.RoleAdmin},
	}
	for _, param := range []string{"low,high", "high,low"} {
		sub, ok := resolveEventKinds(param, table)
		if !ok {
			t.Fatalf("resolveEventKinds(%q) refused a valid table", param)
		}
		if sub.Needed != accounts.RoleAdmin {
			t.Errorf("resolveEventKinds(%q) requires %q, want admin — the requirement must be the "+
				"MAXIMUM over the requested kinds, not whichever entry was listed last", param, sub.Needed)
		}
	}

	// An entry whose MinRole is not a role at all is a bug in the table, and
	// the safe reading of a bug in an authz table is REFUSE — in either order,
	// and never "whatever the next entry happened to say".
	broken := map[string]consoleEventKind{
		"job":        {events.KindJob, accounts.RoleViewer},
		"superadmin": {events.KindToolCall, accounts.Role("superadmin")},
	}
	for _, param := range []string{"superadmin", "superadmin,job", "job,superadmin"} {
		sub, ok := resolveEventKinds(param, broken)
		if ok {
			t.Errorf("resolveEventKinds(%q) admitted a kind whose MinRole is not a role, requiring "+
				"%q — an unrecognised requirement must refuse, not resolve to the entry beside it",
				param, sub.Needed)
		}
		if sub.Kinds != nil {
			t.Errorf("resolveEventKinds(%q) returned kinds alongside its refusal: %v", param, sub.Kinds)
		}
	}
}

// TestConsoleEvents_FrameIDsCannotBreakFrameStructure pins the invariant
// frame() relies on WHERE it is relied on.
//
// json.Marshal escapes newlines inside the payload, so no rendered value can
// split a frame — but the `id:` line is raw concatenation of the event's ID. A
// newline there would end the frame early and let the remainder be read as a
// second, forged event. The bus mints IDs as hex plus a sequence number, so no
// such ID exists; this fails if that ever stops being true.
func TestConsoleEvents_FrameIDsCannotBreakFrameStructure(t *testing.T) {
	bus := newFakeEvents()
	bus.publishJob(events.JobEvent{Transition: events.JobCreated, JobID: "job-1"})
	bus.publish(events.EnrollmentEvent{Outcome: events.EnrollmentRejected, Reason: events.ReasonUnknown})

	recent := bus.Recent([]events.Kind{events.KindJob, events.KindEnrollment}, 10)
	if len(recent) != 2 {
		t.Fatalf("the bus retained %d events, want 2", len(recent))
	}
	for _, ev := range recent {
		if ev.ID == "" {
			t.Error("an event carries no ID, so a reconnect cannot resume from it")
		}
		if strings.ContainsAny(ev.ID, "\r\n") {
			t.Errorf("the event ID %q contains a line break — frameEvent concatenates it into the "+
				"`id:` line unescaped, so this would split one frame into two", ev.ID)
		}
		frame, ok := frameEvent(ev)
		if !ok {
			t.Fatalf("frameEvent declined to render %v", ev.Kind)
		}
		// Exactly one blank-line terminator, at the very end: the frame is one
		// frame.
		if n := strings.Count(frame, "\n\n"); n != 1 || !strings.HasSuffix(frame, "\n\n") {
			t.Errorf("the frame for %v has %d terminators and does not end in one: %q", ev.Kind, n, frame)
		}
	}
}
