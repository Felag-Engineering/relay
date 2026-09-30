package console

// dayone.go is the Console with zero Nodes (spec 10).
//
// # Why an empty registry is a screen and not an empty table
//
// The fleet view's job is to compress thousands of Nodes into the few that
// matter. Handed none, that machinery produces column headings over nothing,
// which reads as "this works, and you have no machines" — a confident statement
// about a fleet, made at the exact moment the operator has not started yet and
// has no way to tell a working Relay from a broken one.
//
// So day one answers a different question: what do I do next, and is anything
// trying to join? It is the only screen in the Console whose job is to be
// replaced, and it succeeds by disappearing the moment a daemon enrolls.
//
// # What it deliberately does not do
//
// It does not mint an Enrollment Token. Minting is `admin` + audited and lives
// on Add Nodes (spec 09, v0.7.0, #434); a one-click token on the empty state
// would put the fleet's join credential behind the least deliberate click in
// the product. Day one points at the door — it is not a second door.
//
// It does not embed the quickstart, and it does not render a checklist of steps
// the Console cannot verify — spec 10's "what this screen is not", in both
// cases. The three-step tutorial this screen used to carry was exactly that
// checklist, and it is gone (#474).
//
// # The live watch, and what it cannot see
//
// The watch is the reason this screen is worth leaving open while a playbook
// runs, and rejected attempts are the half of it that actually debugs a stuck
// install. It renders the retained history first (EventReader.Recent) and then
// resumes the stream from the newest event it rendered, so nothing appears
// twice and nothing falls between the page and the connection.
//
// It states the window it actually has — whatever the seam reports through
// EventReader.RetentionWindow — because a screen claiming a wider view than its
// buffer is the precise failure spec 10's failure-feedback section forbids.
//
// And it says out loud what the Relay cannot attribute at all: a daemon whose
// configured trust root does not match this Relay aborts the TLS handshake
// before it sends anything (the daemon verifies the chain against the CA bundle
// it was installed with — daemon/src/tunnel.rs), so it is not a rejection this
// screen can show. Surfacing those needs a listener hook (#444). Until then the
// fingerprint below is how an operator checks they handed out the right trust
// root, and the screen must not imply it is watching for a failure it cannot
// see.
//
// # The fingerprints, and what is NOT here
//
// The CA fingerprint is rendered first, as the value to check: it identifies
// the trust root every Node's certificate chains to, and it survives the server
// leaf's daily re-issue. ADR-0031 decision 3 makes it the number a daemon will
// PIN, through a join string — neither is built (nothing in relay/, daemon/ or
// proto/ carries a CA fingerprint today), so this screen says what the value is
// for without claiming a mechanism the tree does not have.
//
// The control-plane server leaf is rendered beside it, labelled honestly as
// re-issued about daily and explicitly not a thing to pin — presenting a leaf
// as a comparison ritual is what ADR-0031 rejects, because a browser exception
// pinned to it breaks at every rotation.
//
// There is NO reachable address on this screen. Contents item 4 of spec 10 asks
// for one; acceptance criterion 5 forbids exposing "any Relay configuration
// value", and a listen address is exactly that (invariant 11) — operator-set at
// startup and unreachable from any API, which is a property seams.go states and
// this screen must not be the first thing to weaken. The address a Node dials
// is delivered by whatever installs the daemon (RELAY_ADDR, daemon/src/config.rs),
// and ADR-0031's join string will carry it once that lands.

import (
	"net/http"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/events"
)

// dayOneAttempts is how many retained enrollment attempts the screen renders
// before the stream takes over. A cap, not a page: the seam holds at most a few
// minutes of history and this screen is read from the top.
const dayOneAttempts = 20

// renderDayOne writes the zero-Node screen into an already-built Page.
//
// It takes the Page rather than building one so the shell, the navigation and
// any control-plane banner are identical to every other screen: a Relay that is
// frozen on day one must say so, and an operator whose first screen has a
// different frame learns a different product than the one they will use.
func renderDayOne(w http.ResponseWriter, p Page, d Deps) {
	p.Title = "Day one"

	v := dayOne{
		Account:    p.Account,
		Role:       p.Role,
		CanMint:    p.Role.AtLeast(accounts.RoleAdmin),
		TrustWired: d.Trust != nil,
		Watching:   d.Events != nil,
	}
	if d.Trust != nil {
		v.CAFingerprint = d.Trust.CAFingerprint()
		v.ServerFingerprint = d.Trust.ServerFingerprint()
	}
	if d.Events != nil {
		// The window this bus actually holds, not a constant that would be
		// right until someone changed the bus.
		v.RetentionMinutes = int(d.Events.RetentionWindow() / time.Minute)
		v.Attempts, v.LastEventID = dayOneWatch(d.Events)
		// A screen with no live seam must not load a script that would sit
		// there failing to connect. stream.js FIRST: it defines
		// window.RelayLive, which dayone.js reads at load time.
		p.Scripts = []string{"/console/assets/stream.js", "/console/assets/dayone.js"}
	}

	renderScreen(w, p, dayOneTmpl, v)
}

// dayOneWatch reads the retained enrollment history, newest first, and returns
// the ID the client must resume from.
//
// The ID is the NEWEST rendered event's, so the stream picks up exactly where
// the server render stopped: no attempt is shown twice, and none is lost in the
// window between rendering the page and the browser connecting.
func dayOneWatch(r EventReader) ([]dayOneAttempt, string) {
	recent := r.Recent([]events.Kind{events.KindEnrollment}, dayOneAttempts)
	if len(recent) == 0 {
		return nil, ""
	}

	lastEventID := recent[len(recent)-1].ID
	attempts := make([]dayOneAttempt, 0, len(recent))
	for i := len(recent) - 1; i >= 0; i-- {
		ev := recent[i]
		if ev.Enrollment == nil {
			continue
		}
		a := dayOneAttempt{
			Accepted: ev.Enrollment.Outcome == events.EnrollmentAccepted,
			TokenID:  ev.Enrollment.TokenID,
			Source:   ev.Enrollment.Source,
			At:       ev.At.UTC().Format("2006-01-02 15:04:05Z"),
		}
		// Only a rejection carries a reason. See sseEnrollment.Reason: the
		// seam delivers every ACCEPTED attempt with events.ReasonInternal,
		// so rendering it here would label the first successful enrollment
		// on a new fleet "internal error" — in the bootstrap rows exactly as
		// it would on the stream.
		if !a.Accepted {
			a.Reason = enrollmentReasonText(ev.Enrollment.Reason)
		}
		attempts = append(attempts, a)
	}
	return attempts, lastEventID
}

// dayOne is the screen.
type dayOne struct {
	Account string
	Role    accounts.Role
	CanMint bool

	TrustWired        bool
	CAFingerprint     string
	ServerFingerprint string

	// Watching is whether the event seam is wired. False keeps the screen on
	// its honest "rejected attempts are not shown yet" paragraph, which is
	// what an unwired seam must say — a silent empty list would read as
	// "nothing has tried", the one conclusion an operator must not draw here.
	Watching         bool
	Attempts         []dayOneAttempt
	LastEventID      string
	RetentionMinutes int
}

// dayOneAttempt is one Relay-side enrollment attempt as this screen renders it.
// Reason is already humanised (enrollmentReasonText) so the server-rendered rows
// and the live ones are worded by one implementation.
type dayOneAttempt struct {
	Accepted bool
	Reason   string
	TokenID  string
	Source   string
	At       string
}

// The watch panel's states are rendered as sibling elements and selected by the
// panel's data-live attribute in CSS. That is not a styling trick: it keeps
// every word of display copy in Go, so the script file carries behaviour and no
// product language at all. The same reason the attempt row is a <template> the
// script clones rather than markup the script builds.
var dayOneTmpl = newScreen("dayone", `
<div class="dayone">
  <h2>No Nodes have enrolled yet.</h2>
  <p class="lede">This Relay is running and listening. Nothing has joined it, which on a
  first run is exactly what you would expect.</p>

  <ul class="truths">
    <li>The Relay is up and accepting connections.</li>
    {{if .TrustWired}}<li>Its certificate authority is issued &mdash; the fingerprint is below.</li>{{end}}
    <li>You are signed in as <b>{{.Account}}</b> with the role <b>{{.Role}}</b>, so the first
    Account exists.</li>
  </ul>

  <div class="firststep">
    {{if .CanMint}}
    <p><b>Add Nodes</b> is not built yet. When it is, it will show an Enrollment Token and
    everything a machine needs to join, together and only once.</p>
    {{else}}
    <p>An <code>admin</code> mints the Enrollment Token. Its scope becomes the joining Node&#39;s
    <code>relay:</code> labels, which is the security lane, so it is not a viewer&#39;s to
    create.</p>
    {{end}}
    <p class="note">The end-to-end walkthrough is <code>docs/quickstart.md</code>, which is not
    published with this build.</p>
  </div>

  <section class="watch" id="dayone-watch" data-live-region
           data-live="{{if .Watching}}down{{else}}off{{end}}"
           data-events="/console/events?kinds=enrollment"
           data-last-event-id="{{.LastEventID}}">
    <div class="watchhead">
      <span class="pulse" aria-hidden="true"></span>
      <b>Watching for enrollments.</b>
      <span class="wmsg" data-when="on">Attempts appear here as they happen.</span>
      <span class="wmsg" data-when="down">The live watch is not connected.</span>
      <span class="wmsg" data-when="gap">The live watch fell behind &mdash; reloading.</span>
      <span class="wmsg" data-when="ended">The live watch has stopped. Your session may have ended;
      reload the page to sign in again.</span>
      <span class="wmsg" data-when="off">Live updates are not available on this Relay.</span>
    </div>

    {{if .Watching}}
    <p class="dim" id="dayone-empty"{{if .Attempts}} hidden{{end}}>No enrollment attempts in the
    last {{.RetentionMinutes}} {{plural .RetentionMinutes "minute" "minutes"}}.</p>
    {{end}}

    <ul class="attempts" id="dayone-attempts">
      {{range .Attempts}}
      <li class="attempt" data-outcome="{{if .Accepted}}accepted{{else}}rejected{{end}}">
        <span class="aout">{{if .Accepted}}accepted{{else}}refused{{end}}</span>
        <span class="areason">{{.Reason}}</span>
        <span class="atok"><code>{{.TokenID}}</code></span>
        <span class="asrc">{{.Source}}</span>
        <span class="awhen">{{.At}}</span>
      </li>
      {{end}}
    </ul>

    <template id="dayone-attempt-row">
      <li class="attempt" data-outcome="rejected">
        <span class="aout">refused</span>
        <span class="areason"></span>
        <span class="atok"><code></code></span>
        <span class="asrc"></span>
        <span class="awhen"></span>
      </li>
    </template>
  </section>

  {{if not .Watching}}
  <p class="gap"><b>Rejected attempts are not shown yet.</b> A daemon that dials in with a
  revoked, expired or malformed token is refused by the Relay and does not appear here. So this
  screen shows an empty fleet, not proof that nothing tried to join. Refused attempts appear here
  only when this Relay's live updates are available.</p>
  {{end}}

  <section class="trust">
    <h3>What a machine needs in order to trust this Relay</h3>
    {{if .TrustWired}}
    <dl class="kv">
      <dt>CA fingerprint</dt>
      <dd><code title="{{.CAFingerprint}}">{{short .CAFingerprint}}</code>
      <span class="note">This identifies the certificate authority every Node&#39;s certificate
      chains to. It stays the same when the server certificate below is re-issued. It is
      the value to compare against the one this Relay logged at startup. Today a daemon trusts this authority
      because it was installed with its certificate. Pinning this number directly is not built
      yet.</span></dd>
      <dt>Server certificate</dt>
      <dd><code title="{{.ServerFingerprint}}">{{short .ServerFingerprint}}</code>
      <span class="note">The certificate this Console is served over right now. It is re-issued
      about daily; it is not what you pin.</span></dd>
    </dl>
    {{else}}
    <p class="dim">The CA and server-certificate fingerprints are not wired into this Console, so
    this screen cannot show you what to compare. This is not a certificate problem, and it
    is not something you can configure: it comes from how this Relay was built.</p>
    {{end}}
  </section>

  <details class="about">
    <summary>About this screen</summary>
    <p class="gap"><b>A daemon that refuses this Relay&#39;s certificate never appears here.</b> It
    aborts the handshake before it sends a token, so the Relay sees a connection and no attempt at
    all. What catches that is checking the CA fingerprint above against the one this Relay logged at
    startup before you install a daemon against it &mdash; this screen cannot.</p>
  </details>
</div>
`)
