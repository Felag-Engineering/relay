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

import (
	"net/http"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
)

// renderDayOne writes the zero-Node screen into an already-built Page.
//
// It takes the Page rather than building one so the shell, the navigation and
// any control-plane banner are identical to every other screen: a Relay that is
// frozen on day one must say so, and an operator whose first screen has a
// different frame learns a different product than the one they will use.
func renderDayOne(w http.ResponseWriter, p Page, d Deps) {
	p.Title = "Day one"
	renderScreen(w, p, dayOneTmpl, dayOne{
		CanMint: p.Role.AtLeast(accounts.RoleAdmin),
		// Rejected enrollment attempts are the half of this screen that
		// actually debugs a stuck install — a daemon dialling in with a
		// revoked token, or no token at all, is invisible everywhere else.
		// Surfacing them needs the enrollment publisher on the SSE seam
		// (#416), and daemon-side TLS handshake aborts need #444 on top of
		// that. Saying so is the honest state; a silent empty list would read
		// as "nothing has tried", which is the one conclusion an operator must
		// not draw from this screen.
		AttemptsWired: false,
	})
}

type dayOne struct {
	CanMint       bool
	AttemptsWired bool
}

var dayOneTmpl = newScreen("dayone", `
<div class="dayone">
  <h2>No Nodes have enrolled yet.</h2>
  <p class="lede">This Relay is running and listening. Nothing has joined it, which on a
  first run is exactly what you would expect.</p>

  <ol class="steps">
    <li>
      <b>Mint an Enrollment Token.</b>
      {{if .CanMint}}<a href="/console/nodes/add">Add Nodes</a> renders the token and the join
      artifacts together, once.{{else}}An <code>admin</code> mints one — the token's scope becomes
      the joining Node's <code>relay:</code> labels, which is the security lane, so it is not a
      viewer's to create.{{end}}
    </li>
    <li>
      <b>Install <code>relay-daemon</code> on a machine</b> through your configuration management,
      with the Relay's address, the CA fingerprint and the token.
    </li>
    <li>
      <b>The daemon dials home.</b> It presents the token once, receives a client certificate, and
      from then on its identity <em>is</em> that certificate — the token is spent.
    </li>
  </ol>

  <div class="watching">
    <span class="pulse" aria-hidden="true"></span>
    <div>
      <b>Watching for the first enrollment.</b>
      <div class="sub">Reload to check. Live updates arrive with the event stream.</div>
    </div>
  </div>

  {{if not .AttemptsWired}}
  <p class="gap"><b>Rejected attempts are not shown yet.</b> A daemon that dials in with a
  revoked, expired or malformed token is refused by the Relay and does not appear here — this
  screen currently shows an empty fleet, not the absence of attempts. The enrollment publisher on
  the event seam is what makes the difference visible.</p>
  {{end}}
</div>
`)
