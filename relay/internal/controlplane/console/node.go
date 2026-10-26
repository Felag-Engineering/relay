package console

// node.go is everything Relay knows about one machine (spec 02), and the one
// page in the Console where Facts appear.
//
// # Why Facts are confined to this page
//
// OS, kernel, arch, hostname and IP are self-reported by the daemon, and a
// compromised Node can report whatever it likes. That is tolerable on a detail
// page a human is reading about one machine and intolerable as a targeting axis:
// a fleet-wide `os=ubuntu` filter that a Node can opt itself into is a fleet-wide
// filter an attacker can opt into. Targeting is on labels, whose namespaces have
// enforced writers (invariant 7).
//
// The panel is labelled so an implementer does not later "helpfully" surface a
// Fact on a fleet row. If you are reading this because you were about to: that
// is the thing this file exists to prevent.
//
// # The effective-Policy panel
//
// It renders what the Node's own engine REPORTED (policyview, ADR-0011), stamped
// with when. The Relay never evaluates Policy (invariant 12) and never writes it
// (ADR-0002, invariant 2), and the panel says both out loud — not as a
// disclaimer, but because "read-only" here is structural: there is no code path
// from this screen to a Node's Policy file, and an operator who does not know
// that will go looking for the edit button and conclude the product is broken
// when they cannot find it.
//
// # The one write
//
// Policy and Facts stay read-only. The page's one write is a tag: label, added
// or removed through the capability layer's TagWriter (tags.go) for an Account
// offered it; every other namespace renders with no control (invariant 7).

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/nodestate"
	"github.com/Felag-Engineering/relay/relay/internal/policyview"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// nodeTaskRows bounds the recent-Task list. Node detail is a page about one
// machine, not its whole history — the Activity screen is where history is
// read, filtered.
const nodeTaskRows = 40

type nodeFact struct{ Key, Value string }

type nodeTask struct {
	When      string
	Operation string
	Args      string
	Outcome   string
	JobID     string
	JobHref   string
	Principal string
	Verified  bool

	// Denied carries the deny block when Policy refused this Task. It is the
	// most informative row on the page and is never styled as a failure.
	Denied *Deny

	// RepeatDeny marks a deny whose rule was already explained further up the
	// list. The row keeps its outcome chip; only the duplicated prose is
	// dropped.
	RepeatDeny bool

	// RawExecTier is set only by trailRowName, from the record's ActionKind or
	// RawExecArgv — never from the Operation's name (D18).
	RawExecTier bool
}

type nodeView struct {
	ID       string
	Hostname string

	Connected   bool
	LastSeen    string
	LastSeenAbs string
	Revoked     bool
	RevokedAt   string

	States []Label
	Labels []Label

	// TagEdit is the tag add and remove controls. Nil for an Account not
	// offered the write route, or when the seam is unwired: absent, not
	// disabled.
	TagEdit *nodeTagEdit

	CertFingerprint string
	EnrollingToken  string
	DaemonVersion   string

	// The certificate provenance the Relay issued. Rendered only when
	// CertProvenanceKnown — a Node that enrolled before it was stored has a zero
	// expiry, and printing that would report an identity overdue since 1970.
	CertNotAfter  string
	CertExpiresIn string
	EnrolledAt    string
	RenewalCount  int
	LastRenewedAt string
	// CertProvenanceKnown gates the certificate rows. False means the Relay has
	// nothing recorded for this Node — not that it is fine — so the panel says
	// which, because a missing "expires" row reads as the reassuring answer.
	CertProvenanceKnown bool

	PolicyFingerprint   string
	TemplateFingerprint string
	TemplateUnloadable  bool
	// PolicyShared and TemplateShared are how many Nodes in the fleet report the
	// same fingerprint. That comparison is the whole value of a fingerprint:
	// confirming a rollout landed is string equality, not trust.
	PolicyShared   int
	TemplateShared int

	// PolicyFingerprintHref, TemplateFingerprintHref and
	// TemplateUnloadableHref target every Node reporting the same value, as a
	// Selector. Empty when there is nothing targetable — including when the
	// self-reported value failed nodestate's value validation, in which case
	// the fingerprint renders as text with no link rather than as a sanitised
	// one.
	PolicyFingerprintHref   string
	TemplateFingerprintHref string
	TemplateUnloadableHref  string

	Facts []nodeFact

	Policy         *policyview.Snapshot
	PolicyReported bool

	// A Policy snapshot captured on the tunnel is rendered whatever the
	// registry holds (QRY-7). These three say that the registry holds no
	// Hello-recorded daemon version or Policy fingerprint for the Node, so the
	// Console states that fact and does not count the Node as current or
	// permitted. They make no claim about what the Node's effective Policy is.
	//
	// PolicyUncorroborated is set only when a snapshot is shown and the Node is
	// unreported by the same predicate Fleet uses; the other two name which
	// recorded field is missing.
	PolicyUncorroborated  bool
	VersionUnrecorded     bool
	FingerprintUnrecorded bool

	// PolicyReportedAt and PolicyReportedAgo are when the RELAY received this
	// report, from policyview's own clock. Both stay empty for a snapshot with
	// no receipt time, which the panel says out loud — a zero time rendered
	// absolutely is a Policy read in 1970.
	PolicyReportedAt  string
	PolicyReportedAgo string

	// PolicyStale marks a reported Policy that cannot be re-read: the Node is
	// offline, and the snapshot refreshes on (re)connect and at no other time.
	PolicyStale bool

	// The revocation record, read from the trail. RevokedBy is who did it;
	// RevocationRecorded distinguishes "the trail has no record" from "the
	// record says nothing", because the registry retains RevokedAt whether or
	// not the trail was ever wired.
	//
	// RevocationReason is why, and is EMPTY FOR EVERY REVOCATION RECORDED
	// while the endpoint accepted no reason to record. That is a third
	// state, not a variant of the other two: the trail has a record, the
	// record names an Account, and the reason field is blank because there was
	// nowhere to put one. The template says so rather than rendering an empty
	// space, because "no reason given" and "this Relay could not ask for one"
	// are different facts about the operator who revoked.
	RevokedBy          string
	RevocationReason   string
	RevocationRecorded bool

	// Pin is the pinned set and the bar that draws it (the shared "pin-bar"
	// component). PinHref pins THIS Node and is empty once it is pinned or the
	// set is full — the bar itself says which. Once pinned, this Node's own
	// chip in the bar reads "this Node" rather than linking back here.
	Pin     pinState
	Pinned  bool
	PinHref string

	Tasks       []nodeTask
	TasksElided bool
	AuditWired  bool
}

func handleNode(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The read lane takes a capability.Principal, so this screen reads
		// the one the Authenticator injected as well as the Page the shell
		// needs. Both are context reads; page() resolves the same principal
		// itself.
		caller, ok := principal(w, r)
		if !ok {
			return
		}
		if d.Queries == nil {
			unavailable(w, "the audited read lane")
			return
		}
		d, lane := latched(d)
		ctx := r.Context()
		nodeID := r.PathValue("node_id")

		// THIS READ IS AUDITED (ADR-0025). Node detail is the widest
		// single-Node disclosure the Console makes — every Label namespace,
		// every Fact, the certificate provenance and the Node's own reported
		// Policy — and ADR-0025 names describe_node explicitly. The
		// capability layer writes the access record BEFORE it consults the
		// registry, so the record covers the ATTEMPT: a probe for an id that
		// does not exist is on the trail exactly like a read of one that
		// does, which is what makes enumeration-by-guessing visible.
		//
		// Fail closed, with no exception for this screen or any other: a
		// Console page whose read cannot be audited refuses to render.
		detail, err := d.Queries.DescribeNode(ctx, caller, nodeID)
		switch {
		case errors.Is(err, capability.ErrNodeNotFound), errors.Is(err, capability.ErrInvalidFilter):
			// Both render the same page on purpose. An id the registry does
			// not hold and an id too long to be one are the same answer to
			// the operator — there is no such Node — and telling the two
			// apart on screen would only tell a prober which of their guesses
			// was well-formed.
			p, ok := page(d, w, r, "Node not found")
			if !ok {
				return
			}
			p.Banner = banner(d, r)
			w.WriteHeader(http.StatusNotFound)
			renderScreen(w, p, nodeMissingTmpl, nodeID)
			return
		case err != nil:
			readFailed(w, err, "this Node's registry record")
			return
		}
		n := detail.Node

		// The hostname is self-reported, so it leads only when it is plainly a
		// hostname; otherwise the heading is the full Node ID, never a truncated
		// one that could not tell two Nodes apart.
		host := primaryHostname(n.Facts.Hostname)
		title := host
		if host == "" {
			title = n.NodeID
		}
		p, ok := page(d, w, r, title)
		if !ok {
			return
		}
		p.TitleSelfReported = host != ""
		p.Banner = banner(d, r)
		pins, _ := parsePins(r.URL.Query().Get("pin"))
		resolve, err := pinsResolved(ctx, d, caller, n, pins)
		if err != nil {
			readFailed(w, err, "the pinned Nodes' registry records")
			return
		}
		v := buildNodeView(d, r, detail, pins, resolve)
		v.TagEdit = newNodeTagEdit(d, accounts.Role(caller.Role), n.NodeID, p.CSRFToken)
		if refusedUnaudited(w, lane, "this Node's registry record") {
			return
		}
		renderScreen(w, p, nodeTmpl, v)
	}
}

// pinsResolved resolves the pin bar's ids through the AUDITED lane, one
// describe_node per id, and returns the resolver buildPinState draws with.
//
// One record per pinned Node, not per page view of the fleet: the set is
// bounded at maxPins (3), the current Node is already resolved by the read
// above and is never asked for twice, and every id in it is one an operator
// deliberately pinned. That is the honest accounting — a pin bar telling you
// whether `node-prod-7` exists IS a registry disclosure, and the alternative
// designs were a second unaudited door (FleetReader.Get, which is what this
// replaced) or enumerating the whole fleet to check three ids.
//
// An unknown or malformed id resolves to a dead chip rather than an error:
// that is the answer, and the read that produced it is already recorded. Any
// OTHER error — including an unauditable one — is returned, so the page fails
// closed as a whole rather than silently drawing a bar it could not resolve.
func pinsResolved(ctx context.Context, d Deps, caller capability.Principal, self registry.Node, ids []string) (pinResolver, error) {
	type resolution struct {
		host  string
		known bool
	}
	set := map[string]resolution{self.NodeID: {primaryHostname(self.Facts.Hostname), true}}
	for _, id := range ids {
		if _, seen := set[id]; seen {
			continue
		}
		detail, err := d.Queries.DescribeNode(ctx, caller, id)
		switch {
		case err == nil:
			set[id] = resolution{primaryHostname(detail.Node.Facts.Hostname), true}
		case errors.Is(err, capability.ErrNodeNotFound), errors.Is(err, capability.ErrInvalidFilter):
			set[id] = resolution{}
		default:
			return nil, err
		}
	}
	return func(id string) (string, bool) {
		r := set[id]
		return r.host, r.known
	}, nil
}

func buildNodeView(d Deps, r *http.Request, detail capability.NodeDetail, pins []string, resolve pinResolver) nodeView {
	n := detail.Node
	in := nodestate.Input{Node: n, Now: d.now(), CertExpiringWithin: detail.Eval.CertExpiringWithin}

	v := nodeView{
		ID:                  n.NodeID,
		Hostname:            primaryHostname(n.Facts.Hostname),
		Connected:           n.Connected,
		LastSeen:            nodestate.Since(n.LastSeen, d.now()),
		LastSeenAbs:         utcStamp(n.LastSeen),
		Revoked:             !n.RevokedAt.IsZero(),
		States:              stateChips(nodestate.Markers(in)),
		Labels:              declaredChips(n),
		CertFingerprint:     n.CertFingerprint,
		EnrollingToken:      n.EnrollingTokenID,
		DaemonVersion:       n.DaemonVersion,
		CertProvenanceKnown: nodestate.CertExpiryKnown(n),
		PolicyFingerprint:   n.PolicyFingerprint,
		TemplateFingerprint: n.TemplateSetFingerprint,
		TemplateUnloadable:  n.TemplateSetFingerprint == nodestate.TemplateUnloadable,
		Facts:               factRows(n),
		AuditWired:          d.Audit != nil,
	}
	if v.Revoked {
		v.RevokedAt = utcStamp(n.RevokedAt)
	}
	v.applyCertProvenance(d, n)
	v.applyFingerprintLinks(in)

	v.applyPins(n.NodeID, pins, resolve)

	// Fingerprint sharing counts. Computed by the read lane, behind the same
	// describe_node record (capability.NodeDetail): this screen must not
	// enumerate the whole registry to render two integers about one Node —
	// that would be a far wider disclosure than the read it actually made,
	// and one that would then have to be audited as an enumeration to stay
	// honest.
	v.PolicyShared, v.TemplateShared = detail.PolicyPeers, detail.TemplatePeers

	v.applyReportedPolicy(d, detail)

	if d.Audit != nil {
		if recs, err := d.Audit.ByNode(r.Context(), n.NodeID); err == nil {
			v.applyAuditTrail(recs)
		}
	}
	return v
}

// applyCertProvenance fills the certificate fields, which are shown only for a
// Node whose enrollment recorded when its certificate expires.
func (v *nodeView) applyCertProvenance(d Deps, n registry.Node) {
	if !v.CertProvenanceKnown {
		return
	}
	v.CertNotAfter = utcStamp(n.CertNotAfter)
	v.CertExpiresIn = nodestate.Until(n.CertNotAfter, d.now())
	v.RenewalCount = n.RenewalCount
	if !n.EnrolledAt.IsZero() {
		v.EnrolledAt = utcStamp(n.EnrolledAt)
	}
	if !n.LastRenewedAt.IsZero() {
		v.LastRenewedAt = utcStamp(n.LastRenewedAt)
	}
}

// applyFingerprintLinks sets the fingerprint Selector links, built from
// nodestate's own derivation rather than by concatenating the raw fingerprint
// into a term.
//
// The values are self-reported and reach the registry unvalidated, and this
// link is advertised as directly targetable. nodestate.Facts runs
// validFactValue, which drops a value carrying a comma, whitespace or a
// namespace prefix — the injection that would otherwise let a Node add a
// second Selector term to a link the Console offers. A rejected value
// renders as text with no link; it is never sanitised into one.
func (v *nodeView) applyFingerprintLinks(in nodestate.Input) {
	link := linkContext{}
	for _, l := range nodestate.Facts(in) {
		switch l.Key {
		case string(nodestate.FactPolicyFingerprint):
			v.PolicyFingerprintHref = link.href(l.String())
		case string(nodestate.FactTemplateFingerprint):
			v.TemplateFingerprintHref = link.href(l.String())
		}
	}
	// The unloadable literal is a MARKER, not a fact: nodestate.Facts excludes
	// it by name, because "templates broken" and "this template set" are
	// different claims and only one of them is a fingerprint.
	for _, l := range nodestate.Markers(in) {
		if l.Key == string(nodestate.MarkerTemplateUnloadable) {
			v.TemplateUnloadableHref = link.href(l.String())
		}
	}
}

// applyPins builds the pin bar and this Node's own pin link.
//
// The pin set travels in the query string, which is what keeps this screen
// free of a mutating route: pinning is a link, not a write.
func (v *nodeView) applyPins(nodeID string, pins []string, resolve pinResolver) {
	v.Pin = buildPinState(resolve, pins, "/console/nodes/"+nodeID, "pin")
	for _, id := range pins {
		if id == nodeID {
			v.Pinned = true
		}
	}
	for i := range v.Pin.Pins {
		if v.Pin.Pins[i].ID == nodeID {
			v.Pin.Pins[i].Current = true
			v.Pin.Pins[i].Href = ""
		}
	}
	if !v.Pinned && !v.Pin.Full {
		v.PinHref = "/console/nodes/" + nodeID + pinQuery(append(append([]string(nil), pins...), nodeID))
	}
}

// applyReportedPolicy fills the reported-Policy panel, which arrives with the
// describe_node result itself (QRY-28): detail.Policy/detail.PolicyReported
// are the same lane call already recorded against this Node id, not a second
// door into the display-only policyview cache. ADR-0025 names a Node's Policy
// as part of exactly what describe_node discloses.
func (v *nodeView) applyReportedPolicy(d Deps, detail capability.NodeDetail) {
	if !detail.PolicyReported {
		return
	}
	n := detail.Node
	snap := detail.Policy
	v.Policy = &snap
	v.PolicyReported = true
	if unreported(n) {
		v.PolicyUncorroborated = true
		v.VersionUnrecorded = n.DaemonVersion == ""
		v.FingerprintUnrecorded = n.PolicyFingerprint == ""
	}
	if !snap.ReportedAt.IsZero() {
		v.PolicyReportedAt = utcStamp(snap.ReportedAt)
		v.PolicyReportedAgo = nodestate.Since(snap.ReportedAt, d.now())
	}
	// A snapshot refreshes on (re)connect and at no other moment, so an
	// offline Node's panel is the last thing its engine said and cannot
	// be re-asked. Saying so is the difference between a stale answer
	// and an answer known to be stale.
	v.PolicyStale = !n.Connected
}

// applyAuditTrail fills the revocation summary and the Recent Tasks list from
// the Node's audit trail, oldest first.
func (v *nodeView) applyAuditTrail(recs []audit.Record) {
	// The revocation record is read from the WHOLE trail, not from the
	// windowed rows below: a Node with forty later records would
	// otherwise lose the one act that explains its state.
	//
	// The trail is oldest-first and this takes the FIRST match, which is
	// the causative revocation. Taking the latest would let the reason
	// be relabelled: revoke is idempotent-204, so an admin can re-POST
	// an already-revoked Node with an innocuous reason, and this screen
	// — now the place an operator reads "why" — would show that one
	// instead of the act that actually revoked the Node. Both records
	// survive in the Activity trail either way; what is protected here
	// is which one this summary attributes.
	//
	// The Control API writes no second record for a Node whose cascade
	// revocation this Relay process already recorded, but a repeat
	// operator revoke, and any revoke that follows a Relay restart,
	// still produce one — so first-match stays the defence this screen
	// needs, not a formality.
	for i := range recs {
		if recs[i].Kind == audit.KindNodeRevoke {
			v.RevokedBy = principalText(factsOfRecord(recs[i]))
			v.RevocationReason = recs[i].Reason
			v.RevocationRecorded = true
			break
		}
	}

	// Recent Tasks is Tasks dispatched to this Node, not reads ABOUT
	// it: filter to KindDispatch BEFORE windowing, so forty page
	// views of this very screen (each a describe_node read) cannot
	// push every real Task out of the window. Denies stay —
	// they are KindDispatch rows with outcome denied_by_policy — and
	// refusals stay excluded, as they always were: a refusal is
	// Relay-side and never reached the Node (nodeTaskFrom's doc).
	tasks := make([]audit.Record, 0, len(recs))
	for _, rec := range recs {
		if rec.Kind == audit.KindDispatch {
			tasks = append(tasks, rec)
		}
	}
	rows, elided := windowed(tasks, nodeTaskRows)
	v.TasksElided = elided
	// The same rule denied over and over is ONE fact, not twenty. A
	// Node that has refused the same read every hour for a day would
	// otherwise bury its Policy panel under twenty identical
	// explanations, and the operator would scroll past all of them.
	//
	// So the block renders on the first occurrence of each distinct
	// rule and the repeats keep their outcome chip. The chip is what
	// makes this safe: nothing is hidden, the row is still there, and
	// only the redundant prose is dropped.
	seenRule := map[string]bool{}
	for _, rec := range rows {
		t, ok := nodeTaskFrom(rec)
		if !ok {
			continue
		}
		if t.Denied != nil {
			if seenRule[t.Denied.Rule] {
				t.Denied = nil
				t.RepeatDeny = true
			} else {
				seenRule[t.Denied.Rule] = true
			}
		}
		v.Tasks = append(v.Tasks, t)
	}
}

// factRows renders the self-reported Facts.
//
// Empty values are omitted rather than rendered blank: a daemon that did not
// report a kernel version has not reported one, and an empty row invites the
// reader to wonder whether the machine has no kernel.
func factRows(n registry.Node) []nodeFact {
	var out []nodeFact
	add := func(k, v string) {
		if v != "" {
			out = append(out, nodeFact{Key: k, Value: v})
		}
	}
	add("hostname", n.Facts.Hostname)
	add("os", n.Facts.OS)
	add("kernel", n.Facts.Kernel)
	add("arch", n.Facts.Arch)
	if len(n.Facts.IPAddresses) > 0 {
		add("ip", strings.Join(n.Facts.IPAddresses, ", "))
	}
	return out
}

// nodeTaskFrom projects one audit record into a recent-Task row, or reports
// that it is not one.
//
// Only dispatch records describe something that happened ON this Node —
// Recent Tasks is Tasks dispatched to this Node, denies included (spec 02).
// Control-plane reads ABOUT the Node (describe_node, get_job) are still
// written to the trail and still appear on Activity;
// this panel just does not list them. A refusal is Relay-side —
// nothing reached the machine — and belongs on Activity, where it is
// attributed to the principal who was refused rather than to the Node that
// never heard about it. buildNodeView's caller filters to KindDispatch before
// this function ever sees a row; the switch below is a second, defensive
// gate on the same rule.
func nodeTaskFrom(rec audit.Record) (nodeTask, bool) {
	if rec.Kind != audit.KindDispatch {
		return nodeTask{}, false
	}
	f := factsOfRecord(rec)
	t := nodeTask{
		When:      utcStamp(rec.Timestamp),
		Args:      argsText(f),
		Outcome:   jobs.OutcomeName(rec.Outcome),
		JobID:     rec.JobID,
		Principal: principalText(f),
		Verified:  rec.Attribution.Verified.AccountID != "",
	}
	t.Operation, t.RawExecTier = trailRowName(f)
	if rec.JobID != "" {
		t.JobHref = "/console/jobs/" + rec.JobID
	}
	if rec.Outcome == jobs.OutcomeDeniedByPolicy {
		t.Denied = &Deny{
			NodeID:        rec.NodeID,
			OperationName: t.Operation,
			// The daemon's verdict text is what the Relay was told; it is
			// rendered verbatim and never paraphrased. Where the daemon did not
			// supply a rule, the reason field is what there is, and saying so
			// beats inventing a rule that was never quoted.
			Rule:       denyExplanation(rec),
			PolicyHref: "/console/nodes/" + rec.NodeID,
			Boundary:   DenyBoundaryApply,
		}
	}
	return t, true
}

var nodeMissingTmpl = newScreen("nodemissing", `
<div class="placeholder">
  <p>No Node with the id <code>{{.}}</code> is in this Relay's registry.</p>
  <p>A revoked Node stays readable; an id that was never enrolled has no record.</p>
  <p><a href="/console/">Back to the fleet</a>.</p>
</div>
`)

var nodeTmpl = newScreen("node", `
<div class="nodehead">
  {{/* When Connected, .seen below also renders "connected" — the wording is doubled on
       purpose: the dot's own name is what carries "not connected" when offline, since
       .seen says "last seen X ago" there instead, so the dot cannot be decorative in one state
       and named in the other. */}}
  <span class="dot" data-live="{{if .Connected}}on{{else}}off{{end}}" role="img" aria-label="{{if .Connected}}connected{{else}}not connected{{end}}"></span>
  {{if .Hostname}}<span class="dim">node id</span> <code class="nodeid" title="The identity this Node's certificate proves.">{{.ID}}</code>{{end}}
  <span class="seen" title="{{.LastSeenAbs}}">{{if .Connected}}connected{{else}}last seen {{.LastSeen}} ago{{end}}</span>
  {{if .Revoked}}<span class="chip outcome" data-outcome="cancelled">revoked {{.RevokedAt}}</span>{{end}}
  {{if .Pinned}}<span class="act dim">Pinned to compare</span>
  {{else}}{{with .PinHref}}<a class="act" href="{{.}}">Pin to compare</a>{{end}}{{end}}
</div>

{{if .Pin.Any}}{{template "pin-bar" .Pin}}{{end}}

<div class="labelrow">
  {{range .Labels}}{{template "label-chip" .}}{{if and .IsTag $.TagEdit}}<form class="tagrm" method="post" action="{{$.TagEdit.Action}}">
    <input type="hidden" name="csrf_token" value="{{$.TagEdit.CSRFToken}}">
    <input type="hidden" name="op" value="remove">
    <input type="hidden" name="label" value="{{.KeyTerm}}">
    <button class="btn" type="submit" aria-label="Remove {{.KeyTerm}}">Remove</button>
  </form>{{end}}{{end}}
  {{range .States}}{{template "label-chip" .}}{{end}}
</div>
{{with .TagEdit}}
<form class="ctlform ctlrow tagadd" method="post" action="{{.Action}}">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <input type="hidden" name="op" value="add">
  <div class="fld">
    <label class="fldlabel" for="tag-add-label">Tag</label>
    <input id="tag-add-label" name="label" placeholder="tag:key=value" spellcheck="false" autocomplete="off" required>
  </div>
  <button class="btn grant" type="submit">Add tag</button>
</form>
{{end}}

<div class="panels">
  <div class="pcol">
    <section class="panel">
      <h3>Identity &amp; enrollment</h3>
      <dl class="kv wrapid">
        <dt>node id</dt><dd><code>{{.ID}}</code></dd>
        <dt>certificate</dt><dd><code title="{{.CertFingerprint}}">{{short .CertFingerprint}}</code></dd>
        <dt>enrolled via</dt><dd>{{if .EnrollingToken}}<code>{{.EnrollingToken}}</code>{{else}}<span class="dim">not recorded</span>{{end}}</dd>
        <dt>daemon</dt><dd>{{if .DaemonVersion}}<code>{{.DaemonVersion}}</code>{{else}}<span class="dim">not reported</span>{{end}}</dd>
      </dl>
      {{if .Revoked}}
      {{if .RevocationRecorded}}{{if .RevocationReason}}
      <p class="gap"><b>Revoked at {{.RevokedAt}}</b> by <b>{{.RevokedBy}}</b>, who gave the reason <q>{{.RevocationReason}}</q>.</p>
      {{else}}
      <p class="gap"><b>Revoked at {{.RevokedAt}}</b> by <b>{{.RevokedBy}}</b>, with no reason: this Node was revoked before the endpoint accepted one.</p>
      {{end}}{{else}}
      <p class="gap"><b>Revoked at {{.RevokedAt}}</b>; the audit trail holds no record of this revocation.</p>
      {{end}}
      <p class="note">Its record is kept for investigation; its certificate is revoked and it cannot reconnect.</p>
      {{end}}
      {{if .CertProvenanceKnown}}
      <dl class="kv">
        <dt>enrolled</dt><dd>{{if .EnrolledAt}}{{.EnrolledAt}}{{else}}<span class="dim">before this was recorded</span>{{end}}</dd>
        <dt>expires</dt><dd>{{.CertNotAfter}} <span class="dim">{{.CertExpiresIn}}</span></dd>
        <dt>renewals</dt><dd>{{.RenewalCount}}{{if .LastRenewedAt}} <span class="dim">last {{.LastRenewedAt}}</span>{{else}} <span class="dim">never renewed</span>{{end}}</dd>
      </dl>
      {{else}}
      <p class="gap"><b>This Node's certificate provenance is not recorded</b>, so its expiry is unknown until its next renewal.</p>
      {{end}}
    </section>

    <section class="panel">
      <h3>Fingerprints <span class="phint">reported by the daemon</span></h3>
      <dl>
        <dt>Policy</dt>
        <dd>{{if .PolicyFingerprint}}{{with .PolicyFingerprintHref}}<a href="{{.}}">{{end}}<code title="{{.PolicyFingerprint}}">{{short .PolicyFingerprint}}</code>{{if .PolicyFingerprintHref}}</a>{{end}}
          <span class="dim">{{.PolicyShared}} {{plural .PolicyShared "Node reports" "Nodes report"}} this</span>
        {{else}}<span class="dim">not reported</span>{{end}}</dd>
        <dt>Template set</dt>
        <dd>{{if .TemplateUnloadable}}{{with .TemplateUnloadableHref}}<a href="{{.}}">{{end}}<span class="chip lbl" data-ns="state"><span class="ns">state:</span>template-unloadable</span>{{if .TemplateUnloadableHref}}</a>{{end}}
          <span class="dim">the Node's local template set failed to load; its template vocabulary is empty and it fails closed</span>
        {{else if .TemplateFingerprint}}{{with .TemplateFingerprintHref}}<a href="{{.}}">{{end}}<code title="{{.TemplateFingerprint}}">{{short .TemplateFingerprint}}</code>{{if .TemplateFingerprintHref}}</a>{{end}}
          <span class="dim">{{.TemplateShared}} {{plural .TemplateShared "Node reports" "Nodes report"}} this</span>
        {{else}}<span class="dim">no templates installed</span>{{end}}</dd>
      </dl>
    </section>

    <section class="panel">
      <h3>Facts <span class="phint">self-reported · this page only · never targeted</span></h3>
      {{if .Facts}}
      <dl>{{range .Facts}}<dt>{{.Key}}</dt><dd>{{.Value}}</dd>{{end}}</dl>
      {{else}}<p class="dim">This Node has not reported any Facts.</p>{{end}}
    </section>
  </div>

  <div class="pcol wide">
    <section class="panel">
      <h3>Effective Policy <span class="phint">from this Node's own engine, never the Relay</span></h3>
      {{if .PolicyReported}}
        {{if .PolicyUncorroborated}}
        <p class="gap"><b>Not corroborated by a recorded Hello:</b> the Relay holds no Hello-recorded {{if .FingerprintUnrecorded}}Policy fingerprint{{if .VersionUnrecorded}} and no daemon version{{end}}{{else}}daemon version{{end}}.</p>
        {{if .Policy.PolicyFingerprint}}<p class="note">This snapshot carries its own Policy fingerprint, <code title="{{.Policy.PolicyFingerprint}}">{{short .Policy.PolicyFingerprint}}</code>.</p>
        {{else}}<p class="note">This snapshot carries no Policy fingerprint of its own.</p>{{end}}
        {{if .FingerprintUnrecorded}}<p class="note">It cannot be cross-checked, and the Console does not count this Node as current or permitted.</p>
        {{else}}<p class="note">The Console does not count this Node as current or permitted.</p>{{end}}
        {{end}}
        {{if .PolicyReportedAt}}<p class="dim">Received <time datetime="{{.PolicyReportedAt}}" title="{{.PolicyReportedAt}}">{{.PolicyReportedAgo}} ago</time></p>
        {{else}}<p class="dim">Received at a time that was not recorded.</p>{{end}}
        <div class="polblock">
          <div class="polrow"><span class="pk">raw exec</span>
            {{if .Policy.RawExecEnabled}}<span class="chip risk" data-risk="mutate">enabled</span>{{else}}<span class="chip risk">disabled</span>{{end}}</div>
          {{if .Policy.RawAllowPatterns}}<div class="polrow"><span class="pk">raw allow</span><pre>{{join "\n" .Policy.RawAllowPatterns}}</pre></div>{{end}}
          {{if .Policy.RawDenyPatterns}}<div class="polrow"><span class="pk">raw deny</span><pre>{{join "\n" .Policy.RawDenyPatterns}}</pre></div>{{end}}
          <div class="polrow"><span class="pk">operations</span>
            <div class="oplist">{{range .Policy.AllowedOperations}}<code>{{.}}</code>{{else}}<span class="dim">none allowed</span>{{end}}</div></div>
          {{range .Policy.OperationRules}}
            <div class="polrow"><span class="pk">allow</span><pre>{{.Name}}{{range .AllowedArgs}} [{{join " | " .}}]{{end}}</pre></div>
          {{end}}
          {{range .Policy.DenyRules}}
            <div class="polrow"><span class="pk">deny</span><pre>{{.Name}}{{range .Args}} [{{join " | " .}}]{{end}}</pre></div>
          {{end}}
        </div>
        {{if .PolicyStale}}
        <p class="gap"><b>This Node is offline, so this panel cannot be refreshed.</b></p>
        {{end}}
      {{else}}
        <p class="dim">This Node has not reported its Policy since the Relay last started.</p>
      {{end}}
    </section>

    <section class="panel">
      <h3>Recent Tasks</h3>
      {{if .Tasks}}
      <div class="tablescroll">
      <table class="rows">
        <thead><tr><th scope="col">When</th><th scope="col">Operation</th><th scope="col">By</th><th scope="col">Outcome</th><th scope="col">Job</th></tr></thead>
        <tbody>
        {{range .Tasks}}
          <tr>
            <td class="num">{{.When}}</td>
            <td>{{if .RawExecTier}}<span class="chip" data-tier="raw_exec">Raw Exec</span>{{end}}<code>{{.Operation}}</code>{{with .Args}}<div class="sub mono">{{.}}</div>{{end}}</td>
            <td>{{template "trust-chip" (trust .Principal .Verified)}}</td>
            <td><span class="chip outcome" data-outcome="{{.Outcome}}">{{.Outcome}}</span></td>
            <td>{{if .JobHref}}<a href="{{.JobHref}}"><code>{{short .JobID}}</code></a>{{end}}</td>
          </tr>
          {{with .Denied}}<tr><td></td><td colspan="4">{{template "deny-block" .}}</td></tr>{{end}}
          {{if .RepeatDeny}}<tr><td></td><td colspan="4" class="repeatdeny">Same rule as above.</td></tr>{{end}}
        {{end}}
        </tbody>
      </table>
      </div>
      {{if .TasksElided}}<p class="gap">Older Tasks are not shown; filtered history is on <a href="/console/activity">Activity</a>.</p>{{end}}
      {{else if .AuditWired}}
      <p class="dim">No Tasks have run on this Node.</p>
      {{else}}
      <p class="dim">The audit trail is not wired into this Console.</p>
      {{end}}
    </section>
  </div>
</div>

`)
