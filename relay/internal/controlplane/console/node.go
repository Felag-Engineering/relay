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

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodestate"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
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

	// ReadClass marks a row whose output was deliberately not retained
	// (ADR-0025). Said on the row, because an operator looking for output that
	// is not there needs to know it was never kept rather than lost.
	ReadClass bool
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

	CertFingerprint string
	EnrollingToken  string
	DaemonVersion   string

	// The certificate provenance the Relay issued (#440). Rendered only when
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

	// PolicyReportedAt and PolicyReportedAgo are when the RELAY received this
	// report, from policyview's own clock. Both stay empty for a snapshot with
	// no receipt time, which the panel says out loud — a zero time rendered
	// absolutely is a Policy read in 1970.
	PolicyReportedAt  string
	PolicyReportedAgo string

	// PolicyStale marks a reported Policy that cannot be re-read: the Node is
	// offline, and the snapshot refreshes on (re)connect and at no other time.
	PolicyStale bool

	// RunHref is the composer (/console/run, spec 05), drawn only where the
	// Relay has execution on AND the reader is an operator or above. Absent,
	// never disabled (ADR-0026 decision 5): a greyed-out control gives away
	// the property the console_execution flag exists to preserve.
	//
	// In v0.6.0 this is reachable in tests only. The composition root
	// hard-codes Execution false (cmd/relay/control_surfaces.go) until the
	// composer exists, so its absence in a running Relay is the design and not
	// a bug.
	RunHref string

	// The revocation record, read from the trail. RevokedBy is who did it;
	// RevocationRecorded distinguishes "the trail has no record" from "the
	// record says nothing", because the registry retains RevokedAt whether or
	// not the trail was ever wired.
	//
	// RevocationReason is why, and is EMPTY FOR EVERY REVOCATION PREDATING
	// #487, when the endpoint accepted no reason to record. That is a third
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
	// set is full — the bar itself says which.
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

		// THIS READ IS AUDITED (#450, ADR-0025). Node detail is the widest
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

		p, ok := page(d, w, r, shortHash(n.NodeID))
		if !ok {
			return
		}
		p.Banner = banner(d, r)
		pins, _ := parsePins(r.URL.Query().Get("pin"))
		known, err := pinsKnown(ctx, d, caller, n.NodeID, pins)
		if err != nil {
			readFailed(w, err, "the pinned Nodes' registry records")
			return
		}
		v := buildNodeView(d, r, detail, p.Role, pins, known)
		if refusedUnaudited(w, lane, "this Node's registry record") {
			return
		}
		renderScreen(w, p, nodeTmpl, v)
	}
}

// pinsKnown resolves the pin bar's ids through the AUDITED lane, one
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
func pinsKnown(ctx context.Context, d Deps, caller capability.Principal, self string, ids []string) (func(string) bool, error) {
	set := map[string]bool{self: true}
	for _, id := range ids {
		if _, seen := set[id]; seen {
			continue
		}
		_, err := d.Queries.DescribeNode(ctx, caller, id)
		switch {
		case err == nil:
			set[id] = true
		case errors.Is(err, capability.ErrNodeNotFound), errors.Is(err, capability.ErrInvalidFilter):
			set[id] = false
		default:
			return nil, err
		}
	}
	return func(id string) bool { return set[id] }, nil
}

func buildNodeView(d Deps, r *http.Request, detail capability.NodeDetail, role accounts.Role, pins []string, known func(string) bool) nodeView {
	n := detail.Node
	in := nodestate.Input{Node: n, Now: d.now(), CertExpiringWithin: d.CertExpiringWithin}

	v := nodeView{
		ID:                  n.NodeID,
		Hostname:            n.Facts.Hostname,
		Connected:           n.Connected,
		LastSeen:            nodestate.Since(n.LastSeen, d.now()),
		LastSeenAbs:         n.LastSeen.UTC().Format("2006-01-02 15:04:05Z"),
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
		v.RevokedAt = n.RevokedAt.UTC().Format("2006-01-02 15:04:05Z")
	}
	if v.CertProvenanceKnown {
		v.CertNotAfter = n.CertNotAfter.UTC().Format("2006-01-02 15:04:05Z")
		v.CertExpiresIn = nodestate.Until(n.CertNotAfter, d.now())
		v.RenewalCount = n.RenewalCount
		if !n.EnrolledAt.IsZero() {
			v.EnrolledAt = n.EnrolledAt.UTC().Format("2006-01-02 15:04:05Z")
		}
		if !n.LastRenewedAt.IsZero() {
			v.LastRenewedAt = n.LastRenewedAt.UTC().Format("2006-01-02 15:04:05Z")
		}
	}

	// Fingerprint Selector links, built from nodestate's own derivation rather
	// than by concatenating the raw fingerprint into a term.
	//
	// The values are self-reported and reach the registry unvalidated, and this
	// link is advertised as directly targetable. nodestate.Facts runs
	// validFactValue, which drops a value carrying a comma, whitespace or a
	// namespace prefix — the injection that would otherwise let a Node add a
	// second Selector term to a link the Console offers. A rejected value
	// renders as text with no link; it is never sanitised into one.
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

	if role.AtLeast(accounts.RoleOperator) {
		if d.Execution {
			v.RunHref = "/console/run"
		}
	}

	// The pin set travels in the query string, which is what keeps this screen
	// free of a mutating route: pinning is a link, not a write.
	v.Pin = buildPinState(known, pins, "/console/nodes/"+n.NodeID, "pin")
	for _, id := range pins {
		if id == n.NodeID {
			v.Pinned = true
		}
	}
	if !v.Pinned && !v.Pin.Full {
		v.PinHref = "/console/nodes/" + n.NodeID + pinQuery(append(append([]string(nil), pins...), n.NodeID))
	}

	// Fingerprint sharing counts. Computed by the read lane, behind the same
	// describe_node record (capability.NodeDetail): this screen must not
	// enumerate the whole registry to render two integers about one Node —
	// that would be a far wider disclosure than the read it actually made,
	// and one that would then have to be audited as an enumeration to stay
	// honest.
	v.PolicyShared, v.TemplateShared = detail.PolicyPeers, detail.TemplatePeers

	// The reported-Policy panel reads the display-only policyview cache
	// directly, and that is NOT a second unaudited door: this whole screen is
	// one describe_node read, recorded above against this Node id, and
	// ADR-0025 names a Node's Policy as part of exactly what describe_node
	// discloses. The cache is a Relay-side mirror of what the daemon
	// reported, keyed by the id already on the record — there is nothing here
	// the record does not already say was read.
	if d.Policy != nil {
		if snap, ok := d.Policy.Get(n.NodeID); ok {
			v.Policy = &snap
			v.PolicyReported = true
			if !snap.ReportedAt.IsZero() {
				v.PolicyReportedAt = snap.ReportedAt.UTC().Format("2006-01-02 15:04:05Z")
				v.PolicyReportedAgo = nodestate.Since(snap.ReportedAt, d.now())
			}
			// A snapshot refreshes on (re)connect and at no other moment, so an
			// offline Node's panel is the last thing its engine said and cannot
			// be re-asked. Saying so is the difference between a stale answer
			// and an answer known to be stale.
			v.PolicyStale = !n.Connected
		}
	}

	if d.Audit != nil {
		if recs, err := d.Audit.ByNode(r.Context(), n.NodeID); err == nil {
			// The revocation record is read from the WHOLE trail, not from the
			// windowed rows below: a Node with forty later records would
			// otherwise lose the one act that explains its state. The trail is
			// oldest-first, so the last match is the latest.
			for i := len(recs) - 1; i >= 0; i-- {
				if recs[i].Kind == audit.KindNodeRevoke {
					v.RevokedBy = principalText(factsOfRecord(recs[i]))
					v.RevocationReason = recs[i].Reason
					v.RevocationRecorded = true
					break
				}
			}

			rows, elided := windowed(recs, nodeTaskRows)
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
	}
	return v
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
// Only dispatch and read records describe something that happened ON this Node.
// A refusal is Relay-side — nothing reached the machine — and belongs on
// Activity, where it is attributed to the principal who was refused rather than
// to the Node that never heard about it.
//
// # The admitting switch names the outcome, rather than a corrective one
//
// The outcome chip used to be built from rec.Outcome for both admitted kinds.
// That is right for a dispatch and wrong for a read: auditsink.RecordRead
// writes who read, which tool, what they aimed it at and when, and deliberately
// no per-Node verdict — nothing was dispatched and no daemon decided anything.
// The zero Outcome then rendered "unspecified", the Console saying "we don't
// know" about the one family of record whose disposition is completely known
// (#520; the Agents screen had the same bug, #517).
//
// agentCallFrom fixes its copy with a CORRECTIVE switch after the assignment,
// because it admits eight kinds and only some of them need correcting. This
// function admits exactly two, so a second switch would be a special case
// bolted beside the switch that already decides what a record is. Deciding the
// outcome inside the admitting switch is both smaller and stricter: a kind
// added to it later cannot be admitted without someone naming what its chip
// says, which is precisely the omission that produced this bug.
//
// Dispatch is the only admitted kind with a real per-Node verdict — a
// zero-result dispatch record carries no NodeID at all, so ByNode never returns
// one here — and the word for the other is justified at readOutcomeAudited
// (vocab.go), taken from there rather than re-minted so that two screens naming
// these records cannot name them two ways.
func nodeTaskFrom(rec audit.Record) (nodeTask, bool) {
	var outcome string
	switch rec.Kind {
	case audit.KindDispatch:
		outcome = OutcomeLabel(rec.Outcome)
	case audit.KindRead:
		outcome = readOutcomeAudited
	default:
		return nodeTask{}, false
	}
	f := factsOfRecord(rec)
	t := nodeTask{
		When:      rec.Timestamp.UTC().Format("2006-01-02 15:04:05Z"),
		Operation: operationText(f),
		Args:      argsText(f),
		Outcome:   outcome,
		JobID:     rec.JobID,
		Principal: principalText(f),
		Verified:  rec.Attribution.Verified.AccountID != "",
		ReadClass: rec.Kind == audit.KindRead,
	}
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
		}
	}
	return t, true
}

var nodeMissingTmpl = newScreen("nodemissing", `
<div class="placeholder">
  <p>No Node with the id <code>{{.}}</code> is in this Relay's registry.</p>
  <p>A revoked Node keeps its record and stays readable; an id that was never enrolled has none.
  <a href="/console/">Back to the fleet</a>.</p>
</div>
`)

var nodeTmpl = newScreen("node", `
<div class="nodehead">
  <span class="dot" data-live="{{if .Connected}}on{{else}}off{{end}}"></span>
  <code class="nodeid big">{{.ID}}</code>
  {{with .Hostname}}<span class="sub">{{.}}</span>{{end}}
  <span class="seen" title="{{.LastSeenAbs}}">{{if .Connected}}connected{{else}}last seen {{.LastSeen}} ago{{end}}</span>
  {{if .Revoked}}<span class="chip outcome" data-outcome="cancelled">revoked {{.RevokedAt}}</span>{{end}}
  {{with .RunHref}}<a class="act" href="{{.}}">Run here</a>{{end}}
  {{if .Pinned}}<span class="act dim">Pinned to compare</span>
  {{else}}{{with .PinHref}}<a class="act" href="{{.}}">Pin to compare</a>{{end}}{{end}}
</div>

{{if .Pin.Any}}{{template "pin-bar" .Pin}}{{end}}

<div class="labelrow">
  {{range .Labels}}{{template "label-chip" .}}{{end}}
  {{range .States}}{{template "label-chip" .}}{{end}}
  <span class="labelnote">
    <b>node:</b> set by the machine's config management, immutable to the Relay ·
    <b>tag:</b> set by operators through the control plane, immutable to the Node, and never a valid
    security-lane target — no storage for one exists yet (#430), so none renders here ·
    <b>relay:</b> set by the Relay, immutable to the Node, and the only namespace the security lane may target ·
    <b>state:</b> derived from this record, set by nobody
  </span>
</div>

<div class="panels">
  <div class="pcol">
    <section class="panel">
      <h3>Identity &amp; enrollment</h3>
      <dl>
        <dt>node id</dt><dd><code>{{.ID}}</code></dd>
        <dt>certificate</dt><dd><code title="{{.CertFingerprint}}">{{short .CertFingerprint}}</code></dd>
        <dt>enrolled via</dt><dd>{{if .EnrollingToken}}<code>{{.EnrollingToken}}</code>{{else}}<span class="dim">not recorded</span>{{end}}</dd>
        <dt>daemon</dt><dd>{{if .DaemonVersion}}<code>{{.DaemonVersion}}</code>{{else}}<span class="dim">not reported</span>{{end}}</dd>
      </dl>
      {{if .Revoked}}
      <p class="gap"><b>This Node was revoked at {{.RevokedAt}}.</b>
      {{if .RevocationRecorded}}The trail attributes it to <b>{{.RevokedBy}}</b>{{if .RevocationReason}},
      who gave the reason <q class="rreason">{{.RevocationReason}}</q>.
      {{else}} and records no reason: this Node was revoked before the endpoint accepted one.
      {{end}}
      {{else}}No revocation record is in the trail: the registry keeps the timestamp whether or not
      the trail was wired when it happened, so who did it cannot be answered from here.{{end}}
      The record is retained deliberately, so the machine stays investigable and its history stays
      answerable; the certificate is not, and this Node cannot reconnect.</p>
      {{end}}
      {{if .CertProvenanceKnown}}
      <dl>
        <dt>enrolled</dt><dd>{{if .EnrolledAt}}{{.EnrolledAt}}{{else}}<span class="dim">before this was recorded</span>{{end}}</dd>
        <dt>expires</dt><dd>{{.CertNotAfter}} <span class="dim">{{.CertExpiresIn}}</span></dd>
        <dt>renewals</dt><dd>{{.RenewalCount}}{{if .LastRenewedAt}} <span class="dim">last {{.LastRenewedAt}}</span>{{else}} <span class="dim">never renewed</span>{{end}}</dd>
      </dl>
      {{else}}
      <p class="gap"><b>This Node's certificate provenance is not recorded.</b> It enrolled before
      the Relay began storing certificate validity, so there is no expiry to compare a clock
      against. It fills in at this Node's next renewal, which is at most one leaf lifetime away.</p>
      {{end}}
      <p class="note">Renewal is certificate-authenticated and preserves the node id, so this
      identity chains unbroken back to the Enrollment Token above.</p>
    </section>

    <section class="panel">
      <h3>Fingerprints</h3>
      <dl>
        <dt>Policy</dt>
        <dd>{{if .PolicyFingerprint}}{{with .PolicyFingerprintHref}}<a href="{{.}}">{{end}}<code title="{{.PolicyFingerprint}}">{{short .PolicyFingerprint}}</code>{{if .PolicyFingerprintHref}}</a>{{end}}
          <span class="dim">{{.PolicyShared}} {{plural .PolicyShared "Node" "Nodes"}} report this</span>
        {{else}}<span class="dim">not reported</span>{{end}}</dd>
        <dt>Template set</dt>
        <dd>{{if .TemplateUnloadable}}{{with .TemplateUnloadableHref}}<a href="{{.}}">{{end}}<span class="chip lbl" data-ns="state"><span class="ns">state:</span>template-unloadable</span>{{if .TemplateUnloadableHref}}</a>{{end}}
          <span class="dim">the Node's local template set failed to load; its template vocabulary is empty and it fails closed</span>
        {{else if .TemplateFingerprint}}{{with .TemplateFingerprintHref}}<a href="{{.}}">{{end}}<code title="{{.TemplateFingerprint}}">{{short .TemplateFingerprint}}</code>{{if .TemplateFingerprintHref}}</a>{{end}}
          <span class="dim">{{.TemplateShared}} {{plural .TemplateShared "Node" "Nodes"}} report this</span>
        {{else}}<span class="dim">no templates installed</span>{{end}}</dd>
      </dl>
      <p class="note">Confirming a rollout landed is string equality against these, not trust.
      Relay reports what the daemon says it loaded; it never sets either. Each links to every Node
      reporting the same value — the readable form of <code>state:policy-fingerprint=</code> and
      <code>state:template-fingerprint=</code>, targeted as a Selector. A value the Node reported in
      a shape a Selector cannot carry is shown without a link rather than trimmed to fit.</p>
    </section>

    <section class="panel">
      <h3>Facts <span class="phint">this page only</span></h3>
      {{if .Facts}}
      <dl>{{range .Facts}}<dt>{{.Key}}</dt><dd>{{.Value}}</dd>{{end}}</dl>
      {{else}}<p class="dim">This Node has not reported any Facts.</p>{{end}}
      <p class="note">Self-reported by the daemon. Facts appear here and nowhere else: they are
      not on a fleet row, not in a facet, and never targetable. A compromised Node can report
      anything it likes, so targeting is on labels, whose namespaces have enforced writers.</p>
    </section>
  </div>

  <div class="pcol wide">
    <section class="panel">
      <h3>Effective Policy</h3>
      {{if .PolicyReported}}
        <p class="note">Answered by <b>this Node's own engine</b> and received by the Relay
        {{if .PolicyReportedAt}}at <b>{{.PolicyReportedAt}}</b>, {{.PolicyReportedAgo}} ago{{else}}at <b>a time that was not recorded</b>{{end}}.
        That is a receipt time, not a query time: the snapshot is captured when the Node connects,
        so this is what the Node said then.
        The Relay never evaluates Policy and has no code path that writes it.</p>
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
        <p class="gap"><b>This Node is offline, so this panel cannot be refreshed.</b> It is the last
        thing its engine reported{{with .PolicyReportedAt}}, at {{.}}{{end}}, and nothing has re-asked
        it since — a snapshot is taken when a Node connects and at no other time.</p>
        {{end}}
        <p class="gap">There is no path from this screen to this Node's Policy: Policy is rooted
        on the machine and the Relay is not one of its writers.</p>
      {{else}}
        <p class="dim">This Node has not reported its Policy since the Relay last started.</p>
        <p class="note">The Console shows nothing rather than a remembered answer: a Policy view
        that might be stale is worse than none, because it is the thing an operator checks before
        deciding a Task is safe.</p>
      {{end}}
    </section>

    <section class="panel">
      <h3>Recent Tasks</h3>
      {{if .Tasks}}
      <div class="tablescroll">
      <table class="rows">
        <thead><tr><th>When</th><th>Operation</th><th>By</th><th>Outcome</th><th>Job</th></tr></thead>
        <tbody>
        {{range .Tasks}}
          <tr>
            <td class="num">{{.When}}</td>
            <td><code>{{.Operation}}</code>{{with .Args}}<div class="sub mono">{{.}}</div>{{end}}
              {{if .ReadClass}}<div class="sub">read — output not retained</div>{{end}}</td>
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
      {{if .TasksElided}}<p class="gap">Older Tasks are not shown — this page renders the most
      recent {{len .Tasks}} and the trail has more. Filtered history is on
      <a href="/console/activity">Activity</a>.</p>{{end}}
      {{else if .AuditWired}}
      <p class="dim">No Tasks have run on this Node.</p>
      {{else}}
      <p class="dim">The audit trail is not wired into this Console.</p>
      {{end}}
    </section>
  </div>
</div>
`)
