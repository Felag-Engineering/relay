package console

// access.go is the Access screen (spec 20): who signed in, who failed to,
// who changed an Account, and who minted or revoked it a credential.
//
// # Admin only, in the Console only (D17 ruling 4)
//
// The route's MinRole is admin (console.go), which narrows what this Console
// mounts and nothing else. The records this screen lists stay on the audit
// read lane under its existing role rules, so the Control API returns them
// to any Account those rules already allow — making the records themselves
// admin-only would be a capability-layer decision, and it has not been
// taken. This file interprets no role: it sends every request to
// capability.Service.QueryAudit with the caller unchanged, exactly as every
// other screen on Deps.Queries does (invariant 10, ADR-0025).
//
// # Why a failed sign-in or step-up reconstructs nothing
//
// A failed or throttled sign-in records the typed name only when it is a
// real Account's (D19): a name box can hold a password. This screen draws
// what the record carries and never resolves it against the registry, so a
// record with no typed name is drawn as "a name that is not an Account".
// accessAttempt still has exactly three answers (succeeded, failed,
// throttled) and no fourth that says which half was wrong.
//
// # Why there is no subject filter
//
// The Account a change was made to — the subject of an account or
// api-token row — is written into the record's free-text Reason, which the
// audit query seam cannot filter on. The Actor filter (accessFilter.Account)
// matches the VERIFIED actor instead, the same AccountID Activity's own
// Principal filter matches. The subject is rendered as the record's Reason,
// verbatim, and never resolved through Deps.Accounts — accessRowFrom does
// not touch that seam at all (04-activity.md's "Kind is never read from the
// registry" reasoning applies the same way here).

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
)

// accessPageSize bounds one render. A code constant, unreachable from any
// request (invariant 11), and clamped again by the read lane on the way
// through.
const accessPageSize = 50

// accessKind is the family a row belongs to — the four row kinds spec 20
// names, and the whole vocabulary this screen draws a chip for.
type accessKind string

const (
	accessSignIn   accessKind = "sign-in"
	accessStepUp   accessKind = "step-up"
	accessAccount  accessKind = "account"
	accessAPIToken accessKind = "api-token"
)

// accessKindOrder is every family, in the order spec 20's Row kinds table
// lists them and the order the chips render.
var accessKindOrder = []accessKind{accessSignIn, accessStepUp, accessAccount, accessAPIToken}

// accessKindOf reports which Access family k belongs to, ok=false for every
// other audit kind — Activity's home, or (for a kind neither package names)
// its `other` family.
//
// This is the explicit switch over the 15 kinds spec 20's Row kinds table
// names (4 sign-in + 3 step-up + 6 account + 2 api-token; audit.go's
// declaration order), and it is the ONE place this package names them: every
// derived list below comes from walking audit.Kinds() through this function,
// so Access and Activity (kindOf's own first case) partition the audit
// vocabulary by construction rather than by two lists that have to agree.
//
// Forward risk, not closed by anything here: a future auth kind added to
// internal/audit without a case here falls to
// Activity's `other` family instead of failing loudly. A name-based rule
// (a "_failed" suffix, say) was tried for a neighbouring question and
// rejected — see internal/audit's authFailureKinds doc for why it missed the
// exact case it was written for.
func accessKindOf(k string) (accessKind, bool) {
	switch k {
	case audit.KindLoginSucceeded, audit.KindLoginFailed, audit.KindLoginThrottled, audit.KindLogout:
		return accessSignIn, true
	case audit.KindStepUp, audit.KindStepUpFailed, audit.KindStepUpThrottled:
		return accessStepUp, true
	case audit.KindAccountCreate, audit.KindAccountRole, audit.KindAccountEnable, audit.KindAccountDisable,
		audit.KindPasswordSet, audit.KindPasswordClear:
		return accessAccount, true
	case audit.KindAPITokenMint, audit.KindAPITokenRevoke:
		return accessAPIToken, true
	default:
		return "", false
	}
}

// accessKindsByFamily is accessKindOf's inverse, computed once from
// audit.Kinds() rather than hand-written beside it — the same
// derived-not-enumerated posture activity.go's buildKindsByFamily takes.
//
// It panics at init if any family in accessKindOrder came back empty: an
// empty family would make accessLaneKinds hand capability.AuditFilter an
// empty Kinds slice for that chip, which matches EVERY row on the trail
// rather than none (AuditFilter's zero-value contract) — the one direction a
// filter must never fail. accounts.go's buildAgentCallKinds takes the same
// posture over its own lane.
var accessKindsByFamily = buildAccessKindsByFamily()

func buildAccessKindsByFamily() map[accessKind][]string {
	m := map[accessKind][]string{}
	for _, k := range audit.Kinds() {
		family, ok := accessKindOf(k)
		if !ok {
			continue
		}
		m[family] = append(m[family], k)
	}
	for _, family := range accessKindOrder {
		if len(m[family]) == 0 {
			panic("console: access family " + string(family) + " admits no audit kind — accessKindOf's switch is missing a case")
		}
	}
	return m
}

// accessAllKinds is the union accessKindOf admits, in audit.Kinds() order —
// 15 kinds today, under the read lane's 32-kind cap. What ?kind= with no
// value asks the trail for.
var accessAllKinds = buildAccessAllKinds()

func buildAccessAllKinds() []string {
	var out []string
	for _, k := range audit.Kinds() {
		if _, ok := accessKindOf(k); ok {
			out = append(out, k)
		}
	}
	return out
}

// accessFailureKinds is failures-only's narrower vocabulary: a submitted
// credential that was compared and refused, at either door.
//
// Deliberately NOT audit.AuthFailureKinds(), which also holds the two
// throttled kinds. Spec 20 says a throttled attempt was refused before any
// credential was even compared, so it is never counted as a failure here —
// even though internal/audit's own "is someone grinding a password" question
// answers yes to a throttle too. The two questions are different, and this
// screen asks only the first.
var accessFailureKinds = []string{audit.KindLoginFailed, audit.KindStepUpFailed}

// accessSummary renders the per-kind sentence for one of the 15 Access
// kinds. MOVED, unchanged, from activity.go's summarize — this is the one
// place either screen spells these sentences.
func accessSummary(f trailFacts) string {
	switch f.Kind {
	case audit.KindLoginSucceeded:
		return "signed in to the Console"
	case audit.KindLoginFailed:
		return "failed a Console sign-in"
	case audit.KindLoginThrottled:
		return "was throttled signing in"
	case audit.KindLogout:
		return "signed out"
	case audit.KindStepUp:
		return "re-proved presence for a step-up"
	case audit.KindStepUpFailed:
		return "failed a step-up re-authentication"
	case audit.KindStepUpThrottled:
		return "was throttled re-authenticating for a step-up"
	case audit.KindAccountCreate:
		return "created an Account"
	case audit.KindAccountRole:
		return "changed an Account's role"
	case audit.KindAccountEnable:
		return "enabled an Account"
	case audit.KindAccountDisable:
		return "disabled an Account"
	case audit.KindPasswordSet:
		return "set a Console password"
	case audit.KindPasswordClear:
		// A -clear on an Account with no password is still recorded; the
		// record says so, and so does the sentence.
		if strings.Contains(f.Reason, "removed=false") {
			return "cleared a Console password (none was set)"
		}
		return "removed a Console password"
	case audit.KindAPITokenMint:
		return "minted an API Token"
	case audit.KindAPITokenRevoke:
		return "revoked an API Token"
	default:
		return f.Kind
	}
}

// accessAttempt is the whole outcome vocabulary this screen ever draws: no
// word, field or branch distinguishes an unknown Account from a wrong
// password — see this file's header comment.
func accessAttempt(kind string) string {
	switch kind {
	case audit.KindLoginSucceeded, audit.KindStepUp:
		return "succeeded"
	case audit.KindLoginFailed, audit.KindStepUpFailed:
		return "failed"
	case audit.KindLoginThrottled, audit.KindStepUpThrottled:
		return "throttled"
	default:
		return ""
	}
}

// accessRow is one rendered record. There is NO Password, Hash, Secret,
// Plaintext or Token-value field, and TestAccess_ARowHasNoFieldASecretCouldOccupy
// pins it structurally.
type accessRow struct {
	Kind      accessKind
	EventKind string

	// at is the sort key the row arrived with; When is its rendered form.
	// The template never sees this one.
	at   time.Time
	When string

	// Actor is set ONLY when f.VerifiedAccountID != "" — principalText(f),
	// drawn as a verified chip. A record with no verified Account (every
	// failed or throttled sign-in and step-up, by design) leaves this empty
	// and the template draws a dim "no verified Account" instead: a bare
	// Principal string is never promoted to a verified chip. There is no
	// separate Verified flag — Actor != "" already means verified.
	Actor string

	// ActorHref is set exactly when Actor is set: it filters this screen by
	// the VERIFIED Account ID (D18), never by name.
	ActorHref string

	// HostLever is set only when the record names no verified Account AND its
	// Principal is audit.PrincipalLocalHost: an act by root on the Relay host,
	// neither a verified Account nor an asserted claim, so it gets neither
	// chip.
	HostLever string

	// Asserted is f.OnBehalfOf: what was typed on a sign-in or step-up,
	// rendered as a separate, dashed chip. It is set only when the claim says
	// something the verified chip does not: no verified Account, a failed or
	// throttled attempt, or a name that differs (byte for byte) from the
	// verified one. On a failed or throttled sign-in it is present only when
	// the name was a real Account's (D19); when absent on those kinds,
	// NotAnAccount says so in the asserted slot.
	Asserted string

	// NotAnAccount is set only on a login_failed or login_throttled row whose
	// record carries no asserted name (D19).
	NotAnAccount bool

	Summary string

	// Attempt is accessAttempt(EventKind).
	Attempt string

	// Source is f.Source, copied only on a sign-in row: spec 20's Row kinds
	// table lists the source address for `sign-in` and not for the other
	// three families.
	Source string

	// Record is f.Reason, verbatim — the subject as the record itself names
	// it, never resolved through the Account registry.
	Record string
}

// accessRowFrom builds one row from the shared trail projection. It never
// reads Deps.Accounts or any registry — see this file's header comment.
func accessRowFrom(f trailFacts) accessRow {
	// accessLaneKinds only ever asks the lane for kinds accessKindOf admits,
	// so the record's own kind always resolves to one of the four families.
	family, _ := accessKindOf(f.Kind)
	row := accessRow{
		Kind:      family,
		EventKind: f.Kind,
		at:        f.Timestamp,
		When:      f.Timestamp.UTC().Format("2006-01-02 15:04:05Z"),
		Summary:   accessSummary(f),
		Attempt:   accessAttempt(f.Kind),
		Record:    f.Reason,
	}
	if f.VerifiedAccountID != "" {
		row.Actor = principalText(f)
	} else if f.Principal == audit.PrincipalLocalHost {
		row.HostLever = f.Principal
	}
	attempt := accessAttempt(f.Kind)
	if f.OnBehalfOf != "" && (f.VerifiedAccountID == "" || attempt == "failed" || attempt == "throttled" ||
		f.OnBehalfOf != f.VerifiedAccountName) {
		row.Asserted = f.OnBehalfOf
	}
	row.NotAnAccount = (f.Kind == audit.KindLoginFailed || f.Kind == audit.KindLoginThrottled) && f.OnBehalfOf == ""
	if family == accessSignIn {
		row.Source = f.Source
	}
	return row
}

// accessFilter is this screen's linkable state, parsed from the URL and
// rendered back into every link the page draws.
type accessFilter struct {
	// Kind selects one family; empty runs every family accessKindOf admits.
	Kind string

	// Account is the VERIFIED actor — the same AccountID Activity's own
	// Principal filter matches, never the changed Account (this file's
	// header comment).
	Account string

	// Failures narrows to a submitted credential that was compared and
	// refused — accessFailureKinds, never audit.AuthFailureKinds().
	Failures bool

	timeRange

	Cursor string
}

// parseAccessFilter reads the filter out of the URL, returning a note for
// anything it could not read — the same drop-and-name rule
// parseActivityFilter follows, through the SAME time-range parser
// (parseTimeRange, activity.go) so the two screens cannot come to disagree
// about what a range that quietly became "everything" looks like.
func parseAccessFilter(r *http.Request, now time.Time) (accessFilter, string) {
	q := r.URL.Query()
	f := accessFilter{
		Kind:     strings.TrimSpace(q.Get("kind")),
		Account:  strings.TrimSpace(q.Get("account")),
		Failures: q.Get("failures") == "1",
		Cursor:   q.Get("cursor"),
	}

	tr, notes := parseTimeRange(
		strings.TrimSpace(q.Get("window")), strings.TrimSpace(q.Get("since")), strings.TrimSpace(q.Get("until")), now)
	f.timeRange = tr

	return f, strings.Join(notes, "; ")
}

// values is the filter as URL values, carrying only the parameters this
// screen understands — what newRefresh reloads and what href/base build on.
func (f accessFilter) values() url.Values {
	v := url.Values{}
	if f.Kind != "" {
		v.Set("kind", f.Kind)
	}
	if f.Account != "" {
		v.Set("account", f.Account)
	}
	if f.Failures {
		v.Set("failures", "1")
	}
	if f.Window != "" {
		v.Set("window", f.Window)
	}
	if f.SinceParam != "" {
		v.Set("since", f.SinceParam)
	}
	if f.UntilParam != "" {
		v.Set("until", f.UntilParam)
	}
	return v
}

// href renders the filter back into a URL, with cursor replaced. An empty
// cursor drops the parameter, which is page one.
func (f accessFilter) href(cursor string) string {
	v := f.values()
	if cursor != "" {
		v.Set("cursor", cursor)
	}
	if len(v) == 0 {
		return "/console/access"
	}
	return "/console/access?" + v.Encode()
}

// base is the filter at page one — what every link except "Older" wants.
func (f accessFilter) base() string { return f.href("") }

// narrowing reports whether anything at all was asked for — the same
// "nothing matches" versus "nothing has been recorded yet" split Activity's
// own narrowing draws.
func (f accessFilter) narrowing() bool {
	return f.Kind != "" || f.Account != "" || f.Failures || !f.Since.IsZero() || !f.Until.IsZero()
}

// withKind returns the filter with a different kind and no cursor — what a
// family chip links to. Selecting the current kind CLEARS it, so a chip is a
// toggle.
func (f accessFilter) withKind(k accessKind) accessFilter {
	if f.Kind == string(k) {
		f.Kind = ""
	} else {
		f.Kind = string(k)
	}
	f.Cursor = ""
	return f
}

// withAccount returns the filter narrowed to one verified Account ID, with no
// cursor — what the actor chip on a row links to.
func (f accessFilter) withAccount(id string) accessFilter {
	f.Account = id
	f.Cursor = ""
	return f
}

// withFailures returns the filter with the failures-only toggle flipped and
// no cursor.
func (f accessFilter) withFailures() accessFilter {
	f.Failures = !f.Failures
	f.Cursor = ""
	return f
}

// accessKindChip is one family link — the same shape activity.go's kindChip
// is, kept as its own type because its Kind is accessKind rather than
// rowKind and the two vocabularies must never be interchangeable at compile
// time.
type accessKindChip struct {
	Kind    accessKind
	Current bool
	Href    string
}

func accessKindChips(f accessFilter) []accessKindChip {
	chips := make([]accessKindChip, 0, len(accessKindOrder))
	for _, k := range accessKindOrder {
		chips = append(chips, accessKindChip{
			Kind:    k,
			Current: f.Kind == string(k),
			Href:    f.withKind(k).base(),
		})
	}
	return chips
}

// accessFailuresChip is the "failures only" toggle, drawn beside the family
// chips rather than as one of them: it narrows every family at once, not
// one.
type accessFailuresChip struct {
	Current bool
	Href    string
}

// accessLaneKinds decides which audit kinds a filter selects.
//
// known=false means ?kind= named no family this screen has: NOTHING is
// queried in that case, never falling back to every family — the same rule
// Activity's own activityLanes follows. A failures-only toggle over a family
// with no failure kind (account, api-token) intersects to nothing and is
// spelled with noSuchAuditKind (activity.go's sentinel) rather than an empty
// slice, because an empty Kinds slice matches EVERY row on
// capability.AuditFilter's contract — the one direction a filter must never
// widen.
func accessLaneKinds(f accessFilter) (kinds []string, known bool) {
	if f.Kind == "" {
		kinds, known = accessAllKinds, true
	} else {
		for _, family := range accessKindOrder {
			if f.Kind == string(family) {
				kinds, known = accessKindsByFamily[family], true
				break
			}
		}
	}
	if !known {
		return nil, false
	}
	if f.Failures {
		kinds = intersectAccessKinds(kinds, accessFailureKinds)
		if len(kinds) == 0 {
			kinds = []string{noSuchAuditKind}
		}
	}
	return kinds, true
}

// intersectAccessKinds returns the elements of kinds that are also in with,
// preserving kinds' own order.
func intersectAccessKinds(kinds, with []string) []string {
	keep := map[string]bool{}
	for _, k := range with {
		keep[k] = true
	}
	var out []string
	for _, k := range kinds {
		if keep[k] {
			out = append(out, k)
		}
	}
	return out
}

// accessView is the whole screen.
type accessView struct {
	Rows         []accessRow
	Kinds        []accessKindChip
	FailuresChip accessFailuresChip

	Filter  accessFilter
	Windows []choice

	// Note carries anything parseAccessFilter could not read.
	Note string

	// UnknownKind is set when ?kind= named no family at all. Nothing is
	// queried in that case.
	UnknownKind string

	Narrowing bool
	PageSize  int

	OlderHref string
	ResetHref string

	Refresh Refresh
}

func handleAccess(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := principal(w, r)
		if !ok {
			return
		}
		p, ok := page(d, w, r, "Access")
		if !ok {
			return
		}
		p.Banner = banner(d, r)

		if d.Queries == nil {
			unavailable(w, "the audit query lane")
			return
		}
		d, lane := latched(d)

		f, note := parseAccessFilter(r, d.now())
		kinds, known := accessLaneKinds(f)

		v := accessView{
			Filter:       f,
			Note:         note,
			PageSize:     accessPageSize,
			ResetHref:    "/console/access",
			Narrowing:    f.narrowing(),
			Windows:      windowChoices(f.Window),
			Kinds:        accessKindChips(f),
			FailuresChip: accessFailuresChip{Current: f.Failures, Href: f.withFailures().base()},
		}
		if !known {
			v.UnknownKind = f.Kind
			renderScreen(w, p, accessTmpl, v)
			return
		}

		pg, err := d.Queries.QueryAudit(r.Context(), caller, capability.AuditFilter{
			Kinds:     kinds,
			AccountID: f.Account,
			Since:     f.Since,
			Until:     f.Until,
		}, capability.PageRequest{Limit: accessPageSize, Cursor: f.Cursor})
		if err != nil {
			readFailed(w, err, "the audit trail")
			return
		}
		if refusedUnaudited(w, lane, "the audit trail") {
			return
		}

		for _, row := range pg.Rows {
			facts := factsOfRow(row)
			ar := accessRowFrom(facts)
			if facts.VerifiedAccountID != "" {
				ar.ActorHref = f.withAccount(facts.VerifiedAccountID).base()
			}
			v.Rows = append(v.Rows, ar)
		}
		if pg.Next != "" {
			v.OlderHref = f.href(pg.Next)
		}
		v.Refresh = newRefresh("/console/access", f.values())

		renderScreen(w, p, accessTmpl, v)
	}
}

var accessTmpl = newScreen("access", `
<form class="viewbar" method="get" action="/console/access">
  {{with .Filter.Kind}}<input type="hidden" name="kind" value="{{.}}">{{end}}
  {{if .Filter.Failures}}<input type="hidden" name="failures" value="1">{{end}}
  <div class="vfield">
    <label class="vlabel" for="account">Actor</label>
    <input id="account" name="account" value="{{.Filter.Account}}" placeholder="e.g. acct-…" spellcheck="false" autocomplete="off">
  </div>
  <div class="vfield">
    <label class="vlabel" for="window">When</label>
    <select id="window" name="window">
      <option value="">all recorded time</option>
      {{range .Windows}}<option value="{{.Value}}"{{if .Selected}} selected{{end}}>{{.Label}}</option>{{end}}
    </select>
  </div>
  <div class="vfield">
    <label class="vlabel" for="since">Since</label>
    <input id="since" name="since" value="{{.Filter.SinceParam}}" placeholder="e.g. 2026-08-20T00:00:00Z" spellcheck="false" autocomplete="off">
  </div>
  <div class="vfield">
    <label class="vlabel" for="until">Until</label>
    <input id="until" name="until" value="{{.Filter.UntilParam}}" placeholder="e.g. 2026-08-26T00:00:00Z" spellcheck="false" autocomplete="off">
  </div>
  <button type="submit">Apply</button>
  <a class="act" href="{{.ResetHref}}">Clear</a>
</form>

{{with .Note}}<p class="gap"><b>Part of this URL could not be read:</b> {{.}}.</p>{{end}}

<div class="kindbar">
  {{range .Kinds}}<a class="kchip{{if .Current}} on{{end}}" href="{{.Href}}">{{.Kind}}</a>{{end}}
  <a class="kchip{{if .FailuresChip.Current}} on{{end}}" href="{{.FailuresChip.Href}}">failures only</a>
</div>

{{if .UnknownKind}}
<p class="gap"><b>There is no row kind called &ldquo;{{.UnknownKind}}&rdquo;.</b> Nothing was queried:
an unrecognised filter narrows to nothing here rather than falling back to everything, because a
filter that quietly widens is how an auditor comes to read the whole trail believing it is one
slice of it. Pick a kind above, or <a href="{{.ResetHref}}">clear the filter</a>.</p>
{{else}}

{{template "refresh" .Refresh}}

<div class="feed">
{{range .Rows}}
  <article class="ev" data-kind="{{.Kind}}">
    <div class="evwhen"><time datetime="{{.When}}">{{.When}}</time><span class="evkind">{{.EventKind}}</span></div>
    <div class="evbody">
      <div class="evhead">
        {{if .Actor}}<a class="chiplink" href="{{.ActorHref}}">{{template "trust-chip" (trust .Actor true)}}</a>{{else if .HostLever}}<span class="dim">the Relay host</span> <code>{{.HostLever}}</code>{{else}}<span class="dim">no verified Account</span>{{end}}
        {{with .Asserted}}{{template "trust-chip" (trust . false)}}{{else}}{{if .NotAnAccount}}<span class="dim">a name that is not an Account</span>{{end}}{{end}}
        <span class="evsum">{{.Summary}}</span>
        {{with .Attempt}}<span class="chip attempt" data-attempt="{{.}}">{{.}}</span>{{end}}
      </div>
      <div class="evmeta">
        {{with .Source}}from <code>{{.}}</code>{{end}}
      </div>
      {{with .Record}}<div class="evreason mono">{{.}}</div>{{end}}
    </div>
  </article>
{{else}}
  {{if .Narrowing}}<p class="dim">Nothing matches.</p>
  {{else}}<p class="dim">Nothing has been recorded yet.</p>{{end}}
{{end}}
</div>

<div class="pager">
  {{with .OlderHref}}<a class="act" href="{{.}}">Older</a>{{end}}
</div>

<details class="about">
<summary>About this screen</summary>

<p class="gap"><b>Each page holds up to {{.PageSize}} records</b>, newest first.</p>

<p class="gap"><b>Changes made on the Relay host name the host, not an Account.</b> A Console password is
set or removed only by the host-side <code>relay console-password</code> command, and the first API
Token is minted by <code>relay bootstrap-token</code>. Their rows name <code>local-host</code>: whoever
ran them had root on the Relay host, which no Account's credential proves. They never carry the
password or the token.</p>

<p class="gap"><b>OAuth sign-ins are not listed.</b> An OAuth sign-in happens at the identity provider,
not at the Relay, which sees only the authenticated calls that follow it. This screen lists Console
sign-ins.</p>

<p class="gap"><b>There is no filter by the changed Account.</b> The Account a change was made to is
written into the record's free-text reason, which the audit query cannot filter on. The Actor filter
matches the Account that acted.</p>

<p class="gap"><b>A failed sign-in shows the name typed only when it is a real Account's name.</b> Any
other text may be a password typed into the wrong box, so it is never recorded and the row says "a name
that is not an Account". The person signing in is never told which half was wrong. A failed step-up
always names the session's own Account. A throttled attempt was refused before any credential was
compared, so it is shown as throttled and is not a failure. Records written before this rule was
introduced keep whatever was typed, so on an older failed sign-in the name shown is only what the
caller entered: it may not be an Account, and it may be text typed into the wrong box. An older record
with no name also reads "a name that is not an Account".</p>

<p class="gap"><b>Every Refresh is an audited read</b>, like every read made from this Console.</p>

<p class="gap"><b>This screen is limited to admins in the Console only.</b> The same records remain
readable through the Control API by any Account the audit read rules already allow.</p>
</details>

{{end}}
`)
