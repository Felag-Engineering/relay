package console

// screen.go is the plumbing every screen shares: rendering a screen's own
// template into the shell, and the template functions they all need.
//
// It exists so that no handler in this package ever concatenates HTML. Every
// screen parses a template once at init and executes it into a buffer; the
// buffer becomes Page.Content, which the layout emits as template.HTML. The
// consequence is that Node names, label values, Policy rule text and daemon
// output — all of which a compromised Node controls entirely — are escaped by
// html/template on the way out, in one place, rather than by each screen
// remembering to.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/logctx"
)

// Absolute times in the Console are always UTC and carry the trailing "Z".
const (
	utcStampLayout  = "2006-01-02 15:04:05Z"
	utcMinuteLayout = "2006-01-02 15:04Z"
)

// utcStamp renders t as an absolute UTC timestamp. It does not special-case
// the zero time; callers that need a placeholder check IsZero first.
func utcStamp(t time.Time) string { return t.UTC().Format(utcStampLayout) }

// screenFuncs are the template helpers every screen may use.
//
// They are deliberately few. A template that needs a function this list does
// not have is usually a template doing work that belongs in the handler, where
// it can be tested without parsing HTML.
var screenFuncs = template.FuncMap{
	"pct": func(f float64) string { return fmt.Sprintf("%.2f", f) },

	// trust builds a Trust chip inline, so a template can render an identity
	// without the handler pre-building a struct for every row. The two
	// arguments are deliberately positional and unmissable: the text, and
	// whether the RELAY established it. A template that passes `true` for an
	// asserted name has told the operator the Relay checked something it did
	// not, which is the one confusion the attribution model exists to prevent.
	"trust":   func(text string, verified bool) Trust { return Trust{Text: text, Verified: verified} },
	"risk":    jobs.RiskClassName,
	"outcome": jobs.OutcomeName,

	// selfReportedTitle is the tooltip on a self-reported name drawn as a
	// visual primary (identity.go).
	"selfReportedTitle": func() string { return selfReportedTitle },

	// short truncates a fingerprint to something an eye can compare. Full
	// values stay in the title attribute — the point of a fingerprint on a
	// fleet screen is "same or different", which is a 12-character question.
	"short": shortHash,

	// stamp renders an absolute UTC timestamp. The trail is read across time
	// zones and after the fact, so every absolute time in the Console is UTC
	// and says so; relative times ("4m") are for liveness only.
	"stamp": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return utcStamp(t)
	},

	// join renders a string slice for display.
	"join": func(sep string, xs []string) string { return strings.Join(xs, sep) },

	// cancelControl builds a JobCancel for a per-row template (#595): a
	// screen that draws a row per Job — Activity — cannot
	// pre-build one JobCancel per row in the handler without duplicating
	// cancelJobAction's escaping there too, so the template does it here
	// instead, at the one place both screens already call
	// {{template "job-cancel" ...}}.
	"cancelControl": func(action, token string) JobCancel { return JobCancel{Action: action, CSRFToken: token} },

	// plural picks a suffix and NOTHING ELSE — the number is supplied by the
	// template right beside it ({{.Count}} {{plural .Count "Node" "Nodes"}}).
	// Fleet screens count things constantly and "1 Nodes" reads as a bug in
	// the product.
	//
	// Its Go-side counterpart is countOf (fleet.go), which returns the number
	// AND the word. See countOf's comment for what the two of them sharing a
	// name once cost (#550).
	"plural": func(n int, one, many string) string {
		if n == 1 {
			return one
		}
		return many
	},

	// aboutDoc is the document an About disclosure names, under the shipped
	// choice (aboutDocsShipped). Rendered by the "about-docs" partial.
	"aboutDoc": func(screen string) string { return aboutDocFor(aboutDocsShipped, screen) },
}

// aboutDocsMode is what an "About this screen" disclosure names for further
// reading: a design document, an operator document, or nothing.
type aboutDocsMode int

const (
	aboutDocsNone aboutDocsMode = iota
	aboutDocsDesign
	aboutDocsOperator
)

// aboutDocsShipped is the owner's pending choice of what an About disclosure
// names for further reading. Changing it is the whole change.
const aboutDocsShipped = aboutDocsNone

// aboutDocScreens maps each screen that carries an About disclosure to the
// documents it could name, by mode. No per-screen operator document exists
// yet, so every operator entry is empty and that mode names nothing until one
// is written.
var aboutDocScreens = map[string]struct{ design, operator string }{
	"fleet":     {"docs/design/console/01-fleet-view.md", ""},
	"activity":  {"docs/design/console/04-activity.md", ""},
	"dayone":    {"docs/design/console/10-day-one.md", ""},
	"approvals": {"docs/design/console/14-approval-queue.md", ""},
	"accounts":  {"docs/design/console/15-accounts-and-tokens.md", ""},
	"access":    {"docs/design/console/20-access.md", ""},
}

// aboutDocFor is the document screen's About names under mode, or "" to name
// nothing.
func aboutDocFor(mode aboutDocsMode, screen string) string {
	docs := aboutDocScreens[screen]
	switch mode {
	case aboutDocsDesign:
		return docs.design
	case aboutDocsOperator:
		return docs.operator
	default:
		return ""
	}
}

// shortHash truncates a hex fingerprint for display, keeping enough to be
// unambiguous within a fleet and few enough to compare at a glance.
func shortHash(s string) string {
	s = strings.TrimPrefix(s, "sha256:")
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "…"
}

// newScreen parses a screen template with the shared components available to
// it, so a screen invokes {{template "deny-block" .}} rather than
// reimplementing one.
//
// Cloning componentsTmpl rather than re-parsing it is what guarantees a screen
// and the component it renders are the same component: there is exactly one
// definition of "deny-block" in the process.
func newScreen(name, body string) *template.Template {
	base := template.Must(componentsTmpl.Clone())
	return template.Must(base.New(name).Funcs(screenFuncs).Parse(body))
}

// renderScreen executes tmpl with data and puts the result in p.Content, then writes
// the page.
//
// A template error after the first byte would leave a truncated page with a
// 200, so the buffer is filled completely before anything is written.
func renderScreen(w http.ResponseWriter, p Page, tmpl *template.Template, data any) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		// Template exec errors carry the template name and the SOURCE TEXT of the
		// failing action (e.g. <.BoundaryExplanation>), never rendered values — so
		// a template-reachable method must keep its error messages value-free, or
		// whatever it interpolates is logged here. See Deny.BoundaryExplanation.
		p.logger().Error("console screen render failed", "screen", tmpl.Name(), "error", err)
		http.Error(w, "the Console could not render this page", http.StatusInternalServerError)
		return
	}
	p.Content = template.HTML(buf.String()) //nolint:gosec // G203: buf is html/template output, already contextually escaped
	Render(w, p)
}

// notFoundTmpl is the styled 404, mounted on every unmatched /console/ path
// and reused by every refusal that used to fall through to net/http's plain
// "404 page not found" (see console.go's gated and methodMismatch).
//
// It echoes NOTHING caller-supplied — no request path, no query, no header —
// so a refused, in-role route and a path that was never mounted at all render
// the SAME bytes. That byte-identity is the property ADR-0026 decision 5
// depends on: a viewer must not be able to tell "this route exists but I lack
// the role" from "this route does not exist" by diffing two 404 pages.
var notFoundTmpl = newScreen("notfound", `
<div class="placeholder">
  <p>Nothing in the Console lives at this address.</p>
  <p><a href="/console/">Back to the fleet</a>.</p>
</div>
`)

// renderNotFound renders the styled Console 404: not net/http's plain-text
// one, and not the request path echoed back.
//
// This handler is also the catch-all Register mounts on the bare "/console/"
// pattern, and that pattern is reachable WITHOUT a Principal: login.go's
// Unauthenticated list admits LoginPath and AssetsPrefix before
// Authenticator.Middleware ever authenticates, so a public-path request whose
// method or trailing slash the route table does not claim (an unauthenticated
// OPTIONS /console/login, say) reaches this function with no Principal in
// context. That is an ordinary, reachable case here — not a defensive
// impossibility — so the `!ok` branch renders net/http's plain 404 directly
// and returns, without calling [principal], whose own 500 write would double
// up with the one below it.
//
// Content-Type is set BEFORE WriteHeader, unconditionally: Render (via
// renderScreen) sets it too, but by then the status line is already written
// and a header set after WriteHeader is silently dropped on a real
// connection. Setting it here first is what makes the response text/html
// rather than whatever the ResponseWriter's zero value would otherwise send.
//
// banner() is deliberately not called: it reads Freeze state, which the gated
// and unmounted paths that share this handler must render identically
// regardless of.
func renderNotFound(d Deps, w http.ResponseWriter, r *http.Request) {
	pr, ok := controlplane.PrincipalFromContext(r.Context())
	if !ok {
		http.NotFound(w, r)
		return
	}
	token, _ := sessionCSRFToken(r)
	role := accounts.Role(pr.Role)
	pg := Page{
		Title:   "Not found",
		Account: pr.Account,
		Role:    role,
		// currentPath "" rather than r.URL.Path: a refused in-role nav route
		// (say /console/accounts refused by methodMismatch) must not highlight
		// that nav item while an unmounted path renders the identical page.
		Nav:       Nav(d, role, ""),
		CSRFToken: token,
		log:       d.logger().With(logctx.Attrs(r.Context())...),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	renderScreen(w, pg, notFoundTmpl, nil)
}

// notFoundHandler adapts renderNotFound to an http.HandlerFunc for
// Register's catch-all and for gated/methodMismatch's shared refusal.
func notFoundHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		renderNotFound(d, w, r)
	}
}

// unavailable renders a screen whose backing seam the composition root did not
// wire.
//
// This is a 500 with an explanation rather than an empty screen, because the
// two possible causes — a deliberately unwired dependency and a composition-root
// bug — are indistinguishable to the operator and both are worth saying out
// loud. An empty fleet view means "you have no Nodes", and a Console that
// renders that when it simply cannot see the registry has told a lie about the
// fleet.
func unavailable(w http.ResponseWriter, what string) {
	http.Error(w,
		"the Console cannot render this screen: "+what+" was not wired into this Relay. "+
			"This is a configuration or build problem, not an empty fleet.",
		http.StatusInternalServerError)
}

// unreadable renders a screen whose backing seam IS wired and FAILED.
//
// It is a separate sentence from unavailable's on purpose. The two are
// indistinguishable on screen if they share one message, and they send an
// operator to opposite places: a wiring fault is a build or configuration
// problem to be fixed at the composition root, and a query error is a runtime
// failure of a store that is running right now — which is to say, an incident,
// usually at the moment someone is trying to read a page in order to
// understand a different one.
func unreadable(w http.ResponseWriter, what string) {
	http.Error(w,
		"the Console cannot render this screen: "+what+" could not be read from this Relay. "+
			"This is a runtime failure of a seam that IS wired — not a configuration problem, "+
			"and not an empty result.",
		http.StatusInternalServerError)
}

// unaudited renders a screen REFUSED because the read it needed could not be
// written to the audit trail (ADR-0025 decision 4, capability's
// ErrReadUnaudited).
//
// A third sentence beside unavailable's and unreadable's, for the same reason
// there are two of those: the three send an operator to three different
// places. A wiring fault is a composition-root problem; a query failure is the
// store this Relay is running on; and this one is the AUDIT TRAIL, which is
// the component an operator is least likely to guess at from a generic 500 and
// the one whose failure is most worth knowing about on its own.
//
// It also says the thing the operator most needs to hear, which no generic
// error page can: nothing was disclosed. The refusal happened BEFORE the read,
// because the record is written first (capability's read lane) — so this page
// is the whole event, not the visible half of a read that already happened.
func unaudited(w http.ResponseWriter, what string) {
	http.Error(w,
		"the Console did not serve this screen: "+what+" could not be recorded on the audit trail, "+
			"and a read this Relay cannot audit is refused rather than served unrecorded. "+
			"Nothing was read and nothing was disclosed. The audit trail is the component to check, "+
			"not the one you were trying to look at.",
		http.StatusInternalServerError)
}

// readFailed renders whichever of the two runtime refusals err actually is.
//
// Every screen on the capability read lane calls this rather than unreadable
// directly, so "an unauditable read says so" is one decision in one place
// instead of a sentence each screen has to remember. what names the read in
// the operator's terms and is used by both branches.
func readFailed(w http.ResponseWriter, err error, what string) {
	if errors.Is(err, capability.ErrReadUnaudited) {
		unaudited(w, what)
		return
	}
	unreadable(w, what)
}

// auditLatch wraps a [QueryReader] and remembers whether ANY read through it
// was refused because it could not be audited (capability.ErrReadUnaudited,
// ADR-0025 decision 4).
//
// # Why a latch and not an error return
//
// The rule is one rule with no per-screen exception: a Console page whose read
// cannot be audited refuses to render. Several screens cannot express that
// through their return values, and deliberately so — the approval object
// renders "the trail could not be read" beside a card it CAN render. That
// graceful degradation is right for a store that failed and wrong for a trail
// that cannot record: the first is a partial page, the second is a page the
// Relay was not willing to serve at all.
//
// Threading a distinguishable error out of every one of those builders would
// restructure four screens to state one property. The latch asks the question
// at the seam every one of those reads already goes through, which is both
// smaller and stricter: a NEW read added to any of those screens is latched
// without its author doing anything.
//
// The latch never changes what a read returns. It observes and re-raises
// nothing — the refusal already happened, in the capability layer, BEFORE the
// data was read, which is why a latched page can honestly say nothing was
// disclosed.
type auditLatch struct {
	QueryReader
	unaudited bool
}

// latch records err and returns it unchanged, so a call site reads as a
// pass-through.
func (l *auditLatch) latch(err error) error {
	if errors.Is(err, capability.ErrReadUnaudited) {
		l.unaudited = true
	}
	return err
}

func (l *auditLatch) ListNodes(ctx context.Context, p capability.Principal, selector string) (capability.NodeListing, error) {
	ns, err := l.QueryReader.ListNodes(ctx, p, selector)
	return ns, l.latch(err)
}

func (l *auditLatch) DescribeNode(ctx context.Context, p capability.Principal, nodeID string) (capability.NodeDetail, error) {
	d, err := l.QueryReader.DescribeNode(ctx, p, nodeID)
	return d, l.latch(err)
}

func (l *auditLatch) QueryAudit(ctx context.Context, p capability.Principal, f capability.AuditFilter, page capability.PageRequest) (capability.AuditPage, error) {
	res, err := l.QueryReader.QueryAudit(ctx, p, f, page)
	return res, l.latch(err)
}

func (l *auditLatch) QueryJobs(ctx context.Context, p capability.Principal, f capability.JobFilter, page capability.PageRequest) (capability.JobPage, error) {
	res, err := l.QueryReader.QueryJobs(ctx, p, f, page)
	return res, l.latch(err)
}

func (l *auditLatch) QueryTasks(ctx context.Context, p capability.Principal, f capability.TaskFilter, page capability.PageRequest) (capability.TaskPage, error) {
	res, err := l.QueryReader.QueryTasks(ctx, p, f, page)
	return res, l.latch(err)
}

// RecordEventSubscription is here for the same reason every other method on
// this type is: an un-overridden QueryReader method would bypass the latch
// silently, which is precisely the hole this type's doc comment claims not
// to have. It is NOT exercised by #539's own code path — handleEvents calls
// d.Queries.RecordEventSubscription directly, never through latched(d),
// because it must see the error itself and refuse before writing the 200
// rather than deferring to a page-render-time latch check. Added for
// totality, not because this route uses it.
func (l *auditLatch) RecordEventSubscription(ctx context.Context, p capability.Principal, kinds []string, resumed bool) ([]string, error) {
	names, err := l.QueryReader.RecordEventSubscription(ctx, p, kinds, resumed)
	return names, l.latch(err)
}

// latched returns d with its read lane wrapped for one request, and the latch
// to consult before rendering.
//
// A nil lane is left nil: an unwired seam must keep reading as unwired
// (Deps.Queries's contract, and several screens branch on it), and wrapping
// nothing in a non-nil wrapper would turn "not configured" into "configured
// and empty" — the exact lie seams.go says an empty page must never tell.
func latched(d Deps) (Deps, *auditLatch) {
	if d.Queries == nil {
		return d, &auditLatch{}
	}
	l := &auditLatch{QueryReader: d.Queries}
	d.Queries = l
	return d, l
}

// refusedUnaudited renders the refusal and reports true when any read on this
// page could not be audited. Every screen on the read lane calls it before it
// renders — that call is the "no per-screen exception" part of the rule.
func refusedUnaudited(w http.ResponseWriter, l *auditLatch, what string) bool {
	if !l.unaudited {
		return false
	}
	unaudited(w, what)
	return true
}
