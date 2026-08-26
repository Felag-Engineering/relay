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
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"
)

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
	"risk":    RiskLabel,
	"outcome": OutcomeLabel,

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
		return t.UTC().Format("2006-01-02 15:04:05Z")
	},

	// join renders a string slice for display.
	"join": func(sep string, xs []string) string { return strings.Join(xs, sep) },

	// plural picks a suffix. Fleet screens count things constantly and "1
	// Nodes" reads as a bug in the product.
	"plural": func(n int, one, many string) string {
		if n == 1 {
			return one
		}
		return many
	},
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
		http.Error(w, "the Console could not render this page", http.StatusInternalServerError)
		return
	}
	p.Content = template.HTML(buf.String())
	Render(w, p)
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
