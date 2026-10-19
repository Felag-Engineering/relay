package console

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/logctx"
)

//go:embed assets/*
var assetsFS embed.FS

// BannerKind is a condition about THE CONTROL PLANE ITSELF.
//
// Every other surface in the Console answers one of the four questions about a
// Node. This slot is the only place the Console can speak about the Relay, and
// it exists because the product's most catastrophic failure modes are invisible
// on a screen full of Nodes: the fleet freeze, and the certificates everything
// else depends on.
//
// These are operational alarms, not configuration. Nothing here is editable and
// nothing here is a settings page (invariant 11).
type BannerKind string

const (
	// BannerFreeze: all new Task dispatch halted. It must state what is STILL
	// TRUE — in-flight Tasks keep running, Preflights still resolve — because an
	// emergency stop that looks like a total outage gets released in a panic.
	BannerFreeze BannerKind = "freeze"

	// BannerRelayCertExpiring: automatic rotation of the Relay's server
	// certificate has failed. Both listeners share that certificate, so once it
	// lapses the Console is unreachable too — this warning is only useful
	// BEFORE the event and can never be the only alarm.
	BannerRelayCertExpiring BannerKind = "relay-cert-expiring"

	// BannerCAExpiring: the trust root every Node pins is running out, and
	// there is no rotation path today.
	BannerCAExpiring BannerKind = "ca-expiring"
)

// Banner is a rendered control-plane condition.
type Banner struct {
	Kind   BannerKind
	Text   string
	Detail string
}

// Page is everything the layout needs. Handlers build one and call Render;
// they never assemble HTML by hand.
type Page struct {
	Title string
	// TitleSelfReported is true only when Title is a value the Relay did not
	// establish (a Node's hostname). The layout then never draws it as plain,
	// verified-looking text.
	TitleSelfReported bool
	Account           string
	Role              accounts.Role

	Nav    []NavSection
	Banner *Banner

	// CSRFToken is rendered into the body's hx-headers attribute so every HTMX
	// request carries it without a line of inline script. An ATTRIBUTE is not
	// script and the content security policy does not touch it — which is the
	// entire reason the conventions ban hx-on:, which is.
	//
	// This is the SESSION's derived secret, not a cookie value: it is
	// sessionCSRFToken's read of the ConsoleSession the authentication
	// boundary already resolved, so a page and the request it later submits
	// are checked against the same per-session-per-request derivation rather
	// than against a value a cookie merely carried along. Empty when no
	// browser session is in context — see page()'s comment for why that
	// renders rather than fails.
	CSRFToken string

	// log is the request-correlated logger screens report errors to (nil means
	// slog.Default()). Unexported, so a template cannot reach it.
	log *slog.Logger

	// Scripts are external script files this page loads, each an absolute
	// path under /console/assets/.
	//
	// This is the shell's ONLY script hook, and its shape is the whole
	// point: a src from this origin, deferred, with an EMPTY element body.
	// The content security policy admits `script-src 'self'` and nothing
	// inline, so an inline handler — or an hx-on: attribute, which is
	// script — produces a page that renders and quietly does not work. The
	// specification says the same thing from the other direction:
	// "Behaviour that needs JavaScript lives in an external file served
	// from the Console's own origin."
	//
	// assertNoInlineScript (no_inline_script_test.go) checks every rendered
	// page against exactly that shape, and a source-level guard in the same
	// file permits the `<script` byte sequence in this file and nowhere
	// else in the package.
	Scripts []string

	// Content is the screen's own markup, produced by the screen's template.
	// It is template.HTML, so a screen that interpolates untrusted data without
	// escaping it has defeated the layout's protection rather than the layout
	// having failed. Screens render through html/template; none assembles a
	// string.
	Content template.HTML
}

var layoutTmpl = template.Must(template.New("layout").Funcs(template.FuncMap{"selfReportedTitle": func() string { return selfReportedTitle }}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}{{if .TitleSelfReported}} (self-reported){{end}} &mdash; Relay Console</title>
<link rel="stylesheet" href="/console/assets/console.css">
<link rel="icon" type="image/svg+xml" href="/console/assets/brand/relay-icon.svg">
</head>
<body hx-headers='{"X-CSRF-Token": "{{.CSRFToken}}"}'>
<a class="skiplink" href="#content">Skip to content</a>
<div class="app">
  {{/* The phone menu is a checkbox tied to a label: the CSP allows no inline script, and
       <details> cannot be kept open on desktop in every browser. The checkbox sits outside
       every <form> and submits nothing. */}}
  <aside class="nav">
    <input type="checkbox" id="navtoggle" class="navtoggle" autocomplete="off">
    <div class="navtop"><div class="brand"><picture><source media="(prefers-color-scheme: light)" srcset="/console/assets/brand/relay-wordmark-light.svg"><img src="/console/assets/brand/relay-wordmark-dark.svg" alt="Relay"></picture> <span>console</span></div><label for="navtoggle" class="navbtn">Menu</label></div>
    <div class="navbody">
    <nav class="navgroups" aria-label="Console">
    {{range .Nav}}
    <h2 class="navsec" id="navsec-{{.Slug}}">{{.Group}}</h2>
    <ul class="navlist" aria-labelledby="navsec-{{.Slug}}">
      {{range .Items}}<li><a class="navitem{{if .Current}} on{{end}}" href="{{.Path}}"{{if .Current}} aria-current="page"{{end}}>{{.Label}}</a></li>{{end}}
    </ul>
    {{end}}
    </nav>
    <div class="navfoot">
      <div>signed in as <b>{{.Account}}</b></div>
      <div>role <b>{{.Role}}</b></div>
      <form method="post" action="/console/logout">
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <button type="submit" class="linkbtn">Sign out</button>
      </form>
    </div>
    </div>
  </aside>
  <div class="col">
    {{with .Banner}}<div class="banner" data-kind="{{.Kind}}"><b>{{.Text}}</b> <span>{{.Detail}}</span></div>{{end}}
    <header class="topbar"><h1>{{if .TitleSelfReported}}<span class="selfrep" title="{{selfReportedTitle}}">{{.Title}}</span> <span class="selfreptag">self-reported</span>{{else}}{{.Title}}{{end}}</h1></header>
    <main id="content">{{.Content}}</main>
  </div>
</div>
{{range .Scripts}}<script src="{{.}}" defer></script>{{end}}
</body>
</html>
`))

// Render writes p as a complete Console page.
func Render(w http.ResponseWriter, p Page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := layoutTmpl.Execute(w, p); err != nil {
		// The header is already written, so the response is truncated either
		// way; log-and-stop beats a half page with a 200 and no error anywhere.
		http.Error(w, "the Console could not render this page", http.StatusInternalServerError)
	}
}

// page assembles the layout data common to every handler.
func page(d Deps, w http.ResponseWriter, r *http.Request, title string) (Page, bool) {
	p, ok := principal(w, r)
	if !ok {
		return Page{}, false
	}
	// token is "" when this request has no browser session — a bearer-lane
	// caller rendering Console HTML, which is how every screen test in this
	// package authenticates (console_test.go's request helper). Rendering
	// with an empty token rather than failing the request is safe under two
	// independent guards, neither of which lives here: sessionCSRFValid
	// refuses every unsafe method on the session lane before comparing
	// anything, and consoleauth.CSRFTokensEqual refuses an empty submitted
	// token outright. See sessionCSRFToken's doc for the rest of the
	// argument, including why making Console GETs browser-lane-only (which
	// would remove the need for this fallback) is a separate, larger change.
	token, _ := sessionCSRFToken(r)
	role := accounts.Role(p.Role)
	return Page{
		Title:     title,
		Account:   p.Account,
		Role:      role,
		Nav:       Nav(d, role, r.URL.Path),
		CSRFToken: token,
		log:       d.logger().With(logctx.Attrs(r.Context())...),
	}, true
}

func (p Page) logger() *slog.Logger { return logctx.Or(p.log) }

// placeholder renders the shell around a screen that has not been built yet,
// naming the specification that will replace it.
//
// This is deliberate rather than a stub left lying around: it makes the shell —
// the navigation projection, the security headers, the layout — real and
// reviewable now, and it turns every subsequent screen issue into "replace one
// placeholder", which is a much smaller diff to review than "add a screen and
// the plumbing it needs".
func placeholder(title, spec string) func(Deps) http.HandlerFunc {
	return func(d Deps) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			p, ok := page(d, w, r, title)
			if !ok {
				return
			}
			p.Content = template.HTML(`<div class="placeholder">` + //nolint:gosec // G203: a constant fragment; the one variable part is HTMLEscapeString'd
				`<p>This screen is not built yet.</p>` +
				`<p>Its specification is <code>docs/design/console/` +
				template.HTMLEscapeString(spec) + `</code>.</p></div>`)
			Render(w, p)
		}
	}
}

// assetHandler serves the Console's own static assets. It exists because the
// content security policy admits styles only from this origin and nothing
// inline, so the stylesheet cannot live in the layout.
//
// StripPrefix is load-bearing rather than tidy: the embedded FS is rooted at
// "assets/", and a FileServer handed the request path unmodified looks for
// "console/assets/console.css" and 404s, and every Console page renders
// completely unstyled.
//
// TestConsole_StylesheetIsActuallyServed is the regression guard, and it
// asserts the BODY rather than the status, because a 404 page is also a 200-
// shaped thing to a careless assertion.
func assetHandler(Deps) http.HandlerFunc {
	fs := http.StripPrefix("/console/", http.FileServer(http.FS(assetsFS)))
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		fs.ServeHTTP(w, r)
	}
}
