package console

import (
	"embed"
	"html/template"
	"net/http"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
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
	// TRUE — in-flight Tasks keep running, Plans still resolve — because an
	// emergency stop that looks like a total outage gets released in a panic.
	BannerFreeze BannerKind = "freeze"

	// BannerRelayCertExpiring: automatic rotation of the Relay's server
	// certificate has failed. Both listeners share that certificate, so once it
	// lapses the Console is unreachable too — this warning is only useful
	// BEFORE the event and can never be the only alarm.
	BannerRelayCertExpiring BannerKind = "relay-cert-expiring"

	// BannerCAExpiring: the trust root every Node pins is running out, and
	// there is no rotation path today (issue #412).
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
	Title   string
	Account string
	Role    accounts.Role

	Nav    []NavSection
	Banner *Banner

	// CSRFToken is rendered into the body's hx-headers attribute so every HTMX
	// request carries it without a line of inline script. An ATTRIBUTE is not
	// script and the content security policy does not touch it — which is the
	// entire reason the conventions ban hx-on:, which is.
	CSRFToken string

	// Content is the screen's own markup, produced by the screen's template.
	// It is template.HTML, so a screen that interpolates untrusted data without
	// escaping it has defeated the layout's protection rather than the layout
	// having failed. Screens render through html/template; none assembles a
	// string.
	Content template.HTML
}

var layoutTmpl = template.Must(template.New("layout").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} &mdash; Relay Console</title>
<link rel="stylesheet" href="/console/assets/console.css">
</head>
<body hx-headers='{"X-CSRF-Token": "{{.CSRFToken}}"}'>
<a class="skiplink" href="#content">Skip to content</a>
<div class="app">
  <aside class="nav">
    <div class="brand"><b>Relay</b> <span>console</span></div>
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
  </aside>
  <div class="col">
    {{with .Banner}}<div class="banner" data-kind="{{.Kind}}"><b>{{.Text}}</b> <span>{{.Detail}}</span></div>{{end}}
    <header class="topbar"><h1>{{.Title}}</h1></header>
    <main id="content">{{.Content}}</main>
  </div>
</div>
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
	token, err := ensureCSRFCookie(w, r)
	if err != nil {
		http.Error(w, "could not establish a CSRF token", http.StatusInternalServerError)
		return Page{}, false
	}
	role := accounts.Role(p.Role)
	return Page{
		Title:     title,
		Account:   p.Account,
		Role:      role,
		Nav:       Nav(d, role, r.URL.Path),
		CSRFToken: token,
	}, true
}

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
			p.Content = template.HTML(`<div class="placeholder">` +
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
// "console/assets/console.css" and 404s. That is what it did — every Console
// page rendered completely unstyled, and no test caught it because the shell
// landed before anything mounted it (#439, found when #418 first stood the
// Console up in a browser).
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
