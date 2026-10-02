package console

// accounts_forms_test.go pins the Accounts screen's form presentation to
// 00-foundations.md, "Form controls — one treatment": every write form opts
// into the shared control styling, every visible control keeps a visible
// label, and each submit button carries the weight of what it does to
// authority — filled for an act that grants, quiet for one that reduces.

import (
	"regexp"
	"strings"
	"testing"
)

var (
	formOpenTag   = regexp.MustCompile(`<form\b[^>]*>`)
	buttonElement = regexp.MustCompile(`<button\b([^>]*)>([^<]*)</button>`)
	controlTag    = regexp.MustCompile(`<(input|select)\b[^>]*>`)
	idAttr        = regexp.MustCompile(`\bid="([^"]+)"`)
)

// accountsFormsBodies renders the screen's content twice with the write half
// wired: once with the machine Account that holds a live token selected (role,
// Raise, Lower, Disable, create, mint and Revoke forms) and once with the disabled Account
// selected (its Enable form), so every write form is covered between them.
func accountsFormsBodies(t *testing.T) []string {
	t.Helper()
	return []string{
		contentOf(accountsWriteBody(t, "?account=gleipnir-prod")),
		contentOf(accountsWriteBody(t, "?account=retired-ci")),
	}
}

func TestAccountsForms_EveryWriteFormTakesTheSharedControlStyle(t *testing.T) {
	for _, body := range accountsFormsBodies(t) {
		forms := formOpenTag.FindAllString(body, -1)
		if len(forms) < 5 {
			t.Fatalf("found %d forms, want the role, state, create, mint and revoke forms", len(forms))
		}
		for _, f := range forms {
			if !strings.Contains(f, `class="ctlform`) {
				t.Errorf("a form on the Accounts screen does not opt into the shared control style: %s", f)
			}
		}
	}
}

// TestAccountsForms_ButtonWeightFollowsWhatTheActDoesToAuthority is the
// foundations table, as markup: the granting acts are filled (.btn.grant) and
// the reducing ones quiet (.btn.reduce). The role change is split so no form
// both grants and reduces: Raise role is filled and carries the password field
// to prove it, Lower role is outlined and carries none.
func TestAccountsForms_ButtonWeightFollowsWhatTheActDoesToAuthority(t *testing.T) {
	want := map[string]string{
		"Raise role":     "btn grant",
		"Lower role":     "btn reduce",
		"Enable":         "btn grant",
		"Create Account": "btn grant",
		"Mint API Token": "btn grant",
		"Disable":        "btn reduce",
		"Revoke":         "btn reduce",
	}
	seen := map[string]bool{}
	for _, body := range accountsFormsBodies(t) {
		for _, m := range buttonElement.FindAllStringSubmatch(body, -1) {
			attrs, label := m[1], strings.TrimSpace(m[2])
			class, ok := want[label]
			if !ok {
				t.Errorf("an Accounts button %q has no weight assigned by the form-control rule", label)
				continue
			}
			seen[label] = true
			if !strings.Contains(attrs, `class="`+class+`"`) {
				t.Errorf("the %q button does not carry class %q: <button%s>", label, class, attrs)
			}
		}
	}
	for label := range want {
		if !seen[label] {
			t.Errorf("the %q button did not render in either fixture", label)
		}
	}
}

// TestAccountsForms_EveryControlKeepsAVisibleLabel: each visible input and
// select either sits inside a <label> element with visible text of its own,
// or is named by a <label for=> whose text is not empty. A placeholder is not
// a label and none is accepted in place of one.
func TestAccountsForms_EveryControlKeepsAVisibleLabel(t *testing.T) {
	for _, body := range accountsFormsBodies(t) {
		for _, loc := range controlTag.FindAllStringIndex(body, -1) {
			tag := body[loc[0]:loc[1]]
			if strings.Contains(tag, `type="hidden"`) {
				continue
			}
			if id := idAttr.FindStringSubmatch(tag); id != nil {
				re := regexp.MustCompile(`<label\b[^>]*\bfor="` + regexp.QuoteMeta(id[1]) + `"[^>]*>([^<]+)</label>`)
				m := re.FindStringSubmatch(body)
				if m == nil || strings.TrimSpace(m[1]) == "" {
					t.Errorf("the control %s has no visible <label for=%q>", tag, id[1])
				}
				continue
			}
			open := strings.LastIndex(body[:loc[0]], "<label")
			closed := strings.LastIndex(body[:loc[0]], "</label>")
			if open < 0 || closed > open {
				t.Errorf("the control %s is neither wrapped in a <label> nor named by one", tag)
				continue
			}
			text := regexp.MustCompile(`<[^>]*>`).ReplaceAllString(body[open:loc[0]], "")
			if strings.TrimSpace(text) == "" {
				t.Errorf("the <label> around %s carries no visible text", tag)
			}
		}
	}
}

// TestAccountsForms_NoInlineStyleOrScript: the styling lives in console.css
// and nowhere else — `style-src 'self'` would drop an inline style silently,
// and the strict CSP admits no inline script.
func TestAccountsForms_NoInlineStyleOrScript(t *testing.T) {
	for _, q := range []string{"", "?account=gleipnir-prod", "?account=retired-ci"} {
		body := accountsWriteBody(t, q)
		assertNoInlineScript(t, "/console/accounts"+q, body)
		assertCSPClean(t, "/console/accounts"+q, body)
		if strings.Contains(strings.ToLower(contentOf(body)), " style=") {
			t.Errorf("/console/accounts%s carries an inline style attribute", q)
		}
	}
}

// TestAccountsForms_TheStylesheetWeighsGrantAboveReduce reads the rules the
// markup above relies on: a reducing button has no fill and never borrows the
// failure colour, a granting one is filled, and the shared field rule keeps a
// visible focus ring rather than trusting the browser default.
func TestAccountsForms_TheStylesheetWeighsGrantAboveReduce(t *testing.T) {
	raw, err := assetsFS.ReadFile("assets/console.css")
	if err != nil {
		t.Fatalf("read console.css: %v", err)
	}
	css := cssCommentPattern.ReplaceAllString(string(raw), "")
	decls := func(selector string) string {
		for _, m := range cssRulePattern.FindAllStringSubmatch(css, -1) {
			if strings.TrimSpace(m[1]) == selector {
				return m[2]
			}
		}
		t.Fatalf("console.css has no rule for %q", selector)
		return ""
	}

	grant := decls(".btn.grant")
	if !strings.Contains(grant, "background: var(--color-accent)") {
		t.Errorf(".btn.grant is not filled in the interactive colour: %q", grant)
	}
	reduce := decls(".btn.reduce")
	if !strings.Contains(reduce, "background: transparent") {
		t.Errorf(".btn.reduce is filled — a reducing act must be quiet: %q", reduce)
	}
	for _, sel := range []string{".btn.reduce", ".btn.reduce:hover"} {
		d := decls(sel)
		if strings.Contains(d, "--failure") || strings.Contains(d, "--color-red") {
			t.Errorf("%s borrows the failure colour — red is failure and timeout and nothing else: %q", sel, d)
		}
	}
	invalid := decls(".rolechange:invalid .btn")
	if !strings.Contains(invalid, "opacity") {
		t.Errorf("a role-change form that cannot submit yet does not read as inactive: %q", invalid)
	}
	focus := decls(".ctlform input:focus, .ctlform select:focus")
	if !strings.Contains(focus, "outline: 2px solid var(--color-accent)") {
		t.Errorf("the shared field focus rule does not draw the Console's focus ring: %q", focus)
	}
}
