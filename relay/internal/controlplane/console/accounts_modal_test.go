package console

// accounts_modal_test.go pins the Accounts list's modals (11-console-shell.md,
// "Modals"; 15-accounts-and-tokens.md) at the level that needs no node: the
// list loads one external script and no inline one, the dialog shell is closed
// and holds no form, every trigger is still a real link, and the role panel is
// grouped for narrowing. The script's behaviour is testdata/check_accounts.js,
// run by jsassets_test.go.

import (
	"html"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

func accountsWriteRecorder(t *testing.T, path string) (http.Handler, string, http.Header) {
	t.Helper()
	d := sweepFixture()
	d.AccountAdmin = &fakeAccountAdmin{}
	d.Auth = &fakeAuth{}
	h := newTestHandler(d, accounts.RoleAdmin)
	rec := get(t, h, path)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", path, rec.Code)
	}
	return h, rec.Body.String(), rec.Header()
}

func TestAccounts_TheListLoadsTheAccountsScriptAndNothingInline(t *testing.T) {
	h, body, _ := accountsWriteRecorder(t, accountsScreenPath)

	srcs := scriptSources(body)
	if len(srcs) != 1 || srcs[0] != accountsScript {
		t.Fatalf("the list loads scripts %v, want exactly %s", srcs, accountsScript)
	}
	if !strings.Contains(body, `<script src="`+accountsScript+`" defer></script>`) {
		t.Errorf("the script tag is not the layout's external src+defer shape")
	}

	rec := get(t, h, srcs[0])
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "showModal") {
		t.Errorf("GET %s = %d and does not serve accounts.js", srcs[0], rec.Code)
	}
}

func TestAccounts_TheStandalonePagesLoadNoScript(t *testing.T) {
	for _, path := range []string{newAccountPath, accountPagePath("gleipnir-prod")} {
		_, body, _ := accountsWriteRecorder(t, path)
		if srcs := scriptSources(body); len(srcs) != 0 {
			t.Errorf("%s loads scripts %v; the no-JS pages must be unchanged", path, srcs)
		}
	}
}

func TestAccounts_TheDialogIsClosedLabelledAndHoldsNoForm(t *testing.T) {
	_, body, _ := accountsWriteRecorder(t, accountsScreenPath)

	const open = `<dialog id="acctdlg" class="modal" aria-labelledby="acctdlg-title">`
	i := strings.Index(body, open)
	if i < 0 {
		t.Fatalf("the list has no closed, labelled dialog (%s)", open)
	}
	if !strings.Contains(body, `id="acctdlg-title"`) {
		t.Errorf("the dialog's label target acctdlg-title does not exist")
	}
	j := strings.Index(body[i:], "</dialog>")
	if j < 0 {
		t.Fatalf("the dialog is not closed")
	}
	shell := body[i : i+j]

	var closers []string
	for _, m := range buttonElement.FindAllStringSubmatch(shell, -1) {
		if strings.Contains(m[1], "data-modal-close") {
			closers = append(closers, m[1]+">"+strings.TrimSpace(m[2]))
		}
	}
	if len(closers) != 2 {
		t.Fatalf("the dialog has %d close controls, want 2: %v", len(closers), closers)
	}
	var labelled, cancel bool
	for _, c := range closers {
		if !strings.Contains(c, `type="button"`) {
			t.Errorf("a close control can submit: %s", c)
		}
		labelled = labelled || strings.Contains(c, `aria-label="Close"`)
		cancel = cancel || strings.HasSuffix(c, ">Cancel")
	}
	if !labelled || !cancel {
		t.Errorf("want one aria-label=Close button and one Cancel button, got %v", closers)
	}
	for _, banned := range []string{"<form", "<input", "csrf_token", "password"} {
		if strings.Contains(shell, banned) {
			t.Errorf("the dialog shell holds %q; it must be an empty frame the script fills", banned)
		}
	}
}

var (
	anchorOpenTag  = regexp.MustCompile(`<a\b[^>]*>`)
	hrefAttr       = regexp.MustCompile(`\bhref="([^"]*)"`)
	modalTitleAttr = regexp.MustCompile(`\bdata-modal-title="([^"]*)"`)
)

func TestAccounts_EveryModalTriggerIsStillARealLink(t *testing.T) {
	_, body, _ := accountsWriteRecorder(t, accountsScreenPath)

	var sawNew, sawEdit, sawEnable bool
	for _, tag := range anchorOpenTag.FindAllString(body, -1) {
		href := hrefAttr.FindStringSubmatch(tag)
		if href == nil {
			continue
		}
		trigger := strings.Contains(tag, " data-modal-trigger")
		title := modalTitleAttr.FindStringSubmatch(tag)
		switch {
		case href[1] == newAccountPath:
			sawNew = true
			if !trigger || title == nil || title[1] != "New account" {
				t.Errorf("the New account link is not a modal trigger titled New account: %s", tag)
			}
		case strings.HasPrefix(href[1], "/console/accounts/") && strings.HasSuffix(href[1], "#state"):
			sawEnable = true
			if !trigger || title == nil {
				t.Errorf("an Enable link is not a titled modal trigger: %s", tag)
			}
		case strings.HasPrefix(href[1], "/console/accounts/"):
			sawEdit = true
			if !trigger || title == nil || href[1] != accountPagePath(html.UnescapeString(title[1])) {
				t.Errorf("an Edit link does not carry its Account's name as the modal title: %s", tag)
			}
		default:
			if trigger {
				t.Errorf("a link that is not New account, Edit or Enable opens a modal: %s", tag)
			}
		}
	}
	if !sawNew || !sawEdit || !sawEnable {
		t.Errorf("triggers seen: new=%v edit=%v enable=%v, want all three", sawNew, sawEdit, sawEnable)
	}

	// Disable stays a GET form to its named confirmation page.
	for _, f := range formOpenTag.FindAllString(contentOf(body), -1) {
		if strings.Contains(f, "data-modal-trigger") {
			t.Errorf("a form is a modal trigger: %s", f)
		}
		if !strings.Contains(f, `method="get"`) {
			t.Errorf("a list form is not a GET to a confirmation page: %s", f)
		}
	}
}

func TestAccounts_TheRolePanelGroupsEachRoleForNarrowing(t *testing.T) {
	_, body, _ := accountsWriteRecorder(t, newAccountPath)
	for _, role := range []string{"viewer", "operator", "admin"} {
		want := `<div class="roleline" data-role-line="` + role + `"><dt>` + role + `</dt><dd>`
		if !strings.Contains(body, want) {
			t.Errorf("the role panel does not group %s for narrowing: want %s", role, want)
		}
	}
	if strings.Contains(body, `class="roleline" hidden`) || strings.Contains(body, `hidden data-role-line`) {
		t.Errorf("a role line is hidden server-side; without JavaScript all three are drawn")
	}
}

// A form lifted into the list's dialog resolves a relative action against
// /console/accounts, so every form on a page a trigger opens names its target
// absolutely.
func TestAccounts_EveryFormAModalCanHoldHasAnAbsoluteAction(t *testing.T) {
	actionAttr := regexp.MustCompile(`\baction="([^"]*)"`)
	for _, path := range []string{newAccountPath, accountPagePath("gleipnir-prod")} {
		_, body, _ := accountsWriteRecorder(t, path)
		forms := formOpenTag.FindAllString(contentOf(body), -1)
		if len(forms) == 0 {
			t.Fatalf("%s has no form to check", path)
		}
		for _, f := range forms {
			action := actionAttr.FindStringSubmatch(f)
			if action == nil || !strings.HasPrefix(action[1], "/") || strings.HasPrefix(action[1], "//") {
				t.Errorf("%s: a form has no absolute action: %s", path, f)
			}
		}
	}
}

func TestAccounts_TheModalsLeaveTheCSPPinned(t *testing.T) {
	for _, path := range []string{accountsScreenPath, newAccountPath, accountPagePath("gleipnir-prod")} {
		_, body, header := accountsWriteRecorder(t, path)
		if got := header.Get("Content-Security-Policy"); got != pinnedCSP {
			t.Errorf("%s CSP = %q, want the pinned policy %q", path, got, pinnedCSP)
		}
		assertCSPClean(t, path, body)
	}
}

func TestAccountsJS_OpensAndClosesAndNeverPosts(t *testing.T) {
	var code []string
	for _, line := range strings.Split(readAsset(t, "assets/accounts.js"), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "//") {
			code = append(code, line)
		}
	}
	src := strings.Join(code, "\n")

	for _, want := range []string{"showModal", "DOMParser", "data-modal-trigger", "no-store", "pageshow", "finally"} {
		if !strings.Contains(src, want) {
			t.Errorf("accounts.js does not contain %q", want)
		}
	}
	for _, banned := range []string{
		"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
		"XMLHttpRequest", "sendBeacon", "method:", "body:", ".submit(", "requestSubmit",
		"eval(", "new Function", "localStorage", "sessionStorage", "confirm(",
	} {
		if strings.Contains(src, banned) {
			t.Errorf("accounts.js contains %q", banned)
		}
	}
}
