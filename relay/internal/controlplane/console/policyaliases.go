package console

// policyaliases.go is the Console's Policy alias display and its one write
// seam. An alias is display only and is always drawn beside the full
// fingerprint it names (QRY-33); where none is set, a neutral letter names the
// fingerprint on that page alone.
//
// The write is the capability layer's PolicyAliasAdmin, which decides the admin
// and human-Account floor, the name rules, uniqueness and the audit record
// (invariant 10). This file decides nothing: it names authz.ErrUnauthorized and
// the alias sentinels only to recognise a refusal the capability layer already
// made, and it narrows only what is drawn.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

// PolicyAliasWriter is one of the Console's write seams, with JobCanceller
// (cancel.go), AccountAdministrator (accounts_write.go) and TagWriter
// (tags.go). Like them it lives outside seams.go so that file's "every seam
// here is read-only" stays true.
//
// *capability.PolicyAliasAdmin satisfies it with no adapter.
type PolicyAliasWriter interface {
	SetPolicyAlias(ctx context.Context, p capability.Principal, fingerprint, name string) error
	ClearPolicyAlias(ctx context.Context, p capability.Principal, fingerprint string) error
}

const (
	// policyAliasesPattern is the write route's ServeMux pattern, named so
	// policyAliasesOffered compares against routesFor's output rather than
	// restating a path.
	policyAliasesPattern = "POST /console/policy-aliases"
	policyAliasesAction  = "/console/policy-aliases"

	policyAliasTitle = "Policy alias"

	// policyAliasesReadWhat names an alias read that failed, on every screen
	// that makes one, so it is never reported as another read.
	policyAliasesReadWhat = "this Relay's Policy aliases"

	policyAliasNotChanged = "Nothing was changed."

	// policyAliasUnconfirmedHeading does not say "nothing was changed": the
	// capability layer can return an error after a recorded change.
	policyAliasUnconfirmedHeading = "The Relay could not confirm this alias change. Reload and read the alias before trying again."
)

// policyFP is one Policy fingerprint as a screen draws it. Valid is the
// capability layer's rule for a well-formed fingerprint: only a valid value is
// drawn in full, can carry an alias or a letter, and can be edited. Any other
// reported value keeps the short form it always had.
type policyFP struct {
	Hash   string
	Alias  string
	Letter string
	Valid  bool
}

// Short is the truncated form a malformed reported value is drawn in.
func (f policyFP) Short() string { return shortHash(f.Hash) }

// fpNamer names the fingerprints of one page: a held alias where there is one,
// otherwise a letter in order of first appearance. A letter has no colour and
// ranks nothing.
type fpNamer struct {
	aliases    map[string]string
	aliasNames map[string]bool
	letters    map[string]string
	next       int
}

func newFPNamer(aliases map[string]string) *fpNamer {
	names := make(map[string]bool, len(aliases))
	for _, alias := range aliases {
		names[alias] = true
	}
	return &fpNamer{aliases: aliases, aliasNames: names, letters: map[string]string{}}
}

// name returns hash's alias, or its letter. A fingerprint keeps the letter it
// was first given; an aliased one uses up no letter; and a letter equal to a
// held alias is skipped, so one string never names two fingerprints.
func (n *fpNamer) name(hash string) policyFP {
	fp := policyFP{Hash: hash, Valid: capability.ValidPolicyFingerprint(hash)}
	if !fp.Valid {
		return fp
	}
	if alias := n.aliases[hash]; alias != "" {
		fp.Alias = alias
		return fp
	}
	if letter, ok := n.letters[hash]; ok {
		fp.Letter = letter
		return fp
	}
	for {
		letter := letterAt(n.next)
		n.next++
		if n.aliasNames[letter] {
			continue
		}
		n.letters[hash] = letter
		fp.Letter = letter
		return fp
	}
}

// letterAt is the i'th letter name, counting from zero: A to Z, then AA, AB and
// on (bijective base 26).
func letterAt(i int) string {
	var b []byte
	for i++; i > 0; i = (i - 1) / 26 {
		b = append([]byte{byte('A' + (i-1)%26)}, b...)
	}
	return string(b)
}

// readPolicyAliases reads every held alias through the recorded lane, once, when
// a human caller's page draws a well-formed fingerprint. A page that draws none
// makes no read. A machine principal makes no read either: a machine Account can
// render Console HTML on the bearer lane (page's doc, layout.go), and the
// adapter does not hand an AI-agent an administrator's name for a Policy
// (invariant 10: an adapter narrows only). It is drawn the neutral letter and
// the full hash, no name and no editor. Human is the capability layer's own
// fail-closed predicate, so an empty or unrecognised Kind is treated as machine.
// An unwired alias source is no aliases and no editor, not a failure; any other
// error is the caller's to render with readFailed.
func readPolicyAliases(ctx context.Context, d Deps, caller capability.Principal, draws bool) (aliases map[string]string, available bool, err error) {
	if !draws || !caller.Human() {
		return nil, false, nil
	}
	aliases, err = d.Queries.PolicyAliases(ctx, caller)
	if errors.Is(err, capability.ErrPolicyAliasesUnavailable) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return aliases, true, nil
}

// policyAliasesOffered reports whether caller is shown the Edit alias control.
// QRY-35 offers the write to a human admin only: a machine Account with the
// admin role can render Console HTML on the bearer lane (page's doc, layout.go),
// so the role alone would draw it a control.
//
// This only narrows what is drawn (invariant 10). The human-only floor stays the
// capability layer's: on the bearer lane the Secure CSRF check refuses a
// machine admin's POST before routing, and PolicyAliasAdmin's kind floor is the
// backstop behind it. Human is the capability layer's own fail-closed
// predicate, so an empty or unrecognised Kind is offered nothing.
func policyAliasesOffered(d Deps, caller capability.Principal) bool {
	if d.AliasWriter == nil || !caller.Human() {
		return false
	}
	for _, r := range routesFor(d, accounts.Role(caller.Role)) {
		if r.Pattern() == policyAliasesPattern {
			return true
		}
	}
	return false
}

// policyAliasForm is one Edit alias form: where it posts, the CSRF token, the
// fingerprint and its current alias. NodeID, Filter, Group and Pin only choose
// where a successful write redirects to; Node detail sets NodeID and Fleet sets
// the others.
type policyAliasForm struct {
	Action      string
	CSRFToken   string
	Fingerprint string
	Alias       string
	NodeID      string
	Filter      string
	Group       string
	Pin         string
}

// handleWritePolicyAlias implements POST /console/policy-aliases.
func handleWritePolicyAlias(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := principal(w, r)
		if !ok {
			return
		}
		if d.AliasWriter == nil {
			unavailable(w, "Policy alias writes")
			return
		}
		pg, ok := page(d, w, r, policyAliasTitle)
		if !ok {
			return
		}
		if !readTagForm(w, r, pg, maxFormBodyBytes, fleetPath, "Back to the fleet") {
			return
		}

		// The body is the only input: the action URL's query string never
		// supplies a field. The path back is built here from the fields below
		// and never taken from the request, so there is no open redirect.
		form := r.PostForm
		back, backLabel := policyAliasBack(form)

		fingerprint := form.Get("fingerprint")
		var err error
		switch form.Get("op") {
		case "set":
			err = d.AliasWriter.SetPolicyAlias(r.Context(), caller, fingerprint, form.Get("alias"))
		case "clear":
			err = d.AliasWriter.ClearPolicyAlias(r.Context(), caller, fingerprint)
		default:
			policyAliasRefusal(w, pg, http.StatusBadRequest,
				"An alias change is Save or Clear. "+policyAliasNotChanged, back, backLabel)
			return
		}
		if err != nil {
			policyAliasWriteFailed(w, pg, err, back, backLabel)
			return
		}
		http.Redirect(w, r, back, http.StatusSeeOther) //nolint:gosec // G710: back is a same-origin path built by policyAliasBack (the Fleet path, or a Node path with its ID escaped); the form supplies only values, never a destination
	}
}

// policyAliasBack is where a write returns to: the Node it was made on, or the
// Fleet view it was made on, with the view's filter, grouping and pin.
func policyAliasBack(form url.Values) (href, label string) {
	if nodeID := form.Get("node_id"); nodeID != "" {
		href = "/console/nodes/" + url.PathEscape(nodeID)
		if pin := form.Get("pin"); pin != "" {
			href += "?" + url.Values{"pin": {pin}}.Encode()
		}
		return href, "Back to the Node"
	}
	q := url.Values{}
	for _, k := range []string{"filter", "group", "pin"} {
		if v := form.Get(k); v != "" {
			q.Set(k, v)
		}
	}
	href = fleetPath
	if enc := q.Encode(); enc != "" {
		href += "?" + enc
	}
	return href, "Back to the fleet"
}

// policyAliasRefusal renders a refusal page, which is never cached.
func policyAliasRefusal(w http.ResponseWriter, pg Page, status int, heading, href, label string) {
	w.Header().Set("Cache-Control", "no-store")
	renderWriteResult(w, pg, status, heading, href, label)
}

// policyAliasWriteFailed renders a refusal or failure of an alias write, mapped
// with errors.Is only. A refusal is shown in the capability layer's own words,
// sentence-cased: they name the rule and never echo what the caller typed.
func policyAliasWriteFailed(w http.ResponseWriter, pg Page, err error, back, backLabel string) {
	refuse := func(status int) {
		reason := strings.TrimPrefix(firstJoinedErr(err).Error(), "capability: ")
		heading := sentenceCase(reason)
		if !strings.HasSuffix(heading, ".") {
			heading += "."
		}
		policyAliasRefusal(w, pg, status, heading+" "+policyAliasNotChanged, back, backLabel)
	}
	switch {
	case errors.Is(err, authz.ErrUnauthorized):
		// The capability layer decided this. A refusal reaches here joined with
		// the error from recording it, so only the first is shown: a failed
		// refusal-audit must not put store detail on the page.
		heading := "The Relay refused this alias change: " + firstJoinedErr(err).Error() + ". " + policyAliasNotChanged
		policyAliasRefusal(w, pg, http.StatusForbidden, heading, back, backLabel)
	case errors.Is(err, capability.ErrPolicyFingerprintMalformed),
		errors.Is(err, capability.ErrPolicyAliasEmpty),
		errors.Is(err, capability.ErrPolicyAliasTooLong),
		errors.Is(err, capability.ErrPolicyAliasControlCharacter),
		errors.Is(err, capability.ErrPolicyAliasInvalidUTF8):
		refuse(http.StatusBadRequest)
	case errors.Is(err, capability.ErrPolicyAliasTaken),
		errors.Is(err, capability.ErrPolicyAliasChanged):
		refuse(http.StatusConflict)
	case errors.Is(err, capability.ErrPolicyAliasesUnavailable):
		w.Header().Set("Cache-Control", "no-store")
		unavailable(w, "Policy alias writes")
	default:
		pg.logger().Error("console policy alias write returned an error", "error", err)
		policyAliasRefusal(w, pg, http.StatusInternalServerError, policyAliasUnconfirmedHeading, back, backLabel)
	}
}
