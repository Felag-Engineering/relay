package console

// addnodes.go is Add Nodes (design spec 09), the Console's sixth write seam:
// the form that mints an Enrollment Token. It decides nothing. The admin floor,
// the bounds (capability.EnrollmentTokens' mint-form entry), the record and the
// withdrawal of an unrecorded token are the capability layer's (invariant 10,
// ADR-0026 decision 4). Step-up is per act, a password on every mint (owner
// decision 2026-10-29), because a window would let one password mint a burst of
// fleet-admitting join credentials. The reveal answers the POST itself: no post-redirect-get and no
// GET that renders it, because the join string is returned once and the Relay
// keeps only its hash (EN-4). It imports authz only for ErrUnauthorized.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// EnrollmentTokenMinter is the write seam this file holds. It carries only the
// mint-form entry, so the Console cannot ask for unlimited use.
// The composition root passes a narrowing wrapper (consoleEnrollmentMint)
// holding only this method.
type EnrollmentTokenMinter interface {
	MintEnrollmentTokenFromForm(ctx context.Context, p capability.Principal, f capability.EnrollmentMintForm) (capability.MintedEnrollmentToken, error)
}

const (
	addNodesPath                 = "/console/add-nodes"
	mintEnrollmentTokenAction    = "/console/add-nodes/tokens"
	mintEnrollmentTokenPattern   = "POST /console/add-nodes/tokens"
	defaultEnrollmentTTL         = "2h"
	addNodesUnavailableSubject   = "Enrollment Token minting"
	addNodesNothingMintedSuffix  = " Nothing was minted."
	addNodesRefusedByRelayPrefix = "The Relay refused this mint: "
)

// addNodesTooManyNodes is the sentence for a count above the form's limit.
var addNodesTooManyNodes = "A token from this form is for at most " + strconv.Itoa(capability.MaxEnrollmentFormNodes) +
	" Nodes." + addNodesNothingMintedSuffix

// addNodesTamperedRequest is the sentence for a use limit or expiry the form
// does not offer.
const addNodesTamperedRequest = "This request is not one the form offers." + addNodesNothingMintedSuffix

// enrollmentTTLChoices is the expiry select's CLOSED vocabulary. The submitted
// value is looked up by exact string and never parsed as a duration. The default
// resolves to the capability layer's, so the form and the layer cannot drift.
var enrollmentTTLChoices = []struct {
	Value string
	Label string
	TTL   time.Duration
}{
	{"30m", "30 minutes", 30 * time.Minute},
	{defaultEnrollmentTTL, "2 hours", capability.DefaultEnrollmentTokenTTL},
	{"8h", "8 hours", 8 * time.Hour},
	{"24h", "24 hours", 24 * time.Hour},
	{"168h", "7 days", 7 * 24 * time.Hour},
}

func enrollmentTTLFor(value string) (time.Duration, bool) {
	for _, c := range enrollmentTTLChoices {
		if c.Value == value {
			return c.TTL, true
		}
	}
	return 0, false
}

// addNodesOffered reports whether the screen can mint: a mint whose step-up
// cannot be verified is not offered.
func addNodesOffered(d Deps) bool {
	return d.EnrollmentTokens != nil && d.Auth != nil
}

type addNodesChoice struct {
	Value    string
	Label    string
	Selected bool
}

// addNodesForm is the mint form. The password is never echoed.
type addNodesForm struct {
	CSRFToken   string
	Action      string
	Nodes       string
	MaxNodes    int
	TTL         string
	InitialTags string
	Refusal     string
	Choices     []addNodesChoice
}

func newAddNodesForm(csrf, nodes, ttl, initialTags string) addNodesForm {
	f := addNodesForm{
		CSRFToken: csrf, Action: mintEnrollmentTokenAction,
		Nodes: nodes, MaxNodes: capability.MaxEnrollmentFormNodes, TTL: ttl, InitialTags: initialTags,
	}
	for _, c := range enrollmentTTLChoices {
		f.Choices = append(f.Choices, addNodesChoice{Value: c.Value, Label: c.Label, Selected: c.Value == ttl})
	}
	return f
}

// mintedEnrollmentView is the reveal-once response. JoinString is the one field
// a secret occupies, so LogValue omits it.
type mintedEnrollmentView struct {
	TokenID     string
	Nodes       int
	Expires     string
	InitialTags []string
	JoinString  string
}

// LogValue implements slog.LogValuer, omitting JoinString entirely.
func (v mintedEnrollmentView) LogValue() slog.Value {
	return slog.GroupValue(slog.String("token_id", v.TokenID))
}

// handleAddNodes implements GET /console/add-nodes. It calls no seam.
func handleAddNodes(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := principal(w, r); !ok {
			return
		}
		p, ok := page(d, w, r, "Add Nodes")
		if !ok {
			return
		}
		p.Banner = banner(d, r)
		if !addNodesOffered(d) {
			unavailable(w, addNodesUnavailableSubject)
			return
		}
		renderScreen(w, p, addNodesTmpl, newAddNodesForm(p.CSRFToken, "", defaultEnrollmentTTL, ""))
	}
}

// addNodesRefusal draws a refusal on the form it answers, or on the plain result
// page when the refusal is not one an edit can answer (createRefusal's shape).
func addNodesRefusal(form addNodesForm) writeRefusalRender {
	return func(w http.ResponseWriter, pg Page, status int, heading, href, label string) {
		if href != "" || !refusalAnswerable(status) {
			renderWriteResult(w, pg, status, heading, href, label)
			return
		}
		w.WriteHeader(status)
		answered := newAddNodesForm(pg.CSRFToken, form.Nodes, form.TTL, form.InitialTags)
		answered.Refusal = heading
		renderScreen(w, pg, addNodesTmpl, answered)
	}
}

// handleMintEnrollmentToken implements POST /console/add-nodes/tokens. The
// capability call comes only after a password has been verified in this request.
func handleMintEnrollmentToken(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := principal(w, r)
		if !ok {
			return
		}
		if !addNodesOffered(d) {
			unavailable(w, addNodesUnavailableSubject)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "could not read the submitted form", http.StatusBadRequest)
			return
		}
		pg, ok := page(d, w, r, "Add Nodes")
		if !ok {
			return
		}

		nodes := strings.TrimSpace(r.PostFormValue("nodes"))
		ttlValue := r.PostFormValue("ttl")
		tagsField := r.PostFormValue("initial_tags")
		form := newAddNodesForm(pg.CSRFToken, nodes, ttlValue, tagsField)
		refuse := addNodesRefusal(form)

		// A form-shape narrowing: the capability layer re-decides it.
		count, err := strconv.Atoi(nodes)
		if err != nil || count < 1 {
			refuse(w, pg, http.StatusBadRequest,
				"Say how many Nodes this token is for: a whole number, 1 or more."+addNodesNothingMintedSuffix, "", "")
			return
		}
		if capability.CheckEnrollmentFormNodes(count) != nil {
			refuse(w, pg, http.StatusBadRequest, addNodesTooManyNodes, "", "")
			return
		}
		ttl, ok := enrollmentTTLFor(ttlValue)
		if !ok {
			refuse(w, pg, http.StatusBadRequest,
				"This form did not carry a recognisable expiry."+addNodesNothingMintedSuffix, "", "")
			return
		}
		// One entry per line. Only the CRLF delimiter's "\r" is removed and a
		// line holding no entry is skipped; every other line reaches enroll
		// byte-for-byte, so a padded or malformed entry is refused there,
		// named, and never rewritten (EN-40).
		var tags []string
		for _, line := range strings.Split(tagsField, "\n") {
			line = strings.TrimSuffix(line, "\r")
			if strings.TrimSpace(line) == "" {
				continue
			}
			tags = append(tags, line)
		}

		ask := stepUpAsk{
			mode:     stepUpPerAct,
			required: "Your password is required to mint an Enrollment Token.",
			undone:   "Nothing was minted.",
			act:      "an Enrollment Token mint",
			render:   refuse,
		}
		if !requireStepUp(d, w, r, &pg, ask) {
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		minted, err := d.EnrollmentTokens.MintEnrollmentTokenFromForm(r.Context(), caller,
			capability.EnrollmentMintForm{Nodes: count, TTL: ttl, InitialTags: tags})
		if err != nil {
			mintEnrollmentFailed(d, w, r, pg, err, form)
			return
		}
		renderScreen(w, pg, enrollmentMintedTmpl, mintedEnrollmentView{
			TokenID:     minted.ID(),
			Nodes:       minted.MaxUses(),
			Expires:     utcStamp(minted.ExpiresAt()),
			InitialTags: minted.InitialTags(),
			JoinString:  minted.JoinString(),
		})
	}
}

// mintEnrollmentFailed picks a status and a sentence for a refused or failed
// mint. It decides nothing.
func mintEnrollmentFailed(d Deps, w http.ResponseWriter, r *http.Request, pg Page, err error, form addNodesForm) {
	refuse := addNodesRefusal(form)
	switch {
	case errors.Is(err, authz.ErrUnauthorized), errors.Is(err, capability.ErrEnrollmentInitialTagsNeedHuman):
		// The record error a refusal may be joined with is never shown.
		renderWriteResult(w, pg, http.StatusForbidden,
			addNodesRefusedByRelayPrefix+firstJoinedErr(err).Error()+"."+addNodesNothingMintedSuffix, "", "")
	case errors.Is(err, capability.ErrEnrollmentInitialTags):
		refuse(w, pg, http.StatusBadRequest, initialTagsRefusalText(err), "", "")
	case errors.Is(err, capability.ErrEnrollmentFormNodes):
		refuse(w, pg, http.StatusBadRequest, addNodesTooManyNodes, "", "")
	case errors.Is(err, capability.ErrEnrollmentUseLimit), errors.Is(err, capability.ErrEnrollmentTTL):
		// Unreachable from the form; this is a tampered request. The sentence is
		// constant: the form never offers a use limit, so none is named.
		refuse(w, pg, http.StatusBadRequest, addNodesTamperedRequest, "", "")
	case errors.Is(err, capability.ErrEnrollmentTokenMayBeLive):
		var live *capability.EnrollmentTokenLiveError
		id := ""
		if errors.As(err, &live) {
			id = live.TokenID
		}
		d.logger().ErrorContext(r.Context(), "console enrollment token mint was not recorded and the token was not withdrawn",
			"route", mintEnrollmentTokenPattern, "token_id", id, "error", err)
		renderWriteResult(w, pg, http.StatusInternalServerError,
			"The Relay could not record this mint or withdraw its token. The join string was discarded, but token "+id+
				" may still be live: revoke it over the Control API.", "", "")
	case errors.Is(err, capability.ErrEnrollmentMintNotRecorded):
		d.logger().ErrorContext(r.Context(), "console enrollment token mint was not recorded",
			"route", mintEnrollmentTokenPattern, "error", err)
		renderWriteResult(w, pg, http.StatusInternalServerError,
			"The Relay could not record this mint. Its join string was discarded and the token withdrawn, so it admits no Node. Mint again.", "", "")
	case errors.Is(err, capability.ErrEnrollmentTokensUnavailable):
		unavailable(w, addNodesUnavailableSubject)
	default:
		d.logger().ErrorContext(r.Context(), "console enrollment token mint returned an error",
			"route", mintEnrollmentTokenPattern, "error", err)
		renderWriteResult(w, pg, http.StatusInternalServerError,
			"The Relay could not confirm this mint. Nothing is shown; mint again.", "", "")
	}
}

// initialTagsRefusalText names the refused entry. html/template escapes it.
func initialTagsRefusalText(err error) string {
	if errors.Is(err, registry.ErrTooManyTags) {
		return "A token names at most " + strconv.Itoa(registry.MaxTagsPerNode) + " initial tags." + addNodesNothingMintedSuffix
	}
	var tagErr *registry.InitialTagError
	if !errors.As(err, &tagErr) {
		return "An initial tag was refused." + addNodesNothingMintedSuffix
	}
	var why string
	switch {
	case errors.Is(tagErr.Err, registry.ErrInitialTagRelayLabel):
		why = "relay: labels are written only by the Relay"
	case errors.Is(tagErr.Err, registry.ErrInitialTagKeyTwice):
		why = "a key is named twice"
	default:
		why = "an initial tag is tag:key=value, using letters, digits, dot, underscore and hyphen"
	}
	return "The initial tag " + tagErr.Entry + " was refused: " + why + "." + addNodesNothingMintedSuffix
}

var addNodesTmpl = newScreen("add-nodes", `
<h2>Add Nodes</h2>
<form class="ctlform ctlgrid" method="post" action="{{.Action}}" autocomplete="off">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <div class="fld">
    <label class="fldlabel" for="mint-nodes">How many Nodes</label>
    <input id="mint-nodes" name="nodes" type="number" min="1" max="{{.MaxNodes}}" step="1" required{{with .Nodes}} value="{{.}}"{{end}}>
  </div>
  <div class="fld">
    <label class="fldlabel" for="mint-ttl">Expires after</label>
    <select id="mint-ttl" name="ttl">
      {{range .Choices}}<option value="{{.Value}}"{{if .Selected}} selected{{end}}>{{.Label}}</option>
      {{end}}
    </select>
  </div>
  <div class="fld">
    <label class="fldlabel" for="mint-tags">Initial tags (optional, one per line)</label>
    <textarea id="mint-tags" name="initial_tags" rows="3" placeholder="tag:env=prod">{{.InitialTags}}</textarea>
  </div>
  <div class="fld">
    <label class="fldlabel" for="mint-password">Your password</label>
    <input id="mint-password" name="password" type="password" autocomplete="current-password" required>
  </div>
  {{with .Refusal}}<p class="fielderr" role="alert">{{.}}</p>{{end}}
  <button class="btn grant" type="submit">Mint Enrollment Token</button>
  <p class="note">The join string is shown once.</p>
</form>
`)

var enrollmentMintedTmpl = newScreen("enrollment-minted", `
<section class="panel minted">
  <h3>Enrollment Token minted</h3>
  <p class="note">Shown once. If it is lost, mint another.</p>
  <p>On each Node, run</p>
  <pre><code>sudo relay-daemon join</code></pre>
  <p>then paste this join string at its prompt:</p>
  <pre><code>{{.JoinString}}</code></pre>
  <dl>
    <dt>Token ID</dt><dd><code>{{.TokenID}}</code></dd>
    <dt>Nodes</dt><dd>{{.Nodes}}</dd>
    <dt>Expires</dt><dd>{{.Expires}}</dd>
    <dt>Initial tags</dt><dd>{{if .InitialTags}}{{range .InitialTags}}<code>{{.}}</code> {{end}}{{else}}none{{end}}</dd>
  </dl>
  <p><a href="/console/add-nodes">Add Nodes</a></p>
</section>
`)
