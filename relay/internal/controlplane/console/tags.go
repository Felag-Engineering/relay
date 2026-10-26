package console

// tags.go is the Console's tag controls: add and remove a tag: label on one
// Node from Node detail, and on every Node of a filtered Fleet selection through
// a confirmation page that lists the matched Nodes.
//
// Its write seam is the capability layer's TagWriter, which decides who may
// write a tag (a human Account at operator or above, no step-up), what a tag may
// be, the per-Node cap and the audit record (invariant 10, ADR-0050). This file
// decides nothing. It names authz.ErrUnauthorized only to recognise a refusal
// the capability layer already made, and capability.ParseTagLabel only to
// refuse a malformed label before a page asks an operator to review a selection.
//
// A bulk write sends the Node IDs the confirmation page listed and never the
// filter that produced them, so the set written is the set confirmed.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// TagWriter is the Console's THIRD write seam, after JobCanceller (cancel.go)
// and AccountAdministrator (accounts_write.go). Like them it lives outside
// seams.go so that file's "every seam here is read-only" stays true.
//
// *capability.TagWriter satisfies it, as it satisfies the Control API's own
// interface, with no adapter. The floor, the label rules and the audit record
// are decided there and never here.
type TagWriter interface {
	WriteTag(ctx context.Context, p capability.Principal, w capability.TagWrite) (capability.TagWriteResult, error)
}

const (
	// nodeTagsPattern, confirmTagsPattern and bulkTagsPattern are the three
	// routes' ServeMux patterns, named so tagsOffered compares against
	// routesFor's output rather than restating a path.
	nodeTagsPattern    = "POST /console/nodes/{node_id}/tags"
	confirmTagsPattern = "GET /console/tags/confirm"
	bulkTagsPattern    = "POST /console/tags"

	confirmTagsPath = "/console/tags/confirm"
	bulkTagsAction  = "/console/tags"
)

// The bounds on one tag change. The Node count is the capability layer's; the
// body bound only sizes what the Console reads for it.
const (
	// maxBulkTagNodes is the capability layer's cap on one tag write. The
	// confirmation page draws no form for a larger match, so the Console never
	// offers a form the capability layer would refuse.
	maxBulkTagNodes = capability.MaxTagWriteNodes

	// maxTagNodeIDBytes mirrors the capability layer's unexported maxNodeIDBytes,
	// the longest Node ID it accepts in a tag write. It must follow that constant:
	// were this smaller, the bulk-body bound could refuse a form the confirmation
	// page draws.
	maxTagNodeIDBytes = 256

	// maxBulkTagBodyBytes bounds the bulk POST body: maxBulkTagNodes fields of
	// "node_id=<id>&", each ID at its longest and fully percent-encoded (three
	// bytes per byte), plus room for the CSRF token, op and label. About 258 KiB.
	maxBulkTagBodyBytes = int64(maxBulkTagNodes*(3*maxTagNodeIDBytes+len("node_id=&")) + 64<<10)

	// maxNamedMissingNodes is how many unknown Node IDs a refusal names.
	maxNamedMissingNodes = 5
)

// nodeTagsAction builds the form action for nodeID. The id is escaped: a Node ID
// is whatever enrollment gave the registry.
func nodeTagsAction(nodeID string) string {
	return "/console/nodes/" + url.PathEscape(nodeID) + "/tags"
}

// tagsOffered reports whether role may reach the route named by pattern at all.
// It goes through routesFor so a drawn control and a reachable route stay one
// fact. This is mount-time absence (Deps.Tags nil, or the route's own MinRole),
// never authorization: the human-Account-only rule and the operator floor are
// the capability layer's, and it never reads an Account's kind.
func tagsOffered(d Deps, role accounts.Role, pattern string) bool {
	if d.Tags == nil {
		return false
	}
	for _, r := range routesFor(d, role) {
		if r.Pattern() == pattern {
			return true
		}
	}
	return false
}

// nodeTagEdit is Node detail's tag controls: where the add form and each remove
// form post, and the CSRF token they carry.
type nodeTagEdit struct {
	Action    string
	CSRFToken string
}

// newNodeTagEdit returns the controls for nodeID, or nil when role is not
// offered the write route, so a viewer sees no control at all.
func newNodeTagEdit(d Deps, role accounts.Role, nodeID, csrf string) *nodeTagEdit {
	if !tagsOffered(d, role, nodeTagsPattern) {
		return nil
	}
	return &nodeTagEdit{Action: nodeTagsAction(nodeID), CSRFToken: csrf}
}

// fleetTagSelection is the Fleet view's bulk-tag form: a GET to the
// confirmation page carrying the filter that selected the Nodes, the grouping
// and the pin, so the page can return to the same view.
type fleetTagSelection struct {
	Action  string
	Filter  string
	Group   string
	Pin     string
	Matched int
}

// tagWriteTitle is the page title of every tag result and confirmation page.
const tagWriteTitle = "Tags"

// tagNotChanged ends every refusal heading: what did NOT happen. The fixed
// headings below are named so the copy budget holds each to the heading cap.
const (
	tagNotChanged = "Nothing was changed."

	tagNeedsFilterHeading = "Tagging works on a filtered view. Filter the fleet first. " + tagNotChanged
	tagNoMatchHeading     = "No Node matches this filter. " + tagNotChanged
	tagChangedHeading     = "A tag changed while this was being written. Reload and try again. " + tagNotChanged
	tagNodeGoneHeading    = "A Node in this change is no longer in the registry. " + tagNotChanged
	// tagUnconfirmedHeading does not say "nothing was changed": the capability
	// layer returns an error after a recorded change when something else failed.
	tagUnconfirmedHeading = "The Relay could not confirm this tag change. Reload and read the tags before trying again."
)

// tagTooManyNodesText refuses a tag change over the capability layer's Node cap,
// on the confirmation page and when WriteTag refuses one.
var tagTooManyNodesText = fmt.Sprintf("Tag at most %d Nodes at once; narrow the filter.", maxBulkTagNodes)

// tagMissingNodesHeading names the first maxNamedMissingNodes unknown Node IDs
// and counts the rest, so one request cannot make the page as large as itself.
func tagMissingNodesHeading(ids []string) string {
	named := ids[:min(len(ids), maxNamedMissingNodes)]
	heading := "Not in the registry: " + strings.Join(named, ", ")
	if rest := len(ids) - len(named); rest > 0 {
		heading += " and " + strconv.Itoa(rest) + " more"
	}
	return heading + ". " + tagNotChanged
}

// tagRefusal renders a refusal page. Like the success page it is not cached.
func tagRefusal(w http.ResponseWriter, pg Page, status int, heading, href, label string) {
	w.Header().Set("Cache-Control", "no-store")
	renderWriteResult(w, pg, status, heading, href, label)
}

// readTagForm reads and parses the request body within limit. It reports false
// after answering: a body over the limit is refused as a whole and nothing is
// written. Secure has normally parsed the form already, within the same limit,
// and this is then a no-op.
func readTagForm(w http.ResponseWriter, r *http.Request, pg Page, limit int64, href, label string) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	err := r.ParseForm()
	if err == nil {
		return true
	}
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		tagRefusal(w, pg, http.StatusRequestEntityTooLarge, bodyTooLargeHeading, href, label)
		return false
	}
	http.Error(w, "could not read the submitted form", http.StatusBadRequest)
	return false
}

// handleWriteNodeTag implements POST /console/nodes/{node_id}/tags.
func handleWriteNodeTag(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := principal(w, r)
		if !ok {
			return
		}
		if d.Tags == nil {
			unavailable(w, "Tag writes")
			return
		}
		pg, ok := page(d, w, r, tagWriteTitle)
		if !ok {
			return
		}
		nodeID := r.PathValue("node_id")
		nodePage := "/console/nodes/" + url.PathEscape(nodeID)
		if !readTagForm(w, r, pg, maxFormBodyBytes, nodePage, "Back to the Node") {
			return
		}

		// The body is the only input: the action URL's query string never
		// supplies a field. The label is passed unparsed, as the Control API's
		// body is.
		_, err := d.Tags.WriteTag(r.Context(), caller, capability.TagWrite{
			NodeIDs: []string{nodeID},
			Op:      capability.TagOp(r.PostForm.Get("op")),
			Label:   r.PostForm.Get("label"),
		})
		if err != nil {
			tagWriteFailed(w, pg, err, "node tags", nodePage, "Back to the Node")
			return
		}
		// Post-redirect-get, always to the Node's own page — never to a
		// caller-supplied URL (no open redirect). The chip is the result.
		http.Redirect(w, r, nodePage, http.StatusSeeOther)
	}
}

// handleConfirmTags implements GET /console/tags/confirm, the confirmation step
// of a bulk tag change. It writes nothing and calls no TagWriter method: it
// resolves the filter to Node IDs through the same audited read and the same
// matcher the Fleet view uses, names the operation, the tag and the count, and
// holds the single POST form that sends exactly the IDs it lists.
func handleConfirmTags(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := principal(w, r)
		if !ok {
			return
		}
		if !tagsOffered(d, accounts.Role(caller.Role), bulkTagsPattern) {
			unavailable(w, "Tag writes")
			return
		}
		if d.Queries == nil {
			unavailable(w, "the audited read lane")
			return
		}
		pg, ok := page(d, w, r, tagWriteTitle)
		if !ok {
			return
		}
		pg.Banner = banner(d, r)

		q := r.URL.Query()
		filter, op, label := q.Get("filter"), q.Get("op"), q.Get("label")
		back := url.Values{}
		for _, k := range []string{"filter", "group", "pin"} {
			if v := q.Get(k); v != "" {
				back.Set(k, v)
			}
		}
		backHref := fleetPath
		if enc := back.Encode(); enc != "" {
			backHref += "?" + enc
		}
		refuse := func(status int, heading string) {
			tagRefusal(w, pg, status, heading, backHref, "Back to the fleet")
		}

		if strings.TrimSpace(filter) == "" {
			refuse(http.StatusBadRequest, tagNeedsFilterHeading)
			return
		}
		// A pre-check only: WriteTag parses the label again and audits it.
		if _, _, err := capability.ParseTagLabel(capability.TagOp(op), label); err != nil {
			refuse(http.StatusBadRequest, tagRefusalText(err)+" "+tagNotChanged)
			return
		}

		d, lane := latched(d)
		listing, err := d.Queries.ListNodes(r.Context(), caller, "")
		if err != nil {
			readFailed(w, err, "this Relay's Node registry")
			return
		}
		if refusedUnaudited(w, lane, "this Relay's Node registry") {
			return
		}
		ev := capability.StateEval{Now: d.now(), CertExpiringWithin: listing.Eval.CertExpiringWithin}
		matched, err := matchFleetFilter(listing.Nodes, filter, ev)
		if err != nil {
			refuse(http.StatusBadRequest, err.Error()+" "+tagNotChanged)
			return
		}
		if len(matched) == 0 {
			refuse(http.StatusNotFound, tagNoMatchHeading)
			return
		}

		if len(matched) > maxBulkTagNodes {
			refuse(http.StatusBadRequest, tagTooManyNodesText)
			return
		}

		nodes := make([]tagNode, 0, len(matched))
		for _, n := range matched {
			nodes = append(nodes, tagNode{ID: n.NodeID, Hostname: primaryHostname(n.Facts.Hostname)})
		}
		w.Header().Set("Cache-Control", "no-store")
		renderScreen(w, pg, tagsConfirmTmpl, tagsConfirmView{
			Add:       capability.TagOp(op) == capability.TagAdd,
			Label:     label,
			Op:        op,
			Count:     len(nodes),
			Nodes:     nodes,
			Action:    bulkTagsAction,
			CSRFToken: pg.CSRFToken,
			Back:      backHref,
		})
	}
}

// handleWriteTags implements POST /console/tags. It writes the Node IDs the
// confirmation page listed, in one capability call, and never reads a filter.
func handleWriteTags(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := principal(w, r)
		if !ok {
			return
		}
		if d.Tags == nil {
			unavailable(w, "Tag writes")
			return
		}
		pg, ok := page(d, w, r, tagWriteTitle)
		if !ok {
			return
		}
		if !readTagForm(w, r, pg, maxBulkTagBodyBytes, fleetPath, "Back to the fleet") {
			return
		}
		ids := r.PostForm["node_id"]

		// The body is the only input. One call for the whole list: the
		// capability layer applies it all or not at all, and caps how many Nodes
		// it names, so the Console never loops per Node and never counts them.
		op := capability.TagOp(r.PostForm.Get("op"))
		res, err := d.Tags.WriteTag(r.Context(), caller, capability.TagWrite{
			NodeIDs: ids,
			Op:      op,
			Label:   r.PostForm.Get("label"),
		})
		if err != nil {
			tagWriteFailed(w, pg, err, "bulk tags", fleetPath, "Back to the fleet")
			return
		}

		// A redirect would lose the list of Nodes changed, which is the result.
		view := tagsResultView{
			Label:     r.PostForm.Get("label"),
			Add:       op == capability.TagAdd,
			Unchanged: res.Unchanged,
			Back:      fleetPath,
		}
		for _, c := range res.Changed {
			view.Changed = append(view.Changed, tagChangeRow{
				NodeID: c.NodeID,
				Old:    c.Before.Value, OldSet: c.Before.Set,
				New: c.After.Value, NewSet: c.After.Set,
			})
		}
		renderScreen(w, pg, tagsResultTmpl, view)
	}
}

// tagWriteFailed renders a refusal or failure of WriteTag. Every outcome is
// mapped with errors.Is and errors.As only, and every sentence is the
// Console's own: the capability layer's sentinel text names invariants and is
// never printed. The one exception is a role or kind refusal's reason, which the
// capability layer words for the operator and which is rendered, not restated.
func tagWriteFailed(w http.ResponseWriter, pg Page, err error, route, back, backLabel string) {
	var missing *capability.TagNodesNotFoundError
	switch {
	case errors.Is(err, authz.ErrUnauthorized):
		// The capability layer decided this (invariant 10). A refusal reaches
		// here joined with the error from recording it, so only the first
		// error is shown: a failed refusal-audit must not put store detail on
		// the page.
		tagRefusal(w, pg, http.StatusForbidden,
			"The Relay refused this tag change: "+firstJoinedErr(err).Error()+". "+tagNotChanged, back, backLabel)
	case errors.As(err, &missing):
		heading := tagNodeGoneHeading
		if len(missing.NodeIDs) > 0 {
			heading = tagMissingNodesHeading(missing.NodeIDs)
		}
		tagRefusal(w, pg, http.StatusNotFound, heading, back, backLabel)
	case errors.Is(err, capability.ErrTagChanged):
		tagRefusal(w, pg, http.StatusConflict, tagChangedHeading, back, backLabel)
	case errors.Is(err, capability.ErrTooManyTags):
		tagRefusal(w, pg, http.StatusConflict, tagRefusalText(err)+" "+tagNotChanged, back, backLabel)
	case isTagBadRequest(err):
		tagRefusal(w, pg, http.StatusBadRequest, tagRefusalText(err)+" "+tagNotChanged, back, backLabel)
	case errors.Is(err, capability.ErrTagsUnavailable):
		unavailable(w, "Tag writes")
	default:
		pg.logger().Error("console tag write returned an error", "route", route, "error", err)
		tagRefusal(w, pg, http.StatusInternalServerError, tagUnconfirmedHeading, back, backLabel)
	}
}

// tagBadRequests are the refusals of a malformed request, each with a sentence
// of its own in tagRefusalText.
var tagBadRequests = []error{
	capability.ErrTagNamespaceRequired,
	capability.ErrTagMalformed,
	capability.ErrTagTooLong,
	capability.ErrTagAddNeedsAValue,
	capability.ErrTagRemoveNamesAKey,
	capability.ErrTagOpUnknown,
	capability.ErrTagNoNodes,
	capability.ErrTagNodeIDInvalid,
	capability.ErrTagTooManyNodes,
}

func isTagBadRequest(err error) bool {
	for _, sentinel := range tagBadRequests {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

// tagRefusalText is the operator-voice sentence for one capability tag
// refusal. It is presentation only and never decides whether WriteTag is called.
func tagRefusalText(err error) string {
	switch {
	case errors.Is(err, capability.ErrTagNamespaceRequired):
		return "Only a tag: label is written here. node:, relay: and state: labels never are."
	case errors.Is(err, capability.ErrTagMalformed):
		return "A tag's key must not be empty, and its key and value may hold only ASCII letters, digits, '.', '_' and '-'."
	case errors.Is(err, capability.ErrTagTooLong):
		return fmt.Sprintf("A tag's key is at most %d characters and its value at most %d.",
			registry.MaxTagKeyLen, registry.MaxTagValueLen)
	case errors.Is(err, capability.ErrTagAddNeedsAValue):
		return "Adding a tag names tag:key=value."
	case errors.Is(err, capability.ErrTagRemoveNamesAKey):
		return "Removing a tag names tag:key, with no value."
	case errors.Is(err, capability.ErrTagOpUnknown):
		return "A tag change is either add or remove."
	case errors.Is(err, capability.ErrTagNoNodes):
		return "A tag change names at least one Node."
	case errors.Is(err, capability.ErrTagNodeIDInvalid):
		return "Every Node ID in a tag change must be present and not over-long."
	case errors.Is(err, capability.ErrTagTooManyNodes):
		return tagTooManyNodesText
	case errors.Is(err, capability.ErrTooManyTags):
		return "A Node carries at most " + strconv.Itoa(registry.MaxTagsPerNode) + " tags."
	}
	return sentenceCase(strings.TrimPrefix(err.Error(), "capability: "))
}

// firstJoinedErr returns the first error of an errors.Join result, or err
// itself when it is not one. The capability layer joins a refusal first, so this
// is the refusal without the error from recording it.
func firstJoinedErr(err error) error {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		if errs := joined.Unwrap(); len(errs) > 0 {
			return errs[0]
		}
	}
	return err
}

// tagNode is one listed Node on the confirmation page. It has the fields the
// node-name component reads.
type tagNode struct {
	ID       string
	Hostname string
}

// tagsConfirmView is the confirmation page.
type tagsConfirmView struct {
	Add       bool
	Label     string
	Op        string
	Count     int
	Nodes     []tagNode
	Action    string
	CSRFToken string
	Back      string
}

// tagChangeRow is one Node a bulk tag write changed.
type tagChangeRow struct {
	NodeID string
	Old    string
	OldSet bool
	New    string
	NewSet bool
}

// tagsResultView is the page a successful bulk write renders.
type tagsResultView struct {
	Label     string
	Add       bool
	Changed   []tagChangeRow
	Unchanged []string
	Back      string
}

var tagsConfirmTmpl = newScreen("tags-confirm", `
<section class="panel confirm">
  <p class="confirmq">{{if .Add}}Add{{else}}Remove{{end}} <code>{{.Label}}</code> {{if .Add}}to{{else}}from{{end}} {{.Count}} {{plural .Count "Node" "Nodes"}}?</p>
  <div class="tablescroll">
  <table class="rows">
    <caption class="tcap vh">The Nodes this change applies to.</caption>
    <thead><tr><th scope="col">Node <span class="selfreptag">hostname self-reported</span></th></tr></thead>
    <tbody>
    {{range .Nodes}}<tr><td>{{template "node-name" .}}</td></tr>
    {{end}}
    </tbody>
  </table>
  </div>
  <form class="ctlform ctlrow" method="post" action="{{.Action}}">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    {{range .Nodes}}<input type="hidden" name="node_id" value="{{.ID}}">
    {{end}}
    <input type="hidden" name="op" value="{{.Op}}">
    <input type="hidden" name="label" value="{{.Label}}">
    <button class="btn grant" type="submit">{{if .Add}}Add tag{{else}}Remove tag{{end}}</button>
    <a href="{{.Back}}">Back to the fleet</a>
  </form>
</section>
`)

var tagsResultTmpl = newScreen("tags-result", `
<section class="panel">
  <p class="confirmq">{{if .Add}}Added{{else}}Removed{{end}} <code>{{.Label}}</code>: {{len .Changed}} {{plural (len .Changed) "Node" "Nodes"}} changed{{if .Unchanged}}, {{len .Unchanged}} unchanged{{end}}.</p>
  {{if .Changed}}
  <div class="tablescroll">
  <table class="rows">
    <caption class="tcap vh">The Nodes this change changed.</caption>
    <thead><tr><th scope="col">Node</th><th scope="col">Before</th><th scope="col">After</th></tr></thead>
    <tbody>
    {{range .Changed}}<tr>
      <td><code class="nodeid">{{.NodeID}}</code></td>
      <td>{{if not .OldSet}}<span class="dim">not set</span>{{else if .Old}}<code>{{.Old}}</code>{{else}}<span class="dim">empty</span>{{end}}</td>
      <td>{{if not .NewSet}}<span class="dim">not set</span>{{else if .New}}<code>{{.New}}</code>{{else}}<span class="dim">empty</span>{{end}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{end}}
  {{if .Unchanged}}<p class="note">Already in that state: {{range $i, $id := .Unchanged}}{{if $i}}, {{end}}<code class="nodeid">{{$id}}</code>{{end}}.</p>{{end}}
  <p><a href="{{.Back}}">Back to the fleet</a></p>
</section>
`)
