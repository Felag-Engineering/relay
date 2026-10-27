package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

// TagWriter is the capability layer's tag write: add or remove a tag: label on
// a list of Node IDs. The concrete *capability.TagWriter satisfies it with no
// adapter. The floor (a human Account at operator or above, no step-up), the
// label rules and the audit record are decided inside it (invariant 10,
// ADR-0050); the handlers below only decode, call it and render.
type TagWriter interface {
	WriteTag(ctx context.Context, p capability.Principal, w capability.TagWrite) (capability.TagWriteResult, error)
}

// tagWriteRequest is the POST /api/v1/nodes/{node_id}/tags body. Label is in
// written form: "tag:key=value" to add, "tag:key" to remove. It is passed to
// the capability layer unparsed.
type tagWriteRequest struct {
	Op    string `json:"op"`
	Label string `json:"label"`
}

// bulkTagWriteRequest is the POST /api/v1/tags body: the same write over a list
// of resolved Node IDs.
type bulkTagWriteRequest struct {
	NodeIDs []string `json:"node_ids"`
	Op      string   `json:"op"`
	Label   string   `json:"label"`
}

// tagChangeView is one tag change on one Node. Old and New are nil when the tag
// was absent on that side, so an absent tag and an empty value stay distinct.
type tagChangeView struct {
	NodeID string  `json:"node_id"`
	Label  string  `json:"label"`
	Old    *string `json:"old"`
	New    *string `json:"new"`
}

// tagWriteResponse is the 200 body of both tag routes. Both lists are always
// present, never null.
type tagWriteResponse struct {
	Changed   []tagChangeView `json:"changed"`
	Unchanged []string        `json:"unchanged"`
}

// handleWriteNodeTag implements POST /api/v1/nodes/{node_id}/tags.
func handleWriteNodeTag(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
			return
		}
		if d.Tags == nil {
			writeProblem(w, http.StatusInternalServerError, "tag writes are not wired", "")
			return
		}
		nodeID, ok := pathID(w, r, "node_id", "node id")
		if !ok {
			return
		}
		var req tagWriteRequest
		if !readJSONBody(w, r, &req) {
			return
		}
		writeTag(w, r, d, p, capability.TagWrite{NodeIDs: []string{nodeID}, Op: capability.TagOp(req.Op), Label: req.Label})
	}
}

// handleWriteTags implements POST /api/v1/tags.
func handleWriteTags(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
			return
		}
		if d.Tags == nil {
			writeProblem(w, http.StatusInternalServerError, "tag writes are not wired", "")
			return
		}
		var req bulkTagWriteRequest
		if !readJSONBody(w, r, &req) {
			return
		}
		writeTag(w, r, d, p, capability.TagWrite{NodeIDs: req.NodeIDs, Op: capability.TagOp(req.Op), Label: req.Label})
	}
}

// writeTag calls the capability layer and renders the answer. No role check
// lives here: the floor is in the capability layer.
func writeTag(w http.ResponseWriter, r *http.Request, d Deps, p capability.Principal, req capability.TagWrite) {
	res, err := d.Tags.WriteTag(r.Context(), p, req)
	if err != nil {
		writeTagError(w, err)
		return
	}
	out := tagWriteResponse{Changed: []tagChangeView{}, Unchanged: []string{}}
	out.Unchanged = append(out.Unchanged, res.Unchanged...)
	for _, c := range res.Changed {
		v := tagChangeView{NodeID: c.NodeID, Label: "tag:" + c.Key}
		if c.Before.Set {
			old := c.Before.Value
			v.Old = &old
		}
		if c.After.Set {
			next := c.After.Value
			v.New = &next
		}
		out.Changed = append(out.Changed, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// tagBadRequests are the refusals that render 400 with their own text.
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

// writeTagError maps an error from the capability layer's tag write onto an
// HTTP problem response.
//
// A refusal reaches here joined with the error from recording the refusal, so
// every body is built from the matched sentinel's own text and never from the
// joined error: a failed refusal-audit must not put store detail on the wire.
// A role or human-kind refusal unwraps to authz.ErrUnauthorized and renders 403
// with the gate's reason, which states only the public rule. Anything else is a
// bare 500 with no detail.
func writeTagError(w http.ResponseWriter, err error) {
	var missing *capability.TagNodesNotFoundError
	switch {
	case errors.Is(err, authz.ErrUnauthorized):
		writeProblem(w, http.StatusForbidden, "forbidden", firstJoined(err).Error())
	case errors.As(err, &missing):
		detail := "no Node was changed"
		if len(missing.NodeIDs) > 0 {
			detail = "not in the registry: " + strings.Join(missing.NodeIDs, ", ")
		}
		writeProblem(w, http.StatusNotFound, "node not found", detail)
	case errors.Is(err, capability.ErrTagChanged):
		writeProblem(w, http.StatusConflict, "tag changed concurrently", "a tag changed while this write was being made; reload and retry")
	case errors.Is(err, capability.ErrTooManyTags):
		writeProblem(w, http.StatusConflict, "too many tags", capability.ErrTooManyTags.Error())
	default:
		for _, sentinel := range tagBadRequests {
			if errors.Is(err, sentinel) {
				writeProblem(w, http.StatusBadRequest, "invalid tag write", sentinel.Error())
				return
			}
		}
		writeProblem(w, http.StatusInternalServerError, "tag write failed", "")
	}
}

// firstJoined returns the first error of an errors.Join result, or err itself
// when it is not one. The capability layer joins a refusal first, so this is
// the refusal without the error from recording it.
func firstJoined(err error) error {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		if errs := joined.Unwrap(); len(errs) > 0 {
			return errs[0]
		}
	}
	return err
}
