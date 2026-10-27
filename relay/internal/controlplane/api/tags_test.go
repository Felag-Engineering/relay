package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// fakeTagWriter is a TagWriter that records the call and returns a configured
// answer. It proves what the routes pass through and how they render; the
// floor, the label rules and the audit record are proven in the capability
// layer and the store.
type fakeTagWriter struct {
	got  []capability.TagWrite
	prin []capability.Principal
	res  capability.TagWriteResult
	err  error
}

func (f *fakeTagWriter) WriteTag(_ context.Context, p capability.Principal, w capability.TagWrite) (capability.TagWriteResult, error) {
	f.got = append(f.got, w)
	f.prin = append(f.prin, p)
	return f.res, f.err
}

func tagVal(v string) registry.TagValue { return registry.TagValue{Set: true, Value: v} }

func tagResponse(t *testing.T, body string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("response is not JSON: %v\n%s", err, body)
	}
	return out
}

func TestWriteNodeTag_PassesTheLabelThroughUnparsed(t *testing.T) {
	f := &fakeTagWriter{res: capability.TagWriteResult{
		Changed: []registry.TagChange{
			{NodeID: "node-a", Key: "team", After: tagVal("payments")},
		},
		Unchanged: []string{},
	}}
	h := newTestHandler(Deps{Tags: f})

	// An unparseable label reaches the capability layer verbatim: this surface
	// decides nothing about what a tag is.
	rec := do(t, h, http.MethodPost, "/api/v1/nodes/node-a/tags", map[string]string{"op": "add", "label": "tag:team=payments"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	want := capability.TagWrite{NodeIDs: []string{"node-a"}, Op: capability.TagAdd, Label: "tag:team=payments"}
	if len(f.got) != 1 || !reflect.DeepEqual(f.got[0], want) {
		t.Errorf("WriteTag got %+v, want %+v", f.got, want)
	}
	if f.prin[0] != testPrincipal() {
		t.Errorf("principal = %+v, want the authenticated Account %+v", f.prin[0], testPrincipal())
	}

	out := tagResponse(t, rec.Body.String())
	changed := out["changed"].([]any)
	if len(changed) != 1 {
		t.Fatalf("changed = %v", changed)
	}
	c := changed[0].(map[string]any)
	if c["node_id"] != "node-a" || c["label"] != "tag:team" || c["new"] != "payments" || c["old"] != nil {
		t.Errorf("changed[0] = %v, want node-a tag:team old null new payments", c)
	}

	f.got = nil
	do(t, h, http.MethodPost, "/api/v1/nodes/node-a/tags", map[string]string{"op": "remove", "label": "NOT A TAG"})
	if len(f.got) != 1 || f.got[0].Label != "NOT A TAG" || f.got[0].Op != capability.TagRemove {
		t.Errorf("WriteTag got %+v, want the label and op passed through unparsed", f.got)
	}
}

func TestWriteTags_BulkPassesEveryNodeID(t *testing.T) {
	f := &fakeTagWriter{res: capability.TagWriteResult{
		Changed: []registry.TagChange{
			{NodeID: "a", Key: "team", Before: tagVal("old"), After: tagVal("new")},
			{NodeID: "b", Key: "team", Before: tagVal("old")},
		},
		Unchanged: []string{"c"},
	}}
	h := newTestHandler(Deps{Tags: f})

	rec := do(t, h, http.MethodPost, "/api/v1/tags", map[string]any{"node_ids": []string{"a", "b", "c"}, "op": "add", "label": "tag:team=new"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	want := capability.TagWrite{NodeIDs: []string{"a", "b", "c"}, Op: capability.TagAdd, Label: "tag:team=new"}
	if len(f.got) != 1 || !reflect.DeepEqual(f.got[0], want) {
		t.Errorf("WriteTag got %+v, want %+v", f.got, want)
	}
	out := tagResponse(t, rec.Body.String())
	changed := out["changed"].([]any)
	if len(changed) != 2 {
		t.Fatalf("changed = %v", changed)
	}
	if b := changed[1].(map[string]any); b["old"] != "old" || b["new"] != nil {
		t.Errorf("a removal renders new null, got %v", b)
	}
	if !reflect.DeepEqual(out["unchanged"], []any{"c"}) {
		t.Errorf("unchanged = %v", out["unchanged"])
	}
}

func TestTagRoutes_RenderEmptyListsNotNull(t *testing.T) {
	h := newTestHandler(Deps{Tags: &fakeTagWriter{}})
	for path, body := range map[string]map[string]any{
		"/api/v1/nodes/n/tags": {"op": "add", "label": "tag:a=b"},
		"/api/v1/tags":         {"node_ids": []string{"n"}, "op": "add", "label": "tag:a=b"},
	} {
		rec := do(t, h, http.MethodPost, path, body)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d", path, rec.Code)
		}
		if body := rec.Body.String(); !strings.Contains(body, `"changed":[]`) || !strings.Contains(body, `"unchanged":[]`) {
			t.Errorf("%s: body = %s, want both lists as []", path, body)
		}
	}
}

func TestTagRoutes_RenderRefusals(t *testing.T) {
	auditDown := errors.New("capability: record audit entry: disk /var/lib/relay/relay.db is full")
	missing := &capability.TagNodesNotFoundError{NodeIDs: []string{"ghost"}}
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantDetail string
	}{
		{"forbidden", authzDenied("writing a tag requires role \"operator\", has \"viewer\""), http.StatusForbidden, "writing a tag requires"},
		{"namespace", capability.ErrTagNamespaceRequired, http.StatusBadRequest, "only a tag: label"},
		{"malformed", capability.ErrTagMalformed, http.StatusBadRequest, "key must be non-empty"},
		{"too long", capability.ErrTagTooLong, http.StatusBadRequest, "at most 63 characters"},
		{"add needs a value", capability.ErrTagAddNeedsAValue, http.StatusBadRequest, "tag:key=value"},
		{"remove names a key", capability.ErrTagRemoveNamesAKey, http.StatusBadRequest, "tag:key, with no value"},
		{"unknown op", capability.ErrTagOpUnknown, http.StatusBadRequest, "add or remove"},
		{"no nodes", capability.ErrTagNoNodes, http.StatusBadRequest, "at least one Node"},
		{"bad node id", capability.ErrTagNodeIDInvalid, http.StatusBadRequest, "every Node ID"},
		{"too many nodes", capability.ErrTagTooManyNodes, http.StatusBadRequest, "at most 256 Nodes"},
		{"unknown node", errors.Join(missing, capability.ErrTagNodeNotFound), http.StatusNotFound, "ghost"},
		{"vanished node", errors.Join(&capability.TagNodesNotFoundError{}, capability.ErrTagNodeNotFound), http.StatusNotFound, "no Node was changed"},
		{"changed", capability.ErrTagChanged, http.StatusConflict, "reload and retry"},
		{"too many", capability.ErrTooManyTags, http.StatusConflict, "at most 64"},
		{"unavailable", capability.ErrTagsUnavailable, http.StatusInternalServerError, ""},
		{"anything else", errors.New("capability: record tag write: sql: database is locked"), http.StatusInternalServerError, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newTestHandler(Deps{Tags: &fakeTagWriter{err: c.err}})
			rec := do(t, h, http.MethodPost, "/api/v1/tags", map[string]any{"node_ids": []string{"n"}, "op": "add", "label": "tag:a=b"})
			if rec.Code != c.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, c.wantStatus, rec.Body.String())
			}
			if c.wantDetail != "" && !strings.Contains(rec.Body.String(), c.wantDetail) {
				t.Errorf("body = %s, want it to contain %q", rec.Body.String(), c.wantDetail)
			}
			if c.wantStatus == http.StatusInternalServerError && strings.Contains(rec.Body.String(), "database") {
				t.Errorf("a 500 spilled internals: %s", rec.Body.String())
			}
		})
	}

	// A refusal reaches the surface joined with the error from recording it. The
	// body is built from the refusal's own text, never the joined error.
	for _, refusal := range []error{capability.ErrTagMalformed, capability.ErrTagNoNodes, authzDenied("writing a tag requires role \"operator\"")} {
		h := newTestHandler(Deps{Tags: &fakeTagWriter{err: errors.Join(refusal, auditDown)}})
		rec := do(t, h, http.MethodPost, "/api/v1/tags", map[string]any{"node_ids": []string{"n"}, "op": "add", "label": "tag:a=b"})
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusForbidden {
			t.Fatalf("%v: status = %d", refusal, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "disk") || strings.Contains(rec.Body.String(), "relay.db") {
			t.Errorf("%v: the refusal-audit failure reached the body: %s", refusal, rec.Body.String())
		}
	}
}

// authzDenied builds an error that unwraps to authz.ErrUnauthorized, as the
// gate's refusals do.
func authzDenied(reason string) error {
	return &deniedError{reason: reason}
}

type deniedError struct{ reason string }

func (e *deniedError) Error() string { return "authz: principal denied: " + e.reason }
func (e *deniedError) Unwrap() error { return authz.ErrUnauthorized }

func TestTagRoutes_UnwiredIs500(t *testing.T) {
	h := newTestHandler(Deps{})
	for _, path := range []string{"/api/v1/nodes/n/tags", "/api/v1/tags"} {
		rec := do(t, h, http.MethodPost, path, map[string]any{"op": "add", "label": "tag:a=b"})
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("%s: status = %d, want 500 with no tag writer wired", path, rec.Code)
		}
	}
}

func TestTagRoutes_RejectAnUnknownFieldAndAWrongMediaType(t *testing.T) {
	f := &fakeTagWriter{}
	h := newTestHandler(Deps{Tags: f})
	rec := doRaw(t, h, http.MethodPost, "/api/v1/tags", `{"node_ids":["n"],"op":"add","label":"tag:a=b","relay":"x"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unknown field: status = %d, want 400", rec.Code)
	}
	if len(f.got) != 0 {
		t.Error("a malformed body reached the capability layer")
	}
}
