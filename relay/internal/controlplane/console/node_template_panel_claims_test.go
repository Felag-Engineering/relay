package console

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// templateSetRowOf slices the "Template set" row out of a rendered Node page's
// Fingerprints panel, so the comparison is of the template panel's own text.
func templateSetRowOf(body string) string {
	panel := fingerprintPanelOf(body)
	_, rest, found := strings.Cut(panel, "<dt>Template set</dt>")
	if !found {
		return ""
	}
	row, _, _ := strings.Cut(rest, "</dd>")
	return row
}

// TestNode_TemplatePanelDoesNotDistinguishNeverReportedFromNoneInstalled
// proves QRY-23's Console half (docs/specs/query.md): the Console's template
// panel renders the same "no templates installed" text for a Node that never
// reported a Template snapshot as for a Node that reported an empty one.
//
// The reported-empty Node is armed: the capability read lane is shown to hold
// its empty snapshot as reported, and the never-reported Node as not
// reported, so the equality below compares two real states rather than one
// state twice.
//
// Residual: the panel is sliced out of rendered HTML, so a markup rename
// breaks the test rather than the property; MCP, which does distinguish the
// two, is proved elsewhere.
//
// Proves QRY-23.
func TestNode_TemplatePanelDoesNotDistinguishNeverReportedFromNoneInstalled(t *testing.T) {
	const never, empty = "node-never", "node-empty"
	reg := registry.NewInMemory()
	for _, id := range []string{never, empty} {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	vocab := nodevocab.New()
	vocab.Set(empty, nodevocab.Snapshot{Templates: []nodevocab.Template{}})
	d, svc := lanePanelDeps(t, reg, vocab)

	p := capability.Principal{AccountID: "acct-test"}
	for id, wantReported := range map[string]bool{never: false, empty: true} {
		detail, err := svc.DescribeNode(context.Background(), p, id)
		if err != nil {
			t.Fatalf("DescribeNode %s: %v", id, err)
		}
		if detail.TemplatesReported != wantReported || len(detail.Templates.Templates) != 0 {
			t.Fatalf("%s: lane reports reported=%v with %d template(s), want reported=%v and none; "+
				"the equality below would not compare the two states", id, detail.TemplatesReported,
				len(detail.Templates.Templates), wantReported)
		}
	}

	h := newTestHandler(d, accounts.RoleViewer)
	rows := map[string]string{}
	for _, id := range []string{never, empty} {
		rec := get(t, h, "/console/nodes/"+id)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /console/nodes/%s = %d, want 200", id, rec.Code)
		}
		row := templateSetRowOf(rec.Body.String())
		if row == "" {
			t.Fatalf("%s: no Template set row in the Fingerprints panel", id)
		}
		if !strings.Contains(row, "no templates installed") {
			t.Errorf("%s: template panel = %s\nwant %q", id, row, "no templates installed")
		}
		rows[id] = regexp.MustCompile(regexp.QuoteMeta(id)).ReplaceAllString(row, "NODE")
	}
	if rows[never] != rows[empty] {
		t.Errorf("template panel differs between a never-reported Node and a reported-empty one:\nnever: %s\nempty: %s",
			rows[never], rows[empty])
	}
}
