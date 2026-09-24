package console

// node_query_claims_test.go carries the Query capability's two Console
// claims: QRY-5's rendering half and QRY-14's absence.
//
// Both run on a REAL *capability.Service over a real registry, not on
// fakeQueries. QRY-5 says "the capability read lane's Node detail, AS
// RENDERED BY the Console", and fakeQueries.DescribeNode hand-copies the
// lane's peer-count loop — so a panel test driven through it would prove the
// fake's arithmetic reaches the template, which is not the join the claim
// asserts. realLaneDeps (read_audit_test.go) is the in-package precedent.

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// lanePanelDeps wires renderableDeps' Console onto a real *capability.Service
// reading reg, and returns both so a test can compare what the lane computed
// against what the page rendered.
//
// Modelled on realLaneDeps, and deliberately separate from it: read_audit_test
// .go's sweeps depend on that fixture's exact registry contents.
func lanePanelDeps(t *testing.T, reg *registry.InMemory, opts ...capability.Option) (Deps, *capability.Service) {
	t.Helper()
	sink := auditsink.New(&recordingTrail{}, auditsink.WithClock(func() time.Time { return testNow }))
	svc := capability.New(reg,
		append([]capability.Option{
			capability.WithAuditSink(sink),
			capability.WithQueries(emptyAuditQuery{}, emptyJobQuery{}),
		}, opts...)...)
	d := renderableDeps()
	d.Queries = svc
	return d, svc
}

// fingerprintPanelOf slices the Fingerprints panel out of a rendered Node
// page, shaped exactly like policyPanelOf, so an assertion about the panel is
// not satisfied by the same words appearing elsewhere on the page.
func fingerprintPanelOf(body string) string {
	const open = "<h3>Fingerprints</h3>"
	i := strings.Index(body, open)
	if i < 0 {
		return ""
	}
	rest := body[i:]
	if j := strings.Index(rest, "</section>"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// TestNode_FingerprintPanelReportsThePeerCounts proves QRY-5's Console half
// (docs/specs/query.md): the capability read lane's Node detail, as rendered
// by the Console, reports how many registry Nodes share this Node's non-empty
// Policy fingerprint and template-set fingerprint — and says "not reported" /
// "no templates installed" rather than a count when the Node reported neither.
//
// The numbers come from a real capability.Service, so this proves the lane's
// arithmetic reaches the panel rather than a test double's copy of it.
//
// Residual: proves THIS screen, not every Console page. fingerprintPanelOf is
// a string slice of rendered HTML, so a markup rename breaks the test rather
// than the property. It proves the lane's numbers reach the panel; it does not
// prove the panel's prose is correct English for every n beyond 0 and 1.
func TestNode_FingerprintPanelReportsThePeerCounts(t *testing.T) {
	reg := registry.NewInMemory()
	for _, r := range []registry.Report{
		{NodeID: "node-web-1", PolicyFingerprint: "sha256:aaaa", TemplateSetFingerprint: "sha256:tttt"},
		{NodeID: "node-web-2", PolicyFingerprint: "sha256:aaaa"},
		{NodeID: "node-web-3", PolicyFingerprint: "sha256:bbbb"},
		{NodeID: "node-bare"},
	} {
		if _, err := reg.Upsert(r); err != nil {
			t.Fatalf("seed %s: %v", r.NodeID, err)
		}
	}
	d, _ := lanePanelDeps(t, reg)
	h := newTestHandler(d, accounts.RoleViewer)

	t.Run("a Node reporting both fingerprints", func(t *testing.T) {
		rec := get(t, h, "/console/nodes/node-web-1")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /console/nodes/node-web-1 = %d, want 200", rec.Code)
		}
		panel := fingerprintPanelOf(rec.Body.String())
		if panel == "" {
			t.Fatal("no Fingerprints panel in the rendered page")
		}
		// Self-inclusive: node-web-1 and node-web-2 share the Policy
		// fingerprint; node-web-1 alone reports a template set. `plural`
		// gives the singular at n == 1.
		if !strings.Contains(panel, "2 Nodes report this") {
			t.Errorf("Fingerprints panel = %s\nwant the Policy fingerprint's peer count %q", panel, "2 Nodes report this")
		}
		if !strings.Contains(panel, "1 Node report this") {
			t.Errorf("Fingerprints panel = %s\nwant the template-set fingerprint's peer count %q", panel, "1 Node report this")
		}
		// The counts sit beside the fingerprints they count.
		for _, fp := range []string{"aaaa", "tttt"} {
			if !strings.Contains(panel, ">"+fp+"<") {
				t.Errorf("Fingerprints panel = %s\nwant the reported fingerprint %q rendered", panel, fp)
			}
		}
	})

	t.Run("a Node reporting neither", func(t *testing.T) {
		rec := get(t, h, "/console/nodes/node-bare")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /console/nodes/node-bare = %d, want 200", rec.Code)
		}
		panel := fingerprintPanelOf(rec.Body.String())
		if panel == "" {
			t.Fatal("no Fingerprints panel in the rendered page")
		}
		for _, want := range []string{"not reported", "no templates installed"} {
			if !strings.Contains(panel, want) {
				t.Errorf("Fingerprints panel = %s\nwant %q for a Node that reported nothing", panel, want)
			}
		}
		// An empty fingerprint is not something the other three silent Nodes
		// "share" — the panel must not report a count at all.
		if strings.Contains(panel, "report this") {
			t.Errorf("Fingerprints panel = %s\nreports a peer count for a Node that reported no fingerprint", panel)
		}
	})
}

// flagNodevocabField is QRY-14's structural predicate: no field of the Node
// detail's view struct may carry a type from internal/nodevocab.
func flagNodevocabField(f reflect.StructField) string {
	t := f.Type
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice ||
		t.Kind() == reflect.Array || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	if strings.HasSuffix(t.PkgPath(), "/relay/internal/nodevocab") {
		return "field " + f.Name + " carries " + t.PkgPath() + "." + t.Name()
	}
	return ""
}

// walkViewFields visits every field reachable from t — recursing into struct
// fields and following pointer, slice, array and map element types —
// returning the reasons flag gave and the number of fields visited.
//
// The visit count is what makes the absence honest: a walker that failed to
// descend would otherwise report a clean sweep over nothing.
func walkViewFields(t reflect.Type, flag func(reflect.StructField) string) (flags []string, visited int) {
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type)
	walk = func(rt reflect.Type) {
		for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice ||
			rt.Kind() == reflect.Array || rt.Kind() == reflect.Map {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct || seen[rt] {
			return
		}
		seen[rt] = true
		for i := range rt.NumField() {
			f := rt.Field(i)
			visited++
			if reason := flag(f); reason != "" {
				flags = append(flags, reason)
			}
			walk(f.Type)
		}
	}
	walk(t)
	return flags, visited
}

// TestNode_DetailShowsTheTemplateFingerprintAndNeverTheTemplateVocabulary
// proves QRY-14 (docs/specs/query.md): the Console Node detail shows the
// template-set fingerprint and never the reported Template vocabulary.
//
// The lane is armed first — the vocabulary really is wired, really is
// reported, and really holds two templates — because without that the test
// cannot distinguish "the screen declined to render a vocabulary it was given"
// from "no vocabulary was ever wired".
//
// Residual: proves THIS screen and THIS view struct, not every Console page:
// another screen could render a vocabulary and neither leg would notice. The
// Console's own structural guards (no_dispatch, imports) speak to writers and
// dispatch, not to rendering, so they lend this nothing. QRY-14 names the
// absence as *Future work*: this pins today's behaviour, not a permanent ban.
func TestNode_DetailShowsTheTemplateFingerprintAndNeverTheTemplateVocabulary(t *testing.T) {
	const nodeID = "node-web-1"
	const fingerprint = "sha256:tmplsetzq"

	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: nodeID, TemplateSetFingerprint: fingerprint}); err != nil {
		t.Fatalf("seed %s: %v", nodeID, err)
	}
	vocab := nodevocab.New()
	vocab.Set(nodeID, nodevocab.Snapshot{
		Fingerprint: fingerprint,
		Templates: []nodevocab.Template{
			{Name: "tmpl.zebra.rotate", Slots: []nodevocab.Slot{{Name: "zqslot", Type: "identifier"}}},
			{Name: "tmpl.zebra.tail", Slots: []nodevocab.Slot{{Name: "zqlines", Type: "integer"}}},
		},
	})
	d, svc := lanePanelDeps(t, reg, capability.WithTemplateVocabulary(vocab))

	// Armed: the lane really does hand this screen a vocabulary to decline.
	detail, err := svc.DescribeNode(context.Background(), capability.Principal{AccountID: "acct-test"}, nodeID)
	if err != nil {
		t.Fatalf("DescribeNode: %v", err)
	}
	if !detail.TemplatesReported || len(detail.Templates.Templates) != 2 {
		t.Fatalf("the lane reported %d template(s) (reported=%v) — the absence below would prove "+
			"only that no vocabulary was ever wired", len(detail.Templates.Templates), detail.TemplatesReported)
	}

	rec := get(t, newTestHandler(d, accounts.RoleViewer), "/console/nodes/"+nodeID)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /console/nodes/%s = %d, want 200", nodeID, rec.Code)
	}
	body := rec.Body.String()

	// QRY-14's positive half: the fingerprint IS shown.
	if panel := fingerprintPanelOf(body); !strings.Contains(panel, shortHash(fingerprint)) {
		t.Errorf("Fingerprints panel = %s\nwant the template-set fingerprint %q", panel, shortHash(fingerprint))
	}

	// QRY-14's absence, over the whole page: no template name, no slot name.
	for _, token := range []string{"tmpl.zebra.rotate", "tmpl.zebra.tail", "zqslot", "zqlines"} {
		if strings.Contains(body, token) {
			t.Errorf("the Node detail page renders %q — QRY-14 says it shows the template-set "+
				"fingerprint and never the reported Template vocabulary", token)
		}
	}

	t.Run("structurally, the view struct carries no vocabulary", func(t *testing.T) {
		// Armed, one level down a slice so the recursion is exercised.
		type vocabLeakControl struct {
			Templates []nodevocab.Template
		}
		type vocabLeakWrapper struct {
			Leak *vocabLeakControl
		}
		controlFlags, controlVisited := walkViewFields(reflect.TypeOf(vocabLeakWrapper{}), flagNodevocabField)
		if len(controlFlags) == 0 {
			t.Fatal("the walker did not flag the deliberately vocabulary-carrying control type — it cannot fail and proves nothing")
		}
		if controlVisited == 0 {
			t.Fatal("the walker visited no field of the control type — it did not descend")
		}

		// nodeView is the only value the Node-detail template is executed with.
		flags, visited := walkViewFields(reflect.TypeOf(nodeView{}), flagNodevocabField)
		if visited == 0 {
			t.Fatal("the walker visited no field of nodeView — a clean sweep over nothing")
		}
		if len(flags) != 0 {
			t.Errorf("nodeView carries the reported Template vocabulary: %v", flags)
		}
	})
}
