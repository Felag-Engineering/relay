package capability

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// PF-7 (docs/specs/policy-preflight.md): "The Relay never computes a
// verdict. Every allow and deny is the daemon's live engine's answer and
// every unsupported is the daemon's answer; the Relay consults no Policy
// view and no cached vocabulary to produce one (invariant 12)."
//
// The issue's suggested seam — an import-boundary guard forbidding package
// capability from importing internal/policyview or internal/nodevocab — is
// no longer possible: #702/#680 routed the display-only Policy-view and
// Template-vocabulary reads through the capability read lane
// (readlane_registry.go), and execution_test.go's
// TestCapabilityImportsOnlyRegistryAndJobs already admits both packages by
// name. PF-7's claim is still true today; it just needs proving at a finer
// grain than "this package may not import X". These two tests replace the
// stale guard:
//
//   - TestPreflightNeverConsultsCachedPolicyOrVocabulary proves it
//     BEHAVIOURALLY: a Plan wired to spies that would contradict the
//     daemon's own answer still reports the daemon's answer, with zero Gets.
//   - TestCachedPolicyAndVocabularyReachOnlyTheDisplayReadLane proves it
//     STRUCTURALLY: every reference to the cached seams — the fields, the
//     seam types, the imports, and the display read lane's own exported
//     methods (the indirect route a plan.go shortcut could take) — is
//     confined to the two files that make up that lane.

// newPreflightServiceWithCaches wires a Service exactly like plan_test.go's
// newPlanTestService, plus the two display-only cache seams under test.
func newPreflightServiceWithCaches(t *testing.T, reg registry.Repository, conduit *fakeConduit, pv PolicyViewSource, nv TemplateVocabularySource) *Service {
	t.Helper()
	jobsRepo, tasksRepo := testEngineStore(t)
	return New(reg,
		WithAuthorizer(&spyAuthorizer{}),
		WithCapChecker(&spyCapChecker{}),
		WithAuditSink(&spyAuditSink{}),
		WithFreeze(&fakeFreezeStore{}),
		WithExecution(jobsRepo, tasksRepo, conduit),
		WithPolicyView(pv),
		WithTemplateVocabulary(nv),
	)
}

// recordingPolicyView records every nodeID it was asked about and always
// answers with the fixed snapshot it was built with — deliberately one that
// CONTRADICTS the fake daemon's canned verdict below, so a Plan that ever
// consulted it would read differently.
type recordingPolicyView struct {
	gets []string
	snap policyview.Snapshot
}

func (r *recordingPolicyView) Get(nodeID string) (policyview.Snapshot, bool) {
	r.gets = append(r.gets, nodeID)
	return r.snap, true
}

// recordingTemplateVocab is recordingPolicyView's Template-vocabulary twin.
type recordingTemplateVocab struct {
	gets []string
	snap nodevocab.Snapshot
}

func (r *recordingTemplateVocab) Get(nodeID string) (nodevocab.Snapshot, bool) {
	r.gets = append(r.gets, nodeID)
	return r.snap, true
}

// TestPreflightNeverConsultsCachedPolicyOrVocabulary proves PF-7's
// behavioural half. Five Nodes: one the daemon allows, one it denies (with a
// rule), one it says is unsupported, one offline, and one whose Query itself
// errors (security review cycle 2, SR5 — the branch a "fall back to the
// cached Policy view when the query fails" regression would live in, which
// is exactly the fabricated-allow shape invariant 12 forbids). The wired
// PolicyViewSource/TemplateVocabularySource spies each answer with a
// snapshot that says the OPPOSITE of what the daemon will say — "nothing is
// allowed" and "the vocabulary is empty" — so any shortcut that consulted
// either cache would flip a verdict, not just add a Get call.
func TestPreflightNeverConsultsCachedPolicyOrVocabulary(t *testing.T) {
	reg := registry.NewInMemory(registry.WithMinDaemonVersion("1.2.0"))
	seed := func(nodeID, daemonVersion string) {
		t.Helper()
		if _, err := reg.Upsert(registry.Report{
			NodeID:        nodeID,
			DaemonVersion: daemonVersion,
		}.WithNodeLabels(map[string]string{"role": "web"})); err != nil {
			t.Fatalf("Upsert(%s): %v", nodeID, err)
		}
	}
	seed("node-allow", "1.2.0")
	seed("node-deny", "1.2.0")
	seed("node-unsup", "1.2.0")
	seed("node-offline", "1.0.0")
	seed("node-queryfail", "1.2.0")

	var log []string
	conduit := newFakeConduit(&log)
	conduit.connected["node-allow"] = true
	conduit.connected["node-deny"] = true
	conduit.connected["node-unsup"] = true
	// node-offline is deliberately absent from conduit.connected.
	conduit.connected["node-queryfail"] = true
	conduit.verdicts["node-allow"] = jobs.Verdict{Allowed: true}
	conduit.verdicts["node-deny"] = jobs.Verdict{Allowed: false, DecidingRule: "deny-from-daemon"}
	conduit.verdicts["node-unsup"] = jobs.Verdict{Unsupported: true, DecidingRule: "not in vocabulary"}
	conduit.queryErrs["node-queryfail"] = errors.New("tunnel dropped mid-query")

	pv := &recordingPolicyView{snap: policyview.Snapshot{
		AllowedOperations: nil,
		RawExecEnabled:    false,
		PolicyFingerprint: "cache-says-nothing-is-allowed",
	}}
	nv := &recordingTemplateVocab{snap: nodevocab.Snapshot{
		Fingerprint: "cache-says-empty-vocabulary",
		Templates:   nil,
	}}

	svc := newPreflightServiceWithCaches(t, reg, conduit, pv, nv)

	// A Native Operation: amended PF-7 (ADR-0042) admits a cached-vocabulary
	// read only to decide a TEMPLATE's fan-out and class, so for a Native the
	// zero-Gets property below still holds in full. The Template case — where
	// the cache is read for fan-out but every allow and deny is still the
	// daemon's — is TestPreflightTemplateExclusionNeverDecidesAVerdict
	// (template_test.go).
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "file.read", OperationArgs: map[string]string{"path": "/etc/hostname"}}
	pr, err := svc.Plan(context.Background(), Principal{Account: "alice"}, webSelector(), act)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	// Assertion 1, read FIRST, before anything else (including the armed
	// control below) can touch a spy: the Plan itself consulted neither
	// cache.
	if len(pv.gets) != 0 {
		t.Errorf("policyView.Get was called for %v during a Plan — invariant 12/ADR-0011: the Relay must never consult its Policy view to answer a preflight", pv.gets)
	}
	if len(nv.gets) != 0 {
		t.Errorf("templateVocabulary.Get was called for %v during a Plan — invariant 12/ADR-0011: the Relay must never consult its Template-vocabulary cache to answer a preflight", nv.gets)
	}

	got := map[string]NodeVerdict{}
	for _, v := range pr.Verdicts {
		got[v.NodeID] = v
	}

	if v := got["node-allow"]; v.Status != VerdictAllow {
		t.Errorf("node-allow verdict = %+v, want VerdictAllow (the daemon's answer must win over the cache, which said nothing is allowed)", v)
	}
	if v := got["node-deny"]; v.Status != VerdictDeny || v.DecidingRule != "deny-from-daemon" {
		t.Errorf("node-deny verdict = %+v, want VerdictDeny with DecidingRule %q (the daemon's rule text, never the cache's)", v, "deny-from-daemon")
	}
	if v := got["node-unsup"]; v.Status != VerdictUnsupported {
		t.Errorf("node-unsup verdict = %+v, want VerdictUnsupported (the daemon answered it)", v)
	}
	if v := got["node-allow"]; v.Status == VerdictUnsupported {
		t.Error("node-allow read as VerdictUnsupported even though the cached vocabulary lists no Templates at all — the cache must never be consulted")
	}

	offline, ok := got["node-offline"]
	if !ok {
		t.Fatalf("PlanResult.Verdicts missing node-offline: %+v", pr.Verdicts)
	}
	if offline.Status != VerdictUnknown || offline.Reason != "offline" {
		t.Errorf("node-offline verdict = %+v, want VerdictUnknown/offline", offline)
	}
	var sawOfflineQuery, sawAllowQuery bool
	for _, entry := range log {
		if entry == "query:node-offline" {
			sawOfflineQuery = true
		}
		if entry == "query:node-allow" {
			sawAllowQuery = true
		}
	}
	if sawOfflineQuery {
		t.Error("Query was called for an offline Node — unknown must come from the Relay's \"could not ask\", never a cache")
	}
	// Armed the other way (CR2, code review cycle 2): the absence above is
	// only meaningful if a CONNECTED Node's Query really is called — this
	// pins the fakeConduit log format the absence check depends on, so a
	// future rename of that format cannot let the absence check pass by
	// silently matching nothing.
	if !sawAllowQuery {
		t.Error("the shared conduit log contains no \"query:node-allow\" entry — the absence check above for node-offline is only meaningful if a connected Node's Query is actually logged this way")
	}

	// SR5 (security review, cycle 2): a query that itself failed must
	// conclude unknown/query_failed, never fall back to reading either
	// cache — that fallback is exactly the fabricated-allow shape invariant
	// 12 forbids. Checked here, alongside the zero-Gets assertions above
	// rather than instead of them, so this specific branch is pinned to
	// "never consulted the cache" and not just to "unknown".
	queryFailed, ok := got["node-queryfail"]
	if !ok {
		t.Fatalf("PlanResult.Verdicts missing node-queryfail: %+v", pr.Verdicts)
	}
	if queryFailed.Status != VerdictUnknown || queryFailed.Reason != "query_failed" {
		t.Errorf("node-queryfail verdict = %+v, want VerdictUnknown/query_failed", queryFailed)
	}
	if len(pv.gets) != 0 || len(nv.gets) != 0 {
		t.Errorf("policyView.gets = %v, templateVocabulary.gets = %v after a failed Query — a query failure must conclude unknown, never fall back to consulting a cache", pv.gets, nv.gets)
	}

	// ARMED CONTROL (BLOCKING 2, plan review cycle 1): the zero-Gets
	// assertions above are vacuous on a Service where WithPolicyView/
	// WithTemplateVocabulary never actually landed (a typo in the bespoke
	// constructor, a spy that silently fails to satisfy the seam). Proving
	// the same Service's DescribeNode DOES reach both spies is what confirms
	// the absence measured above is real. Ordered after the zero-call
	// assertions so their counters are read clean.
	if _, err := svc.DescribeNode(context.Background(), Principal{Account: "alice"}, "node-allow"); err != nil {
		t.Fatalf("DescribeNode(node-allow): %v", err)
	}
	if want := []string{"node-allow"}; !reflect.DeepEqual(pv.gets, want) {
		t.Errorf("after DescribeNode, policyView.gets = %v, want %v — without this, the zero-Gets assertions above would pass on a Service the caches were never wired to", pv.gets, want)
	}
	if want := []string{"node-allow"}; !reflect.DeepEqual(nv.gets, want) {
		t.Errorf("after DescribeNode, templateVocabulary.gets = %v, want %v — without this, the zero-Gets assertions above would pass on a Service the caches were never wired to", nv.gets, want)
	}
}

// policyviewImportPath and nodevocabImportPath are the fully-qualified
// import paths TestCachedPolicyAndVocabularyReachOnlyTheDisplayReadLane
// treats as "the cached Policy view" and "the cached Template vocabulary",
// resolved by import path rather than by an assumed local package name.
const (
	policyviewImportPath = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	nodevocabImportPath  = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"
)

// TestCachedPolicyAndVocabularyReachOnlyTheDisplayReadLane proves PF-7's
// structural half with four allowlists over this package's own non-test
// source, mirroring execution_test.go's TestCapabilityImportsOnlyRegistryAndJobs
// and mcp/no_dispatch_test.go's parse-and-inspect style:
//
//   - the FIELDS: an *ast.Ident named policyView or nodeVocab may appear
//     only in service.go (declaration, WithPolicyView/WithTemplateVocabulary)
//     and readlane_registry.go (DescribeNode/ListOperations — the display
//     read lane itself).
//   - the SEAM TYPES: an *ast.Ident named PolicyViewSource or
//     TemplateVocabularySource may appear only in seams.go (declaration) and
//     service.go (field type, Option parameter). This closes the rename
//     hole: a new field of this type elsewhere would evade the field-name
//     allowlist above.
//   - the IMPORTS: internal/policyview and internal/nodevocab may be
//     imported only by seams.go and readlane_registry.go, so no other file
//     can reach the cache types directly.
//   - the READ-LANE METHODS: an *ast.Ident named DescribeNode or
//     ListOperations may appear only in readlane_registry.go. This closes
//     the INDIRECT route the first three allowlists miss — a shortcut in
//     plan.go calling s.DescribeNode(...) and reading NodeDetail.Policy
//     touches neither a field name, a seam type, nor an import.
//
// Residual, deliberately not papered over: readlane_registry.go is
// allowlisted wholesale on all four lists, so a verdict shortcut physically
// placed in that file would pass every one of them. That is accepted
// because it is the display read lane's own file — a shortcut there would be
// reviewed as a read-lane change — and TestPreflightNeverConsultsCachedPolicyOrVocabulary's
// behavioural assertions catch it regardless of which file it lives in.
//
// A second residual, understated in the previous revision (security review
// cycle 2, SR4): service.go is ALSO allowlisted wholesale on the field list,
// because it is where policyView/nodeVocab are declared and wired by
// WithPolicyView/WithTemplateVocabulary. A method placed in service.go
// itself — e.g. `func (s *Service) cachedVerdict(...)` reading
// `s.policyView.Get(...)` — passes the field, type, import AND method
// allowlists: it needs no new import (Go resolves s.policyView's method
// through type inference on an existing field) and calls neither
// DescribeNode nor ListOperations. That is the same acceptance as
// readlane_registry.go above, for the same reason: it is the seam's own
// declaring file, and a change there would be reviewed as touching the seam
// directly.
//
// A third, larger residual (also SR4): these four allowlists pin the two
// cached SOURCES THAT EXIST TODAY, by name — the fields policyView/
// nodeVocab, the types PolicyViewSource/TemplateVocabularySource, the two
// import paths, and the two read-lane methods. They do NOT prove the
// general property "no cached verdict source exists anywhere in this
// package". A new, differently-named, primitive-typed seam — e.g. a
// `type VerdictCache interface { Lookup(node, op string) (bool, string) }`
// declared in a new file and wired from the composition root by an adapter
// wrapping policyview — would trip none of the four lists here: it
// introduces no identifier any allowlist recognises and no import of
// policyview/nodevocab into this package at all. Such a seam would still
// need to be WIRED into plan.go to matter, and
// TestPreflightNeverConsultsCachedPolicyOrVocabulary's behavioural half
// would still catch it operating — the residual is specific to THIS
// structural test's reach, not to PF-7 as a whole.
//
// Every allowlist must ALSO be proven reachable (a walk that matches nothing
// proves nothing, the same failure mode no_dispatch and handlerFuncName were
// bitten by): each of the four counts at least one hit before the test
// trusts its own zero-violations result.
func TestCachedPolicyAndVocabularyReachOnlyTheDisplayReadLane(t *testing.T) {
	// template.go joined the field and import lists with #626 (ADR-0042,
	// PF-7 as amended 2026-10-02): it reads the cached Template vocabulary to
	// decide a Template dispatch's fan-out and risk class, which is the one
	// non-display use PF-7 now admits. It produces no verdict — every allow
	// and deny is still the daemon's, which
	// TestPreflightTemplateExclusionNeverDecidesAVerdict proves behaviourally
	// — and it is the only file admitted; plan.go and service.go reach it
	// only through resolveAction. It is NOT on the type list: it never names
	// a seam type, so a new cached field there would still trip this test.
	fieldAllow := map[string]bool{"service.go": true, "readlane_registry.go": true, "template.go": true}
	typeAllow := map[string]bool{"seams.go": true, "service.go": true}
	importAllow := map[string]bool{"seams.go": true, "readlane_registry.go": true, "template.go": true}
	methodAllow := map[string]bool{"readlane_registry.go": true}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%s): %v", dir, err)
	}

	seen := map[string]int{"field": 0, "type": 0, "import": 0, "method": 0}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		// FULL mode, not ImportsOnly: this walk needs function bodies to see
		// field/method/type references, not just the import block.
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", path, err)
		}

		for _, imp := range file.Imports {
			importPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", imp.Path.Value, name, err)
			}
			if importPath != policyviewImportPath && importPath != nodevocabImportPath {
				continue
			}
			seen["import"]++
			if !importAllow[name] {
				t.Errorf("%s:%d imports %q, which only the display read lane (seams.go, readlane_registry.go) may import — PF-7 (invariant 12): a new consumer of a cached Policy view or Template vocabulary must be reviewed before it can reach outside the read lane",
					name, fset.Position(imp.Pos()).Line, importPath)
			}
		}

		ast.Inspect(file, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			line := fset.Position(id.Pos()).Line
			switch id.Name {
			case "policyView", "nodeVocab":
				seen["field"]++
				if !fieldAllow[name] {
					t.Errorf("%s:%d references %q outside service.go/readlane_registry.go — PF-7: only the display read lane may touch a cached Policy-view or Template-vocabulary field",
						name, line, id.Name)
				}
			case "PolicyViewSource", "TemplateVocabularySource":
				seen["type"]++
				if !typeAllow[name] {
					t.Errorf("%s:%d references %q outside seams.go/service.go — a new field of this type elsewhere would evade the field allowlist above; PF-7 needs it named here too",
						name, line, id.Name)
				}
			case "DescribeNode", "ListOperations":
				seen["method"]++
				if !methodAllow[name] {
					t.Errorf("%s:%d references %q outside readlane_registry.go — this is the indirect route into the display read lane's own cached reads; a call to it from outside the lane must be reviewed against PF-7",
						name, line, id.Name)
				}
			}
			return true
		})
	}

	for kind, count := range seen {
		if count == 0 {
			t.Errorf("the %s allowlist matched zero occurrences in this package — the walk itself may be broken, since a guard that matches nothing proves nothing", kind)
		}
	}
}
