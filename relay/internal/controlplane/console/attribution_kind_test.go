package console

// attribution_kind_test.go proves the kind label (00-foundations.md, "Kind
// label"): the word human or machine beside a requester or an approver, read
// ONLY from the record as it was written — the Job row's requester_kind, a
// Decision's DeciderHuman — and never looked up from the Account registry
// (#540; 04-activity.md, "Kind is never read from the registry").

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// kindLabel is exactly what the kind-label component renders for a value.
func kindLabel(kind string) string {
	return `<span class="kind" data-kind="` + kind + `">` + kind + `</span>`
}

// drawnKinds counts kind labels carrying a data-kind — the lane key's
// explanatory words carry none, so they are not counted.
var drawnKindPattern = regexp.MustCompile(`<span class="kind" data-kind="[^"]*">`)

func drawnKinds(s string) int { return len(drawnKindPattern.FindAllString(s, -1)) }

// section returns the substring of body from the first occurrence of open up
// to the next occurrence of closeTag after it.
func section(t *testing.T, body, open, closeTag string) string {
	t.Helper()
	i := strings.Index(body, open)
	if i < 0 {
		t.Fatalf("no %q in the page", open)
	}
	rest := body[i:]
	j := strings.Index(rest, closeTag)
	if j < 0 {
		t.Fatalf("no %q after %q", closeTag, open)
	}
	return rest[:j]
}

// --- Job detail: the requester ---------------------------------------------

func TestJob_RequesterKindIsTheKindTheJobRecorded(t *testing.T) {
	for _, kind := range []string{"human", "machine"} {
		t.Run(kind, func(t *testing.T) {
			tasks := []capability.TaskRow{mutateTask("node-a", jobs.OutcomeSuccess, "ok")}
			sum := oneJob(tasks, jobs.RiskClassMutate)
			sum.RequesterKind = kind
			body := jobBody(t, jobDeps(&fakeQueries{jobs: []capability.JobSummary{sum}, tasks: tasks}), jobPath(""))

			head := section(t, body, `<section class="jobhead">`, `</section>`)
			if !strings.Contains(head, `>gleipnir</span> `+kindLabel(kind)) {
				t.Errorf("the requester's chip is not followed by the recorded kind %q:\n%s", kind, head)
			}
			if n := drawnKinds(head); n != 1 {
				t.Errorf("the header draws %d kind labels, want exactly 1", n)
			}
		})
	}
}

// TestJob_NoRecordedKindDrawsNoKind: a Job created before the Job row carried
// its requester's kind shows no label — even though the Account registry,
// wired here, knows a kind for that very Account. Reading it would report the
// Account's kind TODAY, which is the retroactive relabelling #540 refused.
func TestJob_NoRecordedKindDrawsNoKind(t *testing.T) {
	tasks := []capability.TaskRow{mutateTask("node-a", jobs.OutcomeSuccess, "ok")}
	sum := oneJob(tasks, jobs.RiskClassMutate) // RequesterKind left empty
	d := jobDeps(&fakeQueries{jobs: []capability.JobSummary{sum}, tasks: tasks})
	d.Accounts = &fakeAccounts{accounts: []accounts.Account{{
		ID: "acct-1", Name: "gleipnir", Kind: accounts.KindMachine, Role: accounts.RoleOperator, Enabled: true,
	}}}
	body := jobBody(t, d, jobPath(""))

	if n := drawnKinds(body); n != 0 {
		t.Errorf("a Job that recorded no kind drew %d kind labels — nothing may be inferred in its place", n)
	}
}

// TestJob_KindFollowsTheRecordNotTheRegistry: an Account converted after the
// fact must not relabel the Jobs it asked for.
func TestJob_KindFollowsTheRecordNotTheRegistry(t *testing.T) {
	tasks := []capability.TaskRow{mutateTask("node-a", jobs.OutcomeSuccess, "ok")}
	sum := oneJob(tasks, jobs.RiskClassMutate)
	sum.RequesterKind = "human"
	d := jobDeps(&fakeQueries{jobs: []capability.JobSummary{sum}, tasks: tasks})
	d.Accounts = &fakeAccounts{accounts: []accounts.Account{{
		ID: "acct-1", Name: "gleipnir", Kind: accounts.KindMachine, Role: accounts.RoleOperator, Enabled: true,
	}}}
	body := jobBody(t, d, jobPath(""))

	if !strings.Contains(body, kindLabel("human")) {
		t.Error("the kind the Job recorded is not shown")
	}
	if strings.Contains(body, kindLabel("machine")) {
		t.Error("the registry's CURRENT kind reached the page — history was relabelled")
	}
}

// TestJob_FallbackPrincipalCarriesNoKind: when the Job row names no requester,
// the chip falls back to the dispatch record's principal, which carries no
// kind. A kind must never sit beside a name the Job row did not supply.
func TestJob_FallbackPrincipalCarriesNoKind(t *testing.T) {
	tasks := []capability.TaskRow{mutateTask("node-a", jobs.OutcomeSuccess, "ok")}
	sum := oneJob(tasks, jobs.RiskClassMutate)
	sum.Requester, sum.RequesterAccountID, sum.RequesterKind = "", "", "machine"
	q := &fakeQueries{
		jobs:  []capability.JobSummary{sum},
		tasks: tasks,
		rows:  []capability.AuditRow{{Kind: audit.KindDispatch, JobID: testJobID, Principal: "legacy-bot:operator"}},
	}
	body := jobBody(t, jobDeps(q), jobPath(""))

	if !strings.Contains(body, "legacy-bot:operator") {
		t.Fatal("the fixture did not fall back to the dispatch record's principal")
	}
	if n := drawnKinds(body); n != 0 {
		t.Errorf("a fallback principal drew %d kind labels, want none", n)
	}
}

// --- Job detail: each approver ---------------------

// twoDeciders is one human and one machine approving Decision, as recorded.
func twoDeciders() []approval.Decision {
	return []approval.Decision{
		{Account: "mike", AccountID: "acct-2", Approve: true, Channel: approval.ChannelOutOfBand, DeciderHuman: true, At: testNow},
		{Account: "relay-bot", AccountID: "acct-9", Approve: true, Channel: approval.ChannelInBand, DeciderHuman: false, OnBehalfOf: "carol", At: testNow},
	}
}

func TestJob_EachApproverCarriesTheKindItsDecisionRecorded(t *testing.T) {
	tasks := []capability.TaskRow{mutateTask("node-a", jobs.OutcomeSuccess, "ok")}
	q := &fakeQueries{
		jobs:  []capability.JobSummary{oneJob(tasks, jobs.RiskClassMutate)},
		tasks: tasks,
		rows:  []capability.AuditRow{{Kind: audit.KindDispatch, JobID: testJobID, ApprovalID: "ap-1"}},
	}
	d := jobDeps(q)
	d.Approvals = &fakeApprovals{pending: []approval.Request{{
		ID: "ap-1", State: approval.StateApproved, RequestedBy: "gleipnir", RequestedByID: "acct-1",
		Require: approval.Requirement{Count: 2}, Decisions: twoDeciders(),
	}}}
	body := jobBody(t, d, jobPath(""))
	approvalSection := section(t, body, `<section class="jobapproval"`, `</section>`)

	if !strings.Contains(approvalSection, `>mike</span> `+kindLabel("human")) {
		t.Errorf("a human decider is not labelled human:\n%s", approvalSection)
	}
	if !strings.Contains(approvalSection, `>relay-bot</span> `+kindLabel("machine")) {
		t.Errorf("a machine decider is not labelled machine:\n%s", approvalSection)
	}
	// The asserted human the machine answered for is an asserted chip and
	// nothing more: a kind qualifies the VERIFIED lane only.
	if strings.Contains(approvalSection, `>carol</span> <span class="kind"`) {
		t.Error("a kind label was drawn beside the asserted on-behalf-of identity")
	}
	// The retired treatment — a grey word for a machine and nothing for a
	// human — must be gone, or a human decider is the unmarked case again.
	if strings.Contains(body, `<span class="dim">machine</span>`) {
		t.Error("the retired grey machine word is still rendered")
	}
}

// --- Activity ---------------------------------------------------------------

func TestActivity_DispatchRowCarriesTheKindTheJobRecorded(t *testing.T) {
	for _, tc := range []struct {
		recorded string
		want     int
	}{
		{"human", 1},
		{"machine", 1},
		{"", 0},
	} {
		name := tc.recorded
		if name == "" {
			name = "none recorded"
		}
		t.Run(name, func(t *testing.T) {
			q := &fakeQueries{jobs: []capability.JobSummary{{
				JobID: "job-1", CreatedAt: testNow, OperationName: "service.restart",
				RiskClass: jobs.RiskClassMutate, Requester: "gleipnir", RequesterAccountID: "acct-1",
				RequesterKind: tc.recorded, Total: 1,
				// Every Task resolved, so Complete: the zero State is Running
				// (iota 0), and a running Job would also draw in Running now.
				State:  jobs.JobStateComplete,
				Counts: map[jobs.Outcome]int{jobs.OutcomeSuccess: 1},
			}}}
			body := get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin), "/console/activity?kind=dispatch").Body.String()

			if n := drawnKinds(body); n != tc.want {
				t.Errorf("the dispatch row drew %d kind labels, want %d", n, tc.want)
			}
			if tc.recorded != "" && !strings.Contains(body, `>gleipnir</span> `+kindLabel(tc.recorded)) {
				t.Errorf("the requester's chip is not followed by the recorded kind %q", tc.recorded)
			}
		})
	}
}

// TestActivity_NonDispatchRowsCarryNoKind: an audit record carries no kind, so
// a trail row shows none.
func TestActivity_NonDispatchRowsCarryNoKind(t *testing.T) {
	q := &fakeQueries{rows: []capability.AuditRow{{
		Kind: audit.KindApprovalDecided, Timestamp: testNow, Principal: "mike:operator",
		Verified:   capability.VerifiedIdentity{AccountID: "acct-2", AccountName: "mike"},
		ApprovalID: "ap-1",
	}}}
	body := get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin), "/console/activity").Body.String()

	if !strings.Contains(body, `data-kind="approval"`) {
		t.Fatal("the fixture's approval row did not render")
	}
	if n := drawnKinds(body); n != 0 {
		t.Errorf("a trail row drew %d kind labels; the audit record carries no kind", n)
	}
}

// --- The one treatment ------------------------------------------------------

// TestConsole_KindLabelIsNotAChip: the kind label must be legible beside a
// filled chip and a dashed chip without being mistaken for either, so the one
// rule that draws it may set neither a border nor a background, and nothing
// may style it as a chip.
func TestConsole_KindLabelIsNotAChip(t *testing.T) {
	css, err := os.ReadFile("assets/console.css")
	if err != nil {
		t.Fatal(err)
	}
	rule := regexp.MustCompile(`(?m)^\.kind \{([^}]*)\}`).FindSubmatch(css)
	if rule == nil {
		t.Fatal("the stylesheet has no .kind rule")
	}
	for _, banned := range []string{"border", "background", "border-radius"} {
		if strings.Contains(string(rule[1]), banned) {
			t.Errorf(".kind sets %s — that is the trust lane's channel, and a kind drawn with it reads as an identity", banned)
		}
	}
	if !strings.Contains(string(rule[1]), "text-transform: uppercase") {
		t.Error(".kind is not set apart from a name by case — the only non-colour channel it has")
	}
	if regexp.MustCompile(`\.chip[^{]*\.kind|\.kind[^{]*\.chip`).Match(css) {
		t.Error("a rule styles the kind label as a chip")
	}
}

// registryKindFiles are the only non-test files in this package allowed to
// hold the Account registry seam or read an Account's registry kind: the
// Accounts screen and its write routes, whose subject IS the Account as it is
// now (00-foundations.md, "Kind label"). The confirmation pages are Accounts
// screens too: they hold the seam only to name their target, and never read
// `.Kind` (TestAccountsConfirm_NoCallerRoleComparisonLivesInTheConfirmationPages
// pins that).
var registryKindFiles = map[string]bool{
	"accounts.go":         true,
	"accounts_write.go":   true,
	"accounts_confirm.go": true,
}

// TestConsole_RegistryKindIsReadOnlyByTheAccountsScreens is the kind rule made
// structural, BY TYPE rather than by spelling. It type-checks the whole
// package (every non-test file) and fails if any file outside
// registryKindFiles
//
//   - evaluates an expression whose type is the AccountReader seam — which
//     covers d.Accounts, a helper parameter of that type, and every method
//     call made on one, whatever the variable is called; or
//   - reads the Kind field of an accounts.Account, the registry's CURRENT kind.
//
// What it does NOT prevent: a file on the allowlist exporting a helper that
// hands a current kind back as a plain string, which another screen could
// then call. That shape passes this test and is left to review. It also does
// not look at test files, or at any package other than this one.
func TestConsole_RegistryKindIsReadOnlyByTheAccountsScreens(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	pkg, err := conf.Check("console", fset, files, info)
	if err != nil {
		t.Fatalf("type-check the console package: %v", err)
	}
	reader := pkg.Scope().Lookup("AccountReader")
	if reader == nil {
		t.Fatal("no AccountReader type in the package — this guard has lost what it guards")
	}

	fileOf := func(p token.Pos) string { return filepath.Base(fset.Position(p).Filename) }
	sawReader, sawKind := false, false
	for expr, tv := range info.Types {
		if tv.Type == nil || tv.IsType() || !types.Identical(tv.Type, reader.Type()) {
			continue
		}
		sawReader = true
		if f := fileOf(expr.Pos()); !registryKindFiles[f] {
			t.Errorf("%s holds the Account registry seam at %s — a kind shown beside a record is read "+
				"from that record, never from the registry's current kind (#540)", f, fset.Position(expr.Pos()))
		}
	}
	for sel, s := range info.Selections {
		if s.Kind() != types.FieldVal || s.Obj().Name() != "Kind" || s.Obj().Pkg() == nil ||
			!strings.HasSuffix(s.Obj().Pkg().Path(), "/internal/accounts") {
			continue
		}
		sawKind = true
		if f := fileOf(sel.Pos()); !registryKindFiles[f] {
			t.Errorf("%s reads an Account's registry Kind at %s — that is the kind TODAY, which would "+
				"relabel history (#540)", f, fset.Position(sel.Pos()))
		}
	}
	// A guard that matches nothing reports success forever: the Accounts
	// screens really do both, so both must have been seen.
	if !sawReader || !sawKind {
		t.Fatalf("the guard saw the registry seam=%v and a registry Kind read=%v; the Accounts screens do "+
			"both, so the guard is not looking at what it thinks it is", sawReader, sawKind)
	}
}
