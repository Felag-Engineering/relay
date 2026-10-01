package console

// read_audit_test.go is the Console's guard for ADR-0025 decision 1: a
// Console screen that reads the fleet leaves a record of having read it, and
// a screen whose read cannot be recorded is not served.
//
// # Why this file exists at all
//
// The audit trail was dispatch-only until #288, and the Console arrived after
// it. Four screens migrated onto the capability layer's read lane during #441
// and #422/#423/#425 and inherited its auditing for free; the rest kept
// reading FleetReader, PolicyReader and AuditReader directly, which is a door
// with no record on the other side of it. #450 moved the fleet listing and
// node detail through that door and closed it behind them, #542 moved agent
// history's whole-trail read onto QueryAudit, and #680 moved the comparison
// screen — every column it reads is now recorded, one describe_node per
// pinned Node — closing the last data-read exemption in the table below.
//
// The thing that stops this recurring is not the migration, it is this file.
// A Console screen is cheap to add — it is a row in [Routes] and a handler —
// and the cheapest handler reads a seam off Deps. Nothing about writing one
// would tell its author that a read is a thing this system records, and a
// reviewer reading a 200-line screen diff is not reliably going to notice an
// absence.
//
// # What it does
//
// It walks the ROUTE TABLE, which is exported as data for exactly this class
// of question (see [Routes]' doc comment), and requires every route to be
// classified in [consoleReadAudit] — audited, or exempt with a written
// reason. A new route is in neither, so adding one fails this file until its
// author has decided which it is. That decision is then in a test file, in
// review, in words.
//
// For an audited route it does not take the classification's word for it: it
// drives the route through a REAL *capability.Service over a REAL
// *auditsink.Sink and asserts a KindRead record came out the other end,
// attributed to the signed-in Account. The fakes in fakes_test.go cannot
// prove this — fakeQueries does not audit, because nothing that is not the
// production sink should be allowed to claim it did. Building the fixture out
// of an audit.Record literal would be worse still: #463, #517 and #520 were
// each a case of these records being RENDERED wrongly, and all three survived
// tests whose fixture was a literal somebody wrote to match the renderer.
//
// # What it catches, and what it does not
//
// It catches: a new Console route added without a decision about its read
// auditing; an audited route that stops writing a record (a screen migrated
// back onto a raw seam, a lane method that stops recording, a sink wired to a
// no-op); a read record that renders as something other than the tool that
// produced it.
//
// It does not catch: a screen that audits ONE of its reads and not another,
// as long as some record is produced — the assertion is "this route records
// the read it is classified for", not "every byte on this page was recorded";
// a read that happens outside the route table entirely (there is none today —
// every handler is reached through [Routes]); or an exemption somebody adds
// with a reason that is not true. That last one is the honest limit of every
// guard of this shape, no_dispatch_test.go's included: it forces the decision
// into the diff, it cannot make the decision.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// readAuditRule is one route's classification.
type readAuditRule struct {
	// path is the concrete URL to drive. Route.Path carries ServeMux wildcards
	// ("{node_id}"), which are not a URL; this is the same route with the
	// fixture's own ids substituted.
	path string

	// tool is the read-lane tool name this route must record, empty for an
	// exempt route. It is asserted on the RECORD, not merely counted, because
	// "a record was written" and "the right record was written" have come
	// apart before (#463, #517, #520).
	tool string

	// why states, for an exempt route, what it reads and why that read is not
	// on the audited lane. Required: an exemption with no reason is a hole
	// nobody has to argue for.
	why string

	// stream marks a route that never returns on its own — GET
	// /console/events, today. Both sweeps below drive it with driveStream
	// instead of get: driveStream cancels the request's own context the
	// moment the fixture's fakeEvents hands out a Subscription, which is the
	// deterministic equivalent of a client disconnecting right after the
	// handler committed to serving it (#539).
	stream bool
}

// audited reports whether this route must produce a read record.
func (r readAuditRule) audited() bool { return r.tool != "" }

// consoleReadAudit classifies every route in [Routes]. Keyed by
// Route.Pattern(), which is method + path and is what makes two routes on one
// path distinguishable.
//
// EXEMPTIONS ARE NOT PERMANENT — but they are of two kinds, and only one of
// them can be closed.
//
// A READ exemption is a screen that reads fleet or trail data off the lane. It
// names the migration that closes it WHERE ONE IS FILED, and it disappears
// when that migration lands. After #680 there is no such exemption left: the
// comparison screen — the last registry read off the lane — now resolves
// every pinned Node through Queries.DescribeNode, one audited record per id.
// One row below deliberately names no issue number: GET /console/approvals
// is classified by what it CAN read — its trail reads ARE on the audited lane
// and are recorded whenever there is a Request to read for, so there is
// nothing to migrate at all.
//
// A WRITE exemption is a route that is not a read at all: the capability layer
// records it under its own kind, and there is no future in which it becomes an
// audited read — so it names no closing issue, and inventing one would be a
// comment claiming more than is true. The write entries here have always
// worked this way: the cancel and decision rows cite #595 and #453, which are
// the issues that BUILT those routes, and the login/logout rows cite nothing
// at all.
//
// What an exemption of EITHER kind must never become is a place to put a
// screen because auditing it was inconvenient — read the entry above it before
// adding one, and if the reason you are about to write is "it is only a small
// read", that is the argument ADR-0025 was written to reject: `read` means
// "cannot change Node state", not "safe to see".
var consoleReadAudit = map[string]readAuditRule{
	// ── The audited fleet reads (#450) ───────────────────────────────────
	"GET /console/{$}": {
		path: "/console/",
		tool: "list_nodes",
	},
	"GET /console/nodes/{node_id}": {
		path: "/console/nodes/" + auditFixtureNode,
		tool: "describe_node",
	},

	// ── Audited by the trail/Job half of the lane (#441, #422/#423/#425) ──
	"GET /console/jobs/{job_id}": {
		path: "/console/jobs/" + auditFixtureJob,
		tool: "query_jobs",
	},
	"GET /console/activity": {
		path: "/console/activity",
		tool: "query_jobs",
	},
	"GET /console/approvals": {
		path: "/console/approvals",
		// The queue reads the approval seam first and the trail only for a
		// Request it found. With an empty queue it records nothing, which is
		// correct — it read no fleet or trail data — so this route is
		// classified by what it CAN read rather than by this fixture.
		why: "reads ApprovalReader; its trail reads go through the audited " +
			"lane (approvals.go) and are recorded when there is a Request to read for",
	},
	"GET /console/approvals/{approval_id}": {
		path: "/console/approvals/" + auditFixtureApproval,
		tool: "query_audit",
	},
	"GET /console/accounts": {
		path: "/console/accounts",
		// WHAT THIS ROW COVERS, AND WHAT IT DOES NOT. The tool named is the
		// LAST-TOOL-CALL read: the one unconditional QueryAudit the screen
		// makes over agentCallKinds (accounts.go), which is audited by the
		// lane exactly like every other row in this table.
		//
		// It does NOT cover the Account and API-Token reads on the same page.
		// ControlAccountRead and ControlAPITokenRead are authorized and
		// answered and write NOTHING on success (capability/accountadmin.go);
		// only a refusal is recorded. So a reader who sees this entry and
		// concludes "the Account disclosure was recorded" has it wrong — who
		// holds an identity on this control plane can be read off this Relay
		// leaving no trace, and the row that IS written describes a different
		// read.
		//
		// That is not an ADR-0025 defect (decision 1 scopes to
		// non-dispatching read TOOLS; these two are ControlActions), and it is
		// not fixable in this package — a RecordRead here is exactly what this
		// file's own failure message forbids. It is tracked in #659 against
		// internal/capability, where the fix belongs, in front of a human.
		tool: "query_audit",
	},
	"GET /console/access": {
		path: "/console/access",
		tool: "query_audit",
	},

	// ── The comparison screen (#680) ──────────────────────────────────────
	"GET /console/compare": {
		path: "/console/compare?nodes=" + auditFixtureNode,
		tool: "describe_node",
	},

	// ── The live-read seam (#539) ─────────────────────────────────────────
	"GET /console/events": {
		path:   "/console/events?kinds=enrollment,job",
		tool:   "watch_events",
		stream: true,
	},

	// ── Not data reads ───────────────────────────────────────────────────
	"GET /console/assets/{path...}": {
		path: "/console/assets/console.css",
		why:  "static assets — the stylesheet and script the CSP forces out of the layout",
	},
	"GET " + LoginPath:  {path: LoginPath, why: "the sign-in form; reads no fleet or trail data"},
	"POST " + LoginPath: {path: "", why: "sign-in; consoleauth records its own audit event"},
	"POST " + LogoutPath: {
		path: "",
		why:  "sign-out; consoleauth records its own audit event",
	},
	"GET /console/run": {
		path: "",
		why: "the v0.7.0 composer placeholder (#438). It renders no data at all today; " +
			"the screen that replaces it dispatches, and dispatch is audited by Service.Run",
	},
	"POST /console/jobs/{job_id}/cancel": {
		path: "",
		why: "a write, not a read (#595): the capability layer records the cancel as " +
			"job_cancel with its Principal, and a refusal as a refusal",
	},
	"POST /console/approvals/{approval_id}/decision": {
		path: "",
		why: "a write, not a read (#453): the capability layer records the decision as " +
			"approval_decided with its Principal, the plan hash and the channel " +
			"(approval_decide.go), and consoleauth records its own step_up event; a " +
			"refusal is rendered as a refusal and appends nothing",
	},

	// ── The Accounts write half (#655) ───────────────────────────────────
	//
	// Five writes, not reads. Each names ITS OWN capability audit kind and is
	// exact about step-up rather than copying one sentence five times — on
	// revoke and on disable the step_up clause would be FALSE, and the
	// negative assertion is the honest version.
	//
	// The standing honesty sentence the GET /console/accounts entry above
	// models applies to all five: these rows describe the WRITE. That a
	// successful Account READ on this screen records nothing is a different
	// fact, tracked in #659 against internal/capability where the fix belongs.
	//
	// These `why` strings are not trusted prose: the audit kind each one names
	// is asserted against the REAL lane by
	// TestAccountsWrite_EveryWriteRecordsItsOwnAuditKindThroughTheRealLane,
	// and the step-up clauses by
	// TestAccountsWrite_AGrantingActAlsoWritesAStepUpEvent — which the two
	// write exemptions above have no equivalent of.
	"POST /console/accounts/create": {
		path: "",
		why: "a write, not a read (#655): the capability layer records the create as " +
			"account_create with its Principal, and consoleauth records its own step_up " +
			"event — creating an Account of any role or kind is privilege-granting",
	},
	"POST /console/accounts/{account_id}/role": {
		path: "",
		why: "a write, not a read (#655): the capability layer records the change as " +
			"account_role with its Principal and the new role, and consoleauth records a " +
			"step_up event WHEN THE CHANGE RAISES THE ROLE; a demote costs no password " +
			"and writes no step_up (owner decision 2026-09-19)",
	},
	"POST /console/accounts/{account_id}/enabled": {
		path: "",
		why: "a write, not a read (#655): the capability layer records it as account_enable " +
			"or account_disable with its Principal, and consoleauth records a step_up event " +
			"ON THE ENABLE ONLY; a disable costs no password and writes no step_up — it is " +
			"the durable off-switch and can only reduce",
	},
	"POST /console/accounts/{account_id}/tokens": {
		path: "",
		why: "a write, not a read (#655): the capability layer records the mint as " +
			"api_token_mint carrying the token ID and never the Plaintext " +
			"(accountadmin.go), and consoleauth records its own step_up event",
	},
	"POST /console/api-tokens/{token_id}/revoke": {
		path: "",
		why: "a write, not a read (#655): the capability layer records the revocation as " +
			"api_token_revoke with its Principal. NO step-up and therefore NO step_up " +
			"event — revocation only reduces, and an incident instrument that costs a " +
			"password is one people route around (owner decision 2026-09-19)",
	},
}

const (
	auditFixtureNode     = "node-web-1"
	auditFixtureNode2    = "node-web-2"
	auditFixtureJob      = "job-1"
	auditFixtureApproval = "ap-1"
)

// TestConsole_EveryRouteIsClassifiedForReadAuditing is the guard proper: the
// route table and the classification table must name the same routes.
//
// Both directions matter. An unclassified route is a screen whose read
// auditing nobody decided about; a classification with no route is a stale
// entry, and a table full of those is one nobody trusts enough to read.
func TestConsole_EveryRouteIsClassifiedForReadAuditing(t *testing.T) {
	// Execution on, so the route only a flagged Relay mounts is classified
	// too — the guard must not have a blind spot exactly where the execution
	// surface appears.
	routes := Routes(withExecution(renderableDeps(), true))
	if len(routes) == 0 {
		t.Fatal("the route table is empty — this guard is inspecting nothing")
	}

	seen := map[string]bool{}
	for _, r := range routes {
		pattern := r.Pattern()
		seen[pattern] = true
		rule, ok := consoleReadAudit[pattern]
		if !ok {
			t.Errorf("route %q is not classified in consoleReadAudit.\n"+
				"Every Console route must declare whether it is an AUDITED read (ADR-0025: who "+
				"read, which tool, what they aimed it at, when) or is exempt WITH A REASON.\n"+
				"If it reads the fleet or the trail, read through Deps.Queries — the capability "+
				"layer's read lane writes the access record before it answers, and fails closed "+
				"when it cannot. Do not add a RecordRead call inside this package (invariant 10).",
				pattern)
			continue
		}
		if !rule.audited() && strings.TrimSpace(rule.why) == "" {
			t.Errorf("route %q is exempt from read auditing with no stated reason", pattern)
		}
		if rule.audited() && rule.path == "" {
			t.Errorf("route %q is classified audited but has no drivable path to prove it with", pattern)
		}
	}
	for pattern := range consoleReadAudit {
		if !seen[pattern] {
			t.Errorf("consoleReadAudit classifies %q, which is not in the route table — "+
				"a stale entry makes the guard read as covering more than it does", pattern)
		}
	}
}

// TestConsole_AuditedRoutesRecordTheirReadThroughTheRealLane drives every
// audited route through a real capability.Service over a real auditsink.Sink
// and asserts the record that came out.
//
// The whole chain is production code: the handler, the read lane, the sink's
// projection onto audit.Record, and the attribution lanes. The only fixture is
// the repository the sink appends into and the registry the lane reads.
func TestConsole_AuditedRoutesRecordTheirReadThroughTheRealLane(t *testing.T) {
	for pattern, rule := range consoleReadAudit {
		if !rule.audited() {
			continue
		}
		t.Run(pattern, func(t *testing.T) {
			trail := &recordingTrail{}
			d := realLaneDeps(trail)

			var rec *httptest.ResponseRecorder
			if rule.stream {
				rec = driveStream(t, d, rule.path)
			} else {
				rec = get(t, newTestHandler(d, accounts.RoleAdmin), rule.path)
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200 — an audited route must still render", rule.path, rec.Code)
			}

			reads := trail.ofKind(audit.KindRead)
			if len(reads) == 0 {
				t.Fatalf("GET %s wrote no %s record. The screen read this Relay's fleet or trail "+
					"and left nothing behind (ADR-0025 decision 1).", rule.path, audit.KindRead)
			}

			var got *audit.Record
			for i := range reads {
				if reads[i].OperationName == rule.tool {
					got = &reads[i]
					break
				}
			}
			if got == nil {
				var names []string
				for _, r := range reads {
					names = append(names, r.OperationName)
				}
				t.Fatalf("GET %s recorded %v, want a record for %q", rule.path, names, rule.tool)
			}

			// Attributed to the SIGNED-IN HUMAN, in the verified lane — not to
			// the Relay, not to a service identity, and not only as a display
			// string. The Account ID is what a later query joins on.
			if got.Attribution.Verified.AccountID != testAccountID(accounts.RoleAdmin) {
				t.Errorf("read record's verified AccountID = %q, want %q — a Console read must be "+
					"attributed to the human who was signed in",
					got.Attribution.Verified.AccountID, testAccountID(accounts.RoleAdmin))
			}
			if got.Attribution.Verified.AccountName != testAccountName(accounts.RoleAdmin) {
				t.Errorf("read record's verified AccountName = %q, want %q",
					got.Attribution.Verified.AccountName, testAccountName(accounts.RoleAdmin))
			}

			// METADATA ONLY (ADR-0025 decision 2). Asserted on the record the
			// production sink actually built, which is the only place this can
			// be asserted honestly — capability.AuditSink.RecordRead has no
			// result parameter to pass, so there is no way to write one from
			// the lane, and this is the check that the sink did not add one
			// from somewhere else.
			if len(got.Stdout) != 0 || len(got.Stderr) != 0 || got.Truncated {
				t.Errorf("read record carries output (stdout %d bytes, stderr %d bytes, truncated %v) — "+
					"a read record records WHAT WAS READ and never WHAT CAME BACK (ADR-0025)",
					len(got.Stdout), len(got.Stderr), got.Truncated)
			}
		})
	}
}

// TestConsole_NodeDetailAimsItsRecordAtTheNode is the "what it was aimed at"
// half of ADR-0025's record, which the sweep above cannot check generically:
// a node-scoped read must carry the Node id, or the trail can say a Node was
// read and not which one.
func TestConsole_NodeDetailAimsItsRecordAtTheNode(t *testing.T) {
	trail := &recordingTrail{}
	d := realLaneDeps(trail)

	get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/"+auditFixtureNode)

	reads := trail.ofKind(audit.KindRead)
	if len(reads) != 1 {
		t.Fatalf("node detail wrote %d read records, want exactly 1", len(reads))
	}
	if reads[0].NodeID != auditFixtureNode {
		t.Errorf("read record's NodeID = %q, want %q", reads[0].NodeID, auditFixtureNode)
	}
}

// TestConsole_ProbingForAMissingNodeIsStillRecorded is why the lane records
// BEFORE it looks: enumeration by guessing ids is exactly what an audited read
// surface exists to make visible, and a trail that recorded only the guesses
// that found something would record only the successful half of a scan.
func TestConsole_ProbingForAMissingNodeIsStillRecorded(t *testing.T) {
	trail := &recordingTrail{}
	d := realLaneDeps(trail)

	rec := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/node-does-not-exist")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET a missing Node = %d, want 404", rec.Code)
	}

	reads := trail.ofKind(audit.KindRead)
	if len(reads) != 1 || reads[0].NodeID != "node-does-not-exist" {
		t.Fatalf("a probe for a Node that does not exist left %d records (%+v); "+
			"want one, aimed at the id that was probed for", len(reads), reads)
	}
}

// TestCompare_RecordsOneReadPerPinnedNode is the comparison screen's own
// proof (#680): pinning two Nodes writes exactly two describe_node records,
// each aimed at one pinned id, and ZERO list_nodes records — the "never
// enumerates the fleet" guard (node_test.go's
// TestCompare_ResolvesOnlyThePinnedNodesAndNeverEnumeratesTheFleet), now
// expressed on the trail rather than on a fake's call count.
func TestCompare_RecordsOneReadPerPinnedNode(t *testing.T) {
	trail := &recordingTrail{}
	d := realLaneDeps(trail)

	rec := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/compare?nodes="+auditFixtureNode+","+auditFixtureNode2)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /console/compare = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	reads := trail.ofKind(audit.KindRead)
	var described []string
	for _, r := range reads {
		switch r.OperationName {
		case "describe_node":
			described = append(described, r.NodeID)
		case "list_nodes":
			t.Error("the comparison screen wrote a list_nodes record — it must never enumerate the fleet")
		}
	}
	want := map[string]bool{auditFixtureNode: true, auditFixtureNode2: true}
	if len(described) != 2 {
		t.Fatalf("describe_node records = %v, want exactly 2", described)
	}
	for _, id := range described {
		if !want[id] {
			t.Errorf("describe_node recorded %q, which was not pinned", id)
		}
	}
}

// TestConsole_AnUnauditableReadRefusesTheScreen is decision 4, demonstrated
// rather than asserted: with the trail refusing writes, every audited route
// must refuse to render.
//
// ONE RULE, NO PER-SCREEN EXCEPTION. The four screens that migrated during
// #441 inherited this from the lane; #450's two inherit the same thing from
// the same place, and this test is what makes "everywhere" checkable rather
// than a claim in a comment.
func TestConsole_AnUnauditableReadRefusesTheScreen(t *testing.T) {
	for pattern, rule := range consoleReadAudit {
		if !rule.audited() {
			continue
		}
		t.Run(pattern, func(t *testing.T) {
			trail := &recordingTrail{appendErr: errTrailDown}
			d := realLaneDeps(trail)

			var rec *httptest.ResponseRecorder
			if rule.stream {
				rec = driveStream(t, d, rule.path)
			} else {
				rec = get(t, newTestHandler(d, accounts.RoleAdmin), rule.path)
			}
			if rec.Code == http.StatusOK {
				t.Fatalf("GET %s = 200 with an unwritable audit trail. A read this Relay cannot "+
					"record must be REFUSED, not served unrecorded (ADR-0025 decision 4).", rule.path)
			}
			body := rec.Body.String()
			// Legible, not a blank 500: the operator has to be able to tell
			// this from "the registry is down", because the two send them to
			// different components and only one of them means nothing leaked.
			for _, want := range []string{"audit trail", "refused"} {
				if !strings.Contains(body, want) {
					t.Errorf("the refusal page does not say %q — it reads as a generic failure:\n%s",
						want, body)
				}
			}
		})
	}
}

// TestConsole_ActivityNamesAConsoleRead is the third acceptance line: a
// Console read is counted beside an AI-agent's, not in a lane of its own — it
// shows in Activity's read kind.
//
// The record is REAL — produced by driving the fleet listing through the real
// lane and sink — and is then projected onto the read lane's row type and fed
// to Activity. That is the join this test exists to prove: a Console read is
// a KindRead record, and the name Activity renders is the tool that wrote it.
// Reads made from a Console session are hidden by default (callfeed.go); the
// test authenticates with a Bearer token, so the record is not one, and asks
// for console=show to pin the display rule rather than lean on that.
//
// This is also the check #463/#517/#520 each wanted and did not have. All
// three were records rendering wrongly, and all three survived a fixture built
// as an audit.Record literal — a literal agrees with the renderer by
// construction, because the same person wrote both.
func TestConsole_ActivityNamesAConsoleRead(t *testing.T) {
	trail := &recordingTrail{}
	get(t, newTestHandler(realLaneDeps(trail), accounts.RoleAdmin), "/console/")

	reads := trail.ofKind(audit.KindRead)
	if len(reads) != 1 {
		t.Fatalf("the fleet listing wrote %d read records, want exactly 1", len(reads))
	}
	real := reads[0]

	// The vocabulary check, on the real record: Activity's read kind selects
	// on Kind, and the name comes through readTargetName.
	if real.Kind != audit.KindRead {
		t.Fatalf("record Kind = %q, want %q — Activity's read kind selects on Kind",
			real.Kind, audit.KindRead)
	}
	if got := readTargetOf(factsOfRecord(real)); got != "list_nodes" {
		t.Errorf("the record renders as %q, want %q — a read record that names itself wrongly "+
			"is what #463/#517/#520 each were", got, "list_nodes")
	}

	// And through the screen. The row is the real record, projected the way
	// the store's query lane projects it.
	d := renderableDeps()
	d.Queries = &fakeQueries{rows: []capability.AuditRow{rowOfRecord(real)}}
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/activity?kind=read&console=show").Body.String()

	// The layout prints the signed-in account on every page, so attribution is
	// checked inside the row, not against the whole body.
	content := contentOf(body)
	at := strings.Index(content, "enumerated list_nodes")
	if at < 0 {
		t.Fatalf("Activity does not name the Console's own read:\n%s", content)
	}
	start := strings.LastIndex(content[:at], `<article class="ev"`)
	end := strings.Index(content[at:], "</article>")
	if start < 0 || end < 0 {
		t.Fatalf("the read is not rendered as a feed row:\n%s", content)
	}
	if row := content[start : at+end]; !strings.Contains(row, testAccountName(accounts.RoleAdmin)) {
		t.Errorf("Activity does not attribute the Console's read to the human who made it:\n%s", row)
	}
}

// rowOfRecord projects a real audit.Record onto the read lane's row type, the
// way internal/store/auditquery.go's SELECT does — minus Stdout/Stderr/
// Truncated, which capability.AuditRow has no field for at all (#441).
func rowOfRecord(r audit.Record) capability.AuditRow {
	return capability.AuditRow{
		ID:        r.ID,
		Timestamp: r.Timestamp,
		Kind:      r.Kind,
		Principal: r.Principal,
		Verified: capability.VerifiedIdentity{
			AccountID:   r.Attribution.Verified.AccountID,
			AccountName: r.Attribution.Verified.AccountName,
			Role:        r.Attribution.Verified.Role,
			TokenID:     r.Attribution.Verified.TokenID,
			Method:      r.Attribution.Verified.Method,
			Source:      r.Attribution.Verified.Source,
		},
		Asserted:      capability.Assertions{OnBehalfOf: r.Attribution.Asserted.OnBehalfOf},
		Selector:      r.Selector,
		JobID:         r.JobID,
		NodeID:        r.NodeID,
		ActionKind:    r.ActionKind,
		OperationName: r.OperationName,
		Args:          r.Args,
		RawExecArgv:   r.RawExecArgv,
		Outcome:       r.Outcome,
		Reason:        r.Reason,
		ApprovalID:    r.ApprovalID,
		GrantID:       r.GrantID,

		ApprovalAnswer:  capability.ApprovalAnswer(r.ApprovalAnswer),
		DecisionChannel: r.DecisionChannel,
		PlanHash:        r.PlanHash,
	}
}

// realLaneDeps is a Console wired to a REAL *capability.Service over a REAL
// *auditsink.Sink appending into trail.
//
// Everything on the audited path is production code. The registry is
// registry.NewInMemory, which is the same implementation a dev fleet runs
// against; the trail is the only fixture, and it is a fixture because the
// production one is SQLite and this package may not import the store.
func realLaneDeps(trail *recordingTrail) Deps {
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{
		NodeID:            auditFixtureNode,
		PolicyFingerprint: "sha256:aaaa",
	}.WithNodeLabels(map[string]string{"role": "web"})); err != nil {
		panic("read_audit_test: seed registry: " + err.Error())
	}
	// A second Node, for TestCompare_RecordsOneReadPerPinnedNode's two-pin
	// case — this file's only test that needs more than one.
	if _, err := reg.Upsert(registry.Report{
		NodeID:            auditFixtureNode2,
		PolicyFingerprint: "sha256:bbbb",
	}.WithNodeLabels(map[string]string{"role": "web"})); err != nil {
		panic("read_audit_test: seed registry: " + err.Error())
	}

	sink := auditsink.New(trail, auditsink.WithClock(func() time.Time { return testNow }))
	// WithPolicyView gives the comparison screen and the Node-detail Policy
	// panel something to render (#680) — both now read it through
	// DescribeNode, the same audited call this fixture proves recorded.
	policy := policyview.New()
	policy.Set(auditFixtureNode, policyview.Snapshot{AllowedOperations: []string{"system.facts"}})
	svc := capability.New(reg,
		capability.WithAuditSink(sink),
		capability.WithQueries(emptyAuditQuery{}, emptyJobQuery{}),
		capability.WithPolicyView(policy),
	)

	d := renderableDeps()
	d.Queries = svc
	d.Approvals = &fakeApprovals{resolved: []approval.Request{{ID: auditFixtureApproval}}}
	// Without this, GET /console/events 503s before RecordEventSubscription
	// is ever reached — d.Events == nil is checked first — which would make
	// this file's sweeps prove nothing about the one route this is the
	// fixture change for. newFakeEvents wraps a real *events.Bus, exactly as
	// every other events.go test uses it; Recent() through it writes no
	// record, so its presence does not change what any OTHER route records.
	d.Events = newFakeEvents()
	return d
}

// driveStream drives a streaming route (GET /console/events) through the
// real handler without hanging the suite and without sleeping.
//
// The mechanism is a deterministic cancel, not a timeout race: fakeEvents'
// onSubscribe hook is wired to the request's own cancel func, so the moment
// handleEvents calls d.Events.Subscribe, this test cancels the very context
// that call is running under. The pump loop's first select then takes the
// r.Context().Done() branch and returns — no sleep, no goroutine, and the
// handler runs its ENTIRE real path first: parse, principal, role, limiter,
// the read record, Subscribe, then 200 and headers flushed.
//
// getBounded's plain timeout (dayone_test.go) is deliberately not what this
// uses: a route that ever stopped calling Subscribe would make a
// timeout-based drive merely SLOW, not fail, and this file needs to
// distinguish "recorded and streamed" from "hung" on every run, not only
// when someone is watching the clock. WithTimeout is kept anyway, as a
// backstop: a handler that neither subscribes nor returns cannot hang this
// suite either.
//
// It proves: the route can render 200 while being driven synchronously by
// this sweep, with the read record and the Subscribe call both having
// already happened by the time it returns. It does NOT prove anything about
// frames crossing the stream afterward — the request is cancelled before
// any would be written, which is dayone_test.go's openStream's job, not
// this file's.
func driveStream(t *testing.T, d Deps, path string) *httptest.ResponseRecorder {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), streamTestTimeout)
	defer cancel()

	if fe, ok := d.Events.(*fakeEvents); ok {
		fe.onSubscribe = cancel
	}

	req := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+testCredential)
	rec := httptest.NewRecorder()
	newTestHandler(d, accounts.RoleAdmin).ServeHTTP(rec, req)
	return rec
}

// recordingTrail is an in-memory audit.Repository: it keeps what was appended
// and can be made to refuse.
//
// The by-key reads are unused — the Console reads the trail through the
// capability layer's query lane, never through Repository — so they answer
// from the same slice rather than pretending to index it.
//
// mu guards records: events_audit_test.go's B7 holds one stream open in a
// goroutine while the test's own goroutine drives a second request, and CI
// runs this package under -race — a bare slice would be a real data race,
// not a theoretical one.
type recordingTrail struct {
	mu        sync.Mutex
	records   []audit.Record
	appendErr error
}

const errTrailDown = constErr("the audit trail cannot be written")

func (t *recordingTrail) Append(_ context.Context, r audit.Record) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.appendErr != nil {
		return t.appendErr
	}
	t.records = append(t.records, r)
	return nil
}

// AppendAll mirrors sqliteAudit.AppendAll's all-or-nothing contract: on
// appendErr, nothing in rs is kept, unlike Append above.
func (t *recordingTrail) AppendAll(_ context.Context, rs []audit.Record) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.appendErr != nil {
		return t.appendErr
	}
	t.records = append(t.records, rs...)
	return nil
}

func (t *recordingTrail) List(context.Context) ([]audit.Record, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]audit.Record, len(t.records))
	copy(out, t.records)
	return out, nil
}

func (t *recordingTrail) ByJob(context.Context, string) ([]audit.Record, error) {
	return t.records, nil
}
func (t *recordingTrail) ByNode(context.Context, string) ([]audit.Record, error) {
	return t.records, nil
}
func (t *recordingTrail) ByAccount(context.Context, string) ([]audit.Record, error) {
	return t.records, nil
}
func (t *recordingTrail) ByApproval(context.Context, string) ([]audit.Record, error) {
	return t.records, nil
}
func (t *recordingTrail) ByGrant(context.Context, string) ([]audit.Record, error) {
	return t.records, nil
}
func (t *recordingTrail) ByOnBehalfOf(context.Context, string) ([]audit.Record, error) {
	return t.records, nil
}

// ofKind returns the appended records of one Kind.
func (t *recordingTrail) ofKind(kind string) []audit.Record {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []audit.Record
	for _, r := range t.records {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	return out
}

// emptyAuditQuery and emptyJobQuery satisfy capability.WithQueries with an
// empty trail and no Jobs.
//
// They are here so a REAL Service can be constructed: WithQueries is what the
// trail/Job half of the read lane needs, and New refuses a Service that has
// it without a real AuditSink. Their answers are empty because this file is
// about the RECORD a screen writes, not about the rows it renders — the
// screens' own tests cover those against fakeQueries.
type emptyAuditQuery struct{}

func (emptyAuditQuery) QueryAudit(context.Context, capability.AuditFilter, capability.PageRequest) (capability.AuditPage, error) {
	return capability.AuditPage{}, nil
}

func (emptyAuditQuery) AuditCounts(context.Context, capability.AuditFilter, time.Duration) ([]capability.PrincipalBucket, error) {
	return nil, nil
}

func (emptyAuditQuery) AuditReach(context.Context, capability.AuditFilter) (capability.Reach, error) {
	return capability.Reach{}, nil
}

type emptyJobQuery struct{}

// QueryJobs answers with the one fixture Job, so the Job-detail route renders
// rather than 404ing. It is the only row this file needs: what is being
// asserted is the RECORD the screen wrote, not the rows it drew.
func (emptyJobQuery) QueryJobs(_ context.Context, f capability.JobFilter, _ capability.PageRequest) (capability.JobPage, error) {
	if f.JobID != "" && f.JobID != auditFixtureJob {
		return capability.JobPage{}, nil
	}
	// The fixture Job is Complete, so a running-only read (Running now's)
	// finds nothing — the same answer the real store gives.
	if f.State != nil && *f.State != jobs.JobStateComplete {
		return capability.JobPage{}, nil
	}
	return capability.JobPage{Jobs: []capability.JobSummary{{
		JobID:     auditFixtureJob,
		CreatedAt: testNow,
		State:     jobs.JobStateComplete,
	}}}, nil
}

func (emptyJobQuery) QueryTasks(context.Context, capability.TaskFilter, capability.PageRequest) (capability.TaskPage, error) {
	return capability.TaskPage{}, nil
}

// TestConsole_UnauditableReadIsDistinguishableFromAFailedOne pins the
// distinction screen.go's three refusals exist to draw. The two errors send an
// operator to different components, and one of them additionally says nothing
// was disclosed — which a generic 500 cannot.
func TestConsole_UnauditableReadIsDistinguishableFromAFailedOne(t *testing.T) {
	unauditable := errors.Join(capability.ErrReadUnaudited, errTrailDown)

	var got, other strings.Builder
	readFailed(&stringWriter{&got}, unauditable, "the fleet")
	readFailed(&stringWriter{&other}, errTrailDown, "the fleet")

	if got.String() == other.String() {
		t.Fatal("an unauditable read and a failed read render identically — the operator " +
			"cannot tell an audit-trail outage from a registry one")
	}
	if !strings.Contains(got.String(), "audit trail") {
		t.Errorf("the unauditable refusal does not name the audit trail:\n%s", got.String())
	}
	if strings.Contains(other.String(), "audit trail") {
		t.Errorf("an ordinary read failure blames the audit trail:\n%s", other.String())
	}
}

// stringWriter adapts a strings.Builder to http.ResponseWriter so the two
// refusal helpers can be compared as text without an HTTP round trip.
type stringWriter struct{ b *strings.Builder }

func (w *stringWriter) Header() http.Header         { return http.Header{} }
func (w *stringWriter) Write(p []byte) (int, error) { return w.b.Write(p) }
func (w *stringWriter) WriteHeader(int)             {}

// TestActivity_RunningNowIsExactlyOneMoreAuditedRead is spec 04's "one audited
// read" for Running now, and the issue's "no new capability call": through the
// real lane, the section adds one query_jobs record whose selector says what
// was asked (running only, oldest first, with a count), and no tool name the
// page did not already record.
func TestActivity_RunningNowIsExactlyOneMoreAuditedRead(t *testing.T) {
	count := func(t *testing.T, path string) (jobReads []audit.Record, tools map[string]int) {
		t.Helper()
		trail := &recordingTrail{}
		rec := get(t, newTestHandler(realLaneDeps(trail), accounts.RoleAdmin), path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, rec.Code)
		}
		tools = map[string]int{}
		for _, r := range trail.ofKind(audit.KindRead) {
			tools[r.OperationName]++
			if r.OperationName == "query_jobs" {
				jobReads = append(jobReads, r)
			}
		}
		return jobReads, tools
	}
	isRunningNow := func(r audit.Record) bool {
		return strings.Contains(r.Selector, "state=running") && strings.Contains(r.Selector, "order=oldest_first")
	}

	jobReads, tools := count(t, "/console/activity")
	if tools["query_jobs"] != 2 || tools["query_audit"] != 1 || len(tools) != 2 {
		t.Fatalf("the default feed recorded %v, want query_jobs x2 and query_audit x1 and nothing else", tools)
	}
	n := 0
	for _, r := range jobReads {
		if isRunningNow(r) {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d of the query_jobs records are Running now's, want exactly 1", n)
	}

	jobReads, tools = count(t, "/console/activity?kind=freeze")
	// A trail-only kind makes no stream Job read, so the one query_jobs record
	// IS Running now's; the trail lane's query_audit is what it always wrote.
	if tools["query_jobs"] != 1 || tools["query_audit"] != 1 || len(tools) != 2 {
		t.Fatalf("?kind=freeze recorded %v, want exactly query_jobs x1 (Running now's) and query_audit x1", tools)
	}
	if !isRunningNow(jobReads[0]) || !strings.Contains(jobReads[0].Selector, "count=matching") {
		t.Errorf("the one Job read's selector = %q, want running, oldest first, counted", jobReads[0].Selector)
	}
}

// TestReadTargetName_FollowsTheTrailsOwnPrecedence.
//
// The store builds AuditReach's distinct-target COALESCE from
// audit.TargetArgKeys (internal/store/auditquery.go's reachTargetExpr). A
// divergent order here makes the Console name a read target differently from how
// the reach aggregate counts it.
//
// The second half REORDERS audit.TargetArgKeys and asserts the naming follows.
// That is what distinguishes "reads the shared slice" from "happens to hold a
// byte-identical copy of it" — a copied literal passes every assertion built
// from the slice's current contents.
func TestReadTargetName_FollowsTheTrailsOwnPrecedence(t *testing.T) {
	if len(audit.TargetArgKeys) < 2 {
		t.Fatalf("audit.TargetArgKeys = %v — this test proves a PRECEDENCE order and "+
			"needs at least two keys to have one. A shorter list means the trail "+
			"changed shape and this test must be rewritten, not skipped.",
			audit.TargetArgKeys)
	}
	first, second := audit.TargetArgKeys[0], audit.TargetArgKeys[1]

	args := map[string]string{first: "/etc/hosts", second: "nginx"}
	if got := readTargetName("file.read", "", args); got != "file.read /etc/hosts" {
		t.Errorf("readTargetName = %q, want the first key in audit.TargetArgKeys to win", got)
	}
	if got := readTargetName("file.read", "", map[string]string{second: "nginx"}); got != "file.read nginx" {
		t.Errorf("readTargetName = %q, want the second key when the first is absent", got)
	}
	// An explicitly EMPTY value falls through to the next key. This is the one
	// documented divergence from the store's COALESCE, which stops at the
	// first key PRESENT; it is unreachable today because no catalog Operation
	// carries two of these keys.
	if got := readTargetName("file.read", "", map[string]string{first: "", second: "nginx"}); got != "file.read nginx" {
		t.Errorf("readTargetName = %q, want an empty first key to fall through", got)
	}

	// Reordered. A local copy of the key list does not move.
	//
	// Hazard: this mutates a package-level var owned by another package and restores
	// it with t.Cleanup. That is only sound while nothing runs
	// concurrently with it — do not add t.Parallel to this test, or to any
	// test that reads audit.TargetArgKeys, without replacing this seam.
	original := audit.TargetArgKeys
	t.Cleanup(func() { audit.TargetArgKeys = original })
	audit.TargetArgKeys = []string{second, first}
	if got := readTargetName("file.read", "", args); got != "file.read nginx" {
		t.Errorf("readTargetName = %q after reordering audit.TargetArgKeys — readTargetName holds its "+
			"own copy of the precedence order, which is exactly how it drifts from the store's COALESCE", got)
	}
}
