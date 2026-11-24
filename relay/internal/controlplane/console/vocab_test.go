package console

import (
	"reflect"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/opvocab"
)

// TestVocab_BothProjectionsCarryTheSameFacts is decision 4's parity guard:
// Activity and the Accounts last-call read project through factsOfRow, node
// detail's Recent Tasks and node_revoke still read factsOfRecord, and nothing
// before this test noticed a field filled by one projection and not the other.
//
// Every trailFacts-relevant field on the fixture Record is set non-zero, so
// that dropping Role (or anything else) from either projection function is
// caught by the zero-sweep rather than by two projections merely agreeing
// with each other on an all-zero field.
func TestVocab_BothProjectionsCarryTheSameFacts(t *testing.T) {
	rec := audit.Record{
		ID:        "rec-1",
		Timestamp: testNow,
		Kind:      audit.KindDispatch,
		Principal: "gleipnir-prod:operator",
		Attribution: audit.Attribution{
			Verified: audit.Verified{
				AccountID:   "acct-1",
				AccountName: "gleipnir-prod",
				Role:        "operator",
				TokenID:     "tok-1",
				Method:      "token",
				Source:      "10.0.0.1",
			},
			Asserted: audit.Asserted{OnBehalfOf: "alice", Traceparent: "00-trace"},
		},
		Selector:      "tag:web",
		JobID:         "job-1",
		NodeID:        "node-a",
		ActionKind:    "operation",
		OperationName: "service.restart",
		Args:          map[string]string{"unit": "nginx"},
		RawExecArgv:   []string{"systemctl", "restart", "nginx"},
		Outcome:       jobs.OutcomeSuccess,
		Reason:        "because",
		ApprovalID:    "appr-1",
		GrantID:       "grant-1",

		ApprovalAnswer:  audit.ApprovalAnswerApproved,
		DecisionChannel: "out_of_band",
		PlanHash:        "hash-1",
	}

	f := factsOfRecord(rec)
	v := reflect.ValueOf(f)
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).IsZero() {
			t.Errorf("the fixture leaves trailFacts.%s zero — it must set every field so a "+
				"projection that drops one is caught by this test", v.Type().Field(i).Name)
		}
	}

	row := rowOfRecord(rec)
	if got := factsOfRow(row); !reflect.DeepEqual(f, got) {
		t.Errorf("factsOfRecord and factsOfRow disagree on the same record:\n"+
			"factsOfRecord = %+v\nfactsOfRow    = %+v", f, got)
	}
}

// TestVocab_NativesKeepTheClassTheFrozenVocabularyGivesThem: every Native
// Operation draws the class opvocab declares for it.
func TestVocab_NativesKeepTheClassTheFrozenVocabularyGivesThem(t *testing.T) {
	var reads, mutates int
	for _, d := range opvocab.Operations() {
		switch d.Risk {
		case jobs.RiskClassRead:
			reads++
		case jobs.RiskClassMutate:
			mutates++
		}
		got := riskOf(trailFacts{Kind: audit.KindDispatch, OperationName: d.Name})
		if got != d.Risk {
			t.Errorf("%s: riskOf = %s, want %s", d.Name, jobs.RiskClassName(got), jobs.RiskClassName(d.Risk))
		}
	}
	if reads == 0 || mutates == 0 {
		t.Fatalf("opvocab gave %d read and %d mutate Operations; the guard is vacuous", reads, mutates)
	}
}

// TestVocab_ATemplateIsNeverReadByName regresses #1399: a Template's class is
// per-Node and is not on the audit record, so a name shared with a shipped read
// Template never proves read.
func TestVocab_ATemplateIsNeverReadByName(t *testing.T) {
	names := []string{
		"proc.list", "service.status", "disk.usage", "net.listening",
		"pkg.inventory", "log.tail", "file.checksum", "customer.template.thing",
	}
	kinds := []string{audit.KindDispatch, audit.KindApprovalRequested, audit.KindRefusal}
	for _, name := range names {
		for _, kind := range kinds {
			rec := audit.Record{Kind: kind, OperationName: name}
			row := capability.AuditRow{Kind: kind, OperationName: name}
			if got := riskOf(factsOfRecord(rec)); got != jobs.RiskClassMutate {
				t.Errorf("%s/%s via record: riskOf = %s, want mutate", name, kind, jobs.RiskClassName(got))
			}
			if got := riskOf(factsOfRow(row)); got != jobs.RiskClassMutate {
				t.Errorf("%s/%s via row: riskOf = %s, want mutate", name, kind, jobs.RiskClassName(got))
			}
		}
	}
}
