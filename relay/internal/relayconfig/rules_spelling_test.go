package relayconfig

import (
	"strings"
	"testing"
)

// The decoder matches names without regard to case, so a variant spelling of the
// rules key or of a rule field would replace, empty or narrow the operator's
// rules unseen. Each is refused naming the schema key, in fixed text.
//
// Proves AP-8, AP-89.
func TestLoad_VariantSpellingOfRulesKeysRefused(t *testing.T) {
	cases := []struct {
		name, src, want string
	}{
		{"an empty array after the rules", minimal + "[[approval.rules]]\nname = \"a\"\n\n[approval]\nRules = []\n", "approval.rules (line 11)"},
		{"a second spelling of the array table", minimal + "[[approval.rules]]\nname = \"a\"\n\n[[approval.Rules]]\nname = \"CANARY\"\n", "approval.rules (line 10)"},
		{"a second spelling of a field in one rule", minimal + "[[approval.rules]]\nname = \"a\"\nrisk_class = \"mutate\"\nRisk_Class = \"read\"\n", "approval.rules.risk_class (line 10)"},
		{"a non-ASCII spelling of a rule field", minimal + "[[approval.rules]]\nname = \"a\"\nrisk_class = \"mutate\"\n\"rİsk_class\" = \"read\"\n", "approval.rules.risk_class (line 10)"},
		{"a non-ASCII spelling of the operation field", minimal + "[[approval.rules]]\nname = \"a\"\noperation = \"x\"\n\"operatİon\" = \"y\"\n", "approval.rules.operation (line 10)"},
		{"an inline array and a table", minimal + "[approval]\nRules = [{name = \"CANARY\"}]\n\n[approval.Rules]\nname = \"CANARY\"\n", "approval.rules (line 8)"},
		{"the approval table", minimal + "[Approval]\nwebhook_url_file = \"x\"\n", "approval (line 7)"},
		{"a webhook key", minimal + "[approval]\nWebhook_URL_File = \"x\"\n", "approval.webhook_url_file (line 8)"},
		{"the rules key inside an inline table", "approval = { Rules = [] }\n" + minimal, "approval.rules (line 1)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := loadErr(t, tc.src)
			if want := tc.want + ": " + reasonSpelling; !strings.Contains(got, want) {
				t.Fatalf("error %q does not contain %q", got, want)
			}
			notContains(t, got, "CANARY", "unrecognised")
		})
	}
}

// A name of only whitespace names no rule.
//
// Proves AP-89.
func TestLoad_WhitespaceOnlyRuleNameRefusedWithLine(t *testing.T) {
	got := loadErr(t, minimal+"[[approval.rules]]\nname = \"  \\t\"\n")
	if !strings.Contains(got, "approval.rules.name (line 8): "+reasonEmpty) {
		t.Fatalf("error %q does not refuse the name at its line", got)
	}
}
