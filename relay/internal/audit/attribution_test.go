package audit

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateAsserted_AcceptsOrdinaryValues(t *testing.T) {
	ok := Asserted{
		OnBehalfOf:  "ops-team",
		Traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		SessionRef:  "conv_01JQ8Z9K2X",
		ChangeRef:   "CHG-4821",
	}
	if err := ValidateAsserted(ok); err != nil {
		t.Fatalf("ValidateAsserted(%+v) = %v, want nil", ok, err)
	}
	if err := ValidateAsserted(Asserted{}); err != nil {
		t.Errorf("the zero value must validate — asserting nothing is the common case: %v", err)
	}

	// Non-ASCII is fine: a team name is not required to be English, and the
	// rule here is about control characters, not alphabet.
	if err := ValidateAsserted(Asserted{OnBehalfOf: "équipe-ops-東京"}); err != nil {
		t.Errorf("a non-ASCII team name was refused: %v", err)
	}
}

// Callers must not be able to size an audit record (#255/#258): an unbounded
// field on an append-only table is a storage-exhaustion primitive handed to
// the least trusted input in the system.
func TestValidateAsserted_RefusesOversizedFields(t *testing.T) {
	long := strings.Repeat("x", MaxAssertedFieldBytes+1)

	for _, c := range []struct {
		field string
		a     Asserted
	}{
		{"on_behalf_of", Asserted{OnBehalfOf: long}},
		{"traceparent", Asserted{Traceparent: long}},
		{"session_ref", Asserted{SessionRef: long}},
		{"change_ref", Asserted{ChangeRef: long}},
	} {
		err := ValidateAsserted(c.a)
		if !errors.Is(err, ErrAssertedFieldTooLong) {
			t.Errorf("[%s] err = %v, want ErrAssertedFieldTooLong", c.field, err)
		}
		if !strings.Contains(err.Error(), c.field) {
			t.Errorf("[%s] err %q does not name the offending field", c.field, err)
		}
	}

	// Exactly at the bound is accepted: the bound is inclusive and stated as
	// such, so a caller sizing to it is not surprised.
	if err := ValidateAsserted(Asserted{OnBehalfOf: strings.Repeat("x", MaxAssertedFieldBytes)}); err != nil {
		t.Errorf("a field exactly at the bound was refused: %v", err)
	}
}

// A newline in an audit field is a log-forging vector: it lets a caller inject
// what looks like a second record into any line-oriented view of the trail —
// during an incident, when the trail must be readable.
func TestValidateAsserted_RefusesControlCharacters(t *testing.T) {
	for _, c := range []struct{ label, value string }{
		{"newline", "ops-team\nfake-record: root did nothing wrong"},
		{"carriage return", "ops\rteam"},
		{"tab", "ops\tteam"},
		{"NUL", "ops\x00team"},
		{"escape", "ops\x1b[31mteam"},
		{"DEL", "ops\x7fteam"},
		{"C1 control (NEL)", "ops\u0085team"},
	} {
		err := ValidateAsserted(Asserted{OnBehalfOf: c.value})
		if !errors.Is(err, ErrAssertedFieldInvalid) {
			t.Errorf("[%s] err = %v, want ErrAssertedFieldInvalid", c.label, err)
		}
	}
}

// The lanes are separate types, not two conventions over one bag of strings.
// A caller-supplied value cannot reach a verified field without someone
// writing a line that visibly moves it across — which is the point.
func TestAttribution_LanesAreStructurallySeparate(t *testing.T) {
	a := Attribution{
		Verified: Verified{AccountID: "acct-1", AccountName: "gleipnir", Role: "operator", TokenID: "tok-1"},
		Asserted: Asserted{OnBehalfOf: "ops-team"},
	}

	// Nothing a caller asserted appears in the verified lane.
	v := a.Verified
	for _, got := range []string{v.AccountID, v.AccountName, v.Role, v.TokenID} {
		if got == a.Asserted.OnBehalfOf {
			t.Errorf("an asserted value (%q) appears in the verified lane", got)
		}
	}
	if a.Asserted.IsZero() {
		t.Error("IsZero() = true for a populated Asserted")
	}
	if !(Asserted{}).IsZero() {
		t.Error("IsZero() = false for the zero value")
	}
}
