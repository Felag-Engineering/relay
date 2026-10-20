package accounts

import "testing"

// Role ordering is the load-bearing part: authorization asks "at least X",
// and both an unknown holder-role and an unknown requirement must fail closed.
func TestRoleAtLeast(t *testing.T) {
	cases := []struct {
		have, want Role
		ok         bool
	}{
		{RoleAdmin, RoleAdmin, true},
		{RoleAdmin, RoleOperator, true},
		{RoleAdmin, RoleViewer, true},
		{RoleOperator, RoleOperator, true},
		{RoleOperator, RoleViewer, true},
		{RoleOperator, RoleAdmin, false},
		{RoleViewer, RoleViewer, true},
		{RoleViewer, RoleOperator, false},
		{RoleViewer, RoleAdmin, false},
		// Fail closed in both directions.
		{Role("root"), RoleViewer, false},
		{Role(""), RoleViewer, false},
		{RoleAdmin, Role("root"), false},
		{RoleAdmin, Role(""), false},
	}
	for _, c := range cases {
		if got := c.have.AtLeast(c.want); got != c.ok {
			t.Errorf("Role(%q).AtLeast(%q) = %v, want %v", c.have, c.want, got, c.ok)
		}
	}
}

func TestRoleAndKindValid(t *testing.T) {
	for _, r := range []Role{RoleViewer, RoleOperator, RoleAdmin} {
		if !r.Valid() {
			t.Errorf("Role(%q).Valid() = false", r)
		}
	}
	for _, r := range []Role{"", "root", "Admin", "superuser"} {
		if Role(r).Valid() {
			t.Errorf("Role(%q).Valid() = true, want false", r)
		}
	}
	for _, k := range []Kind{KindHuman, KindMachine} {
		if !k.Valid() {
			t.Errorf("Kind(%q).Valid() = false", k)
		}
	}
	for _, k := range []Kind{"", "robot", "Human"} {
		if Kind(k).Valid() {
			t.Errorf("Kind(%q).Valid() = true, want false", k)
		}
	}
}

// Names reach audit lines, logs, and the Console, so the charset is narrow by
// design: whitespace, quotes, and control characters are log-forging and
// display-spoofing vectors, and no legitimate Account needs them.
func TestValidateName(t *testing.T) {
	good := []string{"alice", "gleipnir", "ci-runner", "svc.deploy", "a_b", "a1", "A", string(make([]byte, 0)) + "z"}
	for _, n := range good {
		if err := ValidateName(n); err != nil {
			t.Errorf("ValidateName(%q) = %v, want nil", n, err)
		}
	}
	bad := []string{
		"",                       // empty
		"-alice",                 // leading punctuation
		".alice",                 //
		"_alice",                 //
		"bad name",               // whitespace
		"a\tb",                   //
		"a\nb",                   // newline — log forging
		"a\x00b",                 // NUL
		"alice@host",             // outside the charset
		"al/ice",                 //
		"al'ice",                 // quote — display spoofing
		"ali\"ce",                //
		string(make([]rune, 65)), // over 64 bytes (and starts with NUL anyway)
	}
	for _, n := range bad {
		if err := ValidateName(n); err == nil {
			t.Errorf("ValidateName(%q) = nil, want an error", n)
		}
	}

	long := ""
	for i := 0; i < 64; i++ {
		long += "a"
	}
	if err := ValidateName(long); err != nil {
		t.Errorf("ValidateName(64 chars) = %v, want nil", err)
	}
	if err := ValidateName(long + "a"); err == nil {
		t.Error("ValidateName(65 chars) = nil, want an error")
	}
}

func TestNormalizeName(t *testing.T) {
	for in, want := range map[string]string{
		"Alice":    "alice",
		"  bob  ":  "bob",
		"GLEIPNIR": "gleipnir",
	} {
		if got := NormalizeName(in); got != want {
			t.Errorf("NormalizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

// Attribution is what an incident reader sees; it carries the role because
// "what could this Account do at the time" is the second question they ask.
func TestAttribution(t *testing.T) {
	a := Account{Name: "gleipnir", Role: RoleOperator}
	if got := a.Attribution(); got != "gleipnir:operator" {
		t.Errorf("Attribution() = %q, want %q", got, "gleipnir:operator")
	}
	if got := (Account{Name: "x"}).Attribution(); got != "x" {
		t.Errorf("Attribution() with no role = %q, want %q", got, "x")
	}
}
