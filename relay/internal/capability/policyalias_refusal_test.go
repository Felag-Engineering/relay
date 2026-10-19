package capability_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

// The role ladder is the real authz.RoleGate, so this file is an external test
// package (authz imports capability).

const (
	refFPa = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	refFPb = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// aliasTrail is an AuditSink that keeps every entry, and a
// PolicyAliasRecorder that applies each change to its map.
type aliasTrail struct {
	nopAuditSink
	mu      sync.Mutex
	entries []capability.AuditEntry
	events  []capability.PolicyAliasEvent
	held    map[string]string
}

func (a *aliasTrail) Record(_ context.Context, e capability.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return nil
}

func (a *aliasTrail) List(context.Context) (map[string]string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[string]string{}
	for k, v := range a.held {
		out[k] = v
	}
	return out, nil
}

func (a *aliasTrail) RecordPolicyAlias(_ context.Context, e capability.PolicyAliasEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
	if e.New == "" {
		delete(a.held, e.Fingerprint)
	} else {
		a.held[e.Fingerprint] = e.New
	}
	return nil
}

func newAliasAdmin(t *testing.T, seed map[string]string) (*capability.PolicyAliasAdmin, *aliasTrail) {
	t.Helper()
	trail := &aliasTrail{held: map[string]string{}}
	for k, v := range seed {
		trail.held[k] = v
	}
	rec := capability.NewRecorder(trail, nil, nil)
	ctl := capability.NewControl(rec, authz.NewRoleGate(), neverFrozen{})
	return capability.NewPolicyAliasAdmin(ctl, trail), trail
}

func principal(role, kind string) capability.Principal {
	return capability.Principal{
		AccountID: "acct-" + role, Account: "acct-" + role, Role: role, Kind: kind,
		AuthMethod: capability.AuthMethodConsoleSession,
	}
}

var humanAdmin = principal("admin", capability.PrincipalKindHuman)

func TestPolicyAliasAdmin_Refusals(t *testing.T) {
	type call func(*capability.PolicyAliasAdmin) error
	set := func(p capability.Principal, fp, name string) call {
		return func(a *capability.PolicyAliasAdmin) error {
			return a.SetPolicyAlias(context.Background(), p, fp, name)
		}
	}
	clear := func(p capability.Principal, fp string) call {
		return func(a *capability.PolicyAliasAdmin) error {
			return a.ClearPolicyAlias(context.Background(), p, fp)
		}
	}
	mid := func(x string) string { return "web" + x + "prod" }

	cases := []struct {
		name     string
		do       call
		want     error
		reasonIn string
	}{
		{"unauthenticated", set(capability.Principal{}, refFPa, "web"), authz.ErrUnauthorized, "requires role"},
		{"machine viewer", set(principal("viewer", "machine"), refFPa, "web"), authz.ErrUnauthorized, "admin"},
		{"machine operator", set(principal("operator", "machine"), refFPa, "web"), authz.ErrUnauthorized, "admin"},
		{"machine admin", set(principal("admin", "machine"), refFPa, "web"), authz.ErrUnauthorized, "human-only"},
		{"unknown-kind admin", set(principal("admin", ""), refFPa, "web"), authz.ErrUnauthorized, "human-only"},
		{"human viewer", set(principal("viewer", capability.PrincipalKindHuman), refFPa, "web"), authz.ErrUnauthorized, "admin"},
		{"human operator", set(principal("operator", capability.PrincipalKindHuman), refFPa, "web"), authz.ErrUnauthorized, "admin"},
		{"clear by machine admin", clear(principal("admin", "machine"), refFPa), authz.ErrUnauthorized, "human-only"},
		{"clear by human operator", clear(principal("operator", capability.PrincipalKindHuman), refFPa), authz.ErrUnauthorized, "admin"},

		{"empty fingerprint", set(humanAdmin, "", "web"), capability.ErrPolicyFingerprintMalformed, "fingerprint"},
		{"63 hex", set(humanAdmin, refFPa[:63], "web"), capability.ErrPolicyFingerprintMalformed, "fingerprint"},
		{"65 hex", set(humanAdmin, refFPa+"a", "web"), capability.ErrPolicyFingerprintMalformed, "fingerprint"},
		{"uppercase hex", set(humanAdmin, strings.ToUpper(refFPa), "web"), capability.ErrPolicyFingerprintMalformed, "fingerprint"},
		{"non-hex", set(humanAdmin, strings.Repeat("z", 64), "web"), capability.ErrPolicyFingerprintMalformed, "fingerprint"},
		{"clear a malformed fingerprint", clear(humanAdmin, "nope"), capability.ErrPolicyFingerprintMalformed, "fingerprint"},

		{"empty name", set(humanAdmin, refFPa, ""), capability.ErrPolicyAliasEmpty, "empty"},
		{"blank name", set(humanAdmin, refFPa, "   "), capability.ErrPolicyAliasEmpty, "empty"},
		{"65 runes", set(humanAdmin, refFPa, strings.Repeat("é", 65)), capability.ErrPolicyAliasTooLong, "64"},
		{"NUL", set(humanAdmin, refFPa, mid("\x00")), capability.ErrPolicyAliasControlCharacter, "control"},
		{"TAB", set(humanAdmin, refFPa, mid("\t")), capability.ErrPolicyAliasControlCharacter, "control"},
		{"DEL", set(humanAdmin, refFPa, mid("\x7f")), capability.ErrPolicyAliasControlCharacter, "control"},
		{"NEL", set(humanAdmin, refFPa, mid("\u0085")), capability.ErrPolicyAliasControlCharacter, "control"},
		{"RLO", set(humanAdmin, refFPa, mid("\u202e")), capability.ErrPolicyAliasControlCharacter, "control"},
		{"LRI", set(humanAdmin, refFPa, mid("\u2066")), capability.ErrPolicyAliasControlCharacter, "control"},
		{"ZWSP", set(humanAdmin, refFPa, mid("\u200b")), capability.ErrPolicyAliasControlCharacter, "control"},
		{"BOM", set(humanAdmin, refFPa, mid("\ufeff")), capability.ErrPolicyAliasControlCharacter, "control"},
		{"invalid UTF-8", set(humanAdmin, refFPa, mid("\xff")), capability.ErrPolicyAliasInvalidUTF8, "UTF-8"},
		{"a name another fingerprint carries", set(humanAdmin, refFPb, "taken"), capability.ErrPolicyAliasTaken, "another"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			admin, trail := newAliasAdmin(t, map[string]string{refFPa: "taken"})
			err := c.do(admin)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if !strings.Contains(err.Error(), c.reasonIn) {
				t.Errorf("reason %q does not name the rule (%q)", err.Error(), c.reasonIn)
			}
			if len(trail.events) != 0 {
				t.Errorf("a refused change reached the recorder: %+v", trail.events)
			}
			if got, _ := trail.List(context.Background()); len(got) != 1 || got[refFPa] != "taken" {
				t.Errorf("a refused change altered the aliases: %v", got)
			}
			if len(trail.entries) != 1 || trail.entries[0].Kind != capability.AuditKindRefusal {
				t.Errorf("entries = %+v, want exactly one refusal", trail.entries)
			}
		})
	}
}

func TestSetPolicyAlias_StoresTheTrimmedValueAndAcceptsTheLengthBoundary(t *testing.T) {
	long := strings.Repeat("é", 64)
	cases := map[string]string{
		"  web-prod  ":     "web-prod",
		"\tweb-prod\u0085": "web-prod",
		"\nweb-prod\t":     "web-prod",
		long:               long,
		" " + long + " ":   long,
	}
	for in, want := range cases {
		admin, trail := newAliasAdmin(t, nil)
		if err := admin.SetPolicyAlias(context.Background(), humanAdmin, refFPa, in); err != nil {
			t.Fatalf("SetPolicyAlias(%q): %v", in, err)
		}
		if len(trail.events) != 1 || trail.events[0].New != want {
			t.Errorf("SetPolicyAlias(%q) event = %+v, want New %q", in, trail.events, want)
		}
		if len(trail.entries) != 0 {
			t.Errorf("SetPolicyAlias(%q) recorded a refusal: %+v", in, trail.entries)
		}
	}
}

func TestPolicyAliasAdmin_TakesNoStepUp(t *testing.T) {
	admin, trail := newAliasAdmin(t, nil)
	ctx := context.Background() // no step-up evidence of any kind
	if err := admin.SetPolicyAlias(ctx, humanAdmin, refFPa, "web"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := admin.SetPolicyAlias(ctx, humanAdmin, refFPa, "web-prod"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := admin.ClearPolicyAlias(ctx, humanAdmin, refFPa); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if len(trail.events) != 3 || len(trail.entries) != 0 {
		t.Fatalf("events %d, refusals %d; want 3 and 0", len(trail.events), len(trail.entries))
	}
}

func TestClearPolicyAlias_NotSetIsNotAnError(t *testing.T) {
	admin, trail := newAliasAdmin(t, nil)
	if err := admin.ClearPolicyAlias(context.Background(), humanAdmin, refFPa); err != nil {
		t.Fatalf("ClearPolicyAlias of an unset alias = %v", err)
	}
	if len(trail.events) != 0 || len(trail.entries) != 0 {
		t.Errorf("a no-op recorded events %v entries %v", trail.events, trail.entries)
	}
}
