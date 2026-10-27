package registry_test

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// tags_test.go is the structural assertion that a Node report can never reach
// tag-space (invariant 7, ADR-0050): the tag: namespace has one writer, a
// human Account through the capability layer, and the registry's Repository
// offers no method through which anything else could write one.

func TestReport_CarriesNoTagField(t *testing.T) {
	rt := reflect.TypeOf(registry.Report{})
	for i := 0; i < rt.NumField(); i++ {
		if name := rt.Field(i).Name; strings.Contains(strings.ToLower(name), "tag") {
			t.Errorf("registry.Report has a %s field — a Node must not be able to report a tag: label", name)
		}
	}
}

func TestRepository_HasNoTagWriter(t *testing.T) {
	rt := reflect.TypeOf((*registry.Repository)(nil)).Elem()
	for i := 0; i < rt.NumMethod(); i++ {
		if name := rt.Method(i).Name; strings.Contains(name, "Tag") {
			t.Errorf("registry.Repository has a %s method — tag: labels are written only by the audit repository's "+
				"atomic tag write, so a change and its record land together", name)
		}
	}
}

func set(v string) registry.TagValue { return registry.TagValue{Set: true, Value: v} }

func TestTagChange_Validate(t *testing.T) {
	ok := []registry.TagChange{
		{NodeID: "n", Key: "team", After: set("payments")},
		{NodeID: "n", Key: "team", Before: set("a"), After: set("b")},
		{NodeID: "n", Key: "team", Before: set("a")},
		{NodeID: "n", Key: "team", After: set("")},
		{NodeID: "n", Key: strings.Repeat("k", registry.MaxTagKeyLen), After: set(strings.Repeat("v", registry.MaxTagValueLen))},
	}
	for _, c := range ok {
		if err := c.Validate(); err != nil {
			t.Errorf("Validate(%+v) = %v, want nil", c, err)
		}
	}
	bad := map[string]registry.TagChange{
		"no node":        {Key: "team", After: set("a")},
		"no change":      {NodeID: "n", Key: "team", Before: set("a"), After: set("a")},
		"neither set":    {NodeID: "n", Key: "team"},
		"empty key":      {NodeID: "n", Key: "", After: set("a")},
		"comma in key":   {NodeID: "n", Key: "a,b", After: set("a")},
		"space in value": {NodeID: "n", Key: "k", After: set("a b")},
		"colon in value": {NodeID: "n", Key: "k", After: set("a:b")},
		"non-ascii":      {NodeID: "n", Key: "k", After: set("a\u200b")},
		"bad before":     {NodeID: "n", Key: "k", Before: set("a b")},
		"key too long":   {NodeID: "n", Key: strings.Repeat("k", registry.MaxTagKeyLen+1), After: set("a")},
		"value too long": {NodeID: "n", Key: "k", After: set(strings.Repeat("v", registry.MaxTagValueLen+1))},
	}
	for name, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: Validate(%+v) = nil, want an error", name, c)
		}
	}
}

func inMemoryWithNodes(t *testing.T, ids ...string) *registry.InMemory {
	t.Helper()
	reg := registry.NewInMemory()
	for _, id := range ids {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("Upsert(%s): %v", id, err)
		}
	}
	return reg
}

func TestInMemory_ApplyTagChangesIsAllOrNothing(t *testing.T) {
	reg := inMemoryWithNodes(t, "a", "b")

	if err := reg.ApplyTagChanges([]registry.TagChange{
		{NodeID: "a", Key: "team", After: set("x")},
		{NodeID: "ghost", Key: "team", After: set("x")},
	}); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("a list naming an unknown Node = %v, want ErrNotFound", err)
	}
	if n, _ := reg.Get("a"); len(n.TagLabels) != 0 {
		t.Errorf("a was written although the list was refused: %v", n.TagLabels)
	}

	if err := reg.ApplyTagChanges([]registry.TagChange{
		{NodeID: "a", Key: "team", After: set("x")},
		{NodeID: "b", Key: "team", Before: set("stale"), After: set("x")},
	}); !errors.Is(err, registry.ErrTagChanged) {
		t.Fatalf("a stale Before = %v, want ErrTagChanged", err)
	}
	if n, _ := reg.Get("a"); len(n.TagLabels) != 0 {
		t.Errorf("a was written although a later change was stale: %v", n.TagLabels)
	}

	if err := reg.ApplyTagChanges(nil); err == nil {
		t.Error("an empty list was accepted")
	}
	if err := reg.ApplyTagChanges([]registry.TagChange{
		{NodeID: "a", Key: "team", After: set("x")},
		{NodeID: "a", Key: "team", Before: set("x"), After: set("y")},
	}); err == nil {
		t.Error("one tag changed twice in one list was accepted")
	}
}

func TestInMemory_ApplyTagChangesEnforcesTheCap(t *testing.T) {
	reg := inMemoryWithNodes(t, "a")
	var fill []registry.TagChange
	for i := 0; i < registry.MaxTagsPerNode; i++ {
		fill = append(fill, registry.TagChange{NodeID: "a", Key: fmt.Sprintf("k%d", i), After: set("v")})
	}
	if err := reg.ApplyTagChanges(fill); err != nil {
		t.Fatalf("filling to the cap: %v", err)
	}
	if err := reg.ApplyTagChanges([]registry.TagChange{{NodeID: "a", Key: "over", After: set("v")}}); !errors.Is(err, registry.ErrTooManyTags) {
		t.Errorf("the 65th tag = %v, want ErrTooManyTags", err)
	}
	// Replacing and removing stay possible on a full Node.
	if err := reg.ApplyTagChanges([]registry.TagChange{
		{NodeID: "a", Key: "k0", Before: set("v"), After: set("w")},
		{NodeID: "a", Key: "k1", Before: set("v")},
	}); err != nil {
		t.Errorf("replace and remove on a full Node: %v", err)
	}
}

// Proves EN-35, EN-40.
func TestParseInitialTags(t *testing.T) {
	long := func(n int) string { return strings.Repeat("a", n) }
	many := make([]string, 0, registry.MaxTagsPerNode+1)
	for i := 0; i <= registry.MaxTagsPerNode; i++ {
		many = append(many, fmt.Sprintf("tag:k%d=v", i))
	}

	t.Run("well-formed tags parse to bare keys and values", func(t *testing.T) {
		got, err := registry.ParseInitialTags([]string{"tag:env=prod", "tag:marker=", "tag:" + long(63) + "=" + long(255)})
		if err != nil {
			t.Fatalf("ParseInitialTags: %v", err)
		}
		if len(got) != 3 || got["env"] != "prod" || got["marker"] != "" || got[long(63)] != long(255) {
			t.Errorf("parsed %v", got)
		}
	})
	t.Run("none is an empty set", func(t *testing.T) {
		for _, in := range [][]string{nil, {}} {
			got, err := registry.ParseInitialTags(in)
			if err != nil || len(got) != 0 {
				t.Errorf("ParseInitialTags(%v) = %v, %v", in, got, err)
			}
		}
	})
	t.Run("a relay: label is refused naming it", func(t *testing.T) {
		_, err := registry.ParseInitialTags([]string{"tag:ok=1", "relay:node-id=x"})
		var tagErr *registry.InitialTagError
		if !errors.As(err, &tagErr) || !errors.Is(err, registry.ErrInitialTagRelayLabel) {
			t.Fatalf("err = %v, want an InitialTagError wrapping ErrInitialTagRelayLabel", err)
		}
		if tagErr.Entry != "relay:node-id=x" || !strings.Contains(err.Error(), "relay:node-id=x") {
			t.Errorf("the refusal does not name the entry: %v", err)
		}
	})
	t.Run("everything else that is not a tag is refused", func(t *testing.T) {
		for _, bad := range []string{
			"env=prod", "node:env=prod", "state:x=y", "TAG:env=prod", "tag:env", "tag:=v", "tag:", "",
			"tag:a b=c", "tag:a=b=c", "tag:a=b,node:c=d", "tag:k\u200b=v", "tag:" + long(64) + "=v", "tag:k=" + long(256),
		} {
			if _, err := registry.ParseInitialTags([]string{bad}); !errors.Is(err, registry.ErrInitialTagMalformed) {
				t.Errorf("%q: err = %v, want ErrInitialTagMalformed", bad, err)
			}
		}
	})
	t.Run("a key twice and too many keys are refused", func(t *testing.T) {
		if _, err := registry.ParseInitialTags([]string{"tag:env=prod", "tag:env=dev"}); !errors.Is(err, registry.ErrInitialTagKeyTwice) {
			t.Errorf("key twice: err = %v", err)
		}
		if _, err := registry.ParseInitialTags(many); !errors.Is(err, registry.ErrTooManyTags) {
			t.Errorf("%d tags: err = %v, want ErrTooManyTags", len(many), err)
		}
	})
	t.Run("a long entry is bounded before it is quoted", func(t *testing.T) {
		_, err := registry.ParseInitialTags([]string{"tag:" + long(100000) + "=v"})
		if err == nil || len(err.Error()) > 1024 {
			t.Fatalf("want a bounded refusal, got %v", err)
		}
	})
}
