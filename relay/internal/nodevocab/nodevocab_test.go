package nodevocab

import (
	"reflect"
	"testing"
)

func sample() Snapshot {
	return Snapshot{
		Fingerprint: "sha256:abc",
		Templates: []Template{
			{
				Name:      "log.tail",
				RiskClass: 1,
				Slots: []Slot{
					{Name: "lines", Type: "integer"},
					{Name: "unit", Type: "enum", EnumValues: []string{"nginx", "sshd"}},
				},
			},
		},
	}
}

// TestGetMissingIsNotReported pins the discovery contract: an absent entry is
// "nothing reported yet", never "this Node has no templates".
func TestGetMissingIsNotReported(t *testing.T) {
	c := New()
	if _, ok := c.Get("node-a"); ok {
		t.Fatal("Get on an empty cache returned ok = true")
	}
}

func TestSetGetRoundTrip(t *testing.T) {
	c := New()
	c.Set("node-a", sample())

	got, ok := c.Get("node-a")
	if !ok {
		t.Fatal("Get after Set returned ok = false")
	}
	if !reflect.DeepEqual(got, sample()) {
		t.Errorf("Get = %+v, want %+v", got, sample())
	}
}

// TestSetIsDeepCopied proves the cache never shares backing arrays with the
// caller (the policyview.Cache discipline): neither the snapshot handed to Set
// nor one returned by Get can mutate cached state.
func TestSetIsDeepCopied(t *testing.T) {
	c := New()
	in := sample()
	c.Set("node-a", in)

	// Mutate every level of the caller's copy.
	in.Templates[0].Name = "mutated"
	in.Templates[0].Slots[0].Name = "mutated"
	in.Templates[0].Slots[1].EnumValues[0] = "mutated"

	got, _ := c.Get("node-a")
	if !reflect.DeepEqual(got, sample()) {
		t.Errorf("cached snapshot changed through the caller's slices: %+v", got)
	}

	// And through a returned copy.
	got.Templates[0].Slots[1].EnumValues[1] = "mutated"
	again, _ := c.Get("node-a")
	if !reflect.DeepEqual(again, sample()) {
		t.Errorf("cached snapshot changed through a returned copy: %+v", again)
	}
}

func TestSetReplacesPreviousSnapshot(t *testing.T) {
	c := New()
	c.Set("node-a", sample())
	c.Set("node-a", Snapshot{Fingerprint: "sha256:def"})

	got, ok := c.Get("node-a")
	if !ok {
		t.Fatal("Get returned ok = false")
	}
	if got.Fingerprint != "sha256:def" || len(got.Templates) != 0 {
		t.Errorf("Get = %+v, want the replacing snapshot (a reconnect replaces, never merges)", got)
	}
}
