// Tag-space vocabulary. A tag: label is written only through the capability
// layer's tag write, by a human Account (ADR-0050); no Node report reaches it
// (invariant 7).
package registry

import (
	"errors"
	"fmt"
)

// MaxTagsPerNode caps how many tags one Node carries (ADR-0020, kept by
// ADR-0050 decision 1).
const MaxTagsPerNode = 64

// MaxTagKeyLen and MaxTagValueLen bound a tag's key and value in bytes. A tag
// takes the Label bounds (selectors-and-labels "Limits"), the same ones the
// node: ingress applies, so a write cannot grow every Node record, the audit
// chain and each Node read without limit (ADR-0050).
const (
	MaxTagKeyLen   = MaxLabelKeyLen
	MaxTagValueLen = MaxLabelValueLen
)

// ErrTagChanged is returned by an atomic tag write when a tag no longer holds
// the value the caller read. Nothing is written.
var ErrTagChanged = errors.New("registry: a tag changed since it was read")

// ErrTooManyTags is returned by an atomic tag write that would leave a Node
// carrying more than MaxTagsPerNode tags. Nothing is written.
var ErrTooManyTags = errors.New("registry: a Node carries at most 64 tags")

// TagValue is a tag's value or its absence. Presence is a flag because
// WellFormedLabel accepts an empty value, so "" cannot also mean "absent".
type TagValue struct {
	Set   bool
	Value string
}

// TagChange is one tag on one Node moving from Before to After. Keys are bare,
// with no "tag:" prefix: the namespace is decided by the table or map that
// holds them, as for NodeLabels and RelayLabels.
type TagChange struct {
	NodeID string
	Key    string
	Before TagValue
	After  TagValue
}

// Validate refuses a change that could not be stored or that changes nothing.
// It applies WellFormedLabel, the one predicate for every stored Label, and the
// tag length bounds, to whichever side is set. The store and InMemory both call
// it.
func (c TagChange) Validate() error {
	if c.NodeID == "" {
		return ErrEmptyNodeID
	}
	if c.Before == c.After {
		return fmt.Errorf("registry: tag change for %q changes nothing", c.Key)
	}
	if !c.Before.Set && !c.After.Set {
		return fmt.Errorf("registry: tag change for %q sets neither side", c.Key)
	}
	for _, side := range []TagValue{c.Before, c.After} {
		if side.Set && !WellFormedLabel(c.Key, side.Value) {
			return fmt.Errorf("registry: tag %q is not well formed", c.Key)
		}
		if side.Set && (len(c.Key) > MaxTagKeyLen || len(side.Value) > MaxTagValueLen) {
			return fmt.Errorf("registry: a tag's key is at most %d bytes and its value at most %d", MaxTagKeyLen, MaxTagValueLen)
		}
	}
	return nil
}
