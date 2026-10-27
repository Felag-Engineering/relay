// Tag-space vocabulary. A tag: label is written only through the capability
// layer's tag write, by a human Account (ADR-0050); no Node report reaches it
// (invariant 7).
package registry

import (
	"errors"
	"fmt"
	"strings"
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

// Refusals of an Enrollment Token's initial tags.
var (
	// ErrInitialTagRelayLabel refuses a relay: label named where tags are
	// expected, whoever names it (ADR-0050).
	ErrInitialTagRelayLabel = errors.New("registry: a mint names no relay: label; relay: labels are written only by the Relay action that defines them, and relay:node-id by every enrollment (ADR-0050)")

	// ErrInitialTagMalformed refuses an entry that is not tag:key=value with a
	// well-formed key and value.
	ErrInitialTagMalformed = fmt.Errorf("registry: an initial tag is tag:key=value, with a non-empty key, and its key and value hold only A-Z, a-z, 0-9, '.', '_' and '-', the key at most %d characters and the value at most %d", MaxTagKeyLen, MaxTagValueLen)

	// ErrInitialTagKeyTwice refuses initial tags that name one key twice.
	ErrInitialTagKeyTwice = errors.New("registry: an initial tag names each key at most once")
)

// InitialTagError names the entry of an Enrollment Token's initial tags that was
// refused, and why. Err is one of the refusals above, so a caller matches it
// with errors.Is.
type InitialTagError struct {
	Entry string
	Err   error
}

func (e *InitialTagError) Error() string {
	return fmt.Sprintf("registry: initial tag %q: %v", e.Entry, e.Err)
}

func (e *InitialTagError) Unwrap() error { return e.Err }

// ParseInitialTags checks the initial tags an Enrollment Token names, each in
// written form "tag:key=value", and returns them as bare key to value. It is
// the one parse of initial tags: the mint, the check at enrollment and the write
// all call it. A relay: label is refused naming it, so the refusal is the same
// whoever mints; any other entry without the exact-case "tag:" prefix, a key or
// value that fails WellFormedLabel or the tag length bounds, a key named twice,
// and more than MaxTagsPerNode keys are refused too. Nothing is sanitised or
// truncated; nil or empty tags are an empty set. Who may mint tags is not
// decided here.
func ParseInitialTags(tags []string) (map[string]string, error) {
	parsed := make(map[string]string, len(tags))
	for _, entry := range tags {
		bounded, _ := BoundLogKey(entry)
		if strings.HasPrefix(entry, "relay:") {
			return nil, &InitialTagError{Entry: bounded, Err: ErrInitialTagRelayLabel}
		}
		rest, ok := strings.CutPrefix(entry, "tag:")
		if !ok {
			return nil, &InitialTagError{Entry: bounded, Err: ErrInitialTagMalformed}
		}
		key, value, ok := strings.Cut(rest, "=")
		if !ok || !WellFormedLabel(key, value) || len(key) > MaxTagKeyLen || len(value) > MaxTagValueLen {
			return nil, &InitialTagError{Entry: bounded, Err: ErrInitialTagMalformed}
		}
		if _, dup := parsed[key]; dup {
			return nil, &InitialTagError{Entry: bounded, Err: ErrInitialTagKeyTwice}
		}
		parsed[key] = value
	}
	if len(parsed) > MaxTagsPerNode {
		return nil, ErrTooManyTags
	}
	return parsed, nil
}
