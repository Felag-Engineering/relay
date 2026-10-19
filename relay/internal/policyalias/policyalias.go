// Package policyalias holds the domain vocabulary for Policy aliases: a display
// name the Relay keeps for a Policy fingerprint.
//
// An alias is not Policy and never leaves the Relay (invariant 2): it is never
// sent to a Node, never part of a Selector, never an input to a dispatch. It
// attaches to a fingerprint and to nothing else (invariant 9).
package policyalias

import (
	"context"
	"errors"
)

// Reader lists every Policy alias held, fingerprint to alias. The map is fresh
// on each call and never nil.
type Reader interface {
	List(ctx context.Context) (map[string]string, error)
}

// Change is one alias set, rename or clear for a single fingerprint. From and
// To are the alias before and after; "" means no alias. It names no Node,
// Label, Selector or group.
type Change struct {
	Fingerprint string
	From        string
	To          string
}

var (
	// ErrTaken reports that another fingerprint already carries the new alias.
	ErrTaken = errors.New("policyalias: the alias already names another Policy fingerprint")

	// ErrChanged reports that the fingerprint's stored alias is not the From
	// value the change was made against.
	ErrChanged = errors.New("policyalias: the fingerprint's alias changed since it was read")
)
