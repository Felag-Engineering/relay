package console

import (
	"github.com/Felag-Engineering/relay/relay/internal/policyview"
	"github.com/Felag-Engineering/relay/relay/internal/visibletext"
)

// visiblePolicy returns a display copy of a Node-reported Policy snapshot with
// every string a Node chose passed through visibletext.Escape, so a hidden or
// bidirectional character in a pattern, an Operation name or an argument is
// drawn as a visible escape (the rule in audit-and-read-lane.md).
//
// It transforms a copy for presentation only: the policyview cache is never
// touched, and nothing here evaluates or writes Policy (invariants 2 and 12).
// The escaping is injective, so comparing two escaped snapshots, as Compare
// does, is exactly as precise as comparing the raw ones.
func visiblePolicy(s policyview.Snapshot) policyview.Snapshot {
	out := s
	out.RawAllowPatterns = escapeAll(s.RawAllowPatterns)
	out.RawDenyPatterns = escapeAll(s.RawDenyPatterns)
	out.AllowedOperations = escapeAll(s.AllowedOperations)
	if s.OperationRules != nil {
		out.OperationRules = make([]policyview.OperationRule, len(s.OperationRules))
		for i, r := range s.OperationRules {
			out.OperationRules[i] = r
			out.OperationRules[i].Name = visibletext.Escape(r.Name)
			out.OperationRules[i].AllowedArgs = escapeArgSets(r.AllowedArgs)
		}
	}
	if s.DenyRules != nil {
		out.DenyRules = make([]policyview.DenyRule, len(s.DenyRules))
		for i, r := range s.DenyRules {
			out.DenyRules[i] = r
			out.DenyRules[i].Name = visibletext.Escape(r.Name)
			out.DenyRules[i].Args = escapeArgSets(r.Args)
		}
	}
	return out
}

func escapeAll(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = visibletext.Escape(v)
	}
	return out
}

func escapeArgSets(in [][]string) [][]string {
	if in == nil {
		return nil
	}
	out := make([][]string, len(in))
	for i, set := range in {
		out[i] = escapeAll(set)
	}
	return out
}
