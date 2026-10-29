package relayconfig

import (
	"strings"

	"github.com/pelletier/go-toml/v2/unstable"
)

const (
	keyRules = "approval.rules"

	// reasonRulesForm is fixed text: it names no value, no rule and no source
	// line (RC-18).
	reasonRulesForm = "must be written as [[approval.rules]] sections, one per rule"

	// reasonSpelling is fixed text: the decoder matches names without regard to
	// case, so a variant spelling is refused rather than let past the form check.
	reasonSpelling = "must be spelled exactly as the setting is named, in lower case"
)

// approvalNames are the keys of the approval table and ruleFieldNames the keys
// of a rule. A key spelled like one of them in another case is refused.
var (
	approvalNames  = []string{"rules", "webhook_url_file", "webhook_secret_file"}
	ruleFieldNames = []string{"name", "risk_class", "min_fan_out", "selector_namespace", "account", "operation", "raw_exec", "ttl"}
)

// misspelt returns the schema key of the first segment of full, within the
// approval subtree, that matches a schema name without regard to case but not
// byte for byte. The decoder accepts such a spelling, so Rules or Risk_Class
// would otherwise replace, empty or narrow the operator's rules unseen (AP-8).
func misspelt(full []string) (string, bool) {
	if len(full) == 0 || !foldEq(full[0], "approval") {
		return "", false
	}
	if full[0] != "approval" {
		return "approval", true
	}
	exact, variant := foldMatch(full, 1, approvalNames)
	if variant != "" {
		return "approval." + variant, true
	}
	if exact != "rules" {
		return "", false
	}
	_, variant = foldMatch(full, 2, ruleFieldNames)
	if variant != "" {
		return keyRules + "." + variant, true
	}
	return "", false
}

// foldEq reports whether a and the lower-case name n fold together as the
// decoder folds keys: by strings.ToLower, which maps U+0130 to "i" where
// strings.EqualFold does not.
func foldEq(a, n string) bool {
	return strings.EqualFold(a, n) || strings.ToLower(a) == n
}

// foldMatch compares full[i] with names. It returns the name it spells exactly,
// or else the name it matches only in another case; both are empty when full
// has no such segment or it matches no name.
func foldMatch(full []string, i int, names []string) (exact, variant string) {
	if i >= len(full) {
		return "", ""
	}
	for _, n := range names {
		if full[i] == n {
			return n, ""
		}
	}
	for _, n := range names {
		if foldEq(full[i], n) {
			return "", n
		}
	}
	return "", ""
}

// ruleForm refuses every way of writing gate rules other than [[approval.rules]]
// array tables (AP-89): an inline array, any other value written at
// approval.rules, a dotted rules.<field> outside a rule section, and the
// single-bracket [approval.rules] table. One form keeps one line-index element
// per rule, and it keeps a refused field nameable as approval.rules.<field>,
// which the decoder cannot do for a field inside an inline array.
//
// It runs before decode, over the parser's expressions, and reads only keys and
// lines. If the parser stops on a syntax error it returns what it found so far,
// and decode reports the syntax error.
func ruleForm(data []byte) []*Error {
	var (
		errs       []*Error
		p          unstable.Parser
		header     []string
		haveRule   bool                // an [[approval.rules]] section has been seen
		named      = map[string]bool{} // schema keys already refused for their spelling
		refuseForm = func(key, reason string, line int) {
			// A spelling refusal repeats for every variant key of one schema key;
			// the other reasons are each worth their own line.
			if reason == reasonSpelling {
				if named[key] {
					return
				}
				named[key] = true
			}
			errs = append(errs, &Error{Key: key, Line: line, Reason: reason})
		}
	)
	p.Reset(data)
	for p.NextExpression() {
		n := p.Expression()
		switch n.Kind {
		case unstable.Table, unstable.ArrayTable:
			parts, line := keyParts(&p, n)
			header = parts
			key := strings.Join(parts, ".")
			schemaKey, variant := misspelt(parts)
			switch {
			case variant:
				refuseForm(schemaKey, reasonSpelling, line)
			case n.Kind == unstable.Table && key == keyRules:
				refuseForm(keyRules, reasonRulesForm, line)
			case n.Kind == unstable.ArrayTable && key == keyRules:
				haveRule = true
			case strings.HasPrefix(key, keyRules+".") && !haveRule:
				refuseForm(keyRules, reasonRulesForm, line)
			}
		case unstable.KeyValue:
			parts, line := keyParts(&p, n)
			inRules := haveRule && withinRules(strings.Join(header, "."))
			checkRuleKeyValue(&p, n, append(append([]string(nil), header...), parts...), line, inRules, refuseForm)
		}
	}
	return errs
}

// withinRules reports whether a header key is the rules section or a table
// under it.
func withinRules(headerKey string) bool {
	return headerKey == keyRules || strings.HasPrefix(headerKey, keyRules+".")
}

// checkRuleKeyValue refuses a key/value whose full key is spelled in another
// case than the schema's, is approval.rules, or is under it without having been
// written inside a rule section, and recurses into an inline table value so
// approval = { rules = ... } is caught too.
func checkRuleKeyValue(p *unstable.Parser, n *unstable.Node, full []string, line int, inRules bool, refuse func(key, reason string, line int)) {
	if schemaKey, variant := misspelt(full); variant {
		refuse(schemaKey, reasonSpelling, line)
		return
	}
	key := strings.Join(full, ".")
	if key == keyRules || (strings.HasPrefix(key, keyRules+".") && !inRules) {
		refuse(keyRules, reasonRulesForm, line)
		return
	}
	if v := n.Value(); v.Kind == unstable.InlineTable {
		it := v.Children()
		for it.Next() {
			child := it.Node()
			parts, childLine := keyParts(p, child)
			checkRuleKeyValue(p, child, append(append([]string(nil), full...), parts...), childLine, inRules, refuse)
		}
	}
}
