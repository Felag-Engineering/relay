package relayconfig

import (
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/pelletier/go-toml/v2/unstable"
)

// The pre-decode pass over the file's keys: a key the decoder would accept only
// because it folds case is refused, anywhere in the file (RC-54), and so is every
// way of writing gate rules but the [[approval.rules]] array table (RC-53).

// reasonSpelling is fixed text. The decoder folds case at every level, so a
// variant spelling would set, or silently override, the setting it folds to; the
// refusal appends the spelling as written (renderSegment says why that carries
// no value).
const reasonSpelling = "must be spelled exactly as the setting is named, in lower case"

// schemaNode is the keys a table has; a nil value is a leaf.
type schemaNode map[string]schemaNode

// schemaTree is the schema's key tree, derived from document so a key added to
// the schema is covered with no second edit.
var schemaTree = buildSchemaNode(reflect.TypeFor[document]())

func buildSchemaNode(t reflect.Type) schemaNode {
	node := schemaNode{}
	for i := range t.NumField() {
		f := t.Field(i)
		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		// An array table's keys are the element's, so a slice is unwrapped to it.
		if ft.Kind() == reflect.Slice {
			ft = ft.Elem()
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
		}
		var child schemaNode
		if ft.Kind() == reflect.Struct {
			child = buildSchemaNode(ft)
		}
		node[f.Tag.Get("toml")] = child
	}
	return node
}

// foldEq reports whether a and the lower-case name n fold together as the
// decoder folds keys: by strings.ToLower, which maps U+0130 to "i" where
// strings.EqualFold does not.
func foldEq(a, n string) bool {
	return strings.EqualFold(a, n) || strings.ToLower(a) == n
}

// caseVariant walks full from the schema root. It stops at the first segment
// that matches no schema name, or past a leaf, and never reads or renders what
// follows. It returns the schema's spelling of the path walked and the path as
// written, and ok when a segment at index own or later matches only in another
// case. own is where the node's own key parts begin in full: segments before it
// were refused with the node that wrote them.
func caseVariant(full []string, own int) (schemaKey, written string, ok bool) {
	var schemaParts, writtenParts []string
	node := schemaTree
	for i, seg := range full {
		if node == nil {
			break
		}
		name, exact := seg, true
		child, found := node[seg]
		if !found {
			exact = false
			// At most one lower-case schema name folds to a segment, so the
			// first match is the only one whatever the map's order.
			for n, c := range node {
				if foldEq(seg, n) {
					name, child, found = n, c, true
					break
				}
			}
		}
		if !found {
			break
		}
		schemaParts = append(schemaParts, name)
		writtenParts = append(writtenParts, renderSegment(seg, name))
		if !exact && i >= own {
			ok = true
		}
		node = child
	}
	return strings.Join(schemaParts, "."), strings.Join(writtenParts, "."), ok
}

// renderSegment returns the spelling of a segment for a refusal. A segment
// reaches here only after it folds to a schema name, whose runes are lower-case
// ASCII letters, numerals and the underscore; the runes that fold to those are
// ASCII letters, U+0130, U+212A and U+017F, so the spelling carries no value and
// no control or bidi character (RC-18). The rune test is a second guard that
// falls back to the schema spelling.
func renderSegment(written, name string) string {
	if !utf8.ValidString(written) {
		return name
	}
	for _, r := range written {
		if !unicode.IsLetter(r) && (r < '0' || r > '9') && r != '_' {
			return name
		}
	}
	return written
}

// preDecode is the one pass before decode, over the parser's expressions,
// reading only keys and lines. It refuses a case-variant key anywhere in the
// file (RC-54) and every way of writing gate rules other than [[approval.rules]]
// array tables (AP-89, RC-53): an inline array, any other value written at
// approval.rules, a dotted rules.<field> outside a rule section, and the
// single-bracket [approval.rules] table. One form keeps one line-index element
// per rule, and it keeps a refused field nameable as approval.rules.<field>,
// which the decoder cannot do for a field inside an inline array.
//
// If the parser stops on a syntax error it returns what it found so far, and
// decode reports the syntax error.
func preDecode(data []byte) []*Error {
	var (
		errs           []*Error
		p              unstable.Parser
		header         []string
		haveRule       bool                // an [[approval.rules]] section has been seen
		named          = map[string]bool{} // written spellings already refused
		refuseSpelling = func(schemaKey, written string, line int) {
			if named[written] {
				return
			}
			named[written] = true
			errs = append(errs, &Error{Key: schemaKey, Line: line, Reason: reasonSpelling + "; it is written " + written})
		}
		refuseForm = func(key, reason string, line int) {
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
			schemaKey, written, variant := caseVariant(parts, 0)
			switch {
			case variant:
				refuseSpelling(schemaKey, written, line)
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
			full := append(append([]string(nil), header...), parts...)
			checkKeyValue(&p, n, full, len(header), line, inRules, refuseSpelling, refuseForm)
		}
	}
	return errs
}

// checkKeyValue refuses a key/value whose own key parts are spelled in another
// case than the schema's, is approval.rules, or is under it without having been
// written inside a rule section, and recurses into an inline table value so
// approval = { rules = ... } is caught too. own is where the key/value's own
// parts begin in full.
func checkKeyValue(p *unstable.Parser, n *unstable.Node, full []string, own, line int, inRules bool,
	refuseSpelling func(schemaKey, written string, line int), refuseForm func(key, reason string, line int)) {
	if schemaKey, written, variant := caseVariant(full, own); variant {
		refuseSpelling(schemaKey, written, line)
		return
	}
	key := strings.Join(full, ".")
	if key == keyRules || (strings.HasPrefix(key, keyRules+".") && !inRules) {
		refuseForm(keyRules, reasonRulesForm, line)
		return
	}
	if v := n.Value(); v.Kind == unstable.InlineTable {
		it := v.Children()
		for it.Next() {
			child := it.Node()
			parts, childLine := keyParts(p, child)
			checkKeyValue(p, child, append(append([]string(nil), full...), parts...), len(full), childLine, inRules, refuseSpelling, refuseForm)
		}
	}
}
