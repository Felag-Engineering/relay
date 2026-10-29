package relayconfig

import (
	"strings"

	"github.com/pelletier/go-toml/v2/unstable"
)

// lineIndex maps each dotted key written in the file to the line it starts on.
type lineIndex struct {
	lines map[string]int
	// repeats maps a line to the key it writes for a second time.
	repeats map[int][]string
	// elems holds, for each array-table key, one map per element: the line of
	// each full key written inside that element, and the element's own header
	// line under "". An element's keys are recorded here and never as repeats
	// of an earlier element's, because each [[...]] section is a new element
	// rather than a key set twice.
	elems map[string][]map[string]int
}

// keyLines indexes data. It may run on a file that failed to decode; a short
// index only lowers a reported line to its nearest ancestor or to 0.
func keyLines(data []byte) lineIndex {
	idx := lineIndex{lines: map[string]int{}, repeats: map[int][]string{}, elems: map[string][]map[string]int{}}
	var p unstable.Parser
	p.Reset(data)
	var (
		table []string
		// elem is the element of the array table the current header opens, nil
		// under an ordinary table.
		elem map[string]int
	)
	for p.NextExpression() {
		n := p.Expression()
		switch n.Kind {
		case unstable.Table:
			parts, line := keyParts(&p, n)
			table, elem = parts, nil
			idx.record(table, line)
		case unstable.ArrayTable:
			parts, line := keyParts(&p, n)
			table = parts
			k := strings.Join(parts, ".")
			if _, seen := idx.lines[k]; !seen {
				idx.lines[k] = line
			}
			elem = map[string]int{"": line}
			idx.elems[k] = append(idx.elems[k], elem)
		case unstable.KeyValue:
			idx.recordKeyValue(&p, n, table, elem)
		}
	}
	return idx
}

func (idx lineIndex) recordKeyValue(p *unstable.Parser, n *unstable.Node, prefix []string, elem map[string]int) {
	parts, line := keyParts(p, n)
	full := append(append([]string(nil), prefix...), parts...)
	if elem == nil {
		idx.record(full, line)
	} else {
		idx.recordInElement(elem, full, line)
	}
	if v := n.Value(); v.Kind == unstable.InlineTable {
		it := v.Children()
		for it.Next() {
			idx.recordKeyValue(p, it.Node(), full, elem)
		}
	}
}

// recordInElement records a key written inside an array-table element. A key
// repeated within the same element is a repeat; the same key in another element
// is not. The first line seen is also kept in lines, so of() still finds one.
func (idx lineIndex) recordInElement(elem map[string]int, parts []string, line int) {
	k := strings.Join(parts, ".")
	if _, seen := elem[k]; seen {
		idx.repeats[line] = parts
		return
	}
	elem[k] = line
	if _, seen := idx.lines[k]; !seen {
		idx.lines[k] = line
	}
}

func (idx lineIndex) record(parts []string, line int) {
	k := strings.Join(parts, ".")
	if _, seen := idx.lines[k]; seen {
		idx.repeats[line] = parts
		return
	}
	idx.lines[k] = line
}

// keyParts returns the dotted key of a table header or key/value node and the
// line its first part is written on.
func keyParts(p *unstable.Parser, n *unstable.Node) ([]string, int) {
	var parts []string
	line := 0
	it := n.Key()
	for it.Next() {
		k := it.Node()
		if line == 0 {
			line = p.Shape(k.Raw).Start.Line
		}
		parts = append(parts, string(k.Data))
	}
	return parts, line
}

// of returns the line of key, falling back to the nearest recorded ancestor,
// then to 0.
func (idx lineIndex) of(key string) int {
	for key != "" {
		if line, ok := idx.lines[key]; ok {
			return line
		}
		i := strings.LastIndexByte(key, '.')
		if i < 0 {
			return 0
		}
		key = key[:i]
	}
	return 0
}

// elemLine returns the line of field in element i of the array table key: the
// field's own line, else the element's header line, else the key's line, else
// 0. An index outside the elements falls back to of(key), so no input can make
// a lookup go out of range.
func (idx lineIndex) elemLine(key string, i int, field string) int {
	elems := idx.elems[key]
	if i < 0 || i >= len(elems) {
		return idx.of(key)
	}
	if line, ok := elems[i][key+"."+field]; ok {
		return line
	}
	return elems[i][""]
}
