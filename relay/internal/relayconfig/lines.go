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
}

// keyLines indexes data. It may run on a file that failed to decode; a short
// index only lowers a reported line to its nearest ancestor or to 0.
func keyLines(data []byte) lineIndex {
	idx := lineIndex{lines: map[string]int{}, repeats: map[int][]string{}}
	var p unstable.Parser
	p.Reset(data)
	var table []string
	for p.NextExpression() {
		n := p.Expression()
		switch n.Kind {
		case unstable.Table, unstable.ArrayTable:
			parts, line := keyParts(&p, n)
			table = parts
			idx.record(table, line)
		case unstable.KeyValue:
			idx.recordKeyValue(&p, n, table)
		}
	}
	return idx
}

func (idx lineIndex) recordKeyValue(p *unstable.Parser, n *unstable.Node, prefix []string) {
	parts, line := keyParts(p, n)
	full := append(append([]string(nil), prefix...), parts...)
	idx.record(full, line)
	if v := n.Value(); v.Kind == unstable.InlineTable {
		it := v.Children()
		for it.Next() {
			idx.recordKeyValue(p, it.Node(), full)
		}
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
