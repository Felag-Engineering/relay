package relayconfig

import (
	"strconv"
	"strings"
)

// Every message this package produces is text it wrote, formatted only from
// schema facts: key names, bounds and allowed values. Error and Warning have no
// field that could carry a configuration value or a line of source text, so a
// secret on a bad line cannot reach a log or an exit message (ADR-0043,
// invariant 11). The one exception is a key spelled in another case than the
// schema's: its spelling is rendered because every rune of it folds to a schema
// name's (RC-54), so it still cannot carry a value.

// Error is one refused setting: the key, the line it was written on, and why.
type Error struct {
	// Key is the dotted setting name, empty for a syntax error or an
	// unrecognised key.
	Key string
	// Line is 1-based; 0 means the key is absent from the file.
	Line   int
	Reason string

	// class is the only trace of a reader's error that survives: fs.ErrNotExist
	// or fs.ErrPermission, matched by errors.Is. The error itself is dropped,
	// because it can carry text the file check or the host wrote.
	class error
}

func (e *Error) Error() string { return render(e.Key, e.Line, e.Reason) }

// Is reports whether the failure is of the kind target names, for the two
// kinds a caller acts on: fs.ErrNotExist and fs.ErrPermission.
func (e *Error) Is(target error) bool { return e.class != nil && e.class == target }

// Warning is a setting that is accepted and likely wrong.
type Warning struct {
	Key    string
	Line   int
	Reason string
}

func (w Warning) String() string { return render(w.Key, w.Line, w.Reason) }

func render(key string, line int, reason string) string {
	var b strings.Builder
	b.WriteString("configuration: ")
	switch {
	case key != "" && line > 0:
		b.WriteString(key + " (line " + strconv.Itoa(line) + "): ")
	case key != "":
		b.WriteString(key + ": ")
	case line > 0:
		b.WriteString("line " + strconv.Itoa(line) + ": ")
	}
	b.WriteString(reason)
	return b.String()
}

// safeKey renders a key only if it is an exact path of the schema: a section
// or a section's key. Those names come from the schema; any other segment is
// source text and is never rendered. The case-variant check renders a spelling
// only after proving it folds to a schema name.
func safeKey(parts []string) (string, bool) {
	if key, _, depth, removed := removedKey(parts); removed && len(parts) == depth {
		return key, true
	}
	if len(parts) == 0 || schemaPrefix(parts) != len(parts) {
		return "", false
	}
	return strings.Join(parts, "."), true
}

// schemaPrefix is how many leading segments of parts form an exact schema path:
// a section, a section's key, or a gate-rule field.
func schemaPrefix(parts []string) int {
	if len(parts) == 0 || !sections[parts[0]] {
		return 0
	}
	if len(parts) >= 3 && parts[0] == "approval" && parts[1] == "rules" && ruleFields[parts[2]] {
		return 3
	}
	if len(parts) >= 2 && schemaKeySet[parts[0]+"."+parts[1]] {
		return 2
	}
	return 1
}

// unrecognised words an unknown key from the longest schema prefix of its
// path, so no segment outside the schema is rendered.
func unrecognised(parts []string, rest string) string {
	if n := schemaPrefix(parts); n > 0 {
		return "an unrecognised key in [" + strings.Join(parts[:n], ".") + "] " + rest
	}
	return "an unrecognised key " + rest
}
