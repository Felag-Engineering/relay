package hostfile

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// parseCapabilities reads CapInh, CapPrm, CapEff and CapAmb from /proc/<pid>/status. A missing or
// unparseable line is an error, never a zero.
func parseCapabilities(r io.Reader) (inh, prm, eff, amb uint64, err error) {
	var gotInh, gotPrm, gotEff, gotAmb bool
	sc := bufio.NewScanner(io.LimitReader(r, 64<<10))
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		var dst *uint64
		var got *bool
		switch key {
		case "CapInh":
			dst, got = &inh, &gotInh
		case "CapPrm":
			dst, got = &prm, &gotPrm
		case "CapEff":
			dst, got = &eff, &gotEff
		case "CapAmb":
			dst, got = &amb, &gotAmb
		default:
			continue
		}
		v, perr := strconv.ParseUint(strings.TrimSpace(val), 16, 64)
		if perr != nil {
			return 0, 0, 0, 0, fmt.Errorf("hostfile: %s: %w", key, perr)
		}
		*dst, *got = v, true
	}
	if err := sc.Err(); err != nil {
		return 0, 0, 0, 0, err
	}
	if !gotInh || !gotPrm || !gotEff || !gotAmb {
		return 0, 0, 0, 0, errors.New("hostfile: capability lines missing from process status")
	}
	return inh, prm, eff, amb, nil
}
