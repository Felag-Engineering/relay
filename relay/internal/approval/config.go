package approval

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/hostfile"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// The approval-gate file is Relay CONFIGURATION, not a runtime object
// (invariant 11). It sits with the blast cap on the host administrator's side
// of the line: the Control API can never read or write it, and no Account of
// any role can loosen it, because a stolen credential that could edit its own
// approval requirements would make the whole mechanism decorative.
//
// It is a file the Relay's configuration names (approval.gate_rules_path),
// read under the same file check as the configuration itself (ADR-0043), and
// it mirrors a pattern the product already trusts: the relay-daemon's local
// Policy file with a fail-closed loader (ADR-0002).
//
// Format is JSON, parsed by encoding/json from the standard library. That is a
// deliberate trade: TOML or YAML would be friendlier to hand-author, but both
// mean adding a parser dependency to a security-critical control plane to parse
// a security-critical file, and this repo does not add supply-chain surface for
// ergonomics. In practice the file is rendered by config management.

// MaxConfigBytes bounds the config file. A gate file is small; the bound stops
// a pathological file from being read into memory before it is rejected.
const MaxConfigBytes = 1 << 20 // 1 MiB

// fileConfig is the on-disk shape. It is separate from Rule so the wire format
// and the domain model can evolve independently, and so durations can be
// human-authored strings ("2h") rather than nanosecond integers.
type fileConfig struct {
	Rules []fileRule `json:"rules"`
}

type fileRule struct {
	Name  string          `json:"name"`
	Match fileMatch       `json:"match"`
	Req   fileRequirement `json:"require"`
}

type fileMatch struct {
	RiskClass         string `json:"risk_class,omitempty"`
	MinFanOut         int    `json:"min_fan_out,omitempty"`
	SelectorNamespace string `json:"selector_namespace,omitempty"`
	Account           string `json:"account,omitempty"`
	Operation         string `json:"operation,omitempty"`
	RawExec           bool   `json:"raw_exec,omitempty"`
}

type fileRequirement struct {
	Count    int      `json:"count"`
	Audience []string `json:"audience,omitempty"`
	// RequesterAllowed defaults to FALSE when omitted, which is the strict
	// reading: a rule that does not say otherwise requires a second person.
	// This is the one place where Go's zero value happens to be the
	// fail-closed answer, and it is relied on deliberately rather than by
	// accident — see the note in Parse.
	RequesterAllowed bool   `json:"requester_allowed,omitempty"`
	Channel          string `json:"channel,omitempty"`
	TTL              string `json:"ttl,omitempty"`
}

// Load reads and validates the approval-gate configuration at path.
//
// An EMPTY path means "no approvals configured" and returns an empty Gate. That
// is the only way to get a gate-less Relay, and it is explicit.
//
// Every other outcome that is not a fully valid file is an ERROR, never an
// empty Gate. This asymmetry is the entire security property of this function:
// a missing, unreadable, malformed, or suspiciously-permissioned file must
// never degrade into "nothing needs approval". The caller is expected to treat
// the error as fatal at startup, exactly as the relay-daemon treats an
// unloadable Policy file (ADR-0002).
//
// The file is one the configuration names, so it is opened through hostfile's
// check (RC-15, RC-16) and read from the descriptor that was checked; the
// file's own mode rule (RC-8) is applied on that descriptor as well.
func Load(path string) (*Gate, error) {
	if path == "" {
		return NewGate(nil)
	}
	f, err := hostfile.Open(path, hostfile.Named)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Pointedly NOT "no gates configured": the operator named a file,
			// so its absence is a deployment error. Silently continuing here
			// is precisely how an approval mechanism becomes decorative.
			return nil, fmt.Errorf("approval: gate config %s does not exist — "+
				"a configured gate file must be present; configure no path at all to run without approval gates", path)
		}
		return nil, fmt.Errorf("approval: gate config: %w", err)
	}
	return loadOpened(f, path)
}

// loadOpened applies the gate file's own mode rule to f, the descriptor the
// file check passed, then reads and parses it. It closes f.
func loadOpened(f *os.File, path string) (*Gate, error) {
	defer f.Close() //nolint:errcheck // read-only

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("approval: stat gate config %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("approval: gate config %s is not a regular file (mode %s)", path, info.Mode())
	}
	// Group- or world-writable means someone other than the owner can rewrite
	// the fleet's approval requirements (RC-8). This is stricter than the file
	// check, which passes a group-writable file whose group excludes the Relay
	// (root:wheel 0664, say): refuse rather than warn, since a warning in a log
	// nobody reads is not a control.
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return nil, fmt.Errorf("approval: gate config %s is group- or world-writable (mode %04o) — "+
			"it decides what needs human approval, so it must be writable only by its owner (chmod 0644 or stricter)",
			path, perm)
	}

	data, err := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("approval: read %s: %w", path, err)
	}
	if len(data) > MaxConfigBytes {
		return nil, fmt.Errorf("approval: %s is larger than the %d-byte limit for a gate file", path, MaxConfigBytes)
	}

	return Parse(data)
}

// Parse validates raw gate-config bytes into a Gate. Exported so tests and a
// future `relay approval check` subcommand can validate without a file.
func Parse(data []byte) (*Gate, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	// A typo'd field must not be silently ignored: "requester_allowd": true
	// would otherwise leave the strict default in place while the operator
	// believes they relaxed it — or, worse, the mirror-image mistake in the
	// other direction on a field that does relax something.
	dec.DisallowUnknownFields()

	var fc fileConfig
	if err := dec.Decode(&fc); err != nil {
		return nil, fmt.Errorf("approval: parse gate config: %w", err)
	}
	if dec.More() {
		return nil, errors.New("approval: parse gate config: trailing content after the JSON document")
	}

	rules := make([]Rule, 0, len(fc.Rules))
	for i, fr := range fc.Rules {
		r, err := fr.toRule(i)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return NewGate(rules)
}

func (fr fileRule) toRule(index int) (Rule, error) {
	where := fr.Name
	if where == "" {
		where = fmt.Sprintf("rule #%d", index)
	}

	risk, err := parseRiskClass(fr.Match.RiskClass)
	if err != nil {
		return Rule{}, fmt.Errorf("approval: %s: %w", where, err)
	}
	ch, err := parseChannel(fr.Req.Channel)
	if err != nil {
		return Rule{}, fmt.Errorf("approval: %s: %w", where, err)
	}
	ttl, err := parseTTL(fr.Req.TTL)
	if err != nil {
		return Rule{}, fmt.Errorf("approval: %s: %w", where, err)
	}

	return Rule{
		Name: fr.Name,
		Match: Match{
			RiskClass:         risk,
			MinFanOut:         fr.Match.MinFanOut,
			SelectorNamespace: fr.Match.SelectorNamespace,
			Account:           fr.Match.Account,
			Operation:         fr.Match.Operation,
			RawExec:           fr.Match.RawExec,
		},
		Require: Requirement{
			Count:            fr.Req.Count,
			Audience:         fr.Req.Audience,
			RequesterAllowed: fr.Req.RequesterAllowed,
			Channel:          ch,
			TTL:              ttl,
		},
	}, nil
}

// parseRiskClass reads a rule's match criterion. An empty value means the rule
// matches either class.
func parseRiskClass(s string) (jobs.RiskClass, error) {
	if s == "" {
		return jobs.RiskClassUnspecified, nil
	}
	risk, ok := jobs.ParseRiskClass(s)
	if !ok {
		return jobs.RiskClassUnspecified, fmt.Errorf("unknown risk_class %q (want read or mutate)", s)
	}
	return risk, nil
}

func parseChannel(s string) (Channel, error) {
	switch s {
	case "":
		return ChannelUnspecified, nil // normalized() upgrades this to out-of-band
	case "in-band":
		return ChannelInBand, nil
	case "out-of-band":
		return ChannelOutOfBand, nil
	default:
		return ChannelUnspecified, fmt.Errorf("unknown channel %q (want in-band or out-of-band)", s)
	}
}

func parseTTL(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil // normalized() applies DefaultTTL
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid ttl %q: %w", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("ttl %q must be positive", s)
	}
	return d, nil
}
