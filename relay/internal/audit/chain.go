package audit

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// The audit chain (#896). Every audit row carries a seq, the previous row's
// hash, and its own hash over (domain tag, seq, prev_hash, canonical row
// bytes). Edits, middle deletions and out-of-chain inserts break the walk;
// tail truncation and a re-chain are detectable only against an anchor — a
// (seq, hash) pair taken from an earlier checkpoint. This package holds the
// encoding and the verifier's state machine and stays SQL-free: the store
// feeds it decoded Records.

// ChainFormat names the canonical encoding. It is the checkpoint line's
// "format" value and is folded into every hash through chainDomain, so a v2
// encoding can never produce a hash a v1 verifier would accept.
const ChainFormat = "relay-audit-chain/v1"

var chainDomain = []byte(ChainFormat + "\n")

// ChainHash is a SHA-256 chain hash.
type ChainHash [32]byte

// Hex renders h as 64 lowercase hex characters.
func (h ChainHash) Hex() string { return hex.EncodeToString(h[:]) }

// ParseChainHash accepts exactly 64 lowercase hex characters.
func ParseChainHash(s string) (ChainHash, error) {
	var h ChainHash
	if len(s) != 2*len(h) {
		return h, fmt.Errorf("chain hash %q: want %d lowercase hex characters", s, 2*len(h))
	}
	if s != strings.ToLower(s) {
		return h, fmt.Errorf("chain hash %q: must be lowercase hex", s)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return h, fmt.Errorf("chain hash %q: %w", s, err)
	}
	copy(h[:], b)
	return h, nil
}

// GenesisPrevHash is the prev_hash of the first row (seq 1): all zero.
var GenesisPrevHash ChainHash

// ChainHead is the newest chained row's position. An empty trail is
// {0, GenesisPrevHash}.
type ChainHead struct {
	Seq  uint64
	Hash ChainHash
}

// ChainAnchor is a (seq, hash) pair an operator trusts, normally copied from
// an "audit chain checkpoint" log line.
type ChainAnchor struct {
	Seq  uint64
	Hash ChainHash
}

// ParseChainAnchor parses "SEQ:HASH". The checkpoint log line's seq and hash
// values paste straight into this form.
func ParseChainAnchor(s string) (ChainAnchor, error) {
	seqText, hashText, ok := strings.Cut(s, ":")
	if !ok {
		return ChainAnchor{}, fmt.Errorf("anchor %q: want SEQ:HASH", s)
	}
	seq, err := strconv.ParseUint(seqText, 10, 64)
	if err != nil || seq < 1 {
		return ChainAnchor{}, fmt.Errorf("anchor %q: SEQ must be a decimal integer of at least 1", s)
	}
	h, err := ParseChainHash(hashText)
	if err != nil {
		return ChainAnchor{}, fmt.Errorf("anchor %q: %w", s, err)
	}
	return ChainAnchor{Seq: seq, Hash: h}, nil
}

// canonicalTimeLayout is the same layout as the store's auditTimeLayout:
// UTC, nine fractional digits. It is restated here, not imported, because the
// store depends on this package.
const canonicalTimeLayout = "2006-01-02T15:04:05.000000000Z"

// CanonicalBytes is the v1 encoding of r that the chain hashes. Each of the
// 31 fields is written as uint32be(len) followed by its bytes, in a fixed
// order. It encodes the decoded Record, so two stored spellings of one Record
// (NULL and ” for an empty string, two renderings of one instant) hash
// alike; nil and empty maps, slices and byte slices are the same.
func CanonicalBytes(r Record) []byte {
	var b []byte
	field := func(s string) {
		b = binary.BigEndian.AppendUint32(b, uint32(len(s))) //nolint:gosec // G115: a field is far under 4 GiB (the daemon caps output at 1 MiB per stream)
		b = append(b, s...)
	}
	ts := ""
	if !r.Timestamp.IsZero() {
		ts = r.Timestamp.UTC().Format(canonicalTimeLayout)
	}
	v, as := r.Attribution.Verified, r.Attribution.Asserted

	field(r.ID)
	field(ts)
	field(r.Kind)
	field(r.Principal)
	field(v.AccountID)
	field(v.AccountName)
	field(v.Role)
	field(v.TokenID)
	field(v.Method)
	field(v.Source)
	field(as.OnBehalfOf)
	field(as.Traceparent)
	field(as.SessionRef)
	field(as.ChangeRef)
	field(r.Selector)
	field(r.JobID)
	field(r.NodeID)
	field(r.ActionKind)
	field(r.OperationName)

	// Args: a count, then key-sorted pairs.
	keys := make([]string, 0, len(r.Args))
	for k := range r.Args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b = binary.BigEndian.AppendUint32(b, uint32(len(keys))) //nolint:gosec // G115: a map's entry count, far under 4 billion
	for _, k := range keys {
		field(k)
		field(r.Args[k])
	}

	b = binary.BigEndian.AppendUint32(b, uint32(len(r.RawExecArgv))) //nolint:gosec // G115: an argv's length, far under 4 billion
	for _, a := range r.RawExecArgv {
		field(a)
	}

	b = binary.BigEndian.AppendUint64(b, uint64(int64(r.Outcome))) //nolint:gosec // G115: two's-complement bits of the int64, which is the encoding
	field(r.Reason)
	field(string(r.Stdout))
	field(string(r.Stderr))
	if r.Truncated {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	field(r.ApprovalID)
	field(r.GrantID)
	field(r.ApprovalAnswer)
	field(r.DecisionChannel)
	field(r.PlanHash)
	return b
}

// ComputeChainHash is SHA-256(chainDomain ‖ uint64be(seq) ‖ prev ‖ CanonicalBytes(r)).
func ComputeChainHash(seq uint64, prev ChainHash, r Record) ChainHash {
	h := sha256.New()
	h.Write(chainDomain)
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seq)
	h.Write(s[:])
	h.Write(prev[:])
	h.Write(CanonicalBytes(r))
	var out ChainHash
	h.Sum(out[:0])
	return out
}

// BreakReason says how a walk failed.
type BreakReason string

const (
	// BreakSeqGap: a row's seq is not the previous seq + 1. The break is
	// reported against the row AFTER the gap, since that is the only row the
	// walk can see; Detail names the seq that was expected.
	BreakSeqGap BreakReason = "seq_gap"
	// BreakPrevMismatch: prev_hash is not the previous row's hash.
	BreakPrevMismatch BreakReason = "prev_hash_mismatch"
	// BreakHashMismatch: the row's content does not hash to its stored hash.
	BreakHashMismatch BreakReason = "hash_mismatch"
	// BreakMalformed: a chain column is NULL, not valid hex, or seq is not positive.
	BreakMalformed BreakReason = "malformed"
	// BreakAnchorMismatch: the stored hash at an anchor's seq differs from it.
	BreakAnchorMismatch BreakReason = "anchor_mismatch"
	// BreakAnchorBeyondHead: an anchor names a seq past the chain's head.
	BreakAnchorBeyondHead BreakReason = "anchor_beyond_head"
)

// ChainBreak is the first place a walk failed.
type ChainBreak struct {
	Seq     uint64
	AuditID string
	Reason  BreakReason
	Detail  string
}

// ChainVerifier is the walk's state machine. It holds the previous row's
// position and the anchors only, so memory is O(anchors), not O(rows).
type ChainVerifier struct {
	anchors  map[uint64]ChainHash
	consumed map[uint64]struct{}
	head     ChainHead
	rows     uint64
}

// NewChainVerifier builds a verifier that also checks anchors. Two anchors at
// one seq with different hashes contradict each other and are an error.
func NewChainVerifier(anchors ...ChainAnchor) (*ChainVerifier, error) {
	v := &ChainVerifier{
		anchors:  make(map[uint64]ChainHash, len(anchors)),
		consumed: make(map[uint64]struct{}, len(anchors)),
		head:     ChainHead{Hash: GenesisPrevHash},
	}
	for _, a := range anchors {
		if prev, ok := v.anchors[a.Seq]; ok && prev != a.Hash {
			return nil, fmt.Errorf("contradictory anchors at seq %d: %s and %s", a.Seq, prev.Hex(), a.Hash.Hex())
		}
		v.anchors[a.Seq] = a.Hash
	}
	return v, nil
}

// Check verifies the next row in seq order. seq is the row's stored seq (the
// caller rejects a non-positive one as BreakMalformed before converting).
// prevHex and hashHex are the stored columns; a NULL column is passed as ""
// and reported as BreakMalformed. A seq gap is reported against the row after
// the gap, with the expected seq in Detail. It returns nil if the row extends
// the chain, else the break, after which the verifier must not be used.
func (v *ChainVerifier) Check(seq uint64, prevHex, hashHex string, r Record) *ChainBreak {
	brk := func(reason BreakReason, format string, args ...any) *ChainBreak {
		return &ChainBreak{Seq: seq, AuditID: r.ID, Reason: reason, Detail: fmt.Sprintf(format, args...)}
	}

	prev, perr := ParseChainHash(prevHex)
	stored, herr := ParseChainHash(hashHex)
	if err := errors.Join(perr, herr); err != nil {
		return brk(BreakMalformed, "prev_hash or hash column unusable: %v", err)
	}
	if want := v.head.Seq + 1; seq != want {
		return brk(BreakSeqGap, "expected seq %d, found %d", want, seq)
	}
	if prev != v.head.Hash {
		return brk(BreakPrevMismatch, "prev_hash %s is not the previous row's hash %s", prev.Hex(), v.head.Hash.Hex())
	}
	if got := ComputeChainHash(seq, prev, r); got != stored {
		return brk(BreakHashMismatch, "row content hashes to %s, stored hash is %s", got.Hex(), stored.Hex())
	}
	if want, ok := v.anchors[seq]; ok {
		if want != stored {
			return brk(BreakAnchorMismatch, "checkpoint expected %s, store has %s", want.Hex(), stored.Hex())
		}
		v.consumed[seq] = struct{}{}
	}

	v.head = ChainHead{Seq: seq, Hash: stored}
	v.rows++
	return nil
}

// Finish ends a walk that found no break: the lowest anchor the walk never
// reached means rows were truncated from the tail.
func (v *ChainVerifier) Finish() *ChainBreak {
	var lowest uint64
	for seq := range v.anchors {
		if _, done := v.consumed[seq]; done {
			continue
		}
		if lowest == 0 || seq < lowest {
			lowest = seq
		}
	}
	if lowest == 0 {
		return nil
	}
	return &ChainBreak{
		Seq:    lowest,
		Reason: BreakAnchorBeyondHead,
		Detail: fmt.Sprintf("checkpoint at seq %d but chain head is %d: rows truncated from the tail", lowest, v.head.Seq),
	}
}

// Head is the last row Check accepted.
func (v *ChainVerifier) Head() ChainHead { return v.head }

// Rows is how many rows Check accepted.
func (v *ChainVerifier) Rows() uint64 { return v.rows }

// AnchorsChecked is how many anchors the walk reached and matched.
func (v *ChainVerifier) AnchorsChecked() int { return len(v.consumed) }

// ChainVerdict is a complete verification result.
type ChainVerdict struct {
	Rows             uint64
	Head             ChainHead
	AnchorsChecked   int
	Break            *ChainBreak
	Unchained        uint64
	FirstUnchainedID string
}

// Intact: the chain has no break and every row is on it.
func (v ChainVerdict) Intact() bool { return v.Break == nil && v.Unchained == 0 }

// Tampered: the walk found a break. Unchained rows alone are not tampering —
// a pre-#896 binary writes them — and are reported separately.
func (v ChainVerdict) Tampered() bool { return v.Break != nil }

// ChainHeadReader reads the chain's current head.
type ChainHeadReader interface {
	ChainHead(ctx context.Context) (ChainHead, error)
}
