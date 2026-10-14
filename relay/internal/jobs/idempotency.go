package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strconv"
	"time"
)

// IdempotencyRecord binds a caller-supplied idempotency key to the Job the
// first call carrying it created. It is scoped to the verified Account:
// the same key from two Accounts names two unrelated records.
type IdempotencyRecord struct {
	AccountID     string
	Key           string
	RequestDigest string
	JobID         string
	CreatedAt     time.Time
}

// IdempotencyRepository persists idempotency keys. A key is claimed with a
// Job ID reserved before the Job exists (the AP-77 shape), so a re-issued call
// can find it however far the first call got.
type IdempotencyRepository interface {
	// Claim sweeps rows created before notBefore, then binds rec. When a live
	// row for (AccountID, Key) already exists it is returned with claimed=false
	// and nothing is written.
	Claim(ctx context.Context, rec IdempotencyRecord, notBefore time.Time) (existing IdempotencyRecord, claimed bool, err error)

	// Lookup returns the live (not older than notBefore) record, if any.
	Lookup(ctx context.Context, accountID, key string, notBefore time.Time) (IdempotencyRecord, bool, error)

	// Rebind points the key at toJobID, only while it still names fromJobID.
	Rebind(ctx context.Context, accountID, key, fromJobID, toJobID string) error

	// Release deletes the key, only while it still names jobID.
	Release(ctx context.Context, accountID, key, jobID string) error
}

// RequestDigest fingerprints a request so a key reused with different
// arguments is told apart from a genuine re-issue. Every field is
// length-prefixed so no two requests share an encoding, and OperationArgs is
// hashed in key order. RiskClass is excluded: the capability layer derives it
// (invariant 13), so a caller cannot vary it.
func RequestDigest(selector string, a Action) string {
	h := sha256.New()
	num := func(v uint64) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], v)
		h.Write(n[:])
	}
	str := func(s string) {
		num(uint64(len(s)))
		h.Write([]byte(s))
	}
	str(selector)
	str(strconv.Itoa(int(a.Kind)))
	str(a.OperationName)
	keys := make([]string, 0, len(a.OperationArgs))
	for k := range a.OperationArgs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	num(uint64(len(keys)))
	for _, k := range keys {
		str(k)
		str(a.OperationArgs[k])
	}
	num(uint64(len(a.RawExecArgv)))
	for _, v := range a.RawExecArgv {
		str(v)
	}
	str(strconv.Itoa(int(a.TimeoutSeconds)))
	return hex.EncodeToString(h.Sum(nil))
}
