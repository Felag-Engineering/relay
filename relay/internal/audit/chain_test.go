package audit

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

func goldenRecord() Record {
	return Record{
		ID:        "01J0000000000000000000GOLD",
		Timestamp: time.Date(2026, 10, 7, 14, 30, 5, 123456789, time.FixedZone("x", 5*3600+1800)),
		Kind:      KindDispatch,
		Principal: "alice:admin",
		Attribution: Attribution{
			Verified: Verified{AccountID: "acct-1", AccountName: "alice", Role: "admin", TokenID: "tok-1", Method: "api_token", Source: "10.0.0.1"},
			Asserted: Asserted{OnBehalfOf: "bob", Traceparent: "00-aa-bb-01", SessionRef: "sess", ChangeRef: "CHG-1"},
		},
		Selector:        "node:role=web",
		JobID:           "job-1",
		NodeID:          "node-1",
		ActionKind:      "native",
		OperationName:   "service_restart",
		Args:            map[string]string{"zeta": "last", "alpha": "first", "mid": "m\x00id"},
		RawExecArgv:     []string{"/bin/echo", "hi there"},
		Outcome:         jobs.Outcome(2),
		Reason:          "because",
		Stdout:          []byte("out\n"),
		Stderr:          []byte("err\n"),
		Truncated:       true,
		ApprovalID:      "appr-1",
		GrantID:         "grant-1",
		ApprovalAnswer:  "approved",
		DecisionChannel: "console",
		PlanHash:        "ph-1",
	}
}

// The golden pins the v1 encoding. Changing CanonicalBytes' output for any
// Record invalidates every hash already stored, so a diff here means a new
// format version, not an updated constant.
const (
	goldenCanonicalHex = "0000001a30314a30303030303030303030303030303030303030474f4c440000001e323032362d31302d30375430393a30303a30352e3132333435363738395a0000000864697370617463680000000b616c6963653a61646d696e00000006616363742d3100000005616c6963650000000561646d696e00000005746f6b2d31000000096170695f746f6b656e0000000831302e302e302e3100000003626f620000000b30302d61612d62622d30310000000473657373000000054348472d310000000d6e6f64653a726f6c653d776562000000056a6f622d31000000066e6f64652d31000000066e61746976650000000f736572766963655f726573746172740000000300000005616c706861000000056669727374000000036d6964000000046d006964000000047a657461000000046c61737400000002000000092f62696e2f6563686f00000008686920746865726500000000000000020000000762656361757365000000046f75740a000000046572720a0100000006617070722d31000000076772616e742d3100000008617070726f76656400000007636f6e736f6c650000000470682d31"
	goldenHashHex      = "d526ff29ff2d68150bef87f19752ea33b57286f3cb2ed6fac197af16316b8623"
)

func TestCanonicalBytes_Golden(t *testing.T) {
	r := goldenRecord()
	if got := hex.EncodeToString(CanonicalBytes(r)); got != goldenCanonicalHex {
		t.Errorf("CanonicalBytes hex =\n%s\nwant\n%s", got, goldenCanonicalHex)
	}
	if got := ComputeChainHash(1, GenesisPrevHash, r).Hex(); got != goldenHashHex {
		t.Errorf("ComputeChainHash = %s, want %s", got, goldenHashHex)
	}
}

func TestCanonicalBytes_EveryRecordFieldIsCovered(t *testing.T) {
	base := goldenRecord()
	baseline := CanonicalBytes(base)
	leaves := 0

	var walk func(path string, v reflect.Value)
	walk = func(path string, v reflect.Value) {
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			name := path + v.Type().Field(i).Name
			if f.Kind() == reflect.Struct && f.Type() != reflect.TypeOf(time.Time{}) {
				walk(name+".", f)
				continue
			}
			leaves++
			orig := reflect.New(f.Type()).Elem()
			orig.Set(f)
			switch {
			case f.Type() == reflect.TypeOf(time.Time{}):
				f.Set(reflect.ValueOf(f.Interface().(time.Time).Add(time.Second)))
			case f.Kind() == reflect.String:
				f.SetString(f.String() + "~")
			case f.Kind() == reflect.Int:
				f.SetInt(f.Int() + 1)
			case f.Kind() == reflect.Bool:
				f.SetBool(!f.Bool())
			case f.Kind() == reflect.Map && f.Type().Key().Kind() == reflect.String:
				m := reflect.MakeMap(f.Type())
				for _, k := range f.MapKeys() {
					m.SetMapIndex(k, f.MapIndex(k))
				}
				m.SetMapIndex(reflect.ValueOf("added"), reflect.ValueOf("v"))
				f.Set(m)
			case f.Kind() == reflect.Slice && f.Type().Elem().Kind() == reflect.String:
				f.Set(reflect.Append(f, reflect.ValueOf("~")))
			case f.Kind() == reflect.Slice && f.Type().Elem().Kind() == reflect.Uint8:
				f.SetBytes(append(append([]byte{}, f.Bytes()...), '~'))
			default:
				t.Fatalf("field %s has kind %s the coverage test cannot mutate; extend it", name, f.Kind())
			}
			if reflect.DeepEqual(CanonicalBytes(base), baseline) {
				t.Errorf("field %s does not change CanonicalBytes: it would be tamperable without detection", name)
			}
			f.Set(orig)
		}
	}
	walk("", reflect.ValueOf(&base).Elem())

	if leaves != 31 {
		t.Errorf("Record has %d hashed leaf fields, want 31: a new field must be added to CanonicalBytes under a new format version", leaves)
	}
}

func TestCanonicalBytes_NilAndEmptyAreEquivalent(t *testing.T) {
	a := Record{ID: "x"}
	b := Record{ID: "x", Args: map[string]string{}, RawExecArgv: []string{}, Stdout: []byte{}, Stderr: []byte{}}
	if !reflect.DeepEqual(CanonicalBytes(a), CanonicalBytes(b)) {
		t.Error("nil and empty collections must encode identically")
	}
}

func TestCanonicalBytes_ArgsOrderIndependent(t *testing.T) {
	a := Record{Args: map[string]string{"a": "1", "b": "2", "c": "3"}}
	for i := 0; i < 20; i++ {
		b := Record{Args: map[string]string{"c": "3", "b": "2", "a": "1"}}
		if !reflect.DeepEqual(CanonicalBytes(a), CanonicalBytes(b)) {
			t.Fatal("Args encoding depends on map order")
		}
	}
}

func TestCanonicalBytes_FieldBoundariesAreUnambiguous(t *testing.T) {
	a := Record{Kind: "ab", Principal: "c"}
	b := Record{Kind: "a", Principal: "bc"}
	if reflect.DeepEqual(CanonicalBytes(a), CanonicalBytes(b)) {
		t.Error("length prefixes must keep adjacent fields apart")
	}
}

func TestParseChainAnchor(t *testing.T) {
	h := strings.Repeat("ab", 32)
	got, err := ParseChainAnchor("7:" + h)
	if err != nil {
		t.Fatal(err)
	}
	if got.Seq != 7 || got.Hash.Hex() != h {
		t.Errorf("got %+v", got)
	}
	for name, in := range map[string]string{
		"no colon":       "7" + h,
		"seq zero":       "0:" + h,
		"negative seq":   "-1:" + h,
		"uppercase hex":  "7:" + strings.ToUpper(h),
		"63 hex chars":   "7:" + h[:63],
		"trailing junk":  "7:" + h + "x",
		"empty":          "",
		"non-numeric":    "x:" + h,
		"extra colon":    "7:" + h + ":1",
		"space in seq":   " 7:" + h,
		"plus-signed":    "+7:" + h,
		"non-hex digits": "7:" + strings.Repeat("zz", 32),
	} {
		if _, err := ParseChainAnchor(in); err == nil {
			t.Errorf("%s: %q accepted", name, in)
		}
	}
}

// buildChain returns n correctly chained rows.
func buildChain(n int) (recs []Record, prevs, hashes []ChainHash) {
	prev := GenesisPrevHash
	for i := 1; i <= n; i++ {
		r := Record{ID: "id" + string(rune('0'+i)), Kind: KindDispatch, Reason: "r" + string(rune('0'+i))}
		h := ComputeChainHash(uint64(i), prev, r)
		recs, prevs, hashes = append(recs, r), append(prevs, prev), append(hashes, h)
		prev = h
	}
	return recs, prevs, hashes
}

func walk(v *ChainVerifier, recs []Record, prevs, hashes []ChainHash) *ChainBreak {
	for i, r := range recs {
		if b := v.Check(uint64(i+1), prevs[i].Hex(), hashes[i].Hex(), r); b != nil {
			return b
		}
	}
	return nil
}

func TestChainVerifier_IntactChain(t *testing.T) {
	recs, prevs, hashes := buildChain(4)
	v, _ := NewChainVerifier()
	if b := walk(v, recs, prevs, hashes); b != nil {
		t.Fatalf("unexpected break %+v", b)
	}
	if b := v.Finish(); b != nil {
		t.Fatalf("unexpected finish break %+v", b)
	}
	if v.Rows() != 4 || v.Head().Seq != 4 || v.Head().Hash != hashes[3] {
		t.Errorf("rows=%d head=%+v", v.Rows(), v.Head())
	}
}

func TestChainVerifier_SeqGap(t *testing.T) {
	recs, prevs, hashes := buildChain(4)
	v, _ := NewChainVerifier()
	// Row 3 deleted: the walk sees row 4 after row 2.
	recs, prevs, hashes = append(recs[:2], recs[3]), append(prevs[:2], prevs[3]), append(hashes[:2], hashes[3])
	for i := 0; i < 2; i++ {
		if b := v.Check(uint64(i+1), prevs[i].Hex(), hashes[i].Hex(), recs[i]); b != nil {
			t.Fatal(b)
		}
	}
	b := v.Check(4, prevs[2].Hex(), hashes[2].Hex(), recs[2])
	if b == nil || b.Reason != BreakSeqGap || b.Seq != 4 || b.AuditID != recs[2].ID || !strings.Contains(b.Detail, "expected seq 3, found 4") {
		t.Errorf("got %+v", b)
	}
}

func TestChainVerifier_PrevMismatch(t *testing.T) {
	recs, prevs, hashes := buildChain(3)
	prevs[1][0] ^= 1
	v, _ := NewChainVerifier()
	b := walk(v, recs, prevs, hashes)
	if b == nil || b.Reason != BreakPrevMismatch || b.Seq != 2 {
		t.Errorf("got %+v", b)
	}
}

func TestChainVerifier_HashMismatch(t *testing.T) {
	recs, prevs, hashes := buildChain(3)
	recs[1].Reason = "edited"
	v, _ := NewChainVerifier()
	b := walk(v, recs, prevs, hashes)
	if b == nil || b.Reason != BreakHashMismatch || b.Seq != 2 || b.AuditID != recs[1].ID {
		t.Errorf("got %+v", b)
	}
}

func TestChainVerifier_Malformed(t *testing.T) {
	recs, prevs, hashes := buildChain(2)
	for name, c := range map[string][2]string{
		"null hash":    {prevs[0].Hex(), ""},
		"null prev":    {"", hashes[0].Hex()},
		"short hash":   {prevs[0].Hex(), hashes[0].Hex()[:10]},
		"upper hash":   {prevs[0].Hex(), strings.ToUpper(hashes[0].Hex())},
		"non-hex prev": {strings.Repeat("g", 64), hashes[0].Hex()},
	} {
		v, _ := NewChainVerifier()
		b := v.Check(1, c[0], c[1], recs[0])
		if b == nil || b.Reason != BreakMalformed {
			t.Errorf("%s: got %+v", name, b)
		}
	}
}

func TestChainVerifier_AnchorMatches(t *testing.T) {
	recs, prevs, hashes := buildChain(3)
	v, _ := NewChainVerifier(ChainAnchor{2, hashes[1]}, ChainAnchor{2, hashes[1]})
	if b := walk(v, recs, prevs, hashes); b != nil {
		t.Fatal(b)
	}
	if b := v.Finish(); b != nil {
		t.Fatal(b)
	}
	if v.AnchorsChecked() != 1 {
		t.Errorf("AnchorsChecked = %d, want 1", v.AnchorsChecked())
	}
}

func TestChainVerifier_AnchorMismatch(t *testing.T) {
	recs, prevs, hashes := buildChain(3)
	wrong := hashes[1]
	wrong[0] ^= 1
	v, _ := NewChainVerifier(ChainAnchor{2, wrong})
	b := walk(v, recs, prevs, hashes)
	if b == nil || b.Reason != BreakAnchorMismatch || b.Seq != 2 {
		t.Fatalf("got %+v", b)
	}
	if want := "checkpoint expected " + wrong.Hex() + ", store has " + hashes[1].Hex(); b.Detail != want {
		t.Errorf("detail = %q", b.Detail)
	}
}

func TestChainVerifier_AnchorBeyondHead(t *testing.T) {
	recs, prevs, hashes := buildChain(3)
	var h5 ChainHash
	h5[0] = 5
	v, _ := NewChainVerifier(ChainAnchor{5, h5}, ChainAnchor{4, h5})
	if b := walk(v, recs, prevs, hashes); b != nil {
		t.Fatal(b)
	}
	b := v.Finish()
	if b == nil || b.Reason != BreakAnchorBeyondHead || b.Seq != 4 || b.AuditID != "" || !strings.Contains(b.Detail, "chain head is 3") {
		t.Errorf("got %+v", b)
	}
}

func TestNewChainVerifier_ContradictoryAnchors(t *testing.T) {
	var a, b ChainHash
	b[0] = 1
	if _, err := NewChainVerifier(ChainAnchor{2, a}, ChainAnchor{2, b}); err == nil {
		t.Error("contradictory anchors accepted")
	}
}

func TestChainVerdict(t *testing.T) {
	if !(ChainVerdict{}).Intact() {
		t.Error("empty verdict should be intact")
	}
	if (ChainVerdict{Unchained: 1}).Intact() || (ChainVerdict{Unchained: 1}).Tampered() {
		t.Error("unchained rows are not intact but are not tampering")
	}
	if !(ChainVerdict{Break: &ChainBreak{}}).Tampered() {
		t.Error("a break is tampering")
	}
}
