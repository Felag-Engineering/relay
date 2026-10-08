package auditsink

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
)

type fakeHead struct {
	head audit.ChainHead
	err  error
}

func (f *fakeHead) ChainHead(context.Context) (audit.ChainHead, error) { return f.head, f.err }

func newCheckpointer(r audit.ChainHeadReader) (*Checkpointer, *bytes.Buffer) {
	var buf bytes.Buffer
	return NewCheckpointer(r, time.Hour, slog.New(slog.NewTextHandler(&buf, nil))), &buf
}

func headAtSeq(seq uint64) audit.ChainHead {
	var h audit.ChainHash
	h[0], h[31] = byte(seq), 0xab
	return audit.ChainHead{Seq: seq, Hash: h}
}

func TestCheckpointer_EmitsOnFirstCallAndWhenTheHeadAdvances(t *testing.T) {
	r := &fakeHead{head: headAtSeq(3)}
	c, buf := newCheckpointer(r)

	if ok, err := c.Checkpoint(context.Background()); !ok || err != nil {
		t.Fatalf("first Checkpoint = %v, %v", ok, err)
	}
	line := buf.String()
	for _, want := range []string{"audit chain checkpoint", "format=" + audit.ChainFormat, "seq=3", "hash=" + r.head.Hash.Hex()} {
		if !strings.Contains(line, want) {
			t.Errorf("checkpoint line %q lacks %q", line, want)
		}
	}

	buf.Reset()
	if ok, _ := c.Checkpoint(context.Background()); ok || buf.Len() != 0 {
		t.Errorf("an unchanged head emitted %q", buf.String())
	}

	r.head = headAtSeq(4)
	if ok, _ := c.Checkpoint(context.Background()); !ok || !strings.Contains(buf.String(), "seq=4") {
		t.Errorf("an advanced head did not emit; log %q", buf.String())
	}
}

func TestCheckpointer_NeverEmitsAnEmptyTrail(t *testing.T) {
	c, buf := newCheckpointer(&fakeHead{head: audit.ChainHead{Hash: audit.GenesisPrevHash}})
	if ok, err := c.Checkpoint(context.Background()); ok || err != nil || buf.Len() != 0 {
		t.Errorf("empty trail: ok=%v err=%v log=%q", ok, err, buf.String())
	}
}

func TestCheckpointer_RunReportsReaderErrors(t *testing.T) {
	boom := errors.New("boom")
	c, _ := newCheckpointer(&fakeHead{err: boom})
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan error, 1)
	go c.Run(ctx, func(err error) {
		select {
		case got <- err:
		default:
		}
		cancel()
	})
	select {
	case err := <-got:
		if !errors.Is(err, boom) {
			t.Errorf("onError got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run never reported the reader error")
	}
}

// TestCheckpointer_LineValuesPasteIntoExpect proves the operator's workflow:
// the seq and hash a checkpoint line carries are exactly an -expect anchor.
func TestCheckpointer_LineValuesPasteIntoExpect(t *testing.T) {
	r := &fakeHead{head: headAtSeq(7)}
	c, buf := newCheckpointer(r)
	if _, err := c.Checkpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	var seq, hash string
	for _, f := range strings.Fields(buf.String()) {
		if v, ok := strings.CutPrefix(f, "seq="); ok {
			seq = v
		}
		if v, ok := strings.CutPrefix(f, "hash="); ok {
			hash = v
		}
	}
	a, err := audit.ParseChainAnchor(fmt.Sprintf("%s:%s", seq, hash))
	if err != nil {
		t.Fatalf("ParseChainAnchor: %v", err)
	}
	if a.Seq != r.head.Seq || a.Hash != r.head.Hash {
		t.Errorf("anchor = %+v, want the head %+v", a, r.head)
	}
}
