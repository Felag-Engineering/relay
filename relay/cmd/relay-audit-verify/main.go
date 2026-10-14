// Command relay-audit-verify walks the Relay's audit hash chain and
// reports the first break.
//
// It is read-only and never migrates: it opens the database read-only, refuses
// a store that predates the chain, and creates nothing. It is a separate
// binary, not a verb of "relay" (ADR-0030): a check of a local file needs no
// credential and no running Relay, and the "relay" binary does not grow verbs.
//
// Run it as the user that owns the database (normally the Relay's own). SQLite
// may create the -shm and -wal files, and a root-owned one would stop the
// Relay opening its own database; the command refuses to run as any other
// user.
//
// Anchoring. The chain alone detects an edited row, a deleted middle row and a
// row inserted outside it. Tail truncation and a re-chain from some row k are
// detected only against an anchor: take the seq and hash from any
// "audit chain checkpoint" log line the Relay wrote and pass them as
//
//	-expect SEQ:HASH
//
// Repeat the flag for every checkpoint you kept. More, and older, anchors give
// stronger evidence: a rewrite is invisible only before the oldest anchor.
//
// Exit status:
//
//	0  the chain is intact (and every -expect matched)
//	1  tampered: a row, a sequence gap, a link or an anchor does not match
//	2  usage, open, schema or user error: nothing was verified
//	3  no break, but some rows have no chain position. A Relay that was rolled
//	   back to a pre-#896 binary writes such rows. On a Relay that never was,
//	   treat exit 3 as tampering.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

const (
	exitIntact    = 0
	exitTampered  = 1
	exitError     = 2
	exitUnchained = 3
)

// osEnv is the process facts run consults, so a test can fake them.
type osEnv interface {
	Geteuid() int
	// FileOwner returns the owning uid of path. known is false where the
	// platform has no such notion, in which case the guard is skipped.
	FileOwner(path string) (uid int, known bool, err error)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, realEnv{}))
}

// anchorFlags collects the repeatable -expect flag.
type anchorFlags []audit.ChainAnchor

func (a *anchorFlags) String() string { return fmt.Sprint(len(*a), " anchors") }

func (a *anchorFlags) Set(s string) error {
	anchor, err := audit.ParseChainAnchor(s)
	if err != nil {
		return err
	}
	*a = append(*a, anchor)
	return nil
}

func run(args []string, stdout, stderr io.Writer, env osEnv) int {
	fs := flag.NewFlagSet("relay-audit-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("store", "", "path to the Relay's SQLite database (required)")
	var anchors anchorFlags
	fs.Var(&anchors, "expect", "SEQ:HASH from an `audit chain checkpoint` log line; repeatable")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if *path == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: relay-audit-verify -store PATH [-expect SEQ:HASH]...")
		return exitError
	}

	owner, known, err := env.FileOwner(*path)
	if err != nil {
		fmt.Fprintf(stderr, "relay-audit-verify: %v\n", err)
		return exitError
	}
	if known && env.Geteuid() != owner {
		fmt.Fprintf(stderr, "relay-audit-verify: refusing to open %s as uid %d: the database is owned by uid %d. Run as that user (SQLite may create -shm/-wal files the Relay then cannot open).\n",
			*path, env.Geteuid(), owner)
		return exitError
	}

	v, err := store.VerifyAuditChain(context.Background(), *path, anchors)
	if err != nil {
		fmt.Fprintf(stderr, "relay-audit-verify: %v\n", err)
		return exitError
	}

	// Every string below that came out of the database is untrusted text a
	// tamperer chose: %q keeps terminal escape sequences from spoofing output.
	switch {
	case v.Tampered():
		fmt.Fprintf(stdout, "audit chain BROKEN at seq=%d audit_id=%q: %s: detail=%q\n", v.Break.Seq, v.Break.AuditID, v.Break.Reason, v.Break.Detail)
		if v.Unchained > 0 {
			fmt.Fprintf(stdout, "also: %d audit rows carry no chain position (first audit_id=%q)\n", v.Unchained, v.FirstUnchainedID)
		}
		return exitTampered
	case v.Unchained > 0:
		fmt.Fprintf(stdout, "audit chain intact through head_seq=%d, but %d audit rows carry no chain position (first audit_id=%q) — written by a pre-#896 binary or inserted outside the chain\n",
			v.Head.Seq, v.Unchained, v.FirstUnchainedID)
		return exitUnchained
	default:
		fmt.Fprintf(stdout, "audit chain intact: rows=%d head_seq=%d head_hash=%s anchors_checked=%d\n",
			v.Rows, v.Head.Seq, v.Head.Hash.Hex(), v.AnchorsChecked)
		return exitIntact
	}
}
