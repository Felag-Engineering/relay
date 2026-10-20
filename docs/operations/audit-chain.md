# The audit chain and `relay-audit-verify`

Every audit row is hash-chained, and the `audit` table refuses `UPDATE` and `DELETE`. This page
is the operator's guide to what that proves, what it does not, and how to check it.

## What the chain proves

Each row carries `seq`, `prev_hash` and `hash`. `hash` is SHA-256 over a format tag
(`relay-audit-chain/v1`), `seq`, `prev_hash` and a canonical encoding of the row.

**The chain is unkeyed SHA-256.** Anyone who can write the database file can compute valid
hashes, so the chain detects accidental damage and careless tampering, not a careful attacker.

| Tampering | Detected |
|---|---|
| An edited row | Only if its successors were not re-chained. The verifier names the row. |
| A deleted row in the middle | Always, as a sequence gap. |
| A row inserted outside the chain | Always, as an unchained row (exit 3, or exit 1 if it carries a hash). |
| Rows truncated from the tail | **Only against an `-expect` anchor** at a seq at or past the truncation point. |
| History re-chained from row *k* | **Only against an `-expect` anchor** at a seq of *k* or later. |
| A forged row appended at the tail with a valid hash | **Never, locally.** It is indistinguishable from a real row. If it is written before the next checkpoint, the checkpoint anchors it. |
| The whole chain rewritten before the oldest anchor you kept | **Not locally.** It needs keyed or external anchoring (#284). |

The triggers that refuse `UPDATE` and `DELETE` are a guardrail, not a security boundary:
anyone holding the file can `DROP TRIGGER`. The chain makes that visible afterwards.

The encoding hashes the decoded row, so a change that alters only how a value is stored (for
example `NULL` against an empty string in a column) is not a break.

## Building it

It is **source-only**: it is not in the release artifacts or the container images.

```sh
cd relay && CGO_ENABLED=0 go build -trimpath -o bin/relay-audit-verify ./cmd/relay-audit-verify
```

## Running it

```sh
sudo -u relay ./relay-audit-verify -store /var/lib/relay/relay.db \
    -expect 1042:3f5a…   -expect 2210:9c0e…
```

- It is read-only. It never migrates and never creates the database.
- **Run it as the user that owns the database** (normally the Relay's). It refuses any other
  user, because SQLite may create `-shm` and `-wal` files and a root-owned one would stop the
  Relay opening its own database.
- It is safe to run while the Relay is running: it reads one consistent snapshot.
- With Docker, either stop the Relay and copy `relay.db`, `relay.db-wal` and `relay.db-shm`
  out of the volume together (a copy of the main file alone, or of files taken while the Relay
  runs, can be inconsistent), or run it against the mounted volume as uid 10001. Or, inside the
  container, take a consistent copy with `sqlite3 relay.db ".backup /tmp/relay-copy.db"` or
  `VACUUM INTO`, and verify that.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | The chain is intact and every `-expect` matched. |
| 1 | **Tampered.** A hash, a link, a sequence number or an anchor does not match. The first break is printed with its `seq` and `audit_id`. |
| 2 | Nothing was verified: usage error, unreadable store, a store from before migration 28, or the user check refused. |
| 3 | No break, but some rows have no chain position. |

Exit 3 is what a **rollback** looks like: a Relay binary that predates migration 28 writes rows
without a chain position, because the triggers never block `INSERT` (a Relay that cannot write
an audit row cannot dispatch). Those rows can never be removed, so after a rollback the
verifier exits 3 permanently. **On a Relay that was never rolled back, treat exit 3 as
tampering:** someone inserted rows outside the chain.

## Anchoring

Every few minutes, when the chain has advanced, the Relay logs a metadata-only line:

```
audit chain checkpoint format=relay-audit-chain/v1 seq=1042 hash=3f5a…
```

Keep these lines in your log pipeline, and pass the `seq` and `hash` of any of them as
`-expect SEQ:HASH`, once per anchor. More, and older, anchors give stronger evidence: a rewrite
is invisible only before the oldest anchor you kept.

**An anchor is only as trustworthy as where it lives.** Ship the checkpoint lines off the host
promptly: root can rewrite a journal on the same host, and root is the attacker this guards
against. Rows forged before the next checkpoint are anchored along with the genuine ones.
Keyed or external anchoring is tracked in #284.

## Upgrading

Migration 28 chains every existing row, from row one, in one transaction:

- It first canonicalises any legacy timestamps (migration 0024's conversion), because the table
  cannot be updated afterwards.
- It scales with the size of the audit table. Plan on free disk of about 100% of the database
  size for the `-wal`. Running out of disk rolls back safely, and the Relay refuses to start
  with the trail untouched.
- The Relay refuses to start if an existing audit row cannot be decoded. The error names the
  `audit_id`.
- The chain vouches for rows written before the upgrade only as of the upgrade: anything edited
  before then is chained in as it stood.
