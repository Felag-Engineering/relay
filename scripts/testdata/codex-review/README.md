# quota-capture.json — provenance

Recorded 2026-09-23 against plugin `openai-codex/codex/1.0.6`, with the ChatGPT-plan Codex
quota exhausted (resets 2026-09-28). Captured by running the companion directly:

```
node <plugin>/scripts/codex-companion.mjs adversarial-review --scope working-tree \
  --model gpt-5.6-terra --json
```

stdout: 806 bytes. stderr: 0 bytes. Exit status: 1.

This file is **unedited** — a byte-for-byte copy of `.dev-loop/real-capture-quota-dirty-stdout.json`
(`.dev-loop/` is gitignored, so this copy is the only durable record of it). It still carries
the recording host's absolute `context.repoRoot`
(`/home/mrapp/felag/gleipnir-relay/.claude/worktrees/agent-a06660ce3b68775be`) and Codex's
`threadId` (`01a0ce4c-b9dd-7ca0-ab49-6842b9b20873`). Neither is a secret: `threadId` is a LOCAL
Codex thread identifier indexing state under `$CLAUDE_PLUGIN_DATA`/`os.tmpdir()`
(`lib/state.mjs:29-43`), nothing to rotate; the `repoRoot` leaks only a username already present
in every git author line. Both are left in deliberately — editing either would change the file's
806-byte length and would look like a test bug rather than the redaction someone intended.

Its point is to be a *recording*, not a fixture someone hand-tuned: `payload.result` is `null`
and `payload.parseError` carries the ChatGPT-plan usage-limit message verbatim
("You've hit your usage limit. Upgrade to Pro …"). `scripts/codex-review-test.sh` must exit 3
on it (`case-real-quota-capture`) — the suite it replaced PASSED while asserting the opposite
(#673's comment on #694).

What is NOT recorded here, and cannot be until the quota resets 2026-09-28: a successful
payload (`result` non-null). The success fixtures used elsewhere in `codex-review-test.sh` are
synthetic, built from the plugin's `schemas/review-output.schema.json` plus the payload shape at
`codex-companion.mjs:422-441`.
