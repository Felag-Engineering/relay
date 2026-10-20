# Policy-as-code workflow

How Node Policy files are authored, validated, distributed, and verified: as code, in the
customer's IaC repo, never over the wire (ADR-0002). See also
[relay-daemon-install.md](relay-daemon-install.md), [enrollment.md](enrollment.md) (the
distribution role), the annotated example
[`daemon/policy.example.toml`](../../daemon/policy.example.toml), and
[template-packs.md](template-packs.md) (the same workflow for Template Operations, whose names
Policy governs identically).

## The invariant this workflow honors

Policy is **locally-rooted and remotely-immutable** (ADR-0002): the relay-daemon enforces it,
the Relay may *query* it, and nothing (not the Relay, not the AI-agent, not the Control API)
can modify it over the wire. Changing a Node's Policy is deliberately an out-of-band act
through reviewed config management. That inconvenience is the security property: a fully
compromised Relay or a jailbroken AI-agent still cannot exceed a Node's local Policy.

The lifecycle:

```
IaC repo (policy.toml per cohort)
  → PR review
  → CI: relay-daemon policy check
  → config management pushes the file + restarts the daemon
  → registry Policy fingerprints confirm the rollout landed
```

## 1. Author: the Policy file

Policy is a TOML file (default `/etc/relay-daemon/policy.toml`, `RELAY_POLICY_PATH` to
override), root-owned and not group/world-writable. Otherwise the daemon's loader refuses it
and falls back to **deny-all**. The full annotated reference is
[`daemon/policy.example.toml`](../../daemon/policy.example.toml); in brief:

```toml
# Allow service.restart only for nginx and php-fpm; anything else is denied
# (deny-by-default — no rule, no run).
[[operation]]
name = "service.restart"
allowed_args = [["nginx", "php-fpm"]]

# Allow file.read for any path ("*" is the per-position wildcard) ...
[[operation]]
name = "file.read"
allowed_args = [["*"]]

# ... except /etc/shadow: deny-beats-allow, and path denies match in canonical
# form (ADR-0018) so alias spellings and symlinks to the target are denied too.
[[deny]]
name = "file.read"
args = [["/etc/shadow"]]

# Raw Exec: deny-by-default; permitted only when the joined argv matches an
# allow regex in full (enforced by the daemon) and no deny regex; an argv
# element containing whitespace is refused (ADR-0019). Deny regexes are also
# tested against each raw and canonical argv element (ADR-0019).
[raw_exec]
allow = ["^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$"]
deny  = ["--force", "\\brm\\b"]
```

Semantics (details in the example file's comments): deny-by-default; deny-beats-allow;
argument-level granularity, with `allowed_args[i]`/`args[i]` addressing argv position `i`; deny
rules deny vacuously for omitted trailing arguments; Raw Exec gated by a tight allow list
(the whole command must match; write patterns `^...$`), with denies as backstop only.

Organize the repo by cohort, not by Node. The fingerprint check (below) works best when every
Node in a cohort carries byte-identical Policy:

```
iac-repo/
  policies/
    web-prod.toml
    db-prod.toml
    build-fleet.toml
```

## 2. Validate: `policy check` in CI

The daemon binary is also the offline linter: no network, no identity, no root, safe in any
pipeline.

```console
$ relay-daemon policy check policies/web-prod.toml --strict
```

- Catches parse errors, invalid regexes, unresolvable Operation names, and allow rules fully
  shadowed by a deny (a warning; `--strict` makes warnings failures).
- **Always runs the self-reference lint**: a warning when the Policy reaches the daemon's own
  trust root. For **reads** (`file.read`, `file.checksum`, any path-taking Template Operation)
  it probes only the secret-bearing files: the identity private key and the environment file.
  For **writes** (Raw Exec edit in place, overwrite, copy or move over, delete, redirect,
  chmod, symlink) it probes the trust root at the packaged paths: the Policy file and
  directory, the environment file, the state directory's key, certificate, CA bundle and
  persisted address, the template root, `/usr/bin/relay-daemon`, the unit under
  `/usr/lib/systemd/system/`, and the override unit and `override.conf` drop-in under
  `/etc/systemd/system/`. A write finding over the Policy file means the rule lets the wire
  rewrite its own gate. Findings come from probing the real Policy engine, so a finding is
  proof and an explicit `[[deny]]` silences it. The shipped default passes `--strict` with
  `--templates`. Details, and why there is deliberately no daemon-side deny floor:
  [template-packs.md](template-packs.md) and the ADR-0021 amendment.
- **Warns on a Raw Exec allow pattern not written `^...$`.** Allow patterns match the whole
  command, so an unanchored pattern meant as a substring match does not match. Run `--strict`
  in CI before upgrading the daemon so the pipeline finds these first.
- **Pass `--templates <dir>`** when the cohort installs Template Operations (ADR-0021): it
  lints the template files too and resolves Operation names against natives plus those
  templates. Without it, a non-native name is only a warning, since the linter cannot tell a
  Template Operation from a typo. `--strict` fails the pipeline either way.
- `--would-allow` answers a hypothetical **through the same evaluation code the live wire path
  uses** (ADR-0011: there is no second evaluator, so a CI verdict cannot diverge from a real
  dispatch):

```console
$ relay-daemon policy check policies/web-prod.toml \
    --would-allow operation service.restart unit=nginx
would-allow: ALLOW

$ relay-daemon policy check policies/web-prod.toml \
    --would-allow raw-exec -- /usr/bin/systemctl restart nginx --force
would-allow: DENY (deciding rule: ...)
```

- Stable exit codes for pipeline gating: `0` valid (and would-allow ALLOW), `1` invalid (the
  file is broken), `2` would-deny (the file is fine, the action is not permitted). Precedence
  `1 > 2 > 0`.

### Explain a verdict: `policy explain`

`policy explain` asks the same hypothetical as `--would-allow`, through the same code, and
prints **which pass and rule decided it**, so a deny can be traced to its rule's line:

```console
$ relay-daemon policy explain policies/web-prod.toml \
    operation service.restart unit=sshd
explain: DENY
pass: deny
rule: [[deny]] #0, line 12
matched on: the invocation's arguments
reason: denied by explicit rule for operation 'service.restart'

$ relay-daemon policy explain policies/web-prod.toml \
    operation service.restart unit=nginx
explain: ALLOW
pass: allow
rule: [[operation]] #0, line 4
matched on: the invocation's arguments
```

The form is `policy explain <file> [--templates <dir>] <spec>`, where `<spec>` is the same
`operation <name> [key=value ...]` or `raw-exec -- <argv...>` as `--would-allow`. The `pass`
line is one of:

- `precondition` — decided before any rule ran: a non-canonical path argument (ADR-0018) or an
  empty Raw Exec argv. `rule: none`.
- `deny` — a deny rule matched. Deny beats allow.
- `guard` — the Raw Exec whitespace guard refused (ADR-0019). It runs after the deny pass and
  before the allow pass, so a deny pattern that matches an argv keeps the attribution.
  `rule: none`; `matched on` names the argv index, never its value.
- `allow` — an allow rule matched.
- `default` — nothing matched: deny-by-default. `rule: none (deny-by-default)`.

A rule's `line` is where the loader found it; a rule the parser gave no position prints
without one. Exit codes: `0` ALLOW, `2` DENY or UNSUPPORTED, `1` invalid (bad arguments,
unreadable file, invalid Policy).

A minimal CI gate: `policy check --strict` on every `policies/*.toml`, plus `--would-allow`
assertions for the invariants you care about (e.g. "web-prod must never allow
`file.read /etc/shadow`" as an expected-exit-2 test).

Pin the `relay-daemon` binary used in CI to the fleet's version
([release-artifacts.md](release-artifacts.md), verify-then-install) so CI lints with the
vocabulary the fleet enforces.

## 3. Distribute: config management, never the wire

The role that installs the daemon pushes the Policy file ([enrollment.md](enrollment.md)):

```yaml
- name: Install Policy (root-owned, never group/world-writable)
  ansible.builtin.copy:
    src: "policies/{{ relay_policy_cohort }}.toml"
    dest: /etc/relay-daemon/policy.toml
    owner: root
    group: root
    mode: "0644"
  notify: restart relay-daemon
```

The restart matters: the daemon loads Policy **once at startup**, with no hot reload, so a
pushed file takes effect on the next start. The graceful-shutdown drain makes the restart safe
mid-Job ([relay-daemon-install.md](relay-daemon-install.md)).

Under the hardened unit, `ProtectSystem=strict` means even a compromised daemon *process*
cannot rewrite its own Policy file ([daemon-privilege-posture.md](daemon-privilege-posture.md));
the file changes only when config management changes it.

## 4. Verify: registry Policy fingerprints

The daemon reports a **Policy fingerprint** (SHA-256 over the raw Policy file bytes, 64
lowercase hex chars) in its `Hello` and in every `PolicySnapshot`, and the Relay records it in
the registry. The Policy itself never travels; the fingerprint gives fleet-wide drift
visibility without it.

Because it is over raw bytes, it equals what `sha256sum` says about the file in your IaC repo:

```console
$ sha256sum policies/web-prod.toml
9f2c…e41a  policies/web-prod.toml
```

Compare that string against the fleet: `list_nodes` (MCP) reports `policy_fingerprint` per
Node, and `describe_node` also shows the display-only effective-Policy view the daemon last
reported.

- **All Nodes in the cohort match the repo's hash** → the rollout landed everywhere.
- **A Node shows a stale hash** → its daemon has not restarted since the push, or config
  management missed it.
- **A Node shows an unexpected hash** → local drift: the file was edited outside IaC.
  Investigate.
- **`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`** (the empty-input
  SHA-256) → the daemon is running the deny-all fallback: its Policy file was missing or
  unreadable at startup.

Cosmetic edits (whitespace, comments, key order) change the fingerprint. That is the drift
signal wanted: policy-as-code pushes the same file everywhere, so anything non-identical is
worth a look.

## What this workflow never includes

No Relay-side Policy editor, no "update policy" Operation, no Control API route that writes a
Node's Policy. Any of those would collapse the two-layer authorization model (Relay-side
authorization *and* Node-side Policy) into one, and ADR-0002 rejected them. If a task seems to
need one, it needs a new ADR, not a workaround.
