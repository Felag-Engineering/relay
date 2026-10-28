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
IaC repo (policy.toml per cohort, plus any fragments)
  → PR review
  → CI: relay-daemon policy check
  → config management pushes the files + restarts the daemon
  → registry Policy fingerprints confirm the rollout landed
```

## 1. Author: the Policy file

Policy is a TOML file (default `/etc/relay-daemon/policy.toml`, `RELAY_POLICY_PATH` to
override), root-owned and not group/world-writable. Otherwise the daemon's loader refuses it
and falls back to **deny-all**. So does a file with a key the daemon does not read (a mistyped
`[[denny]]`, `alow = [...]`, `nmae = ...`): it is a parse error, never a rule that is quietly
dropped. The full annotated reference is
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

### The Policy directory: fragments

Beside the Policy file the daemon reads a **Policy directory**: `policy.d` in the same
directory as the Policy file (default `/etc/relay-daemon/policy.d`). It has no setting of its
own, so it follows `RELAY_POLICY_PATH`. Every file in it is a **Policy fragment**. The daemon
composes the Policy file and every fragment, in order of file name, into **one Policy with one
Policy fingerprint**. Deny beats allow across all of them, and which file a rule came from
affects only error messages. The package creates the directory empty and never writes into it
again; config management populates it. A Node with an empty directory behaves, and
fingerprints, exactly as a Node without one.

- **`policy.d` holds only fragments.** Every entry is composed, whatever its name. Keep editor
  swap files out of it, and never use Ansible's `backup: yes` there: a backup copy is composed
  too, and can keep a removed allow alive. Package-manager leftovers are composed the same
  way: `.rpmsave`, `.rpmnew`, `.dpkg-old`, `.dpkg-dist` and `~` backup files. **Removing a
  fragment from your repository does not remove it from a Node**: config management that only
  places files leaves the old one in force, so deleting a fragment needs an explicit delete
  task (Ansible `state: absent`). A stray file still shows, because fragment file names are
  part of the fingerprint and appear as drift in section 4.
- **Fragments are root-owned and not group/world-writable**, and so is `policy.d` itself.
- **A `policy.toml` beside fragments is optional.** With no Policy file and at least one
  fragment, the daemon composes the fragments alone, deny-by-default as always. With no Policy
  file and no fragment it runs deny-all. A Node whose `/etc/relay-daemon/policy.d` already
  existed when the package was installed gets no default Policy file, so its fragments are its
  whole Policy. A missing Policy file and an empty one decide the same, but fingerprint
  differently (section 4).
- **Removing `policy.toml` removes its denies.** The fragments' allows keep running, and the
  daemon only logs `no policy file; composing the Policy directory's fragments alone`. The
  shipped default `policy.toml` holds the confidentiality deny-list (`/etc/shadow`, SSH host
  keys, the daemon's own key and environment file), so a Node that keeps it and adds allows
  in `policy.d` must not lose it: keep load-bearing denies in a fragment too (for example
  `policy.d/00-deny.toml`). A mistyped `RELAY_POLICY_PATH` filename has the same effect. To
  lock a Node down to deny-all, remove or empty its fragments as well as the Policy file.
- **A bad fragment stops the daemon; an unreadable one makes the Policy deny-all.** A fragment
  that is a symlink, is not a regular file, or is group/world-writable or owned by neither
  root nor the daemon's user, and a `policy.d` that is insecure the same way, **refuse
  start**: the daemon exits non-zero and the unit shows failed. A fragment that cannot be read
  or parsed, including one with a key the daemon does not read, makes the **whole** Policy
  deny-all, with no partial load. The Policy file's own
  failures stay deny-all, as above. Nothing is applied until the daemon restarts; there is no
  reload.

Organize the repo by cohort, not by Node. The fingerprint check (below) works best when every
Node in a cohort carries byte-identical Policy. A cohort that has fragments keeps them in a
directory beside its Policy file:

```
iac-repo/
  policies/
    web-prod.toml
    web-prod.d/
      10-nginx.toml
      90-deny-shadow.toml
    db-prod.toml
    build-fleet.toml
```

### Change a Node's Policy

1. Write the fragment: add or change `policies/web-prod.d/<name>.toml` in the IaC repo, and
   let config management place it in `/etc/relay-daemon/policy.d`.
2. Check the Policy file and the directory together, the way the daemon will load them:

   ```console
   $ relay-daemon policy check policies/web-prod.toml --policy-dir policies/web-prod.d --strict
   ```

3. Restart the daemon (`systemctl restart relay-daemon`); there is no reload.

## 2. Validate: `policy check` in CI

The daemon binary is also the offline linter: no network, no identity, no root, safe in any
pipeline.

```console
$ relay-daemon policy check policies/web-prod.toml --strict
```

- Catches parse errors (a key the daemon does not read is one), invalid regexes, unresolvable
  Operation names, and allow rules fully shadowed by a deny (a warning; `--strict` makes warnings failures).
- **Pass `--policy-dir <dir>`** when the Node has fragments: it lints the Policy file and every
  file in `<dir>` together, as the daemon will load them. Shadowing works across files, so an
  allow in one file is flagged when a deny in another covers it. A fragment's finding is
  prefixed with its file name in quotes, escaped as the daemon logs it. A key the daemon
  does not read (a mistyped `[[denny]]`, `alow = [...]`, `nmae = ...`), in the Policy file or a
  fragment, is a parse error, reported with the others: the daemon runs the whole Policy
  deny-all rather than load it. A `<dir>` that is a symlink or not a directory, and a symlink or
  a non-regular entry in it, is an error, because the daemon refuses to start on one. Mode and
  owner are not checked: the subcommand runs on a non-root checkout. A `<dir>` that does not
  exist is an error here, although the daemon treats a missing Policy directory as having no
  fragments: a mistyped path should not pass a gate. A Policy file that does not exist is
  checked as the daemon loads it: beside a fragment in `<dir>` the fragments are checked alone,
  with a `warning:` that `--strict` makes a failure, so a mistyped path fails a strict gate;
  with no fragment it is an error, because the daemon runs deny-all.
- **Prints the fingerprint.** On success, `policy check` prints `fingerprint: <hex>` to stdout,
  the Policy fingerprint a Node holding exactly these files will report (section 4). Without
  `--policy-dir` it covers the Policy file alone, and does not match a Node that has fragments.
  When the `policy.d` beside the Policy file exists and holds entries, and `--policy-dir` is not
  given, `policy check` and `policy explain` print a `warning:` saying so; under `--strict` that
  warning fails `policy check`. `policy explain` reads the Policy file only.
- **Two numberings.** Lint findings number a rule within its own file. The daemon's runtime
  reports number it across the composed Policy, the Policy file's rules first, and a
  fragment's rule has no line.
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

A minimal CI gate: `policy check --strict` on every `policies/*.toml`, with
`--policy-dir policies/<name>.d` where a Node has fragments, plus `--would-allow`
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

With the role applied, notify `relay_daemon : Restart relay-daemon` instead.

A Node with fragments needs a Policy file too (an empty one will do), and a task per fragment.
The fragment task is yours. The release's role (`relay_daemon`) carries the restart handler, so a
play that applies the role notifies `relay_daemon : Restart relay-daemon`:

```yaml
- name: Install a Policy fragment (root-owned; no backup, ever)
  ansible.builtin.copy:
    src: "policies/{{ relay_policy_cohort }}.d/10-nginx.toml"
    dest: /etc/relay-daemon/policy.d/10-nginx.toml
    owner: root
    group: root
    mode: "0644"
  notify: "relay_daemon : Restart relay-daemon"
```

A play without the role keeps its own handler. This one is yours, not a shipped one:

```yaml
# handlers/main.yml
- name: restart relay-daemon
  ansible.builtin.systemd:
    name: relay-daemon
    state: restarted
```

The restart matters: the daemon loads Policy **once at startup**, with no hot reload, so a
pushed file or fragment takes effect on the next start. The graceful-shutdown drain makes the
restart safe mid-Job ([relay-daemon-install.md](relay-daemon-install.md)).

Under the hardened unit, `ProtectSystem=strict` means even a compromised daemon *process*
cannot rewrite its own Policy file ([daemon-privilege-posture.md](daemon-privilege-posture.md));
the file changes only when config management changes it.

## 4. Verify: registry Policy fingerprints

The daemon reports a **Policy fingerprint** (64 lowercase hex chars) in its `Hello` and in
every `PolicySnapshot`, and the Relay records it in the registry. The Policy itself never
travels; the fingerprint gives fleet-wide drift visibility without it.

The fingerprint is over raw bytes, never a parsed form. On a Node **with no fragments** it is
the SHA-256 of the Policy file, so it equals what `sha256sum` says about the file in your IaC
repo:

```console
$ sha256sum policies/web-prod.toml
9f2c…e41a  policies/web-prod.toml
```

On a Node **with fragments** it covers the Policy file and every fragment, with each fragment's
file name; the Policy file's own name and the directory paths do not count. On a Node with
fragments and **no Policy file** it covers the fragments alone, so it differs from the same
fragments beside an empty `policy.toml`. Compare it against
the `fingerprint:` line that `policy check` prints over the same files that config management
pushes:

```console
$ relay-daemon policy check policies/web-prod.toml --policy-dir policies/web-prod.d
fingerprint: 4b8d…07c1
```

Leave `--policy-dir` off and the printed fingerprint never matches a Node that has fragments.
The fragment file names must match the Node's too.

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
  unreadable at startup, or a fragment could not be read or parsed, or there is neither a
  Policy file nor a fragment.
- **A Node stopped reporting after a fragment push** → a fragment or its Policy directory was
  refused. `systemctl status relay-daemon` shows the unit failed, and the journal line
  `policy fragment or Policy directory refused` names the reason and the fragment. Step 2 of
  "Change a Node's Policy" is there to catch this before it reaches a Node.

Cosmetic edits (whitespace, comments, key order) change the fingerprint. That is the drift
signal wanted: policy-as-code pushes the same files everywhere, so anything non-identical is
worth a look.

## What this workflow never includes

No Relay-side Policy editor, no "update policy" Operation, no Control API route that writes a
Node's Policy. Any of those would collapse the two-layer authorization model (Relay-side
authorization *and* Node-side Policy) into one, and ADR-0002 rejected them. If a task seems to
need one, it needs a new ADR, not a workaround.
