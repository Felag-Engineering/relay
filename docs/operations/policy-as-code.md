# Policy-as-code workflow

How Node Policy files are authored, validated, distributed, and verified — as
code, in the customer's IaC repo, never over the wire (ADR-0002). Companion
documents: [relay-daemon-install.md](relay-daemon-install.md),
[enrollment.md](enrollment.md) (the distribution role),
[`daemon/policy.example.toml`](../../daemon/policy.example.toml) (the annotated
example Policy file), [template-packs.md](template-packs.md) (the same workflow
for Template Operations, whose names Policy governs identically).

## The invariant this workflow exists to honor

Policy is **locally-rooted and remotely-immutable** (ADR-0002): the relay-daemon
enforces it, the Relay may *query* it, and nothing — not the Relay, not the
AI-agent, not the Control API — can modify it over the wire. Changing a Node's
Policy is deliberately an out-of-band act through the reviewed config-management
path. That inconvenience is the security property: a fully compromised Relay or a
jailbroken AI-agent still cannot exceed a Node's local Policy.

So the lifecycle is:

```
IaC repo (policy.toml per cohort)
  → PR review
  → CI: relay-daemon policy check
  → config management pushes the file + restarts the daemon
  → registry Policy fingerprints confirm the rollout landed
```

## 1. Author: the Policy file

Policy is a TOML file (default path `/etc/relay-daemon/policy.toml`,
`RELAY_POLICY_PATH` to override), root-owned and not group/world-writable — the
daemon's loader refuses it otherwise and falls back to **deny-all** (fail
closed). The full annotated reference is
[`daemon/policy.example.toml`](../../daemon/policy.example.toml); the shape in
brief:

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
# allow regex and no deny regex. Anchor allows; deny regexes are also tested
# against each raw and canonical argv element (ADR-0019).
[raw_exec]
allow = ["^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$"]
deny  = ["--force", "\\brm\\b"]
```

Semantics to keep in mind while authoring (details and rationale in the example
file's comments): deny-by-default; deny-beats-allow; argument-level granularity
with `allowed_args[i]`/`args[i]` addressing argv position `i`; deny rules have
vacuous-deny semantics for omitted trailing arguments; Raw Exec should be gated
by a tight, fully-anchored allow list with denies as backstop only.

Organize the repo by cohort, not by Node — the fingerprint check (below) works
best when every Node in a cohort carries byte-identical Policy:

```
iac-repo/
  policies/
    web-prod.toml
    db-prod.toml
    build-fleet.toml
```

## 2. Validate: `policy check` in CI

The daemon binary doubles as the offline linter — no network, no identity, no
root, safe to run in any pipeline:

```console
$ relay-daemon policy check policies/web-prod.toml --strict
```

- Catches parse errors, invalid regexes, unknown Operation names (checked
  against the proto Operation vocabulary), and allow rules fully shadowed by a
  deny (a warning; `--strict` promotes warnings to failures).
- `--would-allow` answers a hypothetical **through the exact same evaluation
  code the live wire path uses** (ADR-0011 — there is no second evaluator, so a
  CI verdict can never diverge from a real dispatch):

```console
$ relay-daemon policy check policies/web-prod.toml \
    --would-allow operation service.restart unit=nginx
would-allow: ALLOW

$ relay-daemon policy check policies/web-prod.toml \
    --would-allow raw-exec -- /usr/bin/systemctl restart nginx --force
would-allow: DENY (deciding rule: ...)
```

- Stable exit codes for pipeline gating: `0` valid (and would-allow ALLOW),
  `1` invalid (file is broken), `2` would-deny (file is fine, action isn't
  permitted). Precedence `1 > 2 > 0`.

A minimal CI gate: run `policy check --strict` on every `policies/*.toml`, plus
`--would-allow` assertions for the invariants you care about (e.g. "web-prod must
never allow `file.read /etc/shadow`" as an expected-exit-2 test).

Pin the `relay-daemon` binary used in CI to the fleet's version
([release-artifacts.md](release-artifacts.md), verify-then-install) so CI lints
with the same vocabulary the fleet enforces.

## 3. Distribute: config management, never the wire

The same role that installs the daemon pushes the Policy file
([enrollment.md](enrollment.md)):

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

The restart matters: the daemon loads Policy **once at startup** — there is no
hot reload — so a pushed file takes effect on the next daemon start. The
graceful-shutdown drain makes the restart safe mid-Job
([relay-daemon-install.md](relay-daemon-install.md)).

Note that under the hardened unit, `ProtectSystem=strict` means even a
compromised daemon *process* cannot rewrite its own Policy file
([daemon-privilege-posture.md](daemon-privilege-posture.md)) — the file changes
only when config management changes it.

## 4. Verify: registry Policy fingerprints

The daemon reports a **Policy fingerprint** — SHA-256 over the raw Policy file
bytes, 64 lowercase hex chars — in its `Hello` and in every `PolicySnapshot`; the
Relay records it in the registry. The Policy itself never travels; the
fingerprint gives fleet-wide drift visibility without it.

Because the fingerprint is over raw bytes, it equals what `sha256sum` says about
the file in your IaC repo:

```console
$ sha256sum policies/web-prod.toml
9f2c…e41a  policies/web-prod.toml
```

Confirm the rollout by comparing that string against the fleet — `list_nodes`
(MCP) reports `policy_fingerprint` per Node; `describe_node` additionally shows
the display-only effective-Policy view the daemon last reported:

- **All Nodes in the cohort match the repo's hash** → the rollout landed
  everywhere.
- **A Node shows a stale hash** → its daemon hasn't restarted since the push, or
  config management missed it.
- **A Node shows an unexpected hash** → local drift; investigate (the file was
  edited outside IaC — deliberately or otherwise).
- **`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`** (the
  empty-input SHA-256) → the daemon is running the deny-all fallback: its Policy
  file was missing or unreadable at startup.

Byte-identity is deliberate: cosmetic edits (whitespace, comments, key order)
change the fingerprint, which is exactly the drift signal wanted — policy-as-code
pushes the same file everywhere, so anything non-identical is worth a look.

## What this workflow never includes

No Relay-side Policy editor, no "update policy" Operation, no Control API route
that writes a Node's Policy — building any of those would collapse the two-layer
authorization model (Relay-side authorization *and* Node-side Policy) into one
layer, and was explicitly rejected in ADR-0002. If a task seems to need it, it
needs a new ADR, not a workaround.
