# Manual validation — `v0.2.0` (Template Engine & Shipped Catalog)

Delta script on top of [validate-v0.1.0-beta.md](validate-v0.1.0-beta.md) (the
convention: [README.md](README.md)). **Prerequisite: the beta script has passed** — a
Relay and ≥2 enrolled Nodes are running, and config management already distributes
Policy.

This milestone made the Operation vocabulary **per-Node** for the first time (ADR-0021):
Template Operations are loaded from root-owned local files on each Node, so two Nodes in
the same fleet can legitimately answer different vocabularies. Most of what follows is
about proving that honestly — that a Node says what it has, that dispatching what it
does *not* have is neither a failure nor a denial, and that Policy still decides
everything.

### What you need

- The beta fleet: 1 Relay, ≥2 Nodes. **Node A** will get the template pack; **Node B**
  deliberately will not — the `unsupported` steps need a Node without it.
- A `relay-daemon` binary of this milestone's version on the operator workstation for
  the offline `policy check` steps (no root, no network).
- Config management, as always, for placing files on Nodes. Nothing here is placed by
  hand on a Node except where a step is explicitly probing the loader's refusals.
- Reference docs, which are acceptance-bearing here as in the beta script:
  [template-packs.md](../operations/template-packs.md),
  [`daemon/templates.example.toml`](../../daemon/templates.example.toml),
  [`daemon/packaging/templates.d/relay-read/catalog.toml`](../../daemon/packaging/templates.d/relay-read/catalog.toml),
  [`daemon/policy.default.toml`](../../daemon/policy.default.toml).

Record the daemon version, both Node IDs, and the template-set fingerprints in the
sign-off table.

---

## 1. Author a template and distribute it (Node A only)

In the IaC repo, author a small operator template — start from
[`templates.example.toml`](../../daemon/templates.example.toml) — and have config
management place it on **Node A only**, root-owned and not group/world-writable:

```toml
# fleet-templates/local.toml
[[template]]
name = "svc.show"
risk_class = "read"
body = "systemctl show --no-pager --property=Id,ActiveState,SubState -- {{unit}}"

[[template.slots]]
name = "unit"
type = "identifier"
```

```sh
# config management, e.g.:
#   dest: /etc/relay-daemon/templates.d/local.toml   owner root  mode 0644
#   then: restart relay-daemon
```

Add the matching allow rule to Node A's Policy — **loading a template allows nothing by
itself** (ADR-0002 deny-by-default) — and distribute that the same way:

```toml
[[operation]]
name = "svc.show"
allowed_args = [["*"]]
```

**Expect:** the daemon restarts cleanly and logs `loaded template set` with a count and
a 64-hex `template_set_fingerprint`. At no point does a template travel over the
Relay's wire.

**Discharges:** v0.2.0 "an operator authors a local template; the daemon loads it";
ADR-0021 local-loading, ADR-0002 unchanged.

## 2. Fingerprint and discovery (both Nodes)

From the MCP client:

```
list_nodes
describe_node node_id=<Node A>
describe_node node_id=<Node B>
list_operations                       # no node_id
list_operations node_id=<Node A>
list_operations node_id=<Node B>
```

**Expect:**

- `list_nodes` shows `template_set_fingerprint` beside `policy_fingerprint` for both
  Nodes. Node A's is 64-hex; Node B's is **empty** (no templates installed). Neither is
  the literal `unloadable`.
- `describe_node <Node A>` reports `template_vocabulary.reported: true`, the same
  fingerprint, and `svc.show` with `risk_class: "read"` and its `unit` slot typed
  `identifier`. **No template body appears anywhere in the response** — bodies never
  cross the wire.
- `describe_node <Node B>` reports `templates: []` — an empty array, never `null`.
- `list_operations` with no `node_id` returns only the four native Operations, every one
  `source: "native"`.
- `list_operations node_id=<Node A>` returns those four **plus** `svc.show` with
  `source: "template"`, its slot constraint prose, and a usage example.
- `list_operations node_id=<Node B>` returns natives only, with
  `templates_reported: true` (Node B reported a snapshot; it simply has none).

**Discharges:** v0.2.0 "the daemon … fingerprints it", "per-Node vocabulary discovery
via `list_operations`/`describe_node`" (ADR-0021).

## 3. Run the template, and refuse a bad parameter (Node A)

```
run_operation selector="node:<A's selector>" operation=svc.show args={"unit":"sshd"}
run_operation selector="node:<A's selector>" operation=svc.show args={"unit":"; reboot"}
```

**Expect:** the first returns real `systemctl show` output, `outcome: success`. The
second is **refused daemon-side before any spawn** — `outcome: failure`, stderr naming
the slot and the failure class (never echoing the hostile value), and **nothing runs**
on the Node (confirm: `systemctl is-system-running` unchanged, no reboot, nothing in the
Node's journal from a spawned shell).

**Discharges:** v0.2.0 "`run_operation` uses it; a parameter violating its validation is
refused daemon-side".

## 4. `unsupported` on a Node that lacks the template (Node B)

Dispatch the **same** Operation at a Selector matching both Nodes, then plan it:

```
run_operation selector="<matches A and B>" operation=svc.show args={"unit":"sshd"}
run_operation selector="<matches A and B>" operation=svc.show args={"unit":"sshd"} plan=true
```

**Expect:** one Job, two per-Node results — Node A `success`, Node B `unsupported`, with
**no `exit_code` key at all** on B's result (nothing ran). The stderr on B explains the
vocabulary miss and says Policy was not consulted. The plan reports
`verdict: "unsupported"` for Node B and `allow` for Node A — the plan and the apply agree,
including their explanation text.

Confirm it is genuinely not a Policy question: Node B's Policy has no rule for
`svc.show`, and the result is `unsupported`, **not** `denied_by_policy`.

**Discharges:** v0.2.0 "a Node without the template reports `unsupported`"; ADR-0011
plan/apply parity.

## 5. Loader refusals (Node A — deliberately hand-placed, then reverted)

These probe the fail-closed loader, so they are the one place a step touches a Node by
hand. Do them one at a time, restarting the daemon between each, and revert after.

| Do this on Node A | Expect |
|---|---|
| `chmod 0666 /etc/relay-daemon/templates.d/local.toml` | daemon logs a load failure and comes up with **no** Template Operations; `template_set_fingerprint` reads `unloadable` |
| Replace the file with a symlink to an identical file elsewhere | same: refused, `unloadable` |
| Add a second template with a duplicate `name` | same: the **whole set** fails — never a partial vocabulary |
| Add a template whose body is `tail --file={{path}}` | same: refused at load (a placeholder must be a standalone token) |

While in the `unloadable` state, re-run step 3's first call.

**Expect:** `unsupported` — the Node has no template vocabulary at all. Then restore the
good file, restart, and confirm the original 64-hex fingerprint returns.

**Discharges:** v0.2.0's fail-closed loading posture (ADR-0021); the `unloadable`
sentinel's fleet-wide visibility.

## 6. The shipped read catalog, with zero local authoring

Have config management install the packaged pack and the shipped default Policy on
**Node A**, both untouched:

```sh
#   daemon/packaging/templates.d/relay-read/catalog.toml
#     → /etc/relay-daemon/templates.d/relay-read/catalog.toml   root:root 0644
#   daemon/policy.default.toml
#     → /etc/relay-daemon/policy.toml                            root:root 0600
```

Then, from the MCP client, run all seven with **no Policy authoring of your own**:

```
run_operation … operation=proc.list
run_operation … operation=disk.usage
run_operation … operation=net.listening
run_operation … operation=pkg.inventory
run_operation … operation=service.status  args={"unit":"sshd"}
run_operation … operation=log.tail        args={"unit":"sshd"}
run_operation … operation=file.checksum   args={"path":"/etc/os-release"}
```

**Expect:** all seven return structured, size-capped results. `log.tail` returns **at
most 200 lines** no matter what — there is no parameter to raise it. `list_operations
node_id=<Node A>` advertises all seven with schema and `risk_class: "read"`.

**Discharges:** v0.2.0 "a Node enrolled with the shipped default Policy answers the full
read catalog with zero local Policy authoring".

## 7. Deny-listed paths, including the evasions (Node A)

```
run_operation … operation=file.read     args={"path":"/etc/shadow"}
run_operation … operation=file.checksum args={"path":"/etc/shadow"}
run_operation … operation=file.checksum args={"path":"/etc/../etc/shadow"}
run_operation … operation=file.checksum args={"path":"//etc/shadow"}
run_operation … operation=file.checksum args={"path":"/etc/shadow/"}
```

**Expect:** every one `denied_by_policy`, nothing executed. The three non-canonical
spellings are denied citing the **canonical-form precondition** (ADR-0018), not a
string mismatch — the deny cannot be evaded by respelling the path, and the refusal is a
denial rather than a later failure.

**Discharges:** v0.2.0 "a deny-listed path is refused"; "none can be parameterized into
reading a deny-listed path when the default Policy is loaded".

## 8. `policy check` lints templates and flags self-reference (workstation, offline)

Against the IaC repo checkout, no root and no network:

```sh
relay-daemon policy check policy.toml --templates templates.d/            # clean → 0
relay-daemon policy check policy.toml --templates templates.d/ --strict
relay-daemon policy check policy.toml                                     # no --templates
```

Then break things deliberately, one at a time, and confirm each is reported:

| Break | Expect |
|---|---|
| Remove a template's `risk_class` | **error**, exit 1 |
| Glue a placeholder to adjacent text (`--file={{path}}`) | **error**, exit 1, naming the file and the block |
| Name a template `file.read` | **error**, exit 1 (shadows a frozen native) |
| Duplicate a template name across two files | **error**, exit 1 |
| Drop `--templates` from an otherwise-good run | the catalog names become **warnings** that name the fix; exit 0, but exit 1 under `--strict` |

Finally, the self-reference lint — add this to a scratch Policy and check it:

```toml
[raw_exec]
allow = ["^/usr/bin/sed .*$"]
```

**Expect:** a warning naming `/etc/relay-daemon/policy.toml` and the probe argv, with the
"lets the wire rewrite the wire's own gate" reasoning; exit 0 plain, exit 1 under
`--strict`. Adding an explicit `[[deny]]` for that path silences it. A narrow, ordinary
Policy produces no self-reference findings at all.

Also confirm `--would-allow` resolves per-Node vocabulary:

```sh
relay-daemon policy check policy.toml --templates templates.d/ --would-allow operation svc.show unit=sshd
relay-daemon policy check policy.toml --would-allow operation svc.show unit=sshd
```

**Expect:** `ALLOW` (exit 0) with the template root; `UNSUPPORTED` (exit 2) without it —
the same answer a dispatch to a Node lacking it gives.

**Discharges:** v0.2.0 "`policy check` lints templates and flags a self-referential allow
rule" (#292, #287).

## 9. Automated-only acceptance (not manually validated — recorded, not skipped)

- **"The template red-team suite passes; no known bypass survives."** Discharged by the
  32 engine tests in `daemon/src/operations/template.rs` (hostile metacharacters,
  quoting, standalone-token compile rule) plus the shipped-catalog binding tests in
  `daemon/src/catalog.rs`, all run by `make test` on every PR. Manually re-running them
  adds nothing a human can observe that CI does not; step 3 above validates the *live*
  behavior of the same boundary.
- **Structural Policy parity for templates** — proven by the compile-time/structural test
  in `daemon/src/dispatch.rs`, not observable by hand.

## 10. Open at the time of writing

**#288 (decide read auditing / output-retention) is unresolved.** ADR-0021 states it
must be decided *before* the catalog makes reads ubiquitous — which, as of this
milestone, it does. This script deliberately does **not** validate read auditing,
because the posture has not been chosen. Record the decision's status in the sign-off;
if it is still open, the milestone's sign-off is conditional on it.

---

## Sign-off

| Field | Value |
|---|---|
| Date | |
| Version validated (`relay --version` / `relay-daemon --version`) | |
| Node A / Node B IDs | |
| Node A template-set fingerprint (operator template, then shipped catalog) | |
| Node B template-set fingerprint (expected: empty) | |
| Beta script (validate-v0.1.0-beta.md) passed on | |
| Steps passed | |
| Steps skipped (and why) | |
| #288 status at sign-off | |
| Operator | |
