# 06 — Policy Author

**Artboard 10.** Compose a Node Policy from the Operation vocabulary and take the file away.
**Milestone v0.7.0.**

**Governing:** ADR-0001, ADR-0002, ADR-0011, ADR-0012, ADR-0018, ADR-0019, ADR-0021, ADR-0022,
ADR-0033, invariants #1, #2, #3.
**Backend:** `opvocab` golden schema for the native vocabulary; `list_operations` /
`describe_node` for per-Node template vocabulary; `policyview` when seeding from a live Node. **No
write path of any kind.**

## What this screen is for

Policy authoring is the operator's half of the security boundary, and today it happens in a text
editor with `policy.example.toml` open in another tab. This screen makes it compositional: browse
the vocabulary, pick what to permit, set the argument values, get a file.

It is the **proactive** half of a pair. Spec 07 is the reactive half — one rule, born from a
specific deny. This one starts from the whole vocabulary.

## The hard boundary

**The Relay does not transmit Policy and has no code path that could.** Policy is locally-rooted
and remotely-immutable (ADR-0002, invariant #2); that property is what makes a compromised Relay
survivable. This screen ends at the operator's clipboard, deliberately, and says so on the screen
rather than only in a doc.

Generate-and-copy is compatible with the invariant. **Any future "apply to these Nodes" button is
not**, and would need a new ADR and a threat model.

## Layout

Two columns.

**Left — the catalog.** A "start from" control: shipped default (the ADR-0022 read baseline),
empty (deny-all), or a live Node's current Policy read through `policyview`. Then a search box and
the vocabulary, sectioned by risk class:

- **Read** — pre-allowed by the shipped default, so a fresh Node is interrogable on day one.
- **Mutate** — captioned *opt-in; nothing here is permitted until you add it*, which is
  deny-by-default stated as a fact about the screen.
- **Raw Exec** — the `[raw_exec]` regex gate, `admin` only.

Each row carries the Operation name in mono, its source (`native` or the template pack it comes
from), and its argument shape. Selecting one expands an argument editor showing the **real**
constraints from the golden schema — `service.restart`'s `unit` is charset `[A-Za-z0-9@._-]` with
no leading `-`, validated before argv is built, never a shell string.

**Right — three stacked outputs.**

1. The generated `policy.toml`, with unchanged blocks collapsed on screen but copied whole.
2. An **Ansible task** ready to drop into a role (below).
3. **What this grants**, in plain language, plus warnings.

## The vocabulary is real, and per-Node

Native Operations come from `opvocab`: `system.facts`, `file.read`, `service.restart`,
`pkg.install`. The shipped read catalog — `proc.list`, `disk.usage`, `net.listening`,
`pkg.inventory`, `service.status`, `log.tail`, `file.checksum` — are **Template Operations**
(ADR-0021), so vocabulary is per-Node. A rule for a pack a Node has not installed is **inert**:
dispatch reports `unsupported` and Policy is never asked. Say this on the screen, because it is
the difference between "denied" and "never asked" and an operator will otherwise read silence as
permission.

*A Policy rule never creates vocabulary; it only permits it.*

## The Ansible output

```yaml
- name: install the Node Policy
  ansible.builtin.copy:
    src: files/policy.toml
    dest: /etc/relay-daemon/policy.toml
    owner: root
    group: root
    mode: "0644"
    validate: relay-daemon policy check %s --templates /etc/relay-daemon/templates.d
  notify: reload relay-daemon
```

Three real properties are load-bearing here and none may be dropped:

- `validate:` runs the daemon's own checker against the temporary file **before** Ansible moves it
  into place, so a Policy that would fail to load never reaches the Node.
- The mode is fixed because the daemon's fail-closed loader refuses a file that is not root-owned
  or is group/world-writable.
- The file installs as a conffile / `%config(noreplace)` (ADR-0033), so a package upgrade never
  overwrites the operator's edits. An upgrade that restored the shipped default would be a
  fleet-wide unauthored permission change.

## Guidance the screen must carry

Two pieces, both lifted from `daemon/policy.default.toml` because they are the two edits that
matter:

1. **Narrowing `log.tail` is the highest-value edit in the file.** A journal carries whatever a
   service chooses to log, so an unnarrowed `log.tail` is the widest egress surface the read
   catalog has.
2. **`read` does not mean safe to see.** It means *cannot change Node state*. A read result flows
   onward to the model provider — reading is exfiltration by construction (ADR-0021). Narrowing
   `file.read`'s `"*"` to an explicit path list is the other edit worth making.

A Policy authoring tool that lets someone cheerfully tick `file.read "*"` without saying this is
doing them a disservice.

## Must not appear

- Any control that writes, pushes, distributes or applies Policy to a Node.
- Any claim that the Relay will roll this out.
- A generated file that omits the confidentiality deny-list when the operator started from the
  shipped default.

## Acceptance

- [ ] The catalog is generated from the golden schema and `list_operations`, never hand-listed.
- [ ] Argument constraints shown match the daemon's validators exactly.
- [ ] Copy yields a complete, loadable `policy.toml`; the on-screen collapse is presentational.
- [ ] `relay-daemon policy check` accepts every file this screen generates. This is a test, not an
      aspiration.
- [ ] Template Operations are marked as such and carry the inert-on-missing-pack warning.
- [ ] No route on this screen writes anything anywhere.
