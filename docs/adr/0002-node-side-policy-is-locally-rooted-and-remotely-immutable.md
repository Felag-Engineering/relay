# Node-side Policy is locally-rooted and remotely-immutable

Each relay-daemon enforces a local **Policy** that decides what may run on its Node,
and the Relay (and therefore the AI-agent) can **query** that Policy but can **never
modify it over the wire**. Policy lives in a root-owned file on the Node; changing it
requires local or out-of-band access (config management, SSH). Authorization is
therefore two-layered: central **Relay-side authorization** (which principal may send
which Operations to which Nodes) and local **Node-side Policy** (what a Node will ever
execute, regardless of who asked).

## Decision details

- **Deny-by-default.** Nothing runs unless explicitly allowed. The blocklist provides
  carve-outs within allowed sets, and **deny always beats allow**.
- **Argument-level granularity.** Policy constrains not just the Operation type but its
  arguments (e.g. allow `service.restart` for `{nginx, php-fpm}` but not `sshd`). Raw
  Exec is deny-by-default and permitted only when it matches an allow-regex and no
  deny-regex.

## Consequences

- The Node distrusts the Relay by design: a fully compromised Relay or a jailbroken
  AI-agent still cannot exceed a Node's local Policy. This is the core defense-in-depth
  property.
- The AI-agent cannot expand a Node's permissions on the fly; widening Policy is a
  deliberate human/out-of-band act. This inconvenience is the intended security
  property.
- A controlled remote-policy-update path was explicitly rejected for v1 because it would
  collapse the two layers into one.
