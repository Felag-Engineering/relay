# Gleipnir Relay

Gleipnir Relay is a fleet-administration control plane. Non-AI daemons on managed
Linux servers dial home to a central server and hold a persistent connection open;
through that connection the central server can run administrative actions on the
servers. An AI orchestrator drives the whole fleet by using the Relay as a tool,
while per-server policy restricts what may actually run — defense in depth.

## Language

**Relay**:
The central server. Accepts relay-daemon connections, routes Operations to
specific Nodes, returns results, and exposes the tool surface used by the
AI-agent.
_Avoid_: hub, server, master, control plane

**relay-daemon**:
The non-AI daemon installed on each managed Node. Dials home to the Relay, holds
a persistent connection, and executes Operations subject to local Policy.
_Avoid_: agent, thrall, client, minion

**AI-agent**:
The AI orchestrator that administers the fleet by using the Relay as one of its
tools. Explicitly *not* the relay-daemon.
_Avoid_: agent (unqualified), AI, brain, operator

**Node**:
A managed Linux server that runs a relay-daemon.
_Avoid_: host, machine, target

**Operation**:
A structured, typed administrative action from a fixed vocabulary (e.g. restart a
service, read a file, install a package). The primary execution primitive.
_Avoid_: command, task

**Raw Exec**:
The escape hatch: arbitrary command execution, permitted only when it matches a
Node's regex-based Policy. Exceptional path for what the Operation vocabulary
cannot express.
_Avoid_: shell, command string

**Policy**:
The per-relay-daemon rules that decide whether a given Operation or Raw Exec is
allowed to run on that Node. Locally-rooted and remotely-immutable: enforced by the
relay-daemon, queryable by the Relay, never changeable over the wire. The last line
of defense.
_Avoid_: ACL, ruleset, permissions

**Job**:
A single dispatch of an Operation or Raw Exec across the Nodes matched by a Selector.
Comprises one Task per matched Node and is the unit of audit and blast-radius control.
_Avoid_: batch, run, execution

**Task**:
The execution of one Operation or Raw Exec on a single Node, as part of a Job. Carries a
unique ID for at-most-once execution and reports an independent outcome.
_Avoid_: command, unit, step

**Selector**:
A label-based query that targets a set of Nodes (e.g. `role=web, env=prod`). Operations
and Raw Exec fan out to every matching Node and return a per-Node result. A single Node is
just a Selector that matches one.
_Avoid_: filter, query, target spec

**Label**:
A key/value tag on a Node used by Selectors to target it. Lives in one of two
non-overlapping namespaces: **node-space** (`node:…`, self-reported by the daemon, trusted
only as much as the Node) or **relay-space** (`relay:…`, authoritative, set by the Relay).
Security-sensitive Selectors target `relay:` labels.
_Avoid_: tag, attribute, annotation

**Facts**:
Descriptive properties a daemon self-reports about its Node (OS, kernel, hostname, IP,
installed packages). Inform decisions but never used as authoritative targeting — that is
the role of relay-space Labels.
_Avoid_: metadata, attributes, properties

**Enrollment Token**:
The reusable, scoped, expiring, revocable credential a daemon presents to join the fleet.
Distinct from a Node's identity certificate: the token authorizes *enrollment* and stamps
relay-space Labels; the certificate is the resulting *identity*. Can only enroll, never run
Operations.
_Avoid_: API key, secret, join key

**Relay-side authorization**:
The central rules deciding which principal (a human or an AI-agent) may send which
Operations to which Nodes. Distinct from Policy: authorization governs *who may ask*,
Policy governs *what a Node will ever do*.
_Avoid_: permissions, RBAC (when ambiguous with Policy)

**System Model**:
The Relay-maintained graph that links Nodes and Labels into higher-order Services,
Dependencies, and Annotations, giving the AI-agent a persistent, shared understanding of the
fleet. Stored as git-backed YAML; advisory to execution, never authoritative.
_Avoid_: topology, CMDB, knowledge base, map

**Service**:
A named grouping in the System Model defined by a Selector over Labels — how related Labels
are linked into a meaningful unit (e.g. "payments"). Desugars to a Selector for execution.
_Avoid_: app, group, cluster

**Dependency**:
A directed relationship in the System Model between Services (e.g. "payments depends on
postgres-primary"), letting the AI-agent reason about ripple effects and impact.
_Avoid_: link, edge, relation

**Annotation**:
Free-text notes attached to any System Model entity by the AI-agent or a human, carrying
provenance. Descriptive context only, never used for targeting.
_Avoid_: comment, note, tag
