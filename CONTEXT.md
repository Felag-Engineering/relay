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
non-overlapping namespaces, each immutable from the other side: **node-space** (`node:…`,
rooted on the Node and set out-of-band via config management; the Relay records but never
modifies or removes them; authoritative for routine targeting, trusted only as much as the
Node) or **relay-space** (`relay:…`, set by the Relay and immutable to the Node; reserved for
the security-sensitive lane). Remediation/quarantine and secret-distribution Selectors target
`relay:` labels.
_Avoid_: tag, attribute, annotation

**Facts**:
Descriptive properties a daemon self-reports about its Node (OS, kernel, hostname, IP,
installed packages). Inform decisions but are never used for targeting — that is the role of
Labels (see Label).
_Avoid_: metadata, attributes, properties

**Enrollment Token**:
The reusable, scoped, expiring, revocable credential a daemon presents to join the fleet.
Distinct from a Node's identity certificate: the token authorizes *enrollment* and stamps
relay-space Labels; the certificate is the resulting *identity*. Can only enroll, never run
Operations.
_Avoid_: API key, secret, join key

**Certificate renewal**:
A Node rotating its short-lived identity certificate before expiry over its existing mTLS
identity — no Enrollment Token — via the Relay's cert-authenticated `Renew` RPC. The Relay
issues a fresh certificate for the *same* node_id (derived from the verified peer cert, never
the CSR), preserving provenance; renewals are jittered to spread the fleet over time. Distinct
from *enrollment*: enrollment is token-authenticated and mints the first identity; renewal is
cert-authenticated and refreshes the existing one. (ADR-0006)
_Avoid_: re-enroll, reissue, cert refresh

**Relay-side authorization**:
The central rules deciding which Account may send which Operations to which Nodes.
Distinct from Policy: authorization governs *who may ask*, Policy governs *what a Node
will ever do*.
_Avoid_: permissions, RBAC (when ambiguous with Policy)

**Account**:
A named identity — human or machine — with a role (`viewer`, `operator`, `admin`), to
which every credential binds: a human's password or OIDC identity, a machine's API
Tokens. The AI-agent authenticates as a machine Account. The unit of Relay-side
authorization and of audit attribution across all three surfaces (ADR-0010).
_Avoid_: user, principal, service account (say "machine Account")

**API Token**:
A bearer credential bound to an Account, used by machines (and the AI-agent via MCP) to
call the Control API. Named, revocable, optionally expiring, stored only as a hash, and
inheriting its Account's role. Distinct from an **Enrollment Token**, which joins Nodes
to the fleet and can never call the API.
_Avoid_: API key, PAT, bearer token (unqualified)

**Control API**:
The REST/JSON surface (`/api/v1`, OpenAPI-described) through which humans' tooling and
machines drive the control plane — both administration and execution. One of the three
user-facing surfaces (with the MCP surface and the Admin Console), all thin adapters
over the same capability layer; the Control API is the programmable superset
(ADR-0010). It never reaches the Relay's own configuration, which is a root-owned
local file.
_Avoid_: REST API (unqualified), admin API, "the API" (in docs; fine in speech)

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

**Admin Console**:
The human-facing web UI for operators to observe the fleet and administer the control
plane (enrollment lifecycle, revocation, registry/audit views). Admin + observability
only: it has **no execution surface** — Operations and Raw Exec never run from the
Console (ADR-0009). A thin adapter over the same operator capability layer as the MCP
surface (ADR-0003, ADR-0009). Distinct from the **AI-agent**, which drives the Relay
over MCP.
_Avoid_: dashboard, portal, admin panel, "the UI"
