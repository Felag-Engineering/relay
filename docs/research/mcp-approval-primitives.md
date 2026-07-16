# Research: MCP primitives for AI-bypass approval

_High-level research note. Captured 2026-07-15 during long-term planning. Feeds the
approval-callout epic (#210) and its future ADR. Not a decision record — a grounding
brief so the ADR author starts from the right conclusion._

## Question

For Relay's **approval callout** (an action requiring approval routes to a human
**without going through the AI**), is there anything in the MCP protocol — now or
upcoming — we can leverage, and expect other harnesses to leverage, to carry it?

## Bottom line

MCP gives us the **plumbing to surface an approval to a human without the LLM**, and any
compliant harness supports it — but it does **not** give us the two things that make the
feature ours: **audience routing** and a **hard AI-bypass guarantee**. Those stay
Relay/Gleipnir's job. Architecture: **notify via MCP, decide out-of-band.**

## What MCP gives us (leverage; expect other harnesses to support)

- **Elicitation** (`elicitation/create`, stable since spec 2025-06-18) — the directly
  relevant primitive. A **server** asks; the flow is **Server → Client → human User →
  Client → Server**. The client renders UI to the *person*; it does **not** pass through
  the LLM. Response model is `accept` / `decline` / `cancel` → maps 1:1 to
  approve / deny / cancel. Schema is restricted to flat primitives (fine: a boolean/enum
  decision + a reason string); rich context goes in the human-readable `message`. Spec
  says servers **MUST NOT** request sensitive info, and it is "newly introduced… design
  may evolve." Newer drafts/SDKs add a **URL mode** (server returns a link to visit) — the
  cleanest bridge to an out-of-band decision page; treat as emerging, not settled.
- **Tasks extension** (SEP-1686 → moving to an extension in 2026) — the async backbone. A
  `tools/call` may return a **task handle** instead of a result; the client polls
  `tasks/get`, and a task can carry **in-progress server-to-client requests** (i.e., an
  elicitation *during* a long wait). Near-exact match for a **pending-approval Job state**.
  Still stabilizing (lifecycle gaps: retry, expiry) — design against it carefully.
- **HITL norm** — MCP already tells clients they SHOULD keep a human able to deny tool
  invocations, so harness users already expect approval prompts. We build on an
  established expectation.
- **Alignment** — the 2026-07-28 spec RC removes protocol sessions (any request lands on
  any instance). A handle-based, stateless approval flow fits that, and fits Relay (a Job
  is already a durable handle).

## What MCP does NOT give us (we own it)

- **No audience routing.** Elicitation reaches "the current user of the client," not "the
  on-call DB team's channel." Routing to a named audience is inherently harness-specific —
  exactly Gleipnir's value-add.
- **No hard AI-bypass guarantee.** Elicitation/tasks travel **over the MCP session, which
  is the AI's channel and the client's responsibility.** A compromised or naïve client
  could feed the "approval" to its LLM or auto-answer it. MCP HITL is a *client-side
  convention*, and the security literature documents it being attacked (approval fatigue,
  description truncation, consent-overload, an "approval-view fidelity gap" where what the
  human sees isn't what executes). **In-band MCP approval is only as trustworthy as the
  harness.**
- **Roadmap won't rescue this soon.** MCP's 2026 top priorities are Agent Communication
  (Tasks), registry, etc. Human-in-the-loop / approvals / authorization are explicitly
  "On the Horizon," not top-four; the authorization work that *is* moving is OAuth /
  enterprise-auth, not action-approval. Don't bet on a standard "approval" primitive.

## Conclusion — the shape for #210

**Notify via MCP, decide out-of-band.**

1. **The guarantee lives out-of-band.** Relay → approver endpoint → human/HIL → decision →
   Relay. The decision never touches the MCP session, so the proposing AI/harness is
   structurally not in the trust path. Relay authors the request content (operation,
   resolved nodes, blast, plan verdicts), so it can't be truncated/spoofed by the AI
   (directly counters the approval-view-fidelity attacks). Works even for harnesses with
   zero approval features, and for the **API-control drive mode**, which has no MCP session.
2. **Elicitation/Tasks are the interop veneer.** For MCP-driving harnesses, Relay (the
   **server**) issues `elicitation/create` to surface the pending approval; the client
   awaits it (held request for short waits, or the Tasks async pattern for long ones).

### The Gleipnir premium path (the near-term win)
Relay-as-MCP-provider → `elicitation/create` → **Gleipnir (the MCP client)** routes the
elicitation to the **audience assigned to the agent** via its existing HIL router → human
decides → `accept`/`decline` returns to Relay. Standard MCP mechanism; audience routing is
pure Gleipnir. **"Support elicitation in Gleipnir and we're off to the races."**

> **The one line that makes it AI-bypass:** elicitation handling is a *client-side* choice,
> so **Gleipnir's elicitation handler MUST be a deterministic path to the human audience —
> never surfaced to the agent's LLM, never auto-answered.** That is what keeps AI-bypass a
> guarantee rather than a convention. Trivial for a first-party client to enforce; just
> never let the incoming elicitation get fed back to the model.

### Practical notes
- **Long waits → Tasks async**, not one held request (human approval can take minutes/hours).
- **Two paths, by drive mode:** elicitation for the MCP-provider mode (#209 mode 1) and
  for elicitation-capable harnesses; the **out-of-band webhook** for the API-control mode
  (#209 mode 2) and any harness without elicitation. Elicitation is the *primary premium*
  path; the webhook is the *universal* one. Build both.
- **Gate config stays above the AI's reach** (root-owned Relay config decides *when*
  approval is required); elicitation/webhook are only the *delivery*.

## Sources
- Elicitation — MCP spec 2025-06-18: https://modelcontextprotocol.io/specification/2025-06-18/client/elicitation
- MCP client concepts (human-in-the-loop / consent): https://modelcontextprotocol.io/docs/learn/client-concepts
- SEP-1686 Tasks: https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1686 · SEP-2663 Tasks Extension: https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2663
- 2026 MCP Roadmap: https://blog.modelcontextprotocol.io/posts/2026-mcp-roadmap/ · Roadmap page: https://modelcontextprotocol.io/development/roadmap
- 2026-07-28 Spec RC (stateless architecture): https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/
- MCP-38 Threat Taxonomy (approval fatigue/truncation): https://arxiv.org/pdf/2603.18063 · Approval-View Fidelity Gap: https://arxiv.org/pdf/2607.05744
