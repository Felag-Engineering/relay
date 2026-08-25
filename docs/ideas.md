# Ideas backlog — post-v1.0.0 candidates

Captured from product/strategy review conversations (2026-07-02/03). These are **candidate
ideas, not commitments** — distinct from [ROADMAP.md](../ROADMAP.md)'s Deferred section,
which holds items already agreed in principle (each gets an ADR when picked up).

**Graduation path:** idea here → promoted to a ROADMAP milestone or its Deferred list →
ADR at pickup → build. Nothing in this file authorizes work.

**Timing notes:** most entries target post-v1.0.0, but a few carry a *design-reservation*:
a small decision (Policy syntax, proto enum, receipt contents) that is cheap to reserve
now and expensive to retrofit later. Those are flagged ⚠️.

The organizing principle behind most of these: take a control the industry evaluates in
the control plane (approval, audit, rate limiting, change windows, DLP) and re-root its
*verification* on the Node — so it holds even against a compromised Relay or a jailbroken
AI-agent. Each idea should deepen ADR-0002's invariant, never dilute it.

---

## Edge-rooted enforcement & evidence

### 1. Node-countersigned execution receipts ("flight recorder")
Each daemon signs a receipt for every Task it executes — Task ID, Operation, args hash,
timestamps, outcome, output hash — with its node key, chained with a per-Node monotonic
counter so omissions are detectable. The audit trail becomes dual-attested: the Relay's
record and the fleet's cryptographic account must agree. A compromised Relay cannot
fabricate or silently drop history.
- **Why:** converts the audit trail from "trust the control plane" to tamper-evident
  evidence; feeds compliance exports (change-management evidence per Job); enables the
  "your agent cannot lie to you about what it did" claim (see Job narrative, below).
- **Cost:** low-medium — the daemon already holds a key and already reports results.
- ⚠️ **Design-reservation:** decide *what gets signed and how it chains* early (with the
  v0.0.5 audit schema); receipt contents are hard to retrofit.

### 2. Node-verified co-signing (M-of-N approval at the edge)
A Policy rule may require that a high-risk Operation arrive with approval signature(s)
from customer-held keys, **verified by the daemon** — not by the Relay. The wire carries
the co-signature; the Node checks it. Dual control that survives control-plane compromise;
no incumbent's centrally-evaluated approval workflow can claim this.
- **Cost:** high — approval-key UX (custody, expiry, revocation) is genuinely hard.
- ⚠️ **Design-reservation:** shape the Policy format so a rule can express
  `requires co-sign` without a format break. Shares key infrastructure with signed
  Policy distribution (below).

### 3. Signed Policy distribution (the wire carries, the wire never authors)
If node-rooted Policy distribution via customer CM ever becomes the adoption blocker:
allow Policy updates over the Relay connection **only when signed by a customer-held key
the Relay never possesses** (bounded by version monotonicity + freshness windows).
Central-distribution ergonomics; trust root stays outside the control plane. The only
remote-update path consistent with ADR-0002 (which rejected remote update "for v1",
deliberately leaving this door open).
- **Trigger to revisit:** design partners repeatedly needing Policy changes faster than
  their CM cadence; or down-market pull toward teams with no CM pipeline.

### 4. Canary Policy rules + auto-Freeze ("tripwires")
Policy rules markable as tripwires — rules that should never legitimately match
(`file.read /etc/shadow`, Raw Exec touching sshd config). N tripwire hits from one
Account → automatic Freeze + alert. A jailbroken/hallucinating AI-agent's signature is a
deny storm; this turns deny verdicts into a detection surface. All ingredients exist
(deny verdicts, Freeze, per-Account attribution).
- **Cost:** low — Policy-format flag + Relay-side wiring.
- **Timing note:** argued as potentially *launch-critical* (it powers the public
  jailbreak-arena demo and the quickstart jailbreak kit); candidate to pull forward
  to ~v0.0.7, not post-1.0. Decide at v0.0.6 close.

### 5. Node-enforced temporal guardrails (blast radius in time)
Policy-expressible, daemon-enforced limits: mutate-budget per hour per Node, change
windows ("mutations only 02:00–06:00 local"). Complements the Relay-side per-Account
rate limits already in ROADMAP Deferred — this is the Node half, and the Node half is
the differentiated half (holds against a compromised Relay flooding the fleet).
- ⚠️ **Design-reservation:** reserve Policy syntax now; build later.

### 6. Node-side output redaction (secrets never leave the Node)
Policy-defined scrub patterns applied by the daemon *before* Task output hits the wire.
Upgrades the v0.0.7 audit-retention posture from "we store output carefully" to "the
sensitive bytes never left the machine."
- ⚠️ **Design-reservation:** reserve Policy syntax now; build later.

### 7. CA root/intermediate split + trust-bundle verification
Offline root, online issuing intermediate; daemon trusts a *bundle* so an intermediate
can be rotated gracefully under an intact root — mass re-enrollment reserved for true
root compromise. Two-tier disaster runbook (rotate-intermediate vs burn-root).
- **Timing note:** recommended **pre-beta**, not post-1.0 — touches cert-chain issuance
  and daemon verification that exist today and harden every milestone. Listed here only
  until it gets an ADR/issue.

### 8. TPM-bound Node identity / remote attestation
Attest that the daemon binary + Policy are what config management shipped. Thesis-aligned
but heavy; enterprise-tier. **Parked** — revisit on customer pull.

---

## Adoption ladder ("give your AI eyes before hands")

### 9. Shadow mode
A per-Account mode converting every `mutate` dispatch into a Plan (ADR-0011): the
AI-agent believes it is operating, daemons evaluate everything for real, nothing
executes. End-of-period report: "your agent would have executed 214 Operations; 197
allowed, 13 denied by Policy, 4 tripwires." A zero-risk production trial of AI ops —
the strongest sales artifact in the set.
- **Cost:** low-medium — plan mode as a standing Account attribute + a report.
- **Open design question:** does the agent *know* it is shadowed? (Honest-but-behavior-
  changing vs true-measurement-but-deceptive; the deception cuts against the
  transparency posture.) Grill before building.
- **Timing note:** v0.0.6-adjacent in spirit; candidate to pull pre-1.0.

### 10. Read-only fleet mode
One-line Relay config (or obvious preset) capping the entire fleet at `read`-class
Operations (ADR-0012 machinery). Day-one evaluation posture: enroll everything, the
agent sees all, mutates nothing. Completes the graduated-trust ladder:
observe → shadow → read + narrow mutate → earned autonomy.
- **Cost:** low.

### 11. Policy preset packs
Shipped, named, commented baseline Policies (`web-node-baseline`, `database-strict`,
`read-only-everything`), validated by `policy check` in CI. Kills the deny-by-default
cold-start problem; the first curated, audited command-level policy library in an
industry hand-rolling sudoers since 1986. Natural companion to Template packs (v1.1.0).
- **Cost:** low (documentation-shaped; dev-loop-friendly).

---

## Self-serve proof & legibility

### 12. `relay redteam` — packaged hostile-agent self-test
One command running a maintained suite of adversarial prompts/Operation sequences
(prompt-injection payloads, exfil attempts, tripwire probes, Raw Exec escapes) against
the fleet's *actual* Policy; emits a scored held/would-pass report. "Pentest your AI ops
in five minutes." Same regression suite as the v0.0.8 red-team, aimed at customers;
every install reproduces the public arena locally.

### 13. Job narrative / black-box replay
Render a Job (or an agent session) as a human-readable timeline: what was asked, what
the Plan predicted, what Policy denied and why, what ran, what each Node's receipt
attests. With receipts (#1) underneath: **the agent cannot misrepresent what it did**
(the canonical industry incident — Replit, July 2025 — was destruction *plus*
misrepresentation). Mostly a rendering layer over the v0.0.5 audit schema.

### 14. Denials that teach (structured verdicts for LLMs)
Deny responses carry the matched rule, failure class, and — consistent with Policy
visibility already exposed via `describe_node` — the nearby allowed set
("`service.restart` denied for `sshd`; allowed on this Node: `{nginx, php-fpm}`").
Agents self-correct instead of flailing or escalating to Raw Exec. Extends the v0.0.6
vocabulary-legibility deliverable from descriptions to verdicts.

### 15. Agent driving record (per-Account trust scorecard)
Advisory report over existing audit data: deny rate, tripwire hits, plan-before-apply
ratio, Raw Exec reliance, blast-cap near-misses — evidence for "how much do we trust
this agent," per Account, over time. **Must never auto-widen Grants** (that would invert
the trust model); a human reads it and decides.

### 16. Raw Exec promotion telemetry
Make ADR-0001's "recurring Raw Exec patterns are candidates for promotion to Native
Operations" a mechanism instead of an intent: a report surfacing top recurring Raw Exec
shapes per fleet from the audit trail. The scariest path becomes vocabulary-design
telemetry. Cheap (audit data exists); candidate beta deliverable.

---

## Ecosystem & go-to-market (not features, tracked so they aren't lost)

- **Open Policy/verdict spec** — publish the Policy file format and verdict semantics as
  an open standard any agent framework can target; BSL on the implementation, open on
  the contract. The layer-not-vendor play.
- **Public jailbreak arena** — standing sandbox fleet + hostile AI-agent + bounty on any
  Policy bypass; live tripwire/Freeze dashboard. Launch only after v0.0.8 holds.
  Doubles as continuous red-teaming.
- **Quickstart jailbreak kit** — ship `jailbreak.md` in the beta quickstart: twenty
  minutes to a fleet, then try to break your own Policy. Onboarding = the demo.
- **"Sudoers is from 1986" essay** — name the post-access enforcement gap; the
  category-naming content piece. Cheap; do early.
- **Controls mapping doc** — Relay's audit/deny-by-default/attribution mapped to
  SOC 2 / ISO 27001 change-management and access controls; sells to budgets that exist.
- **Public security page** — threat model (v0.0.8 output), red-team regression stats,
  arena statistics, signed reproducible builds, receipt design. The trust artifact
  stack, published.
- **Third-party audit** of daemon + enrollment path post-v0.0.8, report published.
- **Positioning notes:** lead with the post-access gap and fleet-execution semantics
  (felt, budgeted pains); AI-agent story as accelerant; control-plane-compromise
  survival as the closer, not the opener. The competitor is the
  Teleport + Ansible + sudoers sandwich, not any single product. Keep the contrarian
  frame pure: *every other vendor says "trust our AI"; Relay assumes yours is hostile.*

---

## Supply-chain & operational hardening (mostly pre-1.0; parked here until tracked)

- **Reproducible builds** for the musl daemon (achievable: Rust + musl + pinned
  toolchain); "rebuild our daemon bit-for-bit" as a trust claim. Fold into CD (#44).
- **Hardened systemd unit as a product artifact** (NoNewPrivileges, ProtectSystem=strict,
  seccomp) shipped as the default in install docs — the audited profile *is* the
  deployment, not a finding.
- **Vocabulary breadth pass** — a dozen boring, mostly `read`-class Native Operations
  (service status/start/stop, journal tail, process list, disk/memory, file stat/
  checksum, package query) chosen from design-partner usage; pre-beta candidate.
- **Template Operations ADR written early, built per v1.1.0** — the design artifact
  exists for design partners and the v0.0.8 red team to attack on paper.
