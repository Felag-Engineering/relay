# 09 — Add Nodes

**Artboard 7.** Mint an Enrollment Token and render what the machines need, in one act.

> **Superseded in part by ADR-0048.** Nothing is rendered: the form asks how many Nodes the token is
> for, Labels are optional, and the reveal shows `sudo relay-daemon join` and the join string to
> paste at its prompt, apart. The rendering sections below are history until v0.7.0 redesigns the
> screen.
**Milestone v0.7.0.**

**Governing:** ADR-0006, ADR-0030, ADR-0031, ADR-0032, ADR-0033, invariants #7, #11.
**Backend:** `POST /api/v1/enrollment-tokens` with the `render` field and `renderings` response
(ADR-0032); the pure renderer; `admin` gating (`requiredControlRole` floors
`ControlMintEnrollmentToken` at `admin`).

**Only the `admin` gate exists.** Read *Backend prerequisites* below before planning this screen:
they are why #434 is blocked.

## What this screen is for

Getting the first Node — and the next fifty — into the fleet. On a fresh install it is the second
screen a new operator sees (spec 10 is the first).

## The constraint that shapes everything

**The Enrollment Token's plaintext is returned exactly once.** The Relay stores only its hash, so
an artifact that *contains* a token — a playbook, a shell one-liner, a join string — can only be
produced at the moment of minting, and never reproduced afterwards, by anyone.

Consequences for this screen, all mandatory:

- **Rendering format is chosen before minting**, not after. There is no "render this existing
  token" affordance, because that endpoint cannot work.
- The result behaves like a **secret reveal**: shown once, prominently marked as such, not a
  document to return to.
- **There is no re-render.** Losing the artifact means minting another token and revoking the
  first. That is cheap and correct; a re-render button would be a lie.

## Layout

**Left — the mint form.** The `relay:` labels this token will stamp, max uses, expiry, and the
render formats. Then "Mint and render". Below it, the outstanding-token inventory with revoke.

**Right — the reveal.** A once-only banner, then the rendered artifacts in tabs (`ansible`, `join`,
env file), each with copy and download. Below, "what happens on each machine".

## Scope is the security lane

The labels a token stamps are `relay:` labels — Relay-set, Node-immutable, and the only valid
target for quarantine and secret-distribution Selectors. Minting a token that stamps
`relay:env=prod` is therefore a privilege-granting act, which is why it requires `admin`
(`authz/control_test.go` pins the gate).

## The renderings

Three formats at beta, all renderings of the same three fields (join string, scope, expiry), so a
fourth is a template, not an architectural change.

- **`ansible`** — a playbook that installs the pinned daemon version by digest (`get_url` +
  `checksum`, so verify-then-install survives), writes the env file at mode `0600`, and enables the
  unit. Carries the token inline, and its expiry in a header comment.
- **`join`** — the bare `glp_join_…` string: one opaque, `glp_`-prefixed token that is greppable by
  secret scanners and safe unquoted in a shell.
- **env file** — `RELAY_JOIN` plus `RELAY_NODE_LABELS`, the two lines a Node needs.

## What happens on each machine

Three steps, stated on screen because they are the trust story:

1. The daemon verifies the certificate the Relay presents against the **fingerprint pinned inside
   the join string**, before anything else. Wrong fingerprint and it exits — there is no fallback.
2. It presents the token once, receives its own identity certificate, and the Relay stamps the
   `relay:` labels on it.
3. It loads its Policy and comes up **read-only** per ADR-0022 — interrogable, unable to change
   anything, until the operator widens Policy themselves.

## Must not appear

- A re-render control, in any form, for any token.
- The token plaintext anywhere outside the one-time reveal — not in a list, not in an audit view,
  not in a log.
- Any Relay configuration.

## Backend prerequisites

**This screen is blocked, and the blockers are backend, not design.** Recorded on 2026-09-20 after
a dev-loop attempt on #434 escalated; the E-numbers are `docs/design/self-serve-enrollment.md`'s.
ADR-0032 said what this would mean:

> *"The Console at v0.7.0 is a template and a copy button. … If the Console work turns out to need
> backend changes, this ADR was implemented wrong."*

| | Blocker | Evidence |
|---|---|---|
| **B1** | **ADR-0032's renderer does not exist** (E3). `mintTokenRequest`/`mintTokenResponse` carry no `render` field and no `renderings`; there is no renderer package; there is no build-time daemon version + SHA-256 for ADR-0032 §6's `get_url`+`checksum` pair (`internal/version` carries the Relay's own build identity only, and says so). | `controlplane/api/tokens.go`; `internal/version` |
| **B2** | **Partly cleared.** ADR-0031's join string is built (`relay.v1.JoinString`, minted by `enroll.Minter`, returned by the Control API mint as `join_string`, consumed by `relay-daemon join`). Still open: two of the three renderings also carry the Relay listen address, which invariant 11 reasoning refused to render on spec 10, and a guard fails the build if the Console says "join string". | `proto/relay/v1/relay.proto`; `internal/enroll/mint.go`; guard in `console/dayone_test.go` |
| **B3** | **There is no capability-layer mint, and the Console may not build one.** No capability service has a mint method; there is only the `ControlMintEnrollmentToken` *action constant*. `internal/enroll` transitively imports `internal/relay/v1`, which is on the capability package's own **forbidden-import** list — so the obvious seam breaks that package's guard. The three alternatives are each a human decision: the Console consulting `authz` (blocked by `no_dispatch_test.go`, citing invariant 10), a composition-root adapter (a fourth decision site and a parallel control path — invariant 10 again), or a proto-free capability seam, which is its own issue sized like #653. | `capability/seams.go`; forbidden list in `capability/execution_test.go`; `go list -deps ./internal/enroll` |
| **B4** | **No token-listing seam** for the outstanding-token inventory with revoke. `enroll.Repository` is Create/ByID/Save only; `store/tokens.go` has no List. | `internal/enroll/token.go`; `internal/store/tokens.go` |
| **B5** | **One acceptance checkbox is Rust-side**, not Console-side (E5/E6) — the daemon refusing a wrong CA fingerprint, which it checks against the join string's pin. | `docs/specs/enrollment.md`; `daemon/src/config.rs` |

**Net: two of the six acceptance checkboxes are not Console-side at all**, and the other four
depend on B1–B4. B3 is the wall: there is no legitimate path for the Console to mint.

### Two findings worth keeping, from the same attempt

**The route paths are forced** (driven through a real `ServeMux`). `Register` mounts a method
pattern *plus* a bare `r.Path` for every route that constrains reach, so:

- `GET /console/nodes/add` — the path this doc's layout implies — **panics at registration**
  against the existing `GET /console/nodes/{node_id}`: a constrained literal under a constrained
  `{id}` of the same shape.
- `GET` and `POST` both constrained on **one** path also panics (the bare path is registered
  twice). So the mint POST must live on a path of its own.
- `GET /console/add-nodes` + `POST /console/add-nodes/tokens` (+ `.../{token_id}/revoke`)
  register cleanly and collide with nothing.

**The step-up idiom is decided: per-action password, inline on the mint form** — not
`RequireStepUp`/`StepUpFresh`/the `StepUp` component. Four reasons, in the order they bind:
the `StepUp` component models a *standalone* confirmation with its own `FormAction`, and the mint
form must carry scope/TTL/max-uses/render-format in the same submission because the format is
chosen *before* minting (a nested `<form>` is invalid HTML, which `components.go` already records);
a freshness window lets one password buy a burst of `relay:`-stamping grants, and minting is
privilege-granting under invariant 7; a window invites refuse → prompt → replay, which would make
a *pending mint* cross a request boundary — the artefact `decide.go` already rejected, except here
the replayed thing is a fleet join credential; and an adapter may be stricter than the layer
(invariant 10), never looser.

## Acceptance

- [ ] Minting requires `admin`; a `viewer` and an `operator` are refused.
- [ ] Exactly one audit event per mint, recording what was rendered.
- [ ] The renderer has **no store dependency** — assert it structurally.
- [ ] Navigating away from the reveal and back does not show the artifacts again.
- [ ] The token plaintext appears in exactly one response and is never persisted.
- [ ] A daemon given a wrong CA fingerprint refuses enrollment and exits without falling back.
