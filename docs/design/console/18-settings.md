# 18 — Settings

**No artboard.** The operator settings a human `admin` changes, and the security floor rendered
read-only. **Milestone v0.7.0.**

**Governing:** ADR-0010 (amended 2026-09-15), ADR-0004 and ADR-0012 (amended 2026-09-15),
ADR-0014, invariants #5, #10, #11, #14. Behaviour: `docs/specs/relay-configuration.md`.
**Backend:** store-backed operator settings (unbuilt — today every value here is an environment
variable read at startup); step-up (#428); audit.

Decided with the owner, 2026-09-16: gate rules are a separate page (spec 19); the confirm step
shows old → new and nothing more; the screen keeps no change history.

## What this screen is for

Turning the dials an operator turns as confidence in a fleet grows — without editing a file and
restarting a service — and seeing, in one place, the host-set values nobody can change from here.

## Navigation

**Administer › Settings.** `admin` only: for any other role the destination is absent, not
disabled (ADR-0026, spec 11). Administer becomes Add Nodes · Accounts · Incident · Settings.

## Sections

### Operator settings — editable

| Setting | Control | Notes shown beside it |
|---|---|---|
| Read blast cap | integer | "Most Nodes one read-class dispatch may reach." |
| Mutate blast cap | integer | "Most Nodes one mutate-class dispatch, Raw Exec, or quarantine engage may reach." |
| Minimum daemon version | version string, or empty for off | "Nodes below it are `state:outdated` and refused mutate dispatch." |
| `state:cert-expiring` fraction | 0–1 | "Share of a Node certificate's lifetime remaining at which it is flagged." |
| Enrollment rate limits | per-IP rate and burst, global rate and burst, tracked-IP ceiling | "Flood protection on the enrollment listener." |
| Node cap | integer | "Enrollments beyond this are refused." |
| Retention and page sizes | per setting | "Housekeeping." |

Each row shows the current value and its default. **No history, no "last changed by"** — the
owner decided against it. Every change is still an audit record (ADR-0010's amendment; R15's
compensating control), so it is on the audit trail like any other act (Activity lists tool calls only, owner
decision 2026-10-01, #829); this screen does not re-present it.

Gate rules are not here — spec 19.

### Security floor — read-only

The non-secret floor values, rendered so an operator can see the terms the Relay runs on: listen
addresses, certificate hostname, OAuth issuer, audience, claim, required scope and public URL,
Console session maximum age and idle timeout, step-up window, `console_execution`, approval
webhook URL and timeout. One line above the section: *"Set on the host. Change the environment
file and send SIGHUP, or restart for listener, CA or store changes."*

**Never rendered:** file paths, the CA directory, the store path, or the contents of any secret
file (`relay-configuration.md` §Visibility). No control of any kind in this section — not a
disabled field, not a copy-to-edit affordance.

## Changing a setting

1. Edit one value. Client-side validation mirrors the server's type check only; the capability
   layer decides validity and says why a value is refused.
2. **Confirm step: old → new, and nothing more.** The owner decided against an impact preview.
3. **Step-up**, every change, whatever the value and whichever direction. Lowering a cap still
   steps up: a lowered cap is how a hijacked session denies service.
4. The change applies to the next request. The screen says so on success, once.

A coherent-but-probably-wrong value — a mutate cap above the read cap — saves, and renders a
warning on the row for as long as it holds (`relay-configuration.md` §Validation). A value that
cannot work is refused with the reason.

## Must not appear

- Any secret, path, or CA material.
- Any edit control on the security floor.
- A history, timeline or diff view of past changes.
- A per-setting role check computed by the Console: the capability layer decides who may change
  what (invariant 10).
- The destination, for any role but `admin`.

## States

- **Unbuilt backend** (today): the page is not mounted. Settings are environment variables.
- **Step-up expired mid-edit:** the save re-prompts; the edited value is kept in the form.
- **Refused value:** the row stays in edit with the capability layer's reason under it.

## Acceptance

- A `viewer` and an `operator` have no Settings destination, and `GET` on its route is 404 for
  both (the shell's absent-beats-forbidden sweep covers it).
- Every save requires a fresh step-up; a save without one changes nothing and is audited as a
  refusal.
- A saved change is one audit record carrying setting, old value, new value and actor.
- No rendered page of this screen contains a file path, the CA directory, the store path or any
  secret file's contents (render test against a fixture with every floor value set).
- The security floor section contains no `<input>`, `<select>`, `<textarea>` or `<button>`.
- No MCP tool or Control API route writes a blast cap (structural test, per the configuration
  spec).
