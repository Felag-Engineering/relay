# Gate rules edited in the Console

**Status:** idea (`2026-10-22`). Origin: `approval.md` AP-72 and AP-55, designed for v0.7.0 and
cut from the MVP by ADR-0047.

## Problem

Gate rules live in a section of the Relay configuration file, so changing what waits for a human
means editing a file on the Relay's host and reloading. An operator without host access cannot
tighten or loosen a rule, and the record of who changed one is whatever the host keeps.

## Proposal

Rules become runtime objects in the Relay's store, edited by a human `admin` in the Admin Console
with step-up re-authentication, audited per rule with old and new values, in effect from the
next dispatch. No MCP tool and no Control API route writes them, and none may be added: an
AI-agent must never be able to edit the gate that gates it. A Relay whose store holds no rules at
first start seeds the shipped default once, as an audited act of the system, and never re-seeds.
This was ADR-0010's 2026-09-15 amendment and ADR-0027's store-backed rules.

## Changes

`approval.md` (the rule-source claims, AP-4 to AP-8, become store claims); `relay-configuration.md`
(the gate section goes); the Console's screens; ADR-0047 decision 7 superseded.

## Objections

1. **A compromised human Console session could remove every gate.** — Accepted in the earlier
   design as threat-model R15; it returns with this proposal.
2. **The configuration file is stricter: only whoever administers the host can change it.** Is
   Console editing worth that loss for the MVP's users? — open; the reason ADR-0047 kept the file.
