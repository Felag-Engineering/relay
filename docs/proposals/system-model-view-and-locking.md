# System Model: a graphic view, and entry locking

**Status:** idea (`2026-10-22`). Origin: the ADR-0008 notes; after milestone v1.1.0.

## Problem

The System Model is a git-backed graph that an AI-agent may edit freely. A human has no
picture of it, and no way to pin an entry the agent must not change.

## Proposal

Two additions after v1.1.0: a graphic view of Services, Dependencies and Annotations in the
Console, read-only; and per-entry locking so an operator can mark an entry that only a human
may edit. Neither changes the model's standing: it stays advisory, never a desired-state spec
(invariant 9).

## Changes

`system-model.md`; ADR-0008; the Console screens under `docs/design/console/`.

## Objections

1. **A lock is a write the AI-agent cannot make; does that make it a `relay:`-like authority
   the model does not have today?** — open.
