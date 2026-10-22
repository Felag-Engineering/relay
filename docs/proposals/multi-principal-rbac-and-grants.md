# Multi-principal RBAC and Grants

**Status:** shaping (`2026-10-22`). Origin: #285; direction settled in ADR-0041 (Proposed).

## Problem

Every Account with a role may reach every Node that role may reach. There is no way to say
that one principal may run one set of Operations against one part of the fleet and nothing
else, which is what a customer with more than one team needs before a second team is given
access.

## Proposal

Per-Account authorization rules, Grants, as Operation × Selector, deny-by-default. A Grant only
ever narrows what a Node's Policy allows; it never widens it. A Grant used as a security
boundary scopes by `relay:` Labels only, because they are the namespace no Node can write
(ADR-0006, invariant 7). Engine candidate: Cedar, evaluated together with the approval-rule
grammar so Relay never hand-rolls two policy engines. Picked up with the identity work after
the demo; it stays here until that milestone exists.

## Changes

`accounts-and-access.md`; `approval.md` where grant scope meets gate rules; ADR-0010 (the
Account model); ADR-0041 carries the direction and becomes Accepted when the milestone opens.

## Objections

1. **Two policy engines, one on the Node and one on the Relay, invite the Relay-side one to
   drift into reimplementing Policy (invariant 12).** — A Grant decides *who may ask*, never
   *what a Node will run*; the Node's engine stays the only one that evaluates Policy. Recorded
   in ADR-0041.
2. **A Grant keyed on `node:` Labels is a boundary a compromised Node can move itself out of.**
   — Hence `relay:` only for any Grant that is a security boundary; `node:` may narrow routine
   targeting and nothing more.
