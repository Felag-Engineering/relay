# HA and horizontal Relay scaling

**Status:** idea (`2026-10-22`). Origin: #139; the ADR-0005 caveat.

## Problem

One Relay process holds every Node connection and every Job. A Relay that stops takes the
fleet's control plane with it, and a fleet larger than one process can serve has no path.

## Proposal

A Node-to-instance routing registry so that several Relay instances can share a fleet, with a
Node connected to exactly one instance at a time and a dispatch routed to the instance that
holds it. The build is deferred; the design spike is required before the v1.0.0 freeze.

## Changes

ADR-0005 (transport) and its single-Relay caveat; `node-connection.md`; the store, which the
Postgres proposal covers; the Freeze, which must reach every instance.

## Objections

1. **Does a routing registry become a second source of truth about which Nodes exist?** — open.
2. **What does at-most-once (invariant 4) mean when a Node moves between instances mid-Job?**
   — open.
