# A Postgres store behind the repository interface

**Status:** idea (`2026-10-22`). Origin: the HA discussion (#139).

## Problem

The store is SQLite on a single connection, which is right for one Relay on one host and
wrong the moment there are two Relay instances or a fleet whose audit volume outgrows one
file.

## Proposal

Swap Postgres in behind the existing repository interface when HA lands, with no change to
the capability layer above it. The interface is the seam; nothing above it learns which
engine is underneath.

## Changes

`relay-configuration.md` for the new settings; the deployment stack under `deploy/`. No ADR
until the HA design spike names the shape.

## Objections

1. **Does the single-connection discipline that gives SQLite its write ordering have a
   Postgres equivalent the audit lane depends on?** — open.
