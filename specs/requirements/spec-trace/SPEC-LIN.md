---
artifact_id: SPEC-LIN
artifact_type: specification
title: Trace Lineage and Requirement Evolution
domain: spec-trace
capability: trace-lineage
status: draft
owner: spec-trace-maintainers
tags:
  - spec-trace
  - lineage
  - traceability
  - evolution
---

# [`SPEC-LIN`](./SPEC-LIN.md) - Trace Lineage and Requirement Evolution

## Purpose

Define how requirement IDs stay stable while requirements evolve, and how the standard records lightweight upstream trace without workflow states or tombstone records.

## Scope

This specification covers editorial clarifications, semantic changes, split and merge cases, moved requirements, ID reuse, and the optional lineage and source fields in requirement Trace blocks.

## Context

Requirements change over time, but traceability only stays useful if the repository can distinguish wording edits from new obligations.

## [`REQ-LIN-0001`](./SPEC-LIN.md) Keep editorial clarifications on the same requirement ID
Editorial clarifications MUST keep the same `REQ-...` identifier when the obligation does not change.

Notes:
- Clarifications include wording fixes, formatting changes, and other non-semantic edits.
- A moved requirement may keep the same identifier if its semantics do not change.

## [`REQ-LIN-0002`](./SPEC-LIN.md) Assign a new requirement ID for semantic changes
A semantic change MUST use a new `REQ-...` identifier.

Notes:
- New obligations, altered acceptance criteria, and changed invariants are semantic changes.

## [`REQ-LIN-0003`](./SPEC-LIN.md) Assign new requirement IDs for split and merge outcomes
Split and merge scenarios MUST produce new `REQ-...` identifiers for the resulting requirements.

Notes:
- Use lineage fields to preserve the relationship to the source requirement IDs.
- The active repository does not need tombstone requirement records for retired IDs.

## [`REQ-LIN-0004`](./SPEC-LIN.md) Preserve identifiers when a requirement moves without semantic change
A requirement MAY keep the same `REQ-...` identifier when it moves to another file or section and its semantics do not change.

Notes:
- File moves and section moves are editorial changes when the obligation stays the same.

## [`REQ-LIN-0005`](./SPEC-LIN.md) Never reuse retired requirement IDs
A retired `REQ-...` identifier MUST NOT be reused for a different obligation.

## [`REQ-LIN-0006`](./SPEC-LIN.md) Keep upstream trace lightweight
A requirement MAY use `Derived From`, `Supersedes`, and `Source Refs` in its Trace block to record lineage and upstream material without adding per-requirement workflow states.

Notes:
- `Derived From` records refinement lineage.
- `Supersedes` records forward replacement lineage.
- `Source Refs` records free-form external references such as laws, contracts, tickets, incidents, customer asks, and policies.
- The repository does not require tombstone requirement records for old identifiers.

## [`REQ-LIN-0007`](./SPEC-LIN.md) Keep inline references separate from Trace
Inline references MUST NOT be treated as `Derived From`, `Supersedes`, or `Source Refs` entries.

Notes:
- Requirements can still mention other artifact identifiers in prose using backtick-delimited inline references.
- Such mentions are lightweight links and do not establish lineage or upstream material on their own.
- Use Trace fields when the relationship needs typed, toolable semantics.
- Inline references do not imply copying, inheritance, or replacement.
