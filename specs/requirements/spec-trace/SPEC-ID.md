---
artifact_id: SPEC-ID
artifact_type: specification
title: Identifier Policy and Grouping-Key Registry
domain: spec-trace
capability: identifier-policy
status: draft
owner: spec-trace-maintainers
tags:
  - spec-trace
  - identifiers
  - policy
---

# [`SPEC-ID`](./SPEC-ID.md) - Identifier Policy and Grouping-Key Registry

## Purpose

Define the shape, stability, and published metadata for identifiers used by the standard.

## Scope

This specification covers artifact identifiers, specification identifiers, requirement identifiers, grouping segments, terminal sequence rules for sequence-bearing identifiers, and the machine-readable grouping-key registry.

## Context

Stable identifiers are the backbone of traceability. The standard cannot answer coverage questions if requirement IDs and artifact IDs drift or collapse into file-name conventions.

## [`REQ-ID-0001`](./SPEC-ID.md) Use approved identifier prefixes
Artifact documents MUST use `SPEC`, `ARC`, `WI`, or `VER` as applicable.

Notes:
- Decision records are not part of the core standard today; if a repository adds them, it should do so through an optional local extension.

## [`REQ-ID-0010`](./SPEC-ID.md) Use the REQ prefix for requirement clauses
Requirement clauses MUST use the `REQ` prefix.

## [`REQ-ID-0002`](./SPEC-ID.md) Keep domain and grouping tokens uppercase and letter-starting
Domain and grouping tokens MUST be uppercase alphanumeric text that starts with a letter.

## [`REQ-ID-0003`](./SPEC-ID.md) Allow stable optional grouping segments
Identifiers MAY include zero or more grouping segments after the domain token.

Notes:
- Grouping segments should reflect stable structure, not dates or workflow state.

## [`REQ-ID-0004`](./SPEC-ID.md) Use terminal-free specification identifiers
Specification artifact identifiers MUST use `SPEC-<DOMAIN>(-<GROUPING>...)`.

## [`REQ-ID-0005`](./SPEC-ID.md) Preserve identifier stability
An assigned identifier MUST remain stable.

## [`REQ-ID-0011`](./SPEC-ID.md) Prevent identifier reuse
An assigned identifier MUST NOT be reused for a different artifact or requirement.

## [`REQ-ID-0006`](./SPEC-ID.md) Keep identifiers authoritative inside the document
The identifier in front matter or a requirement heading MUST be authoritative.

## [`REQ-ID-0012`](./SPEC-ID.md) Keep file names non-authoritative
The file name MUST NOT replace the document or requirement identifier in traceability links.

## [`REQ-ID-0007`](./SPEC-ID.md) Keep requirement IDs aligned with their specification context
A requirement identifier SHOULD reuse the domain and grouping segments of the specification that contains it.

Notes:
- This keeps related clauses easy to find and trace, especially from tests and code references.

## [`REQ-ID-0008`](./SPEC-ID.md) Publish machine-readable grouping metadata
The reference package MUST publish a machine-readable grouping-key registry and identifier summary in [`artifact-id-policy.json`](../../../artifact-id-policy.json).

## [`REQ-ID-0009`](./SPEC-ID.md) Describe requirement identifiers alongside artifact identifiers
The identifier catalog MUST define the `REQ-<DOMAIN>(-<GROUPING>...)-<SEQUENCE:4+>` identifier shape alongside the document artifact identifier shapes.
