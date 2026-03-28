---
artifact_id: ARC-<DOMAIN>[-<GROUPING>...]-<SEQUENCE:4+>
artifact_type: architecture
title: <Architecture or Design Title>
domain: <domain>
status: draft
owner: <team-or-role>
satisfies:
  - REQ-<DOMAIN>[-<GROUPING>...]-<SEQUENCE:4+>
related_artifacts:
  - SPEC-<DOMAIN>[-<GROUPING>...]
---

# ARC-<DOMAIN>[-<GROUPING>...]-<SEQUENCE:4+> - <Architecture or Design Title>

Use one of the approved architecture statuses: `draft`, `proposed`, `approved`, `implemented`, `verified`, `superseded`, or `retired`.

## Purpose

State how this design satisfies the named requirements.

## Requirements Satisfied

- REQ-<DOMAIN>[-<GROUPING>...]-<SEQUENCE:4+>

## Design Summary

Summarize the chosen design and the core mechanism that satisfies the requirement set.

## Key Components

- <component or concept>
- <component or concept>

## Data And State Considerations

Describe the state, data, and ordering rules that materially affect requirement satisfaction.

## Edge Cases And Constraints

Call out boundary cases, failure paths, retries, or invariants that matter to the requirements.

## Alternatives Considered

- <alternative and reason rejected>

## Risks

- <risk or follow-up>

## Open Questions

- <question>
