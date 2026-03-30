---
artifact_id: VER-<DOMAIN>[-<GROUPING>...]-<SEQUENCE:4+>
artifact_type: verification
title: <Verification Title>
domain: <domain>
status: planned
owner: <team-or-role>
verifies:
  - REQ-<DOMAIN>[-<GROUPING>...]-<SEQUENCE:4+>
related_artifacts:
  - SPEC-<DOMAIN>[-<GROUPING>...]
  - ARC-<DOMAIN>[-<GROUPING>...]-<SEQUENCE:4+>
  - WI-<DOMAIN>[-<GROUPING>...]-<SEQUENCE:4+>
---

# VER-<DOMAIN>[-<GROUPING>...]-<SEQUENCE:4+> - <Verification Title>

Use one of the approved verification statuses: `planned`, `passed`,
`failed`, `blocked`, `waived`, or `obsolete`.

## Scope

State what is being verified.

## Requirements Verified

- REQ-<DOMAIN>[-<GROUPING>...]-<SEQUENCE:4+>

## Verification Method

Describe the method in tooling-agnostic terms, such as execution, inspection,
analysis, or manual review.

## Preconditions

- <precondition>

## Procedure or Approach

Describe the steps or approach used to verify the requirement set.

## Expected Result

Describe the expected outcome in plain language.

## Evidence

- <evidence or test reference>

## Status

The status below applies to every requirement listed in `verifies`. If the
requirements do not share one outcome, split them into separate verification
artifacts.

planned

## Related Artifacts

- SPEC-<DOMAIN>[-<GROUPING>...]
- ARC-<DOMAIN>[-<GROUPING>...]-<SEQUENCE:4+>
- WI-<DOMAIN>[-<GROUPING>...]-<SEQUENCE:4+>
