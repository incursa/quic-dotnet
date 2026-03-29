---
artifact_id: SPEC-PRF
artifact_type: specification
title: Conformance Profiles and Enforcement Levels
domain: spec-trace
capability: conformance-profiles
status: draft
owner: spec-trace-maintainers
tags:
  - spec-trace
  - profiles
  - conformance
  - validation
---

# [`SPEC-PRF`](./SPEC-PRF.md) - Conformance Profiles and Enforcement Levels

## Purpose

Define the lightweight conformance profiles that let the standard stay easy on day one while supporting stricter repository policies when stronger traceability is needed.

## Scope

This specification covers the canonical profile names, the checks included in each profile, and the rule that profile choice stays repository-level rather than becoming per-artifact metadata.

## Context

Not every repository wants the same enforcement baseline. Some only need correct shapes and stable identifiers. Others want a stricter trace graph without turning the standard into a certification program.

## [`REQ-PRF-0001`](./SPEC-PRF.md) Define the canonical conformance profiles
The standard MUST define `core`, `traceable`, and `auditable` as its only canonical conformance profiles.

Notes:
- The profiles are ordered from least strict to most strict.
- The profile names are canonical; repositories may add local policy names, but not new canonical profiles.

## [`REQ-PRF-0002`](./SPEC-PRF.md) Keep the core profile minimal
The `core` profile MUST require schema-conformant shape, identifier correctness, and approved normative keyword correctness only.

Notes:
- `core` is the low-burden baseline.
- `core` does not require downstream trace completeness, verification coverage, or reciprocal trace checks.

## [`REQ-PRF-0003`](./SPEC-PRF.md) Define the traceable profile as core plus graph hygiene
The `traceable` profile MUST require the `core` profile plus no unresolved artifact or requirement references, no duplicate IDs, and at least one downstream trace link for every requirement.

Notes:
- Downstream trace links are `Satisfied By`, `Implemented By`, and `Verified By`.
- Upstream lineage fields such as `Derived From`, `Supersedes`, and `Source Refs` do not satisfy the downstream-trace requirement by themselves.

## [`REQ-PRF-0004`](./SPEC-PRF.md) Define the auditable profile as traceable plus proof coverage
The `auditable` profile MUST require the `traceable` profile plus verification coverage for every requirement, reciprocal trace agreement where reciprocal fields exist, and no orphan ARC, WI, or VER artifacts.

Notes:
- Verification coverage means each requirement has at least one `Verified By` link.
- Reciprocal fields exist when a linked architecture, work item, or verification artifact can mirror the requirement's downstream trace.
- An orphan ARC, WI, or VER artifact is an artifact that is not targeted by any requirement's downstream trace links.

## [`REQ-PRF-0005`](./SPEC-PRF.md) Keep profile choice lightweight and repository-scoped
The standard MUST remain usable at `core` level without per-artifact profile fields or certification records.

Notes:
- A repository MAY choose one canonical profile as its local enforcement target.
- Profile choice is repository policy, not canonical artifact metadata.
