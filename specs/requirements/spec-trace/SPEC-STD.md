---
artifact_id: SPEC-STD
artifact_type: specification
title: Core Standard Model and Publication Rules
domain: spec-trace
capability: core-standard-model
status: draft
owner: spec-trace-maintainers
tags:
  - spec-trace
  - standard
  - traceability
  - governance
---

# [`SPEC-STD`](./SPEC-STD.md) - Core Standard Model and Publication Rules

## Purpose

Define the core vocabulary, authority model, and publication rules for the spec-trace standard.

## Scope

This specification covers what a specification is, what a requirement is, where the canonical standard lives, how the reference package keeps its support material aligned, how the canonical conformance profiles are named, and how inline identifier references and structured trace differ.

## Context

The repository exists to make precise software requirements easy to author, review, and trace in plain Markdown. That goal only works if the requirement itself stays short and direct, and the repository also needs a low-burden baseline so teams can adopt the standard without committing to a stricter traceability policy on day one.

## [`REQ-STD-0001`](./SPEC-STD.md) Distinguish specifications from requirements
A specification MUST group one or more related requirements for a capability, behavior area, interface, or narrow technical concern.

Notes:
- A specification carries document-level context. It is not the smallest normative unit.

## [`REQ-STD-0002`](./SPEC-STD.md) Treat the requirement as the atomic normative unit
A requirement MUST be the smallest normative, testable statement in the system.

Notes:
- The requirement clause is the normative content.
- The standard uses BCP 14-style uppercase requirement language inspired by RFC 2119 and RFC 8174, but only the approved uppercase keyword set in [`SPEC-TPL`](./SPEC-TPL.md) carries defined normative meaning.
- Lowercase spellings are plain English.

## [`REQ-STD-0014`](./SPEC-STD.md) Give each requirement a stable identifier
Each canonical requirement MUST have a stable `REQ-...` identifier.

## [`REQ-STD-0003`](./SPEC-STD.md) Keep the canonical standard in the SPEC suite
The `spec-trace` standard MUST be expressed as the canonical SPEC suite under [`specs/requirements/spec-trace/`](./).

Trace:
- Related:
  - [SPEC-ID](./SPEC-ID.md)
  - [SPEC-LIN](./SPEC-LIN.md)
  - [SPEC-PRF](./SPEC-PRF.md)
  - [SPEC-LAY](./SPEC-LAY.md)
  - [SPEC-TPL](./SPEC-TPL.md)
  - [SPEC-SCH](./SPEC-SCH.md)
  - [SPEC-EXM](./SPEC-EXM.md)

## [`REQ-STD-0004`](./SPEC-STD.md) Keep root guidance subordinate to the SPEC suite
[`README.md`](../../../README.md), [`overview.md`](../../../overview.md), [`layout.md`](../../../layout.md), the root templates, the schemas, and the examples MUST align with the SPEC suite.

## [`REQ-STD-0015`](./SPEC-STD.md) Keep root guidance non-authoritative
[`README.md`](../../../README.md), [`overview.md`](../../../overview.md), [`layout.md`](../../../layout.md), the root templates, the schemas, and the examples MUST NOT override the SPEC suite.

## [`REQ-STD-0005`](./SPEC-STD.md) Make traceability a first-class goal
The standard MUST support explicit links from each requirement to relevant design, work-item, verification, test, and code artifacts.

Notes:
- Test and code references may be curated inline, derived by tooling, or both.

## [`REQ-STD-0021`](./SPEC-STD.md) Treat inline identifier references as lightweight links
The standard MUST treat a backtick-delimited canonical artifact identifier in prose as a lightweight, human-readable, machine-detectable inline identifier reference.

Trace:
- Related:
  - [SPEC-TPL](./SPEC-TPL.md)
  - [SPEC-SCH](./SPEC-SCH.md)
  - [SPEC-EXM](./SPEC-EXM.md)

Notes:
- An inline identifier reference can indicate that the current artifact, requirement, or descriptive passage depends on, complies with, is constrained by, or otherwise explicitly relates to the referenced artifact.
- Inline identifier references do not imply inheritance or copying.
- Inline identifier references do not replace `Trace` fields or lineage labels such as `Derived From` and `Supersedes`.
- Inline identifier references can appear in requirement clauses, `Notes`, and other descriptive sections.
- They are useful for component conformance, token usage, and cross-spec relationships when a full trace block would be heavier than necessary.

## [`REQ-STD-0022`](./SPEC-STD.md) Keep inline identifier references separate from structured trace
The standard MUST treat an inline identifier reference as a prose reference rather than a structured trace edge, lineage record, or inferred relationship type.

Notes:
- The surrounding prose carries any additional meaning.
- A backtick-delimited identifier alone does not encode dependency, inheritance, satisfaction, implementation, or verification.
- Inline identifier references do not replace `Trace` fields.

## [`REQ-STD-0006`](./SPEC-STD.md) Treat generated outputs as derived material
Generated indexes, traceability matrices, and coverage reports MUST be treated as derived outputs rather than canonical requirements.

## [`REQ-STD-0007`](./SPEC-STD.md) Update canonical surfaces together
A change to a canonical field, identifier rule, template shape, schema contract, or example pattern MUST update the affected specs, templates, schemas, and examples in the same change set.

## [`REQ-STD-0008`](./SPEC-STD.md) Use the reference repository as a proving ground
The reference repository MUST use the standard to specify itself under [`specs/requirements/spec-trace/`](./).

## [`REQ-STD-0009`](./SPEC-STD.md) Keep canonical requirements inside specifications
Each specification Markdown file MUST contain one specification.

## [`REQ-STD-0016`](./SPEC-STD.md) Keep canonical requirements inside specifications
A canonical requirement MUST appear inside its specification document rather than stand alone as an unlabeled prose fragment.

## [`REQ-STD-0010`](./SPEC-STD.md) Distinguish work items from requirements
A work item MUST describe implementation work rather than normative requirement text.

## [`REQ-STD-0011`](./SPEC-STD.md) Distinguish architecture from requirements
An architecture or design artifact MUST explain how one or more requirements are satisfied rather than replace those requirements.

## [`REQ-STD-0012`](./SPEC-STD.md) Distinguish verification artifacts and tests from requirements
A verification artifact MUST record how one or more requirements were verified.

## [`REQ-STD-0019`](./SPEC-STD.md) Keep verification outcomes homogeneous within one artifact
A verification artifact MUST only list requirements in `verifies` when the artifact status applies to every listed requirement; mixed outcomes belong in separate verification artifacts.

## [`REQ-STD-0020`](./SPEC-STD.md) Define canonical conformance profiles
The standard MUST define `core`, `traceable`, and `auditable` as its canonical conformance profiles.

Trace:
- Related:
  - [SPEC-PRF](./SPEC-PRF.md)

Notes:
- `core` is the low-burden baseline.
- `traceable` and `auditable` are stricter optional repository profiles.
- Profiles are repository-level enforcement targets, not per-artifact metadata.

## [`REQ-STD-0013`](./SPEC-STD.md) Distinguish code references from requirements
Tests MAY reference requirement identifiers directly without becoming the requirements themselves.

## [`REQ-STD-0017`](./SPEC-STD.md) Distinguish code references from requirements
Code references MAY identify implementation created because of a requirement.

## [`REQ-STD-0018`](./SPEC-STD.md) Keep code non-normative
Source code and code comments MUST NOT be treated as the normative requirement text.
