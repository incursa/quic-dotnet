---
artifact_id: SPEC-TPL
artifact_type: specification
title: Templates and Compact Requirement Grammar
domain: spec-trace
capability: templates-and-grammar
status: draft
owner: spec-trace-maintainers
tags:
  - spec-trace
  - templates
  - grammar
  - front-matter
---

# [`SPEC-TPL`](./SPEC-TPL.md) - Templates and Compact Requirement Grammar

## Purpose

Define the canonical file-level metadata and the compact requirement clause grammar used by the standard.

## Scope

This specification covers front matter keys, specification roles, requirement headings, normative keyword usage, optional trace blocks, requirement title guidance, trace label semantics, lineage and upstream source labels, inline identifier reference syntax, and the reference structure for architecture, work-item, and verification documents.

## Context

The standard needs predictable documents, but the requirement itself should not be hidden under record-management boilerplate. Core front matter stays fixed; repositories may add optional namespaced `x_...` keys for local extensions.

## [`REQ-TPL-0001`](./SPEC-TPL.md) Keep specification front matter document-level and compact
Specification documents MUST use the file-level keys `artifact_id`, `artifact_type`, `title`, `domain`, `capability`, `status`, and `owner`.

Notes:
- `tags` and `related_artifacts` are optional.

## [`REQ-TPL-0002`](./SPEC-TPL.md) Keep architecture front matter focused on satisfaction links
Architecture documents MUST use the file-level keys `artifact_id`, `artifact_type`, `title`, `domain`, `status`, `owner`, and `satisfies`.

Notes:
- `related_artifacts` is optional.

## [`REQ-TPL-0003`](./SPEC-TPL.md) Keep work-item front matter focused on implementation links
Work-item documents MUST use the file-level keys `artifact_id`, `artifact_type`, `title`, `domain`, `status`, `owner`, `addresses`, `design_links`, and `verification_links`.

Notes:
- `related_artifacts` is optional.

## [`REQ-TPL-0004`](./SPEC-TPL.md) Keep verification front matter focused on proof links
Verification documents MUST use the file-level keys `artifact_id`, `artifact_type`, `title`, `domain`, `status`, `owner`, and `verifies`.

Notes:
- `related_artifacts` is optional.
- The `status` field is artifact-scoped; if the requirements in `verifies` do not share one outcome, split them into separate verification artifacts.

## [`REQ-TPL-0005`](./SPEC-TPL.md) Use REQ headings as the requirement entry point
A canonical requirement section MUST use an H2 heading that begins with a `REQ-...` identifier followed by a short title.

## [`REQ-TPL-0006`](./SPEC-TPL.md) Require BCP 14-style uppercase normative keywords in every clause
The requirement clause MUST contain exactly one approved all-caps normative keyword.

Notes:
- The standard uses BCP 14-style uppercase requirement language, inspired by RFC 2119 and RFC 8174.
- Only uppercase forms carry the defined normative meaning; lowercase forms are plain English.
- The approved keywords are `MUST`, `MUST NOT`, `SHALL`, `SHALL NOT`, `SHOULD`, `SHOULD NOT`, and `MAY`.
- The keyword does not need to be the first word in the clause.

## [`REQ-TPL-0007`](./SPEC-TPL.md) Make the compact clause the canonical requirement form
The canonical requirement form MUST place the normative clause immediately after the requirement heading.

Notes:
- Richer management metadata is allowed only as an optional local extension and should not obscure the clause itself.

## [`REQ-TPL-0008`](./SPEC-TPL.md) Keep the requirement Trace block small and explicit
When a requirement includes a `Trace` block, it MUST use only the labels `Satisfied By`, `Implemented By`, `Verified By`, `Derived From`, `Supersedes`, `Source Refs`, `Test Refs`, `Code Refs`, and `Related`.

Notes:
- `Derived From` and `Supersedes` are optional lineage labels.
- `Source Refs` is an optional free-form upstream source label.

## [`REQ-TPL-0017`](./SPEC-TPL.md) Keep Trace and Notes optional
The canonical requirement form MAY follow the normative clause with optional `Trace` and `Notes` blocks.

Notes:
- When lineage matters, prefer `Derived From`, `Supersedes`, and `Source Refs` over prose history.

## [`REQ-TPL-0027`](./SPEC-TPL.md) Use backticks for inline identifier references
Any inline reference to a canonical artifact identifier MUST use backticks.

Trace:
- Related:
  - [SPEC-STD](./SPEC-STD.md)
  - [SPEC-SCH](./SPEC-SCH.md)
  - [SPEC-EXM](./SPEC-EXM.md)

Notes:
- Inline identifier references can appear in requirement clauses, `Notes`, and other descriptive sections.
- Use them for lightweight, human-readable cross-links such as component conformance, token usage, and cross-spec relationships.
- Prefer structured trace fields when the relationship needs to be captured as explicit trace metadata.

## [`REQ-TPL-0028`](./SPEC-TPL.md) Constrain inline identifier references to canonical artifact identifiers
An inline identifier reference MUST identify a valid artifact identifier defined by the standard.

Trace:
- Related:
  - [SPEC-ID](./SPEC-ID.md)
  - [SPEC-STD](./SPEC-STD.md)
  - [SPEC-SCH](./SPEC-SCH.md)

Notes:
- The standard currently defines the `REQ-...`, `SPEC-...`, `ARC-...`, `WI-...`, and `VER-...` artifact families.
- The identifier begins with the known prefix for its family and otherwise satisfies the identifier policy.
- Inline identifier references are not file names, URLs, or loose prose labels.

## [`REQ-TPL-0029`](./SPEC-TPL.md) Give requirement titles descriptive meaning
The requirement title SHOULD name the obligation or concern in a short human-readable phrase rather than repeat the full clause or encode implementation detail.

Notes:
- Requirement titles are scan aids, not the normative statement.
- A title should help a reader recognize the subject of the requirement quickly.

## [`REQ-TPL-0030`](./SPEC-TPL.md) Define trace label semantics by family
A requirement `Trace` block MUST treat `Satisfied By`, `Implemented By`, and `Verified By` as typed downstream trace links; `Derived From` and `Supersedes` as lineage; `Source Refs` as upstream source citations; `Test Refs` and `Code Refs` as implementation-specific string references; and `Related` as a loose association.

Notes:
- The trace block records explicit relationships, while the surrounding prose may add context.
- Inline identifier references stay separate from the trace block and do not change the meaning of its labels.

## [`REQ-TPL-0009`](./SPEC-TPL.md) Keep one specification and its requirements in the same file
A specification document MUST represent one specification in one Markdown file.

## [`REQ-TPL-0025`](./SPEC-TPL.md) Keep related requirements under their specification
A specification document MUST place one or more related `REQ-...` clauses under that specification.

## [`REQ-TPL-0010`](./SPEC-TPL.md) Keep work-item trace labels canonical
A work-item `Trace Links` section MUST use the labels `Addresses`, `Uses Design`, and `Verified By`.

## [`REQ-TPL-0011`](./SPEC-TPL.md) Keep the supporting artifact templates predictable
Architecture, work-item, and verification documents SHOULD follow the section order shown in the reference templates so readers and tooling see a consistent structure.

## [`REQ-TPL-0012`](./SPEC-TPL.md) Normalize normative keyword meaning
Each approved normative keyword MUST have one defined meaning in the standard.

## [`REQ-TPL-0018`](./SPEC-TPL.md) Define meaning of MUST
This keyword MUST indicate a required condition.

## [`REQ-TPL-0019`](./SPEC-TPL.md) Define meaning of MUST NOT
This keyword MUST indicate a prohibited condition.

## [`REQ-TPL-0020`](./SPEC-TPL.md) Define meaning of SHALL
This keyword MUST indicate a required condition.

## [`REQ-TPL-0021`](./SPEC-TPL.md) Define meaning of SHALL NOT
This keyword MUST indicate a prohibited condition.

## [`REQ-TPL-0022`](./SPEC-TPL.md) Define meaning of SHOULD
This keyword MUST indicate a recommended but not strictly required condition.

## [`REQ-TPL-0023`](./SPEC-TPL.md) Define meaning of MAY
This keyword MUST indicate a permitted or optional condition.

## [`REQ-TPL-0026`](./SPEC-TPL.md) Define meaning of SHOULD NOT
This keyword MUST indicate a recommended-against condition.

## [`REQ-TPL-0013`](./SPEC-TPL.md) Keep requirement clauses atomic and short
A canonical requirement clause MUST express one obligation, rule, or constraint.

## [`REQ-TPL-0024`](./SPEC-TPL.md) Keep requirement clauses concise by default
A canonical requirement clause SHOULD remain a single sentence unless a short paragraph is required for precision.

## [`REQ-TPL-0014`](./SPEC-TPL.md) Keep extension metadata optional and behind the clause
Any local extension metadata MUST remain optional and follow the normative clause.

## [`REQ-TPL-0015`](./SPEC-TPL.md) Keep front matter at document scope
Front matter MUST describe the document as a whole rather than carry per-requirement metadata.

## [`REQ-TPL-0016`](./SPEC-TPL.md) Keep test and code references implementation-specific
The standard MUST leave `Test Refs` and `Code Refs` implementation-specific rather than prescribe a test framework, code comment format, or language-specific syntax.
