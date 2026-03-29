---
artifact_id: SPEC-SCH
artifact_type: specification
title: Schemas and Validation Rules
domain: spec-trace
capability: schema-validation
status: draft
owner: spec-trace-maintainers
tags:
  - spec-trace
  - schemas
  - validation
  - tooling
---

# [`SPEC-SCH`](./SPEC-SCH.md) - Schemas and Validation Rules

## Purpose

Define the machine-readable contracts that support the standard without prescribing one parser or build system.

## Scope

This specification covers the reference schemas, the extracted metadata shapes they validate, the inline identifier reference convention as documented schema guidance, and the validation capabilities expected from tooling.

## Context

The standard depends on compact requirement clauses, file-level front matter, explicit trace links, lightweight upstream lineage, and repository-level graph checks. Tooling needs a machine-readable contract for those shapes and link families. The schema layer provides the `core` profile baseline, while `traceable` and `auditable` profiles add repository-level graph checks on top.

## [`REQ-SCH-0001`](./SPEC-SCH.md) Provide schemas for the core extracted shapes
The reference package MUST provide schemas for artifact front matter, identifier policy metadata, compact requirement clauses, requirement trace fields, and work-item trace fields.

## [`REQ-SCH-0002`](./SPEC-SCH.md) Keep front matter validation strict by document family
[`artifact-frontmatter.schema.json`](../../../schemas/artifact-frontmatter.schema.json) MUST validate `artifact_type`, status vocabularies, and artifact identifier patterns for each document family.

Notes:
- Namespaced `x_...` keys may appear as optional local extensions in front matter, but the core family-specific keys stay fixed.

## [`REQ-SCH-0003`](./SPEC-SCH.md) Validate requirement identifiers as part of the identifier catalog
[`artifact-id-policy.schema.json`](../../../schemas/artifact-id-policy.schema.json) MUST validate both artifact identifier rules and `REQ-...` identifier rules.

## [`REQ-SCH-0004`](./SPEC-SCH.md) Validate the compact requirement clause shape
[`requirement-clause.schema.json`](../../../schemas/requirement-clause.schema.json) MUST validate a `REQ-...` identifier, short title, normative clause, extracted normative keyword, and optional trace or notes data.

Notes:
- The clause schema enforces the narrowed BCP 14-style uppercase keyword set used by the standard.

## [`REQ-SCH-0005`](./SPEC-SCH.md) Keep requirement trace labels canonical
[`requirement-trace-fields.schema.json`](../../../schemas/requirement-trace-fields.schema.json) MUST allow only `Satisfied By`, `Implemented By`, `Verified By`, `Derived From`, `Supersedes`, `Source Refs`, `Test Refs`, `Code Refs`, and `Related`.

Notes:
- `Satisfied By` accepts ARC IDs, `Implemented By` accepts WI IDs, `Verified By` accepts VER IDs, `Derived From` and `Supersedes` accept REQ IDs, and `Source Refs`, `Test Refs`, and `Code Refs` remain free-form strings. `Related` may mix requirement IDs and other core artifact IDs.

## [`REQ-SCH-0006`](./SPEC-SCH.md) Treat schemas as extracted-shape contracts
The reference schemas MUST describe extracted metadata shapes rather than require one specific raw Markdown parser implementation.

## [`REQ-SCH-0007`](./SPEC-SCH.md) Resolve explicit traceability links
Validation tooling MUST be able to resolve requirement links to design, work-item, verification, test, and code references when those references are present in extracted metadata.

## [`REQ-SCH-0008`](./SPEC-SCH.md) Report traceability gaps
Validation tooling SHOULD be able to report requirements missing design, implementation, verification, test, or code references.

## [`REQ-SCH-0009`](./SPEC-SCH.md) Keep test and code references schema-agnostic
The requirement trace and requirement clause schemas MUST model `Test Refs` and `Code Refs` as arrays of non-empty strings rather than as a framework-specific grammar.

## [`REQ-SCH-0010`](./SPEC-SCH.md) Surface direct test and code coverage views
Validation tooling SHOULD be able to report which requirements have direct test references and which have direct code references.

## [`REQ-SCH-0011`](./SPEC-SCH.md) Constrain trace-bearing identifier families
The published schemas MUST constrain the direct trace-bearing lists in front matter and requirement or work-item trace blocks to the identifier family each field is meant to carry rather than accept generic non-empty strings.

## [`REQ-SCH-0012`](./SPEC-SCH.md) Detect duplicate identifiers
Validation tooling MUST detect duplicate artifact IDs and duplicate requirement IDs in the repository.

## [`REQ-SCH-0013`](./SPEC-SCH.md) Resolve explicit trace references
Validation tooling MUST resolve explicit trace references and report unresolved requirement or artifact references in direct trace-bearing fields.

## [`REQ-SCH-0014`](./SPEC-SCH.md) Enforce reciprocal trace consistency
Validation tooling MUST report when a requirement link is not reciprocated by the linked architecture, work-item, or verification artifact, or when a work-item or verification document body diverges from its front matter trace lists.

## [`REQ-SCH-0015`](./SPEC-SCH.md) Keep namespaces aligned
Validation tooling MUST report when a document's front matter domain value or identifier namespace does not align with the directory namespace that owns the file.

## [`REQ-SCH-0016`](./SPEC-SCH.md) Model lineage and source refs explicitly
[`requirement-trace-fields.schema.json`](../../../schemas/requirement-trace-fields.schema.json) MUST model `Derived From` and `Supersedes` as requirement-reference arrays and `Source Refs` as a non-empty string array.

## [`REQ-SCH-0017`](./SPEC-SCH.md) Allow lineage references without tombstones
Validation tooling MUST accept `Derived From` and `Supersedes` references even when the referenced requirement IDs are not present as active documents in the repository.

## [`REQ-SCH-0018`](./SPEC-SCH.md) Document inline identifier references in schema contracts
The reference schemas MUST document inline identifier references as backtick-delimited canonical artifact identifiers whose full resolution may require repository-level validation beyond JSON Schema.

Trace:
- Related:
  - [SPEC-STD](./SPEC-STD.md)
  - [SPEC-TPL](./SPEC-TPL.md)
  - [SPEC-EXM](./SPEC-EXM.md)

Notes:
- Inline identifier references are prose links, not `Trace`-block fields.
- JSON Schema can describe the extracted clause shape, but it cannot fully resolve cross-file links by itself.
- Repository-level tooling can extract and validate inline references against the repository's known artifact IDs.

## [`REQ-SCH-0019`](./SPEC-SCH.md) Prevent trace inference from inline identifier references
Validation tooling MUST NOT infer typed trace edges from inline identifier references alone.

Notes:
- Inline references can be reported as mentions, but they are not a substitute for structured trace data.

## [`REQ-SCH-0020`](./SPEC-SCH.md) Extract inline identifier references when practical
Validation tooling SHOULD extract inline identifier references separately from structured trace fields when it can do so.

Notes:
- Separate extraction supports lightweight mention reporting without promoting prose references into graph edges.
