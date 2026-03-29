---
artifact_id: SPEC-EXM
artifact_type: specification
title: Worked Examples and Traceability Coverage
domain: spec-trace
capability: worked-examples
status: draft
owner: spec-trace-maintainers
tags:
  - spec-trace
  - examples
  - traceability
  - reference-material
---

# [`SPEC-EXM`](./SPEC-EXM.md) - Worked Examples and Traceability Coverage

## Purpose

Define what the worked examples must demonstrate so the standard feels concrete instead of ceremonial.

## Scope

This specification covers the example sets, the traceability chain they demonstrate, inline identifier reference examples, and the requirement that the examples stay aligned with the canonical templates and schemas.

## Context

Examples are where readers decide whether the standard is practical. The package therefore needs both a product-style example and a narrow technical example.

## [`REQ-EXM-0001`](./SPEC-EXM.md) Provide a product-style traceability chain
The repository MUST provide a product-style example set that includes linked specification, architecture, work-item, and verification artifacts.

## [`REQ-EXM-0002`](./SPEC-EXM.md) Use compact requirement clauses in example specifications
Example specifications MUST use the compact requirement clause model and show direct traceability to tests and code references.

## [`REQ-EXM-0003`](./SPEC-EXM.md) Keep the payments example concrete and recognizable
The payments example MUST remain a recognizable duplicate-batch scenario that demonstrates both business-rule and edge-case requirements.

## [`REQ-EXM-0004`](./SPEC-EXM.md) Include a narrow technical example
The repository MUST include a narrow technical example that demonstrates method-level and edge-case requirements in a single specification file.

## [`REQ-EXM-0005`](./SPEC-EXM.md) Keep examples aligned with the current standard
Examples MUST stay aligned with the current templates, schemas, and identifier policy.

## [`REQ-EXM-0006`](./SPEC-EXM.md) Keep example prose illustrative rather than canonical
Example prose MUST remain illustrative rather than become hidden normative content outside the SPEC suite.

## [`REQ-EXM-0007`](./SPEC-EXM.md) Demonstrate upstream trace when it is part of the example
Example specifications SHOULD use `Derived From`, `Supersedes`, or `Source Refs` when the worked example includes requirement evolution or upstream source material.

## [`REQ-EXM-0008`](./SPEC-EXM.md) Demonstrate inline identifier references
Worked examples SHOULD show inline identifier references to a requirement, a specification, and a requirement that governs clause grammar or token usage.

Trace:
- Related:
  - [SPEC-STD](./SPEC-STD.md)
  - [SPEC-TPL](./SPEC-TPL.md)
  - [SPEC-SCH](./SPEC-SCH.md)

Notes:
- In this repository, concrete examples can use [`REQ-PAY-ACH-0013`](../../examples/payments/SPEC-PAY-ACH.md), [`REQ-TPL-0006`](./SPEC-TPL.md), [`REQ-TPL-0007`](./SPEC-TPL.md), and [`SPEC-TPL`](./SPEC-TPL.md).
- The examples demonstrate the pattern in requirement clauses, `Notes`, and descriptive prose without turning the example set into hidden normative content outside the SPEC suite.
