# Authoring Guide

Use this guide when writing or revising spec-trace artifacts in this repository.

## Canonical Format

- Author canonical artifacts in sibling `.json` files under `specs/`.
- Do not add sibling canonical `.md` companions for those artifact families.
- Point workflow surfaces, trace references, and generated metadata at the canonical `.json` path.

## Specifications

- Start from the owning `SPEC-...` artifact.
- Use the published family-specific top-level fields such as `purpose`, `scope`, `context`, `design_summary`, `summary`, or `verification_method`.
- Put extra narrative sections that do not have a published top-level field into `supplemental_sections[]`.
- Represent each requirement as a structured `artifact.requirements[]` entry with stable `id`, `title`, and `statement`.
- Keep normative statements atomic and testable.
- Keep explanatory detail in `notes[]` instead of folding it into the clause.

## Trace Links

- Use `upstream_refs` for upstream RFC or other source material.
- Use `satisfied_by`, `implemented_by`, and `verified_by` for downstream trace links.
- Use `derived_from` and `supersedes` for lineage only.
- Use `x_test_refs` and `x_code_refs` for repo-local implementation-specific references so the canonical JSON stays compatible with the published schema.
- Keep inline artifact IDs in prose as lightweight references; keep structured trace in the trace object.

## Style

- Keep titles short and descriptive.
- Keep clauses atomic and testable.
- Use backticks for inline artifact identifiers.
- Keep root guidance non-authoritative; the owning spec files are canonical.

## Templates

- [`specs/templates/spec-template.json`](specs/templates/spec-template.json)
- [`specs/templates/architecture-template.json`](specs/templates/architecture-template.json)
- [`specs/templates/work-item-template.json`](specs/templates/work-item-template.json)
- [`specs/templates/verification-template.json`](specs/templates/verification-template.json)

## Validation

`Validate-SpecTraceJson.ps1` fetches the upstream SpecTrace model schema from [incursa/spec-trace](https://github.com/incursa/spec-trace/raw/refs/heads/main/model/model.schema.json) by default. Pass `-SchemaUri` only when you intentionally need a different published schema source.

```powershell
pwsh -NoProfile -File scripts/Validate-SpecTraceJson.ps1 -Profiles core
dotnet tool run workbench -- --format json validate --profile core
```
