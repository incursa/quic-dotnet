# Authoring Guide

Use this guide when writing or revising spec-trace artifacts in this repository.

## Requirements

- Start from the owning `SPEC-...` file.
- Use an H2 heading of the form `REQ-... Short Title`.
- Place one normative clause immediately after the heading.
- Use exactly one approved all-caps normative keyword in the clause.
- Add `Trace` and `Notes` blocks only when they add real value.

## Trace Links

- Use `Source Refs` for upstream RFC or other source material.
- Use `Satisfied By`, `Implemented By`, and `Verified By` for downstream trace links.
- Use `Derived From` and `Supersedes` for lineage only.
- Use `Test Refs` and `Code Refs` for implementation-specific references.

## Style

- Keep titles short and descriptive.
- Keep clauses atomic and testable.
- Use backticks for inline artifact identifiers.
- Keep root guidance non-authoritative; the owning spec files are canonical.

## Templates

- [`specs/templates/spec-template.md`](specs/templates/spec-template.md)
- [`specs/templates/verification-template.md`](specs/templates/verification-template.md)
