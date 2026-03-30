# Spec Trace Schemas

This directory contains the canonical JSON schemas used by the SpecTrace
requirements, architecture, work-item, and verification workflows.

## Files

- [`artifact-frontmatter.schema.json`](artifact-frontmatter.schema.json)
- [`artifact-id-policy.schema.json`](artifact-id-policy.schema.json)
- [`requirement-clause.schema.json`](requirement-clause.schema.json)
- [`requirement-trace-fields.schema.json`](requirement-trace-fields.schema.json)
- [`work-item-trace-fields.schema.json`](work-item-trace-fields.schema.json)

## Notes

- These schemas are consumed by the local `workbench` tool when it validates
  canonical SpecTrace documents.
- Keep the schema set stable unless the repository-wide trace contract changes.
