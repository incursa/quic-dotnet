# Schemas

This directory contains the canonical JSON schemas used by the quality and
repository-config tooling.

## Files

- [`workbench-config.schema.json`](workbench-config.schema.json)
- [`test-inventory.schema.json`](test-inventory.schema.json)
- [`test-run-summary.schema.json`](test-run-summary.schema.json)
- [`coverage-summary.schema.json`](coverage-summary.schema.json)
- [`quality-report.schema.json`](quality-report.schema.json)

## Notes

- The schemas are consumed by the local `workbench` tool for quality artifacts
  and repository config validation.
- SpecTrace validation schemas live under [`../specs/schemas/`](../specs/schemas/README.md).
- Keep the schema set stable unless the repo-wide quality contract changes.
