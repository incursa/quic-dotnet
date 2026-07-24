# Schemas

This directory contains the canonical JSON schemas used by the quality and
repository-config tooling.

## Files

- [`workbench-config.schema.json`](workbench-config.schema.json)
- [`test-inventory.schema.json`](test-inventory.schema.json)
- [`test-run-summary.schema.json`](test-run-summary.schema.json)
- [`coverage-summary.schema.json`](coverage-summary.schema.json)
- [`quality-report.schema.json`](quality-report.schema.json)
- [`adaptive-runtime-policy-local-result-v1.schema.json`](adaptive-runtime-policy-local-result-v1.schema.json)
- [`adaptive-runtime-policy-epoch-dataset-v1.schema.json`](adaptive-runtime-policy-epoch-dataset-v1.schema.json)
- [`adaptive-runtime-policy-catalog-v1.schema.json`](adaptive-runtime-policy-catalog-v1.schema.json)
- [`adaptive-runtime-policy-phase-transition-schedule-v1.schema.json`](adaptive-runtime-policy-phase-transition-schedule-v1.schema.json)
- [`adaptive-runtime-same-connection-phase-execution-v1.schema.json`](adaptive-runtime-same-connection-phase-execution-v1.schema.json)
- [`adaptive-runtime-policy-normalized-dataset-v1.schema.json`](adaptive-runtime-policy-normalized-dataset-v1.schema.json)
- [`adaptive-runtime-policy-curated-manifest-v1.schema.json`](adaptive-runtime-policy-curated-manifest-v1.schema.json)
- [`adaptive-runtime-policy-split-manifest-v1.schema.json`](adaptive-runtime-policy-split-manifest-v1.schema.json)
- [`adaptive-runtime-application-send-turn-analysis-v1.schema.json`](adaptive-runtime-application-send-turn-analysis-v1.schema.json)
- [`adaptive-runtime-protocol-lab-campaign-v1.schema.json`](adaptive-runtime-protocol-lab-campaign-v1.schema.json)
- [`adaptive-runtime-stage1-unified-epoch-v1.schema.json`](adaptive-runtime-stage1-unified-epoch-v1.schema.json)
- [`adaptive-runtime-stage1-axis-decision-v1.schema.json`](adaptive-runtime-stage1-axis-decision-v1.schema.json)
- [`adaptive-runtime-buffer-release-observation-v1.schema.json`](adaptive-runtime-buffer-release-observation-v1.schema.json)
- [`adaptive-runtime-buffer-release-observation-v2.schema.json`](adaptive-runtime-buffer-release-observation-v2.schema.json)
- [`adaptive-runtime-buffer-release-observation-v3.schema.json`](adaptive-runtime-buffer-release-observation-v3.schema.json)
- [`adaptive-runtime-buffer-release-observation-v4.schema.json`](adaptive-runtime-buffer-release-observation-v4.schema.json)
- [`adaptive-runtime-buffer-copy-raw-v2.schema.json`](adaptive-runtime-buffer-copy-raw-v2.schema.json)
- [`adaptive-runtime-buffer-release-raw-v1.schema.json`](adaptive-runtime-buffer-release-raw-v1.schema.json)
- [`adaptive-runtime-buffer-release-raw-v2.schema.json`](adaptive-runtime-buffer-release-raw-v2.schema.json)
- [`adaptive-runtime-buffer-release-raw-v3.schema.json`](adaptive-runtime-buffer-release-raw-v3.schema.json)
- [`adaptive-runtime-buffer-release-raw-v4.schema.json`](adaptive-runtime-buffer-release-raw-v4.schema.json)
- [`adaptive-runtime-buffer-evidence-export-failure-v1.schema.json`](adaptive-runtime-buffer-evidence-export-failure-v1.schema.json)

## Notes

- The schemas are consumed by the local `workbench` tool for quality artifacts
  and repository config validation.
- The adaptive-runtime catalog and dataset schemas remain measurement-only and
  do not authorize runtime activation, axis widening, or online learning.
- SpecTrace validation schemas live under [`../specs/schemas/`](../specs/schemas/README.md).
- Keep the schema set stable unless the repo-wide quality contract changes.
