# Spec-Trace Scripts

This directory holds repo-local helpers for canonical JSON-authored SpecTrace
artifacts.

## Commands

- [`Align-SpecTraceJsonToPublishedSchema.ps1`](./Align-SpecTraceJsonToPublishedSchema.ps1): rewrite canonical JSON artifacts and JSON templates to the published schema shape and stamp the public `$schema` URL.
- [`Backup-SpecTraceCanonicalArtifacts.ps1`](./Backup-SpecTraceCanonicalArtifacts.ps1): snapshot the current canonical artifact corpus to `artifacts/spec-trace-json-migration/backups/<timestamp>/`.
- [`Convert-SpecTraceCueToJson.ps1`](./Convert-SpecTraceCueToJson.ps1): convert legacy sibling `.cue` artifacts into canonical `.json` files.
- [`Test-SpecTraceJsonMigration.ps1`](./Test-SpecTraceJsonMigration.ps1): compare migrated JSON artifacts against a backup manifest and fail on semantic drift.
- [`Invoke-SpecTraceJsonMigration.ps1`](./Invoke-SpecTraceJsonMigration.ps1): run backup, conversion, schema alignment, and migration verification in one command.

## Notes

- Canonical SpecTrace artifacts are authored in `.json`, and the repository does not keep sibling canonical `.md` companions for those families.
- `Validate-SpecTraceJson.ps1` uses the published model schema at [incursa/spec-trace](https://github.com/incursa/spec-trace/raw/refs/heads/main/model/model.schema.json) by default instead of a checked-in repo-local copy.
- `Test-SpecTraceJsonMigration.ps1` normalizes legacy section-based snapshots to the published schema shape before comparing them, so pre-alignment backups remain useful as migration parity baselines.
- Local migration backups live under `artifacts/spec-trace-json-migration/backups/` and are excluded from repository validation.
- Use `-Scope` when migrating or checking a subset such as `specs/requirements/quic`.
