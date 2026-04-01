# Templates

These templates are copy-ready starting points for canonical JSON-authored
spec-trace artifacts.

They are aligned to the published SpecTrace schema at
[incursa/spec-trace](https://github.com/incursa/spec-trace/raw/refs/heads/main/model/model.schema.json).
Repo-local implementation-specific trace references should stay under `x_...`
extension keys such as `x_test_refs` and `x_code_refs`.

## Files

- [`spec-template.json`](spec-template.json): specification template
- [`architecture-template.json`](architecture-template.json): architecture template
- [`work-item-template.json`](work-item-template.json): work-item template
- [`verification-template.json`](verification-template.json): verification template

Author new artifacts from the `.json` templates, then validate them with
`scripts/Validate-SpecTraceJson.ps1` or `workbench validate --profile core`.
