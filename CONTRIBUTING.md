# Contributing

Keep changes focused, reviewable, and aligned with the public library and traceability model in this repository.

- For protocol behavior, start with [`docs/requirements-workflow.md`](docs/requirements-workflow.md) and the canonical artifacts under [`specs/`](specs/README.md) before writing code.
- Check [`specs/requirements/quic/REQUIREMENT-GAPS.md`](specs/requirements/quic/REQUIREMENT-GAPS.md) before implementing RFC-derived behavior. Resolve missing or ambiguous rules there and in the owning `SPEC-...` artifact first.
- Define proof for each protocol slice across positive tests, negative tests, fuzzing, and benchmarks unless the linked verification artifact documents why a proof lane does not apply.
- Prefer shared defaults in [`Directory.Build.props`](Directory.Build.props), [`Directory.Build.targets`](Directory.Build.targets), and [`Directory.Packages.props`](Directory.Packages.props) over repeating settings in individual projects.
- Keep public API changes synchronized with [`src/Incursa.Quic/PublicAPI.Shipped.txt`](src/Incursa.Quic/PublicAPI.Shipped.txt) and [`src/Incursa.Quic/PublicAPI.Unshipped.txt`](src/Incursa.Quic/PublicAPI.Unshipped.txt).
- Use repository-relative links in Markdown for repository content.

Run the baseline validation before opening a pull request:

```powershell
dotnet tool restore
pwsh -NoProfile -File scripts/Validate-SpecTraceJson.ps1 -Profiles core
dotnet tool run workbench -- --format json validate --profile core
dotnet restore Incursa.Quic.slnx
dotnet build Incursa.Quic.slnx -c Release
dotnet test Incursa.Quic.slnx -c Release
pwsh -NoProfile -File scripts/quality/run-smoke-tests.ps1
pwsh -NoProfile -File scripts/quality/run-blocking-tests.ps1
pwsh -NoProfile -File scripts/compliance/update-notice.ps1
```

`Validate-SpecTraceJson.ps1` downloads the upstream SpecTrace schema from [incursa/spec-trace](https://github.com/incursa/spec-trace/raw/refs/heads/main/model/model.schema.json) by default, so that validation step requires network access unless you override `-SchemaUri`.

Unless a file already carries a different notice, treat contributions as licensed under the repository MIT license.
