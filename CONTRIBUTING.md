# Contributing

Keep changes focused, reviewable, and aligned with the library shape this repository is establishing.

- For protocol behavior, start with [`docs/requirements-workflow.md`](docs/requirements-workflow.md) and the canonical artifacts under [`specs/`](specs/README.md) before writing code.
- Check [`specs/requirements/quic/REQUIREMENT-GAPS.md`](specs/requirements/quic/REQUIREMENT-GAPS.md) before implementing any RFC-driven behavior. Missing or ambiguous rules must be resolved there and in the owning `SPEC-...` artifact first.
- Every protocol slice is expected to define proof across positive tests, negative tests, fuzzing, and benchmarks for processing or serialization hot paths unless the verification artifact explicitly says why a surface does not apply.
- Prefer shared defaults in [`Directory.Build.props`](Directory.Build.props), [`Directory.Build.targets`](Directory.Build.targets), and [`Directory.Packages.props`](Directory.Packages.props) over copy-pasting settings into individual projects.
- Keep public API changes synchronized with [`src/Incursa.Quic/PublicAPI.Shipped.txt`](src/Incursa.Quic/PublicAPI.Shipped.txt) and [`src/Incursa.Quic/PublicAPI.Unshipped.txt`](src/Incursa.Quic/PublicAPI.Unshipped.txt).
- Run the baseline validation before opening a pull request.

`Validate-SpecTraceJson.ps1` downloads the upstream SpecTrace schema from [incursa/spec-trace](https://github.com/incursa/spec-trace/raw/refs/heads/main/model/model.schema.json) by default, so the validation step requires network access unless you override `-SchemaUri`.

```powershell
dotnet tool restore
pwsh -NoProfile -File scripts/Validate-SpecTraceJson.ps1 -Profiles core
dotnet tool run workbench -- --format json validate --profile core
dotnet restore
dotnet build
dotnet test
python -m pip install pre-commit
pwsh -NoProfile -File scripts/quality/run-smoke-tests.ps1
pwsh -NoProfile -File scripts/quality/run-blocking-tests.ps1
pwsh -NoProfile -File scripts/compliance/update-notice.ps1
```

- Use repository-relative links in Markdown for repository content.
- Unless a file already carries a different notice, treat contributions as licensed under the repository MIT license.
