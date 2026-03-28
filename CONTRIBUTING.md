# Contributing

Keep changes focused, reviewable, and aligned with the library shape this repository is establishing.

- Prefer shared defaults in [`Directory.Build.props`](Directory.Build.props), [`Directory.Build.targets`](Directory.Build.targets), and [`Directory.Packages.props`](Directory.Packages.props) over copy-pasting settings into individual projects.
- Keep public API changes synchronized with [`src/Incursa.Quic/PublicAPI.Shipped.txt`](src/Incursa.Quic/PublicAPI.Shipped.txt) and [`src/Incursa.Quic/PublicAPI.Unshipped.txt`](src/Incursa.Quic/PublicAPI.Unshipped.txt).
- For protocol behavior changes, start with [`docs/requirements-workflow.md`](docs/requirements-workflow.md) and record unresolved RFC questions in [`specs/requirements/REQUIREMENT-GAPS.md`](specs/requirements/REQUIREMENT-GAPS.md) before implementation.
- For parser, serializer, or packet-processing code, add positive, negative, fuzz/property, and benchmark coverage as part of the same change.
- Run the baseline validation before opening a pull request.

```powershell
dotnet tool restore
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
