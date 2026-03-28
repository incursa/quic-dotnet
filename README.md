# Incursa.Quic

[![CI](https://github.com/incursa/quic-dotnet/actions/workflows/ci.yml/badge.svg)](https://github.com/incursa/quic-dotnet/actions/workflows/ci.yml)

`Incursa.Quic` is the starter repository for the Incursa QUIC library. It currently contains the build, test, packaging, and documentation scaffold only. The runtime implementation will be added later.

## What is included

- [`specs/`](specs/README.md): landing zone for future RFC-derived requirement artifacts and gap tracking
- [`Incursa.Quic`](src/Incursa.Quic/README.md): the packable library project and NuGet package root
- [`Incursa.Quic.Tests`](tests/Incursa.Quic.Tests/README.md): the test project with scaffold smoke and blocking checks
- [`docs/`](docs/README.md): repository documentation
- [`docs/requirements-workflow.md`](docs/requirements-workflow.md): local order of operations for requirements, testing, fuzzing, and benchmarking
- [`scripts/quality`](scripts/quality/README.md): smoke and blocking test lanes
- [`scripts/release`](scripts/release/README.md): versioning and release-policy checks
- [`CONTRIBUTING.md`](CONTRIBUTING.md): contribution and validation guidance
- [`AGENTS.md`](AGENTS.md): repository-specific agent instructions
- [`LLMS.txt`](LLMS.txt): AI bootstrap and reading order
- [`NOTICE.md`](NOTICE.md): generated dependency inventory
- [`.config/dotnet-tools.json`](.config/dotnet-tools.json): local tooling manifest for Workbench, test docs, and related utilities

## Quick start

```bash
dotnet tool restore
dotnet restore Incursa.Quic.slnx
dotnet build Incursa.Quic.slnx -c Release
dotnet test Incursa.Quic.slnx -c Release
dotnet pack src/Incursa.Quic/Incursa.Quic.csproj -c Release
python -m pip install pre-commit
pwsh -File cleanup.ps1
```

## Versioning and packaging

- The repository version is defined in [`Directory.Build.props`](Directory.Build.props).
- The NuGet package metadata, readme, icon, and symbol settings are also centralized there.
- Package versions for test dependencies are centralized in [`Directory.Packages.props`](Directory.Packages.props).
- Public API release checks are enforced by [`scripts/release/validate-public-api-versioning.ps1`](scripts/release/validate-public-api-versioning.ps1).

## Repository layout

- [`specs/`](specs/README.md)
- [`src/Incursa.Quic`](src/Incursa.Quic)
- [`tests/Incursa.Quic.Tests`](tests/Incursa.Quic.Tests)
- [`docs`](docs)
- [`scripts`](scripts)
- [`assets`](assets)
- [`AGENTS.md`](AGENTS.md)
- [`LLMS.txt`](LLMS.txt)
- [`.githooks`](.githooks)
- [`CONTRIBUTING.md`](CONTRIBUTING.md)
- [`NOTICE.md`](NOTICE.md)

## Documentation tooling

The repository carries the same local docs-oriented toolchain used in the other Incursa repositories:

- `dotnet-stryker`
- `workbench`
- `incursa-testdocs`

Install them with:

```bash
dotnet tool restore
```

Then use the repository docs pages for the build and packaging flow:

- [Repository docs](docs/README.md)
- [Quickstart](docs/quickstart.md)
- [Packaging](docs/packaging.md)
- [Testing docs](docs/testing/README.md)
