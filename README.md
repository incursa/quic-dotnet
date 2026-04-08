# Incursa.Quic

[![CI](https://github.com/incursa/quic-dotnet/actions/workflows/ci.yml/badge.svg)](https://github.com/incursa/quic-dotnet/actions/workflows/ci.yml)

`Incursa.Quic` is the trace-first repository for the Incursa QUIC library. It already contains live helper-layer implementation, tests, packaging, and documentation for the packet/header, frame, transport-parameter, recovery, and validation surfaces that are present in the tree.

The repository is also prepared for a SpecTrace-first workflow so RFC-derived protocol slices can be translated into canonical requirements, gaps, work items, verification artifacts, and generated outputs before implementation.
Canonical SpecTrace artifacts are authored as `.json` files under [`specs/`](specs/README.md), and the repository no longer depends on sibling Markdown companions for those canonical families.
The repo-local JSON validator fetches the upstream SpecTrace model schema from [incursa/spec-trace](https://github.com/incursa/spec-trace/raw/refs/heads/main/model/model.schema.json) at runtime so this repository does not carry a stale checked-in copy.

## What is included

- [`specs/`](specs/README.md): canonical requirements, gaps, architecture, work items, verification artifacts, and generated traceability outputs
- [`benchmarks/`](benchmarks/README.md): permanent microbenchmark suites and performance evidence
- [`fuzz/`](fuzz/README.md): SharpFuzz harnesses for wire-facing parser slices
- [`Incursa.Quic`](src/Incursa.Quic/README.md): the packable helper-layer library project and NuGet package root
- [`Incursa.Quic.InteropHarness`](src/Incursa.Quic.InteropHarness/README.md): the companion interop runner endpoint project and Docker image entrypoint
- [`Incursa.Quic.Tests`](tests/Incursa.Quic.Tests/README.md): the test project with requirement-tagged positive, negative, property, fuzz, smoke, and blocking checks
- [`docs/`](docs/README.md): repository documentation
- [`docs/requirements-workflow.md`](docs/requirements-workflow.md): local order of operations for requirements, testing, fuzzing, and benchmarking
- [`quality/testing-intent.yaml`](quality/testing-intent.yaml): repo-level testing intent for quality tooling
- [`schemas/`](schemas/README.md): repository-level quality and config schemas
- [`scripts/spec-trace`](scripts/spec-trace/README.md): JSON validation, migration, backup, and parity-check helpers
- [`scripts/quality`](scripts/quality/README.md): smoke, blocking, and quality attestation evidence lanes
- [`scripts/release`](scripts/release/README.md): versioning and release-policy checks
- [`CONTRIBUTING.md`](CONTRIBUTING.md): contribution and validation guidance
- [`AGENTS.md`](AGENTS.md): repository-specific agent instructions
- [`LLMS.txt`](LLMS.txt): AI bootstrap and reading order
- [`NOTICE.md`](NOTICE.md): generated dependency inventory
- [`.config/dotnet-tools.json`](.config/dotnet-tools.json): local tooling manifest for mutation and fuzz tooling

## Quick start

```bash
dotnet tool restore
pwsh -NoProfile -File scripts/Validate-SpecTraceJson.ps1 -Profiles core
dotnet tool run workbench -- --format json validate --profile core
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

- [`specs`](specs/README.md)
- [`benchmarks`](benchmarks/README.md)
- [`fuzz`](fuzz/README.md)
- [`src/Incursa.Quic`](src/Incursa.Quic/README.md)
- [`src/Incursa.Quic.InteropHarness`](src/Incursa.Quic.InteropHarness/README.md)
- [`tests/Incursa.Quic.Tests`](tests/Incursa.Quic.Tests/README.md)
- [`docs`](docs/README.md)
- [`schemas`](schemas/README.md)
- [`scripts`](scripts/README.md)
- [`assets`](assets/README.md)
- [`AGENTS.md`](AGENTS.md)
- [`LLMS.txt`](LLMS.txt)
- [`.githooks`](.githooks)
- [`CONTRIBUTING.md`](CONTRIBUTING.md)
- [`NOTICE.md`](NOTICE.md)

## Documentation tooling

The repository carries repo-local quality tooling for mutation, fuzz support, and SpecTrace validation:

- `dotnet-stryker`
- `SharpFuzz.CommandLine`
- `workbench`

Install them with:

```bash
dotnet tool restore
```

Then use the repository docs pages for the build and packaging flow:

- [Repository docs](docs/README.md)
- [Requirements workflow](docs/requirements-workflow.md)
- [SpecTrace prep](docs/spec-trace-prep.md)
- [Quickstart](docs/quickstart.md)
- [Packaging](docs/packaging.md)
- [Testing docs](docs/testing/README.md)
