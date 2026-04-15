# Incursa.Quic

[![CI](https://github.com/incursa/quic-dotnet/actions/workflows/ci.yml/badge.svg)](https://github.com/incursa/quic-dotnet/actions/workflows/ci.yml)
[![Quality](https://github.com/incursa/quic-dotnet/actions/workflows/library-fast-quality.yml/badge.svg)](https://github.com/incursa/quic-dotnet/actions/workflows/library-fast-quality.yml)
[![License](https://img.shields.io/github/license/incursa/quic-dotnet)](LICENSE)

`Incursa.Quic` is a trace-first .NET QUIC repository. It combines a managed QUIC surface for consumers with canonical requirements, verification artifacts, fuzzing, and benchmarks so protocol work stays reviewable and reproducible.

## Packages

- [`Incursa.Quic`](src/Incursa.Quic/README.md): consumer-facing `QuicConnection`, `QuicListener`, `QuicStream`, option types, and error vocabulary.
- [`Incursa.Quic.Qlog`](src/Incursa.Quic.Qlog/README.md): qlog capture support layered on top of `Incursa.Quic`.

## Repository Scope

- Managed QUIC connection, listener, and stream APIs.
- qlog capture support for connection and listener flows.
- Canonical requirements, architecture, work items, and verification artifacts under [`specs/`](specs/README.md).
- xUnit coverage, SharpFuzz harnesses, and BenchmarkDotNet suites for wire-facing and hot-path code.

## Requirements

- .NET SDK `10.0.201+` (managed by [`global.json`](global.json))
- PowerShell `7+` for the repo scripts
- Python if you want to install and run `pre-commit`

## Quickstart

```bash
dotnet tool restore
pwsh -NoProfile -File scripts/Validate-SpecTraceJson.ps1 -Profiles core
dotnet tool run workbench -- --format json validate --profile core
dotnet restore Incursa.Quic.slnx
dotnet build Incursa.Quic.slnx -c Release
dotnet test Incursa.Quic.slnx -c Release
dotnet pack src/Incursa.Quic/Incursa.Quic.csproj -c Release
dotnet pack src/Incursa.Quic.Qlog/Incursa.Quic.Qlog.csproj -c Release
```

## Repository At A Glance

- [`src/Incursa.Quic`](src/Incursa.Quic/README.md): packable core QUIC library.
- [`src/Incursa.Quic.Qlog`](src/Incursa.Quic.Qlog/README.md): qlog adapter package.
- [`src/Incursa.Quic.InteropHarness`](src/Incursa.Quic.InteropHarness/README.md): local interop-runner companion process.
- [`tests/Incursa.Quic.Tests`](tests/Incursa.Quic.Tests/README.md): requirement-linked unit and integration tests.
- [`benchmarks`](benchmarks/README.md): permanent performance suites.
- [`fuzz`](fuzz/README.md): fuzz harnesses for wire-facing code.
- [`docs`](docs/README.md): build, packaging, testing, and contributor guides.
- [`specs`](specs/README.md): canonical traceability artifacts.

## Development Model

1. Start with [`docs/requirements-workflow.md`](docs/requirements-workflow.md).
2. Check [`specs/requirements/quic/REQUIREMENT-GAPS.md`](specs/requirements/quic/REQUIREMENT-GAPS.md) and the owning `SPEC-...` artifact before implementing protocol behavior.
3. Update requirements, architecture, work items, and verification artifacts before relying on code or tests as the source of truth.
4. Prove wire-facing work with positive tests, negative tests, fuzzing, and benchmarks.

## Documentation

- [Quickstart](docs/quickstart.md)
- [Packaging](docs/packaging.md)
- [Requirements workflow](docs/requirements-workflow.md)
- [SpecTrace prep](docs/spec-trace-prep.md)
- [Testing docs](docs/testing/README.md)

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for contributor workflow and validation expectations.

## License

This repository is licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) and [`NOTICE.md`](NOTICE.md).
