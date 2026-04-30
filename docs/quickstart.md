# Quickstart

Use this guide to validate the repository and produce local packages.

## Prerequisites

- .NET SDK `10.0.201+`
- PowerShell `7+`

## Validate The Repository

See [Current repository status](current-status.md) before interpreting these
commands. As of 2026-04-30, the local Release build, full no-build test suite,
repo-local SpecTrace validation, Workbench core validation, Dry and Short
benchmark baselines, and final local trace/gap closure checks are green across
the current closure train. Hosted CI, hosted CodeQL, manual library
fast-quality, and the advisory hosted interop-runner handshake lane are green
on their latest recorded hosted runs. The repo-controlled Python setup and
artifact upload action pins in the hosted workflows are on Node 24-compatible
majors.

```bash
dotnet tool restore
pwsh -NoProfile -File scripts/Validate-SpecTraceJson.ps1 -Profiles core
dotnet tool run workbench -- --format json validate --profile core
dotnet build Incursa.Quic.slnx -c Release
dotnet test Incursa.Quic.slnx -c Release --no-build -m:1
```

## Produce Local Packages

```bash
dotnet pack src/Incursa.Quic/Incursa.Quic.csproj -c Release
dotnet pack src/Incursa.Quic.Qlog/Incursa.Quic.Qlog.csproj -c Release
```

## Optional Local Tooling

If you use the repo-local Git hooks:

```bash
python -m pip install pre-commit
pwsh -NoProfile -File scripts/setup-git-hooks.ps1
```
