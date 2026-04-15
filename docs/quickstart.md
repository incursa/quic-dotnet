# Quickstart

Use this guide to validate the repository and produce local packages.

## Prerequisites

- .NET SDK `10.0.201+`
- PowerShell `7+`

## Validate The Repository

```bash
dotnet tool restore
pwsh -NoProfile -File scripts/Validate-SpecTraceJson.ps1 -Profiles core
dotnet tool run workbench -- --format json validate --profile core
dotnet restore Incursa.Quic.slnx
dotnet build Incursa.Quic.slnx -c Release
dotnet test Incursa.Quic.slnx -c Release
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
