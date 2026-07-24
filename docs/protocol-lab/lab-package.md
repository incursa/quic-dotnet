---
title: "ProtocolLab Lab Package"
---

# ProtocolLab Lab Package

This repo can produce trusted internal ProtocolLab package v2 implementation archives (`.plabpkg`) from the current working tree and submit them to a lab controller.

The default package target is `samples/Incursa.Http3.Samples.TechEmpower`. It is staged as the ProtocolLab implementation `quic-dotnet-dev` and supports HTTP/3 application scenarios only, including deterministic 1KB, 64KB, and 1MB byte-payload downloads.

Raw QUIC uses a separate package target, `quic-dotnet-raw-dev`. It packages framework-dependent Linux x64 and Windows x64 raw QUIC adapter/server payloads owned under `eng/protocol-lab` and built against this working tree, then launches the right payload through a package-local PowerShell entrypoint. Do not use `quic-dotnet-dev` for raw QUIC validation.

The package and run helpers enforce that separation. `quic-dotnet-dev` stays on the HTTP/3 suite/protocol/scenario declarations in its package template, and `quic-dotnet-raw-dev` accepts only the raw QUIC suite, protocol `quic`, and the currently declared raw scenarios. H3-shaped raw invocations are rejected before packaging, upload, or controller submission.

For the rack-lab API workflow and current controller endpoint, see [`rack-lab-controller.md`](rack-lab-controller.md).

## Build a Package

From the `quic-dotnet` repo:

```powershell
pwsh ./eng/protocol-lab/New-QuicDotNetProtocolLabPackage.ps1 `
  -ProtocolLabRoot ../protocol-lab `
  -RuntimeIdentifier linux-x64 `
  -Force
```

The script writes generated files under `artifacts/protocol-lab/` and returns
JSON with the package path, SHA-256, build-attestation path, source commit, and
parity eligibility. Clean package inputs produce deterministic archives with
embedded provenance and a matching external build attestation. A dirty package
scope is rejected unless `-AllowDirtySource` is supplied; those packages are
explicitly diagnostic-only and are not eligible for source/package parity or
publication.

Build the raw QUIC package explicitly:

```powershell
pwsh ./eng/protocol-lab/New-QuicDotNetProtocolLabPackage.ps1 `
  -PackageTarget RawQuic `
  -ProtocolLabRoot ../protocol-lab `
  -Force
```

The raw target builds both `linux-x64` and `win-x64` payloads by default. Pass `-RuntimeIdentifier linux-x64` or `-RuntimeIdentifier win-x64` when you need a single-platform package.

For an adaptive-runtime application-send turn campaign, stamp exactly one
internal treatment into the raw package:

```powershell
pwsh ./eng/protocol-lab/New-QuicDotNetProtocolLabPackage.ps1 `
  -PackageTarget RawQuic `
  -ProtocolLabRoot ../protocol-lab `
  -AdaptiveRuntimeApplicationSendTurnPolicy shadow `
  -Force
```

The supported package identities are `legacy_current`, `conservative`,
`observe_only`, and `shadow`. They remain internal measurement controls.
Forced identities bypass selection only, observe-only emits no recommendation,
shadow still applies `legacy_current`, and all runtime safety guards remain
authoritative.

## Submit a Lab Run

```powershell
pwsh ./eng/protocol-lab/Invoke-QuicDotNetProtocolLabRun.ps1 `
  -ProtocolLabRoot ../protocol-lab `
  -ControllerUri http://10.10.99.176:5088 `
  -ScenarioId http3.payload.bytes.1kb `
  -LoadProfileId smoke
```

The script packages the current working tree, uploads the package, submits a job for `quic-dotnet-dev`, polls until completion unless `-NoWait` is provided, and writes job result JSON under `artifacts/protocol-lab/results/`.

Submit raw QUIC explicitly:

```powershell
pwsh ./eng/protocol-lab/Invoke-QuicDotNetProtocolLabRun.ps1 `
  -PackageTarget RawQuic `
  -ProtocolLabRoot ../protocol-lab `
  -ControllerUri http://10.10.99.176:5088 `
  -ScenarioId quic.transport.multiplex.100x64kb,quic.transport.duplex-streams `
  -Protocol quic `
  -AdaptiveRuntimeApplicationSendTurnPolicy shadow `
  -LoadProfileId smoke
```

The raw package manifest and implementation manifest advertise protocol `quic`,
workload family `quic.transport`, cold handshake, connection churn, stream
throughput, multiplex, duplex, and peer-matrix scenarios, plus the
`quicTransport`, `quicStreams`, `quicMultiplexing`, and `quicDuplex`
capabilities. The package requires worker-installed `dotnet` and `pwsh`, does
not require `bash`, and still requires the worker environment primitive
`libmsquic`. The submit helper accepts the same application-send turn
measurement identities as the package builder and rejects them for the HTTP/3
package target.

For raw QUIC, the run helper also builds and uploads the public ProtocolLab raw QUIC test-executor and scenario-pack packages with the `quic-dotnet-raw-dev` implementation package. Use `-PackageReference` to append prebuilt or environment-specific component package references when the controller should resolve an additional package that has already been uploaded. Use `-UsePackageReferenceOnly` when all selected packages have already been admitted by the controller and the helper should submit pinned package references without rebuilding or uploading.

## Notes

- Package v2 archives are trusted internal code, not a sandbox.
- The package is SHA-256 pinned when submitted to the controller.
- Generated package sources, package archives, publish output, and run results live under ignored `artifacts/protocol-lab/`.
- The worker must support ProtocolLab package v2 and resolve package-relative implementation manifest paths into the per-attempt workspace before invoking the ProtocolLab runner.
- Scenario packs and test-executor packages are supplied separately by public ProtocolLab package tooling or another package producer; quic-dotnet only produces implementation packages.
- The `-ProtocolLabRoot` argument is still required for neutral package tooling, submission scripts, schemas, and shared public contract/model projects. Raw QUIC implementation source is local to quic-dotnet and is not resolved from public production adapter projects. Package project paths must resolve under the quic-dotnet repository root.
- `quic-dotnet-dev` advertises HTTP/3 only, including `http3.payload.bytes.1kb`.
- `quic-dotnet-raw-dev` is the only package target for raw QUIC lab validation. Its default package carries `linux-x64` and `win-x64` framework-dependent payloads without duplicate self-contained .NET runtime trees.
