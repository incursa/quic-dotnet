---
title: "ProtocolLab Rack Lab Controller"
---

# ProtocolLab Rack Lab Controller

This repo can send trusted development builds to the internal ProtocolLab rack lab for cleaner benchmark and regression feedback.

Controller UI and API:

```text
http://10.10.99.176:5088
```

Use the lab when a performance or protocol change needs a quieter worker than the developer workstation. Rack-lab evidence is regression evidence unless a later provenance gate says otherwise.

## Execution Model

The QUIC.NET repo should interact with the lab through a package boundary:

1. Build the implementation or adapter from the current working tree.
2. Create a `.plabpkg` archive containing the prebuilt files, scripts, and ProtocolLab implementation manifest.
3. Upload the package to the controller.
4. Submit a job that references the package by `packageId`, `packageVersion`, and `sha256`.
5. Poll the job until it reaches `Completed`, `Failed`, or `Cancelled`.
6. Record the job ID, run ID, package identity, package SHA-256, worker node, and outcome in the relevant verification artifact.

Do not make ordinary QUIC.NET lab execution depend on a full ProtocolLab source checkout. ProtocolLab remains the harness and artifact contract, but QUIC.NET should consume that contract through package tooling, NuGet-delivered helpers, or a small CLI/API client.

The existing `eng/protocol-lab/*.ps1` scripts call a local ProtocolLab checkout for neutral package tooling, schema validation, and submission scripts. They must not resolve quic-dotnet raw adapter/server source from public ProtocolLab production adapter projects.

The helpers validate the selected package target against the suite, protocol, scenarios, and capability declarations in the package templates. Raw QUIC submissions that use HTTP/3 protocol or scenario arguments fail before package upload or controller submission.

## Package Format

Package files use the `.plabpkg` extension. The file is ZIP-compatible, but treat it as a ProtocolLab lab package rather than a generic ZIP.

Required root file:

```text
protocol-lab-package.json
protocol-lab.internal.json
```

Public package manifest fields:

```json
{
  "schemaVersion": "protocol-lab-package-v2",
  "packageId": "quic-dotnet-dev",
  "packageVersion": "dev-20260607T120000Z-local",
  "kind": "implementation",
  "displayName": "QUIC.NET development build",
  "entryManifests": [
    "implementations/quic-dotnet-dev.yaml"
  ],
  "providedImplementations": [
    {
      "implementationId": "quic-dotnet-dev",
      "displayName": "QUIC.NET development build",
      "protocols": ["h3"],
      "scenarios": ["http3.payload.bytes.1kb", "http3.payload.bytes.64kb"]
    }
  ]
}
```

Internal execution manifest fields:

```json
{
  "schemaVersion": "protocol-lab-internal-execution-v1",
  "environments": [
    {
      "os": "linux",
      "arch": "x64",
      "entrypoint": {
        "kind": "bash",
        "path": "scripts/run-linux.sh",
        "arguments": [],
        "workingDirectory": "."
      }
    }
  ],
  "dependencies": {
    "requiresDotNet": true,
    "requiresDocker": false,
    "requiresPwsh": true,
    "requiresBash": true
  }
}
```

Implementation manifests live inside the package, normally under `implementations/*.yaml`. Paths inside those manifests are package-relative; the worker resolves them into the per-attempt package workspace before invoking the ProtocolLab runner.

The default QUIC.NET template creates `quic-dotnet-dev` for `samples/Incursa.Http3.Samples.TechEmpower` and advertises HTTP/3 scenarios only, including the deterministic 1KB byte-payload lane. Raw QUIC is supported only by the separate `quic-dotnet-raw-dev` target, which packages framework-dependent Linux x64 and Windows x64 raw QUIC adapter/server payloads owned under `eng/protocol-lab` and advertises `quic` protocol support, workload family `quic.transport`, and `quic.transport.stream-throughput.1mb`, `quic.transport.multiplex.100x64kb`, and `quic.transport.duplex-streams`. The raw QUIC package requires worker-installed `dotnet` and `pwsh`, does not require `bash`, and still declares `libmsquic` as a worker environment prerequisite.

## API Workflow

Upload a package:

```http
POST /api/lab/packages
Content-Type: multipart/form-data
```

The response includes `packageId`, `packageVersion`, `sha256`, and manifest metadata. Jobs must reference the returned SHA-256.

List packages:

```http
GET /api/lab/packages
```

Submit a job:

```http
POST /api/lab/jobs
Content-Type: application/json
```

Example body:

```json
{
  "suiteIds": ["ci-public-report"],
  "implementationIds": ["quic-dotnet-dev"],
  "scenarioIds": ["http3.core.status"],
  "protocols": ["h3"],
  "workflowProfile": "Quick",
  "targetMode": "process",
  "placementPolicy": "controller-decides",
  "runIdPrefix": "quic-dotnet-dev",
  "packages": [
    {
      "packageId": "quic-dotnet-dev",
      "packageVersion": "dev-20260607T120000Z-local",
      "sha256": "<sha256 returned by upload>"
    }
  ],
  "maxAttempts": 1,
  "requiredCapabilities": []
}
```

Poll status:

```http
GET /api/lab/jobs/{jobId}
```

The controller owns worker selection. Do not hard-code SUT or load worker IDs unless a test is specifically validating placement behavior.

## Local Helper Path

Build and submit through the current compatibility helper:

```powershell
pwsh ./eng/protocol-lab/Invoke-QuicDotNetProtocolLabRun.ps1 `
  -ProtocolLabRoot ../protocol-lab `
  -ControllerUri http://10.10.99.176:5088 `
  -ScenarioId http3.payload.bytes.1kb `
  -Protocol h3 `
  -LoadProfileId smoke
```

Raw QUIC package-backed runs must select the raw target:

```powershell
pwsh ./eng/protocol-lab/Invoke-QuicDotNetProtocolLabRun.ps1 `
  -PackageTarget RawQuic `
  -ProtocolLabRoot ../protocol-lab `
  -ControllerUri http://10.10.99.176:5088 `
  -ScenarioId quic.transport.multiplex.100x64kb,quic.transport.duplex-streams `
  -Protocol quic `
  -LoadProfileId smoke
```

Build only:

```powershell
pwsh ./eng/protocol-lab/New-QuicDotNetProtocolLabPackage.ps1 `
  -ProtocolLabRoot ../protocol-lab `
  -RuntimeIdentifier linux-x64 `
  -Force
```

Build raw QUIC explicitly:

```powershell
pwsh ./eng/protocol-lab/New-QuicDotNetProtocolLabPackage.ps1 `
  -PackageTarget RawQuic `
  -ProtocolLabRoot ../protocol-lab `
  -Force
```

The raw package target builds both `linux-x64` and `win-x64` payloads by default. Use `-RuntimeIdentifier` to constrain the package to a single worker platform.

The package and result files are written under `artifacts/protocol-lab/`.

For raw QUIC, the helper builds and uploads the `quic-dotnet-raw-dev`
implementation package plus the public ProtocolLab raw QUIC test-executor and
scenario-pack component packages. Add `-PackageReference` only when the
controller should include extra component packages that have already been
uploaded. Add `-UsePackageReferenceOnly` when every selected implementation,
test-executor, and scenario-pack package has already been admitted by the
controller and the helper should submit pinned package references without a
build/upload step.

Do not override the raw helper onto the H3 lane. `RawQuic` accepts only suite
`quic-transport-v1-comparison`, protocol `quic`, and scenarios
`quic.transport.stream-throughput.1mb`,
`quic.transport.multiplex.100x64kb`, and
`quic.transport.duplex-streams`.

## Verification Guidance

For performance work, local tests and benchmarks prove correctness and local trends; the rack lab provides cleaner regression evidence. A verification artifact should include:

- Controller job ID.
- Package ID, version, and SHA-256.
- Selected suite, implementation, scenario, protocol, and load profile.
- Worker node and run ID.
- Completion status and failure kind.
- Outcome summary from the controller UI or job JSON.
- Link or path to the resulting ProtocolLab run artifacts when available.

Do not claim raw QUIC coverage from `quic-dotnet-dev`; raw QUIC package-backed validation must use `quic-dotnet-raw-dev`. Do not claim publishable benchmark provenance from the rack lab unless the provenance gate has been explicitly satisfied.
