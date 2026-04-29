# Current Repository Status

Last verified: 2026-04-27.

This page is an operator snapshot. It records the current repo state and the
next recommended work lane, but it does not replace the canonical requirements,
architecture, work items, or verification artifacts under `specs/`.

## Executive Read

The repository is a real but narrow managed QUIC implementation. It is not a
broad QUIC-complete implementation and should not be described as interop-ready.

The current code builds cleanly, but the test and SpecTrace validation baselines
are red. The next useful work is a bounded stabilization slice around
Application Data control-packet protection on the active transfer and
multiconnect paths, especially `MAX_DATA`, `MAX_STREAM_DATA`, and stream
capacity release packet emission.

## Verified Commands

Run from the repository root.

```powershell
git status --short --branch
dotnet tool restore
dotnet build Incursa.Quic.slnx -c Release
dotnet test Incursa.Quic.slnx -c Release --no-build -m:1
pwsh -NoProfile -File scripts\Validate-SpecTraceJson.ps1 -Profiles core
dotnet tool run workbench -- --format json validate --profile core
```

Observed results on 2026-04-27:

| Command | Result |
|---|---|
| `git status --short --branch` | Clean `main`, tracking `origin/main` |
| `dotnet tool restore` | Passed |
| `dotnet build Incursa.Quic.slnx -c Release` | Passed with 0 warnings and 0 errors |
| `dotnet test Incursa.Quic.slnx -c Release --no-build -m:1` | Failed: 3,233 passed, 38 failed, 0 skipped, 3,271 total |
| `pwsh -NoProfile -File scripts\Validate-SpecTraceJson.ps1 -Profiles core` | Failed with 6,975 errors |
| `dotnet tool run workbench -- --format json validate --profile core` | Failed with schema, link, and repo-state errors |

The latest observed commit during this snapshot was `46c8f6ab` on `main`.

## Trace Surface

The QUIC trace corpus is large and useful, but the repo-wide validation baseline
is currently noisy.

Current artifact inventory:

| Surface | Count |
|---|---:|
| Requirement specs in `specs/requirements/quic` | 7 |
| Requirement clauses | 1,946 |
| Architecture artifacts | 99 |
| Work-item artifacts | 100 |
| Verification artifacts | 101 |

Requirement family counts:

| Family | Requirement clauses |
|---|---:|
| `SPEC-QUIC-API` | 16 |
| `SPEC-QUIC-CRT` | 148 |
| `SPEC-QUIC-INT` | 12 |
| `SPEC-QUIC-RFC8999` | 8 |
| `SPEC-QUIC-RFC9000` | 1,443 |
| `SPEC-QUIC-RFC9001` | 95 |
| `SPEC-QUIC-RFC9002` | 224 |

Status summary across architecture, work-item, and verification JSON artifacts:

| Artifact type | Passed or implemented | Planned or draft |
|---|---:|---:|
| Architecture | 68 implemented | 31 draft |
| Work items | 88 complete/completed | 12 planned |
| Verification | 88 passed | 13 planned |

Important: the repo-wide SpecTrace validators currently report known broad
baseline failures, including schema shape issues, unresolved references, and
residual canonical Markdown siblings. For a bounded runtime slice, do not treat
that global noise as proof that the local slice failed unless the slice makes it
worse. If canonical JSON artifacts are changed, run scoped render/check commands
for the touched artifacts and record the repo-wide baseline separately.

## Implementation State

The implementation is beyond scaffolding. The solution contains:

- [`src/Incursa.Quic`](../src/Incursa.Quic): packable managed QUIC library.
- [`src/Incursa.Quic.Qlog`](../src/Incursa.Quic.Qlog): qlog adapter package.
- [`src/Incursa.Quic.InteropHarness`](../src/Incursa.Quic.InteropHarness): local interop-runner companion process.
- [`tests/Incursa.Quic.Tests`](../tests/Incursa.Quic.Tests): requirement-home and integration proof corpus.
- [`benchmarks/Incursa.Quic.Benchmarks`](../benchmarks): BenchmarkDotNet suites.
- [`fuzz/Incursa.Quic.Fuzz`](../fuzz): fuzz harness project.

The current honest support boundary is narrow:

- Public facade and core option/error/stream types exist.
- Managed loopback connect/listen and narrow stream open/accept behavior exist.
- Narrow write/completion, abort, stream-capacity, and selected TLS/trust floors
  are implemented and traced.
- Interop harness dispatch exists for `handshake`, `post-handshake-stream`,
  `multiconnect`, `retry`, and `transfer`, but the current test baseline shows
  the transfer and multiconnect paths are not green.

Do not claim broad QUIC support, broad public early-data support, broad key
update support, or broad interop readiness from the current state.

## Current Red Clusters

The failing tests are not isolated random failures. They cluster around a few
runtime seams:

- Active-path control-packet protection for `MAX_DATA`, `MAX_STREAM_DATA`, and
  stream-capacity release packets.
- Interop endpoint-host handshake, transfer, and multiconnect smoke paths.
- 0-RTT and early-data packet emission and cleanup.
- First key-phase and key-update behavior.
- Retry Initial replay expectations.
- Stream reset and `STOP_SENDING` retransmission/protection retention.
- ACK and recovery details.

Representative failure messages:

```text
The connection runtime could not protect the MAX_DATA packet.
The connection runtime could not protect the MAX_STREAM_DATA packet.
The connection runtime could not protect the stream capacity release packet.
```

## Recommended Next Slice

Start with the active-path flow-control/control-packet protection slice.

Why this is the best next slice:

- It is a bounded runtime stabilization problem, not a broad protocol rewrite.
- It explains multiple red interop and transfer/multiconnect failures.
- It directly affects the honest supported loopback and harness paths.
- It should not require public API widening or global SpecTrace cleanup.

Primary focused repro:

```powershell
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build -m:1 --filter "FullyQualifiedName~REQ_QUIC_INT_0010|FullyQualifiedName~REQ_QUIC_INT_0014|FullyQualifiedName~REQ_QUIC_INT_0015|FullyQualifiedName~REQ_QUIC_INT_0008"
```

Likely starting files:

- [`src/Incursa.Quic/QuicConnectionRuntime.Streams.cs`](../src/Incursa.Quic/QuicConnectionRuntime.Streams.cs)
- [`src/Incursa.Quic/QuicConnectionRuntime.cs`](../src/Incursa.Quic/QuicConnectionRuntime.cs)
- [`src/Incursa.Quic/QuicConnectionSendRuntime.cs`](../src/Incursa.Quic/QuicConnectionSendRuntime.cs)
- [`tests/Incursa.Quic.Tests/RequirementHomes/INT/REQ-QUIC-INT-0010.cs`](../tests/Incursa.Quic.Tests/RequirementHomes/INT/REQ-QUIC-INT-0010.cs)
- [`tests/Incursa.Quic.Tests/RequirementHomes/INT/REQ-QUIC-INT-0014.cs`](../tests/Incursa.Quic.Tests/RequirementHomes/INT/REQ-QUIC-INT-0014.cs)
- [`tests/Incursa.Quic.Tests/RequirementHomes/INT/REQ-QUIC-INT-0015.cs`](../tests/Incursa.Quic.Tests/RequirementHomes/INT/REQ-QUIC-INT-0015.cs)
- [`tests/Incursa.Quic.Tests/RequirementHomes/INT/REQ-QUIC-INT-0008.cs`](../tests/Incursa.Quic.Tests/RequirementHomes/INT/REQ-QUIC-INT-0008.cs)

Nearest trace owners to inspect before editing:

- [`docs/requirements-workflow.md`](requirements-workflow.md)
- [`specs/requirements/quic/REQUIREMENT-GAPS.md`](../specs/requirements/quic/REQUIREMENT-GAPS.md)
- [`specs/requirements/quic/SPEC-QUIC-INT.json`](../specs/requirements/quic/SPEC-QUIC-INT.json)
- [`specs/requirements/quic/SPEC-QUIC-RFC9000.json`](../specs/requirements/quic/SPEC-QUIC-RFC9000.json)
- [`specs/architecture/quic/ARC-QUIC-INT-0003.json`](../specs/architecture/quic/ARC-QUIC-INT-0003.json)
- [`specs/architecture/quic/ARC-QUIC-INT-0007.json`](../specs/architecture/quic/ARC-QUIC-INT-0007.json)
- [`specs/architecture/quic/ARC-QUIC-INT-0008.json`](../specs/architecture/quic/ARC-QUIC-INT-0008.json)
- [`specs/architecture/quic/ARC-QUIC-RFC9000-0009.json`](../specs/architecture/quic/ARC-QUIC-RFC9000-0009.json)
- [`specs/work-items/quic/WI-QUIC-INT-0003.json`](../specs/work-items/quic/WI-QUIC-INT-0003.json)
- [`specs/work-items/quic/WI-QUIC-INT-0007.json`](../specs/work-items/quic/WI-QUIC-INT-0007.json)
- [`specs/work-items/quic/WI-QUIC-INT-0008.json`](../specs/work-items/quic/WI-QUIC-INT-0008.json)
- [`specs/work-items/quic/WI-QUIC-RFC9000-0009.json`](../specs/work-items/quic/WI-QUIC-RFC9000-0009.json)
- [`specs/verification/quic/VER-QUIC-INT-0003.json`](../specs/verification/quic/VER-QUIC-INT-0003.json)
- [`specs/verification/quic/VER-QUIC-INT-0007.json`](../specs/verification/quic/VER-QUIC-INT-0007.json)
- [`specs/verification/quic/VER-QUIC-INT-0008.json`](../specs/verification/quic/VER-QUIC-INT-0008.json)
- [`specs/verification/quic/VER-QUIC-RFC9000-0009.json`](../specs/verification/quic/VER-QUIC-RFC9000-0009.json)

The paste-ready prompt for this slice lives at
[`prompts/next-runtime-control-packet-protection.md`](../prompts/next-runtime-control-packet-protection.md).
