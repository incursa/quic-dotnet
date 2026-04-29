# Current Repository Status

Last verified: 2026-04-29.

This page is an operator snapshot. It records the current repo state and the
next recommended work lane, but it does not replace the canonical requirements,
architecture, work items, or verification artifacts under `specs/`.

## Executive Read

The repository now has a green local executable and SpecTrace baseline. The
Release build passes, the full requirement-linked test suite passes, the
repo-local SpecTrace validator passes, Workbench core validation passes, and
the repo-defined Dry and Short benchmark baseline jobs complete.

This is not a broad QUIC-complete claim and should not be described as
interop-ready. The supported boundary remains narrow: managed loopback,
selected stream/control behavior, selected TLS/trust floors, and local harness
contracts that are backed by requirement-home proof. External runner
corroboration and any public-surface widening remain separate work.

## Verified Commands

Run from the repository root.

```powershell
dotnet tool restore
dotnet build Incursa.Quic.slnx -c Release
dotnet test Incursa.Quic.slnx -c Release --no-build -m:1
pwsh -NoProfile -File scripts\Validate-SpecTraceJson.ps1 -Profiles core
dotnet tool run workbench -- --format json validate --profile core
.\scripts\benchmarks\Invoke-QuicBaseline.ps1 -Job Dry
.\scripts\benchmarks\Invoke-QuicBaseline.ps1 -Job Short
```

Observed results on 2026-04-29:

| Command | Result |
|---|---|
| `dotnet tool restore` | Passed; restored `dotnet-stryker` 4.14.0, `sharpfuzz.commandline` 2.2.0, and `incursa.workbench` 2026.4.15.1172 |
| `dotnet build Incursa.Quic.slnx -c Release` | Passed with 0 warnings and 0 errors |
| `dotnet test Incursa.Quic.slnx -c Release --no-build -m:1` | Passed: 3,271 passed, 0 failed, 0 skipped, 3,271 total |
| `pwsh -NoProfile -File scripts\Validate-SpecTraceJson.ps1 -Profiles core` | Passed: validated 307 SpecTrace JSON artifacts |
| `dotnet tool run workbench -- --format json validate --profile core` | Passed: 0 errors, 0 warnings, 100 work items, 301 markdown files |
| `.\scripts\benchmarks\Invoke-QuicBaseline.ps1 -Job Dry` | Passed for congestion-control, RTT-estimator, and connection stream-state benchmark slices |
| `.\scripts\benchmarks\Invoke-QuicBaseline.ps1 -Job Short` | Passed for congestion-control, RTT-estimator, and connection stream-state benchmark slices |

BenchmarkDotNet reported expected evidence-quality warnings in these smoke
lanes, including Dry minimum-iteration-time warnings and Short zero-measurement
warnings for trivial helper methods. Treat the benchmark results as preserved
local evidence that the benchmark suites execute, not as a rigorous public
performance comparison.

## Trace Surface

The QUIC trace corpus is now green under the repo-local core validation path.
Canonical SpecTrace artifacts are JSON-first; generated summaries and
documentation remain derived surfaces.

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
| Work items | 88 complete | 12 planned |
| Verification | 88 passed | 13 planned |

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
- Narrow write/completion, abort, stream-capacity, retry replay, packet
  protection, recovery, and selected TLS/trust floors are implemented and
  traced.
- Interop harness dispatch exists for `handshake`, `post-handshake-stream`,
  `multiconnect`, `retry`, and `transfer`, with local requirement-home and
  integration proof now green.

Do not claim broad QUIC support, broad public early-data support, broad key
update support, public API stability beyond the traced facade, or broad interop
readiness from this state.

## Remaining Work

There are no known red clusters in the current local full test or core trace
baseline. Remaining work should be selected from explicit requirements and gap
records, not inferred from the green baseline.

The next useful lanes are:

- External CI and interop-runner corroboration for the local green harness
  paths.
- Narrow public-surface hardening only where the existing API requirements
  already authorize it.
- Additional fuzz and benchmark evidence for any newly touched wire-facing or
  hot-path code.
- Planned or draft trace artifacts that still need implementation or proof,
  without treating their planned status as a failure of the current executable
  baseline.

When starting a new protocol slice, follow
[`docs/requirements-workflow.md`](requirements-workflow.md), inspect
[`specs/requirements/quic/REQUIREMENT-GAPS.md`](../specs/requirements/quic/REQUIREMENT-GAPS.md),
and use the owning `SPEC-...`, `ARC-...`, `WI-...`, and `VER-...` artifacts
before editing code.
