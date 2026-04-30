# Current Repository Status

Last verified: 2026-04-30.

This page is an operator snapshot. It records the current repo state and the
next recommended work lane, but it does not replace the canonical requirements,
architecture, work items, or verification artifacts under `specs/`.

## Executive Read

The repository now has a green local executable and SpecTrace baseline. The
Release build passes, the full requirement-linked test suite passes, the
repo-local SpecTrace validator passes, Workbench core validation passes, and
the repo-defined Dry and Short benchmark baseline jobs complete after local
commit `7dda7669`. Hosted CI and CodeQL workflows also passed for the latest
hosted-validated runtime/trace commit `ee86bb13`.
A manual hosted
interop-runner handshake workflow is configured as an advisory artifact
collection lane, and the narrow server-role handshake dispatch passed on GitHub
Actions run `25145021654` for commit `e6dcbb80` after the workflow moved its
repo-controlled Python setup and artifact upload actions to Node 24-compatible
majors.

This is not a broad QUIC-complete claim and should not be described as
interop-ready. The supported boundary remains narrow: managed loopback,
selected stream/control behavior, selected TLS/trust floors, and local harness
contracts that are backed by requirement-home proof. Broader hosted runner
matrices and any public-surface widening remain separate work.

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
pwsh -NoProfile -File scripts\interop\Invoke-QuicInteropRunner.ps1 -DryRun -LocalRole server -PeerImplementationSlots quic-go -TestCases handshake
pwsh -NoProfile -File scripts\interop\Invoke-QuicInteropRunner.ps1 -LocalRole server -PeerImplementationSlots quic-go -TestCases handshake
gh workflow run interop-runner-handshake.yml --repo incursa/quic-dotnet --ref main
gh run watch 25145021654 --repo incursa/quic-dotnet --exit-status
gh run watch 25145022368 --repo incursa/quic-dotnet --exit-status
gh run watch 25146253564 --repo incursa/quic-dotnet --exit-status
gh run watch 25146253205 --repo incursa/quic-dotnet --exit-status
gh run watch 25147850307 --repo incursa/quic-dotnet --exit-status
gh run watch 25147850047 --repo incursa/quic-dotnet --exit-status
gh run watch 25147993693 --repo incursa/quic-dotnet --exit-status
gh run watch 25147993402 --repo incursa/quic-dotnet --exit-status
gh run watch 25149446012 --repo incursa/quic-dotnet --exit-status
gh run watch 25149445624 --repo incursa/quic-dotnet --exit-status
gh run watch 25149650001 --repo incursa/quic-dotnet --exit-status
gh run watch 25149649726 --repo incursa/quic-dotnet --exit-status
gh run watch 25149821476 --repo incursa/quic-dotnet --exit-status
gh run watch 25149821187 --repo incursa/quic-dotnet --exit-status
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build -m:1 --filter "FullyQualifiedName~REQ_QUIC_API_0001|FullyQualifiedName~REQ_QUIC_API_0005|FullyQualifiedName~REQ_QUIC_API_0008|FullyQualifiedName~REQ_QUIC_API_0009"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build -m:1 --filter "FullyQualifiedName~REQ_QUIC_API_0012|FullyQualifiedName~REQ_QUIC_API_0005|FullyQualifiedName~REQ_QUIC_CRT_0123"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release -m:1 --filter "FullyQualifiedName~REQ_QUIC_API_0001|FullyQualifiedName~REQ_QUIC_API_0002|FullyQualifiedName~REQ_QUIC_API_0003|FullyQualifiedName~REQ_QUIC_API_0004|FullyQualifiedName~REQ_QUIC_API_0005|FullyQualifiedName~REQ_QUIC_API_0006|FullyQualifiedName~REQ_QUIC_API_0007|FullyQualifiedName~REQ_QUIC_API_0008|FullyQualifiedName~REQ_QUIC_API_0009|FullyQualifiedName~REQ_QUIC_API_0010|FullyQualifiedName~REQ_QUIC_API_0011"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build -m:1 --filter "FullyQualifiedName~REQ_QUIC_CRT_"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release -m:1 --filter "FullyQualifiedName~REQ_QUIC_CRT_0134|FullyQualifiedName~REQ_QUIC_CRT_0135"
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicDiagnosticsBenchmarks*"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build -m:1 --filter "FullyQualifiedName~REQ_QUIC_INT_0008"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release -m:1 --filter "FullyQualifiedName~REQ_QUIC_INT_0001|FullyQualifiedName~REQ_QUIC_INT_0002|FullyQualifiedName~REQ_QUIC_INT_0003|FullyQualifiedName~REQ_QUIC_INT_0004|FullyQualifiedName~REQ_QUIC_INT_0005"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release -m:1 --filter "FullyQualifiedName~REQ_QUIC_CRT_0045|FullyQualifiedName~REQ_QUIC_CRT_0047|FullyQualifiedName~REQ_QUIC_CRT_0048|FullyQualifiedName~REQ_QUIC_CRT_0049|FullyQualifiedName~REQ_QUIC_CRT_0050|FullyQualifiedName~REQ_QUIC_CRT_0051|FullyQualifiedName~REQ_QUIC_CRT_0052|FullyQualifiedName~REQ_QUIC_CRT_0053|FullyQualifiedName~REQ_QUIC_CRT_0054|FullyQualifiedName~REQ_QUIC_CRT_0057"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release -m:1 --filter "FullyQualifiedName~REQ_QUIC_CRT_0002|FullyQualifiedName~REQ_QUIC_CRT_0012|FullyQualifiedName~REQ_QUIC_CRT_0013|FullyQualifiedName~REQ_QUIC_CRT_0014|FullyQualifiedName~REQ_QUIC_CRT_0015|FullyQualifiedName~REQ_QUIC_CRT_0016|FullyQualifiedName~REQ_QUIC_CRT_0080|FullyQualifiedName~REQ_QUIC_CRT_0082|FullyQualifiedName~REQ_QUIC_CRT_0083|FullyQualifiedName~REQ_QUIC_CRT_0085|FullyQualifiedName~REQ_QUIC_CRT_0086"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release -m:1 --filter "FullyQualifiedName~REQ_QUIC_CRT_0001|FullyQualifiedName~REQ_QUIC_CRT_0004|FullyQualifiedName~REQ_QUIC_CRT_0005|FullyQualifiedName~REQ_QUIC_CRT_0006|FullyQualifiedName~REQ_QUIC_CRT_0008|FullyQualifiedName~REQ_QUIC_CRT_0009|FullyQualifiedName~REQ_QUIC_CRT_0010|FullyQualifiedName~REQ_QUIC_CRT_0014|FullyQualifiedName~REQ_QUIC_CRT_0017|FullyQualifiedName~REQ_QUIC_CRT_0018|FullyQualifiedName~REQ_QUIC_CRT_0020|FullyQualifiedName~REQ_QUIC_CRT_0093|FullyQualifiedName~REQ_QUIC_CRT_0094|FullyQualifiedName~REQ_QUIC_CRT_0095|FullyQualifiedName~REQ_QUIC_CRT_0096"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build -m:1 --filter "FullyQualifiedName~REQ_QUIC_RFC8999_S5P1"
dotnet build fuzz\Incursa.Quic.Fuzz.csproj -c Release
dotnet tool run sharpfuzz -- fuzz\bin\Release\net10.0\Incursa.Quic.dll
"abc" | dotnet fuzz\bin\Release\net10.0\Incursa.Quic.Fuzz.dll
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicHeaderParsingBenchmarks*"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build -m:1 --filter "FullyQualifiedName~RFC9000|FullyQualifiedName~QuicFrameCodec|FullyQualifiedName~QuicHeaderFuzzTests|FullyQualifiedName~QuicHeaderPropertyTests|FullyQualifiedName~QuicPacketParserTests|FullyQualifiedName~QuicStreamFrameTests|FullyQualifiedName~QuicStreamIdTests|FullyQualifiedName~QuicTransportParameters|FullyQualifiedName~QuicVersionNegotiation|FullyQualifiedName~QuicConnectionStreamState"
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicFrameCodecBenchmarks*"
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicStreamParsingBenchmarks*"
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicVariableLengthIntegerBenchmarks*"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build -m:1 --filter "FullyQualifiedName~RFC9001|FullyQualifiedName~QuicInitialPacketProtection|FullyQualifiedName~QuicHandshakePacketProtection|FullyQualifiedName~QuicRetryIntegrity|FullyQualifiedName~QuicTls|FullyQualifiedName~QuicAeadUsageLimitCalculator"
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicInitialPacketProtectionBenchmarks*"
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicHandshakePacketProtectionBenchmarks*"
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicRetryIntegrityBenchmarks*"
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicAeadUsageLimitCalculatorBenchmarks*"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build -m:1 --filter "FullyQualifiedName~RFC9002"
```

Observed results through 2026-04-30:

| Command | Result |
|---|---|
| `dotnet tool restore` | Passed; restored `dotnet-stryker` 4.14.0, `sharpfuzz.commandline` 2.2.0, and `incursa.workbench` 2026.4.15.1172 |
| `dotnet build Incursa.Quic.slnx -c Release` | Passed with 0 warnings and 0 errors |
| `dotnet test Incursa.Quic.slnx -c Release --no-build -m:1` | Passed on 2026-04-30 after local commit `7dda7669`: 3,299 passed, 0 failed, 0 skipped, 3,299 total |
| `pwsh -NoProfile -File scripts\Validate-SpecTraceJson.ps1 -Profiles core` | Passed on 2026-04-30 after local commit `7dda7669`: validated 313 SpecTrace JSON artifacts |
| `dotnet tool run workbench -- --format json validate --profile core` | Passed on 2026-04-30 after local commit `7dda7669`: 0 errors, 0 warnings, 102 work items, 319 markdown files |
| `.\scripts\benchmarks\Invoke-QuicBaseline.ps1 -Job Dry` | Passed on 2026-04-30 after local commit `7dda7669`: built the benchmark project and executed the congestion-control, RTT-estimator, and connection stream-state Dry slices |
| `.\scripts\benchmarks\Invoke-QuicBaseline.ps1 -Job Short` | Passed on 2026-04-30 after local commit `7dda7669`: built the benchmark project and executed the congestion-control, RTT-estimator, and connection stream-state Short slices |
| `pwsh -NoProfile -File scripts\interop\Invoke-QuicInteropRunner.ps1 -DryRun -LocalRole server -PeerImplementationSlots quic-go -TestCases handshake` | Passed: resolved the hosted-corresponding plan to server-role `nginx` replacement against quic-go for `handshake` |
| `pwsh -NoProfile -File scripts\interop\Invoke-QuicInteropRunner.ps1 -LocalRole server -PeerImplementationSlots quic-go -TestCases handshake` | Passed through the helper's advisory path: harness image build was cached, the runner exited `1`, the helper exited `0`, and artifacts were preserved under `artifacts/interop-runner/20260429-170106187-server-nginx/` after the upstream post-check failed |
| `gh run watch 25145021654 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted workflow `Interop Runner Handshake` completed in 1m53s on commit `e6dcbb80`; the run used Node 24-compatible Python setup and artifact upload actions, uploaded the runner bundle, and had no Node.js deprecation log hits |
| `gh run watch 25145022368 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `Library Fast Quality` workflow completed in 1m13s on commit `e6dcbb80` after its artifact upload action moved to the Node 24-compatible major |
| `gh run watch 25146253564 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CI` workflow completed `build-test-pack` in 2m28s on commit `c26008e7` |
| `gh run watch 25146253205 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CodeQL` workflow completed `actions` and `csharp` analysis jobs on commit `c26008e7` |
| `gh run watch 25147850307 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CI` workflow completed `build-test-pack` in 2m36s on commit `7df0d60d` |
| `gh run watch 25147850047 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CodeQL` workflow completed on commit `7df0d60d` |
| `gh run watch 25147993693 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CI` workflow completed `build-test-pack` in 2m33s on commit `16e575e4` |
| `gh run watch 25147993402 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CodeQL` workflow completed on commit `16e575e4` |
| `gh run watch 25149446012 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CI` workflow completed `build-test-pack` in 3m4s on commit `b03f879e` |
| `gh run watch 25149445624 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CodeQL` workflow completed on commit `b03f879e` |
| `gh run watch 25149650001 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CI` workflow completed `build-test-pack` in 2m29s on commit `88a3172e` |
| `gh run watch 25149649726 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CodeQL` workflow completed on commit `88a3172e` |
| `gh run watch 25149821476 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CI` workflow completed `build-test-pack` in 2m26s on commit `ee86bb13` |
| `gh run watch 25149821187 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CodeQL` workflow completed on commit `ee86bb13` |
| focused API stream-capacity filter | Passed on 2026-04-30: 48 passed, 0 failed, 0 skipped |
| focused pinned-policy API/CRT filter | Passed on 2026-04-30: 28 passed, 0 failed, 0 skipped |
| focused public API surface filter | Passed on 2026-04-30: 81 passed, 0 failed, 0 skipped |
| full `REQ_QUIC_CRT_` requirement-home filter | Passed on 2026-04-30: 304 passed, 0 failed, 0 skipped |
| focused diagnostics CRT filter | Passed on 2026-04-30: 4 passed, 0 failed, 0 skipped |
| `QuicDiagnosticsBenchmarks` Dry run | Passed on 2026-04-30: 4 benchmarks executed; disabled no-op/guarded paths allocated 0 B and enabled typed-event construction allocated 192 B |
| focused endpoint-host shell INT filter | Passed on 2026-04-30: 8 passed, 0 failed, 0 skipped |
| focused harness-foundation INT filter | Passed on 2026-04-30: 11 passed, 0 failed, 0 skipped |
| focused CRT deadline-scheduler filter | Passed on 2026-04-30: 12 passed, 0 failed, 0 skipped |
| focused CRT endpoint-ingress filter | Passed on 2026-04-30: 20 passed, 0 failed, 0 skipped |
| focused CRT high-density execution filter | Passed on 2026-04-30: 18 passed, 0 failed, 0 skipped |
| focused RFC 8999 packet-invariant filter | Passed on 2026-04-30: 22 passed, 0 failed, 0 skipped |
| RFC 8999 fuzz harness build/instrument/smoke | Passed on 2026-04-30: fuzz project built, `sharpfuzz` instrumented `fuzz\bin\Release\net10.0\Incursa.Quic.dll`, and stdin smoke through `Incursa.Quic.Fuzz.dll` exited 0 |
| `QuicHeaderParsingBenchmarks` Dry run | Passed on 2026-04-30: 9 benchmarks executed; BenchmarkDotNet reported expected Dry minimum-iteration-time warnings |
| focused RFC 9000 transport filter | Passed on 2026-04-30: 1,682 passed, 0 failed, 0 skipped |
| `QuicFrameCodecBenchmarks` Dry run | Passed on 2026-04-30: 12 benchmarks executed; BenchmarkDotNet reported expected Dry minimum-iteration-time warnings |
| `QuicStreamParsingBenchmarks` Dry run | Passed on 2026-04-30: 4 benchmarks executed; BenchmarkDotNet reported expected Dry minimum-iteration-time warnings |
| `QuicVariableLengthIntegerBenchmarks` Dry run | Passed on 2026-04-30: 8 benchmarks executed; BenchmarkDotNet reported expected Dry minimum-iteration-time warnings |
| focused RFC 9001 packet-protection/TLS helper filter | Passed on 2026-04-30: 323 passed, 0 failed, 0 skipped |
| `QuicInitialPacketProtectionBenchmarks` Dry run | Passed on 2026-04-30: 3 benchmarks executed; BenchmarkDotNet reported expected Dry minimum-iteration-time warnings |
| `QuicHandshakePacketProtectionBenchmarks` Dry run | Passed on 2026-04-30: 10 benchmarks executed; BenchmarkDotNet reported expected Dry minimum-iteration-time warnings |
| `QuicRetryIntegrityBenchmarks` Dry run | Passed on 2026-04-30: 4 benchmarks executed; BenchmarkDotNet reported expected Dry minimum-iteration-time warnings |
| `QuicAeadUsageLimitCalculatorBenchmarks` Dry run | Passed on 2026-04-30: 4 benchmarks executed; BenchmarkDotNet reported expected Dry minimum-iteration-time warnings |
| focused RFC 9001 repeated key-update lifecycle filter | Passed on 2026-04-30 after local commit `df0414f3`: 229 passed, 0 failed, 0 skipped |
| focused RFC 9002 recovery/congestion filter | Passed on 2026-04-30: 576 passed, 0 failed, 0 skipped |

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
| Requirement clauses | 1,948 |
| Architecture artifacts | 101 |
| Work-item artifacts | 102 |
| Verification artifacts | 103 |

Requirement family counts:

| Family | Requirement clauses |
|---|---:|
| `SPEC-QUIC-API` | 16 |
| `SPEC-QUIC-CRT` | 148 |
| `SPEC-QUIC-INT` | 13 |
| `SPEC-QUIC-RFC8999` | 8 |
| `SPEC-QUIC-RFC9000` | 1,443 |
| `SPEC-QUIC-RFC9001` | 96 |
| `SPEC-QUIC-RFC9002` | 224 |

Status summary across architecture, work-item, and verification JSON artifacts:

| Artifact type | Passed or implemented | Planned or draft |
|---|---:|---:|
| Architecture | 101 implemented | 0 draft |
| Work items | 102 complete | 0 planned |
| Verification | 103 passed | 0 planned |

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
- Internal repeated 1-RTT key-update lifecycle proof is closed for the bounded
  moving-window runtime model, including wide internal epoch identifiers, but
  this remains outside the public support promise.
- Hosted CI and CodeQL workflows passed on `main` for the latest hosted-validated runtime/trace
  commit `ee86bb13` (`25149821476` and `25149821187`).
- A manual hosted GitHub Actions lane now runs the server-role `handshake`
  helper cell against quic-go and uploads the complete interop-runner artifact
  tree for advisory review. Run `25145021654` passed on 2026-04-30 for commit
  `e6dcbb80` after the workflow moved its repo-controlled Python setup and
  artifact upload actions to Node 24-compatible majors; the log had no Node.js
  deprecation hits.
- The manual Library Fast Quality workflow passed on run `25145022368` at
  commit `e6dcbb80` after its artifact upload action moved to the
  Node 24-compatible major.

Do not claim broad QUIC support, broad public early-data support, broad key
update support, public API stability beyond the traced facade, or broad interop
readiness from this state.

## Remaining Work

There are no known red clusters in the current local full test, core trace,
hosted CI, or hosted CodeQL baseline. Remaining work should be selected from
explicit requirements and gap records, not inferred from the green baseline.

The next useful lanes are:

- Keep any hosted interop expansion separate and requirement-owned; the current
  hosted proof covers only the server-role `handshake` cell against quic-go.
- Narrow public-surface hardening only where the existing API requirements
  already authorize it.
- Additional fuzz and benchmark evidence for any newly touched wire-facing or
  hot-path code.
- No known planned or draft trace artifacts remain in the current core QUIC
  artifact set. The RFC 9002 recovery/congestion front door is closed for the
  current repository-owned executable proof surface. Future work should be
  selected from explicit gap records such as path migration, hosted interop
  expansion, public-surface hardening, 0-RTT receive/anti-replay, or newly
  discovered behavior gaps. The internal repeated key-update lifecycle and
  epoch-cap slices are closed, but they are not broad public key-update support
  claims.

When starting a new protocol slice, follow
[`docs/requirements-workflow.md`](requirements-workflow.md), inspect
[`specs/requirements/quic/REQUIREMENT-GAPS.md`](../specs/requirements/quic/REQUIREMENT-GAPS.md),
and use the owning `SPEC-...`, `ARC-...`, `WI-...`, and `VER-...` artifacts
before editing code.
