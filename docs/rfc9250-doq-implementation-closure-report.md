# RFC 9250 DoQ Implementation Closure Report

Timestamp: `2026-05-30 15:34:27 -06:00`

Status: `[SPEC-QUIC-RFC9250.json](../specs/requirements/quic/SPEC-QUIC-RFC9250.json)` is `stable`.

## Requirement Coverage

- RFC 9250 DoQ requirements are now fully traced: `141/141` unique `REQ-QUIC-RFC9250-0001` through `REQ-QUIC-RFC9250-0141`.
- Every DoQ slice from `0001` through `0022` has matching `ARC`, `WI`, and `VER` artifacts with consistent naming.
- The late closure slices now included in the canonical spec are:
  - `0002` stream lifecycle and connection reuse
  - `0009` message size and EDNS(0) payload-size handling
  - `0013` 0-RTT replay protection
  - `0014` idle-timeout reuse gating and resumption-ticket policy
  - `0021` flow control
  - `0022` section 3 residue and IANA registry governance

## Verification Evidence

- `[dotnet restore tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj](../tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj)` completed successfully.
- `[dotnet build tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --no-restore](../tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj)` completed successfully.
- Focused DoQ closure tests passed: `22/22`.
- Full test project run completed with `6085` passed and `5` failed tests.
- Edited SpecTrace JSON files parse successfully with `ConvertFrom-Json`.
- `git diff --check` passed.
- `scripts/Validate-SpecTraceJson.ps1 -RepoRoot . -Profiles core` still reports repo-wide historical SpecTrace debt outside the RFC 9250 closure slice; the edited DoQ files themselves parse and trace cleanly.

## Commands Run

- `pwsh -NoProfile -File scripts/Validate-SpecTraceJson.ps1 -RepoRoot . -Profiles core`
- `dotnet restore tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj`
- `dotnet build tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --no-restore`
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --no-build`
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --no-build --filter "FullyQualifiedName~REQ_QUIC_RFC9250_0002|FullyQualifiedName~REQ_QUIC_RFC9250_0021|FullyQualifiedName~REQ_QUIC_RFC9250_0022|FullyQualifiedName~DoqStreamLifecycleTests.LargeDnsResponsesFlowThroughTheDoqStreamPath|FullyQualifiedName~DoqStreamLifecycleTests.ReusesExistingHealthyConnection|FullyQualifiedName~DoqStreamLifecycleTests.DoesNotReuseConnectionTooCloseToIdleTimeout|FullyQualifiedName~DoqFoundationTests.AlpnByteSequenceMatchesDoqDefaultsAlpn|FullyQualifiedName~DoqFoundationTests.ErrorCodeValuesMatchRfc9250Registry|FullyQualifiedName~DoqFatalProtocolErrorTests.NormalizeReceivedErrorCode_MapsUnknownCodesToUnspecifiedError|FullyQualifiedName~DoqFatalProtocolErrorTests.NormalizeReceivedErrorCode_PassesThroughKnownCodes|FullyQualifiedName~DoqFatalProtocolErrorTests.RegisteredErrorCodePathwayIsDocumentedInDoqErrorCode"`
- `Get-Content` / `ConvertFrom-Json` sanity checks on the edited DoQ SpecTrace JSON files

## Remaining Known Limitations

- The full `Incursa.Quic.Tests` suite still has `5` failing tests unrelated to this RFC 9250 slice:
  - `REQ_QUIC_RFC9250_0006.DoqServfailResponseCodeAndTestsAreTraceLinked`
  - `REQ_QUIC_RFC9000_S4P5_0001.TryRegisterLoss_RetransmitsFinTerminationWithTheSameFinalSize`
  - `REQ_QUIC_CRT_0095.ConcurrentEventPostingUsesShardQueueWithoutConnectionLockFields`
  - `REQ_QUIC_RFC9287_S3_0003.RuntimeAcceptQueueSurfacesPeerStreamsImplicitlyOpenedByHigherStreamId`
  - `REQ_QUIC_INT_0015.LocalhostMulticonnectSmokeCompletesSequentialHttp09DownloadsWithQlogCapture`
- No exact `DoqMessageCodec` or `DoqStream` fuzz tests exist in the repo, so there was nothing DoQ-specific to run in that lane.
- No exact `DoqMessageCodec.TryDecode`, `DoqMessageCodec.Encode`, or `DoqStream.ReadMessageAsync` benchmark targets exist in the benchmark project, so no DoQ-specific benchmark run was available.

## External Interop Status

- External DoQ interop was not exercised in this closure pass.
- This closure is local/spec/contract verification only.
- Any external interoperability proof remains a separate future verification lane.
