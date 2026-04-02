# 9000-20-datagram-and-mtu Implementation Summary

## Requirements Completed
- ECN accounting and validation:
  - `REQ-QUIC-RFC9000-S13P4-0001`
  - `REQ-QUIC-RFC9000-S13P4P1-0004`
  - `REQ-QUIC-RFC9000-S13P4P1-0005`
  - `REQ-QUIC-RFC9000-S13P4P1-0006`
  - `REQ-QUIC-RFC9000-S13P4P2-0001`
  - `REQ-QUIC-RFC9000-S13P4P2-0006`
  - `REQ-QUIC-RFC9000-S13P4P2P1-0001`
  - `REQ-QUIC-RFC9000-S13P4P2P1-0002`
  - `REQ-QUIC-RFC9000-S13P4P2P1-0003`
  - `REQ-QUIC-RFC9000-S13P4P2P1-0004`
  - `REQ-QUIC-RFC9000-S13P4P2P1-0005`
  - `REQ-QUIC-RFC9000-S13P4P2P1-0006`
  - `REQ-QUIC-RFC9000-S13P4P2P1-0007`
  - `REQ-QUIC-RFC9000-S13P4P2P1-0008`
  - `REQ-QUIC-RFC9000-S13P4P2P2-0001`
  - `REQ-QUIC-RFC9000-S13P4P2P2-0003`
  - `REQ-QUIC-RFC9000-S13P4P2P2-0004`
  - `REQ-QUIC-RFC9000-S13P4P2P2-0005`
- Datagram sizing and Initial padding:
  - `REQ-QUIC-RFC9000-S14-0003`
  - `REQ-QUIC-RFC9000-S14-0004`
  - `REQ-QUIC-RFC9000-S14P1-0001`
  - `REQ-QUIC-RFC9000-S14P1-0003`
  - `REQ-QUIC-RFC9000-S14P1-0008`
- PMTU probe loss:
  - `REQ-QUIC-RFC9000-S14P4-0002`

## Files Changed
- [src/Incursa.Quic/QuicCongestionControlState.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicCongestionControlState.cs)
- [src/Incursa.Quic/QuicEcnMarking.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicEcnMarking.cs)
- [src/Incursa.Quic/QuicEcnValidationState.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicEcnValidationState.cs)
- [src/Incursa.Quic/PublicAPI.Unshipped.txt](C:/src/incursa/quic-dotnet/src/Incursa.Quic/PublicAPI.Unshipped.txt)
- [tests/Incursa.Quic.Tests/QuicAckGenerationStateTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicAckGenerationStateTests.cs)
- [tests/Incursa.Quic.Tests/QuicAddressValidationTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicAddressValidationTests.cs)
- [tests/Incursa.Quic.Tests/QuicAntiAmplificationBudgetTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicAntiAmplificationBudgetTests.cs)
- [tests/Incursa.Quic.Tests/QuicCongestionControlStateTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicCongestionControlStateTests.cs)
- [tests/Incursa.Quic.Tests/QuicEcnValidationStateTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicEcnValidationStateTests.cs)
- [tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs)
- [tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs)
- [specs/generated/quic/chunks/9000-20-datagram-and-mtu.implementation-summary.md](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9000-20-datagram-and-mtu.implementation-summary.md)
- [specs/generated/quic/chunks/9000-20-datagram-and-mtu.implementation-summary.json](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9000-20-datagram-and-mtu.implementation-summary.json)

## Tests Added Or Updated
- [tests/Incursa.Quic.Tests/QuicEcnValidationStateTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicEcnValidationStateTests.cs): added ECN validation coverage for positive, negative, reorder, disable, and revalidation paths.
- [tests/Incursa.Quic.Tests/QuicCongestionControlStateTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicCongestionControlStateTests.cs): added probe-loss coverage and tagged the ECN reaction path.
- [tests/Incursa.Quic.Tests/QuicAckGenerationStateTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicAckGenerationStateTests.cs): tightened ECN round-trip coverage and packet-number-space independence assertions.
- [tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs): tagged ACK ECN round-trip coverage.
- [tests/Incursa.Quic.Tests/QuicAddressValidationTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicAddressValidationTests.cs): tagged Initial datagram padding coverage.
- [tests/Incursa.Quic.Tests/QuicAntiAmplificationBudgetTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicAntiAmplificationBudgetTests.cs): tagged anti-amplification coverage.
- [tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs): tagged the minimum Initial payload helper coverage.

## Tests Run And Results
- `dotnet test .\tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicEcnValidationStateTests|FullyQualifiedName~QuicCongestionControlStateTests|FullyQualifiedName~QuicAckGenerationStateTests|FullyQualifiedName~QuicFrameCodecTests|FullyQualifiedName~QuicAddressValidationTests|FullyQualifiedName~QuicAntiAmplificationBudgetTests|FullyQualifiedName~QuicVersionNegotiationTests"`
  - Result: `59 passed, 0 failed, 0 skipped`
- `dotnet test .\tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj`
  - Result: `338 passed, 0 failed, 0 skipped`

## Remaining Open Requirements In Scope
- `S13P4`: `REQ-QUIC-RFC9000-S13P4-0002`
- `S13P4P1`: `REQ-QUIC-RFC9000-S13P4P1-0001`, `REQ-QUIC-RFC9000-S13P4P1-0002`, `REQ-QUIC-RFC9000-S13P4P1-0003`, `REQ-QUIC-RFC9000-S13P4P1-0007`, `REQ-QUIC-RFC9000-S13P4P1-0008`, `REQ-QUIC-RFC9000-S13P4P1-0009`
- `S13P4P2`: `REQ-QUIC-RFC9000-S13P4P2-0002`, `REQ-QUIC-RFC9000-S13P4P2-0003`, `REQ-QUIC-RFC9000-S13P4P2-0004`, `REQ-QUIC-RFC9000-S13P4P2-0005`
- `S13P4P2P2`: `REQ-QUIC-RFC9000-S13P4P2P2-0002`
- `S14`: `REQ-QUIC-RFC9000-S14-0001`, `REQ-QUIC-RFC9000-S14-0002`, `REQ-QUIC-RFC9000-S14-0005`, `REQ-QUIC-RFC9000-S14-0006`, `REQ-QUIC-RFC9000-S14-0007`, `REQ-QUIC-RFC9000-S14-0008`, `REQ-QUIC-RFC9000-S14-0009`
- `S14P1`: `REQ-QUIC-RFC9000-S14P1-0002`, `REQ-QUIC-RFC9000-S14P1-0004`, `REQ-QUIC-RFC9000-S14P1-0005`, `REQ-QUIC-RFC9000-S14P1-0006`, `REQ-QUIC-RFC9000-S14P1-0007`
- `S14P2`: `REQ-QUIC-RFC9000-S14P2-0001` through `REQ-QUIC-RFC9000-S14P2-0010`
- `S14P2P1`: `REQ-QUIC-RFC9000-S14P2P1-0001` through `REQ-QUIC-RFC9000-S14P2P1-0007`
- `S14P3`: `REQ-QUIC-RFC9000-S14P3-0001` through `REQ-QUIC-RFC9000-S14P3-0004`
- `S14P4`: `REQ-QUIC-RFC9000-S14P4-0001`
- Deferred guidance that remains intentionally unmodeled: `REQ-QUIC-RFC9000-S13P4P2-0005`

## Risks Or Follow-up Notes
- The ECN validation work is helper-level and does not yet wire into a full connection state machine that chooses when to mark outgoing packets ECT or when to switch paths.
- `REQ-QUIC-RFC9000-S13P4-0002` stays blocked until the sender can determine path support and peer ECN support before enabling ECN.
- PMTU discovery, ICMP validation, fragmentation control, DPLPMTUD probe scheduling, and datagram coalescing remain blocked by missing packet-assembly and path-management surfaces.
- `REQ-QUIC-RFC9000-S13P4P2-0005` is permissive guidance and was left as deferred rather than forcing a no-op code path.
