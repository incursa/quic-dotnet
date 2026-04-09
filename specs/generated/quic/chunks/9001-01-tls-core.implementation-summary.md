# 9001-01-tls-core Implementation Summary

## Requirements Completed
- `REQ-QUIC-RFC9001-S3-0012` Send data as QUIC frames
- `REQ-QUIC-RFC9001-S4-0001` Carry handshake data in CRYPTO frames
- `REQ-QUIC-RFC9001-S4-0002` Define CRYPTO frame boundaries
- `REQ-QUIC-RFC9001-S5-0003` Leave Version Negotiation packets unprotected

## Requirements Partially Completed
- `REQ-QUIC-RFC9001-S5-0001` Protect packets with TLS-derived keys
- `REQ-QUIC-RFC9001-S5-0002` Use the TLS-negotiated AEAD

## Files Changed
- [QuicFrameCodec.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicFrameCodec.cs)
- [PublicAPI.Unshipped.txt](C:/src/incursa/quic-dotnet/src/Incursa.Quic/PublicAPI.Unshipped.txt)
- [QuicVersionNegotiation.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicVersionNegotiation.cs)
- [QuicAeadAlgorithm.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicAeadAlgorithm.cs)
- [QuicTlsPacketProtectionMaterial.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicTlsPacketProtectionMaterial.cs)
- [QuicTlsTransport.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicTlsTransport.cs)
- [QuicTransportTlsBridgeState.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicTransportTlsBridgeState.cs)
- [QuicFrameCodecPart3Tests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecPart3Tests.cs)
- [QuicFrameCodecFuzzTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs)
- [QuicHeaderFuzzTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs)
- [QuicStreamFrameTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicStreamFrameTests.cs)
- [QuicStreamFuzzTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicStreamFuzzTests.cs)
- [QuicVersionNegotiationTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs)
- [REQ-QUIC-RFC9001-S5-0001.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/RequirementHomes/RFC9001/REQ-QUIC-RFC9001-S5-0001.cs)
- [REQ-QUIC-RFC9001-S5-0002.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/RequirementHomes/RFC9001/REQ-QUIC-RFC9001-S5-0002.cs)
- [QuicFrameCodecBenchmarks.cs](C:/src/incursa/quic-dotnet/benchmarks/QuicFrameCodecBenchmarks.cs)
- [README.md](C:/src/incursa/quic-dotnet/benchmarks/README.md)
- [9001-01-tls-core.implementation-summary.md](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9001-01-tls-core.implementation-summary.md)
- [9001-01-tls-core.implementation-summary.json](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9001-01-tls-core.implementation-summary.json)

## Tests Added Or Updated
- [QuicStreamFrameTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicStreamFrameTests.cs): added STREAM-frame formatter round-trip and negative coverage for `REQ-QUIC-RFC9001-S3-0012`.
- [QuicStreamFuzzTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicStreamFuzzTests.cs): extended the fuzz loop to format parsed STREAM frames back to bytes for `REQ-QUIC-RFC9001-S3-0012`.
- [QuicFrameCodecPart3Tests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecPart3Tests.cs): retained CRYPTO frame boundary tests for `REQ-QUIC-RFC9001-S4-0001` and `REQ-QUIC-RFC9001-S4-0002`.
- [QuicFrameCodecFuzzTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs): retained CRYPTO frame round-trip fuzz coverage for `REQ-QUIC-RFC9001-S4-0001` and `REQ-QUIC-RFC9001-S4-0002`.
- [QuicHeaderFuzzTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs): retained Version Negotiation response formatting fuzz coverage for `REQ-QUIC-RFC9001-S5-0003`.
- [QuicVersionNegotiationTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs): retained Version Negotiation response formatting coverage for `REQ-QUIC-RFC9001-S5-0003`.
- [REQ-QUIC-RFC9001-S5-0001.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/RequirementHomes/RFC9001/REQ-QUIC-RFC9001-S5-0001.cs): added packet-protection material shape, level typing, and malformed-input coverage for `REQ-QUIC-RFC9001-S5-0001`.
- [REQ-QUIC-RFC9001-S5-0002.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/RequirementHomes/RFC9001/REQ-QUIC-RFC9001-S5-0002.cs): added runtime-seam AEAD-binding coverage and unsupported-AEAD rejection for `REQ-QUIC-RFC9001-S5-0002`.

## Benchmark Evidence
- [QuicFrameCodecBenchmarks.cs](C:/src/incursa/quic-dotnet/benchmarks/QuicFrameCodecBenchmarks.cs): added a STREAM frame formatting benchmark to cover the new hot path.
- `dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicFrameCodecBenchmarks*"`
  - Result: Passed
  - Summary: 3 benchmarks executed successfully in Dry mode

## Tests Run And Results
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj`
  - Result: Passed
  - Summary: 1461 passed, 0 failed, 0 skipped

## Remaining Open Requirements In Scope
- `REQ-QUIC-RFC9001-S2-0001`
- `REQ-QUIC-RFC9001-S3-0001` through `REQ-QUIC-RFC9001-S3-0011`
- `REQ-QUIC-RFC9001-S4-0003` through `REQ-QUIC-RFC9001-S4-0011`
- `REQ-QUIC-RFC9001-S5-0001` and `REQ-QUIC-RFC9001-S5-0002` are partially implemented; `REQ-QUIC-RFC9001-S5-0004` through `REQ-QUIC-RFC9001-S5-0010` remain blocked.

## Risks Or Follow-Up Notes
- The remaining RFC 9001 clauses are still blocked by the absence of a TLS handshake, packet-protection packet I/O, and key-update implementation surface in `src/Incursa.Quic`.
- This pass closes the STREAM-frame formatter gap, adds the non-Initial packet-protection material boundary, and preserves the existing CRYPTO and Version Negotiation proof surfaces; it does not add TLS packet I/O or handshake packet protect/open logic.
- The benchmark lane now includes the new STREAM formatting hot path, but no long-running benchmark suite or baseline comparison was collected here.
- `REQ-QUIC-RFC9001-S2-0001` remains a document-level rule and should stay deferred until the repository defines a canonical artifact for it.
