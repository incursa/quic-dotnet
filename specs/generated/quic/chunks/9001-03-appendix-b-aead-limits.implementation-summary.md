# 9001-03-appendix-b-aead-limits Implementation Summary

## Requirements Completed
- `REQ-QUIC-RFC9001-SB-0001` Restrict larger packet-size-derived limits
- `REQ-QUIC-RFC9001-SB-0002` Require AEAD usage limits
- `REQ-QUIC-RFC9001-SBP1P1-0001` Limit GCM confidentiality at 2^11 bytes
- `REQ-QUIC-RFC9001-SBP1P1-0002` Limit GCM confidentiality at 2^16 bytes
- `REQ-QUIC-RFC9001-SBP1P2-0001` Limit GCM integrity at 2^11 bytes
- `REQ-QUIC-RFC9001-SBP1P2-0002` Limit GCM integrity at unrestricted size
- `REQ-QUIC-RFC9001-SBP1P2-0003` Apply one GCM integrity limit to both functions
- `REQ-QUIC-RFC9001-SBP2-0001` Limit CCM at 2^11 bytes
- `REQ-QUIC-RFC9001-SBP2-0002` Limit CCM at unrestricted packet size

## Files Changed
- [QuicAeadAlgorithm.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicAeadAlgorithm.cs)
- [QuicAeadPacketSizeProfile.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicAeadPacketSizeProfile.cs)
- [QuicAeadUsageLimits.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicAeadUsageLimits.cs)
- [QuicAeadUsageLimitCalculator.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicAeadUsageLimitCalculator.cs)
- [PublicAPI.Unshipped.txt](C:/src/incursa/quic-dotnet/src/Incursa.Quic/PublicAPI.Unshipped.txt)
- [QuicAeadUsageLimitCalculatorTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicAeadUsageLimitCalculatorTests.cs)
- [9001-03-appendix-b-aead-limits.implementation-summary.md](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9001-03-appendix-b-aead-limits.implementation-summary.md)
- [9001-03-appendix-b-aead-limits.implementation-summary.json](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9001-03-appendix-b-aead-limits.implementation-summary.json)

## Tests Added Or Updated
- [QuicAeadUsageLimitCalculatorTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicAeadUsageLimitCalculatorTests.cs): added positive coverage for GCM confidentiality limits, GCM integrity limits, shared AES-128/AES-256 GCM integrity limits, CCM paired limits, and negative coverage for unsupported policy combinations.

## Tests Run And Results
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicAeadUsageLimitCalculatorTests"`
  - Result: Passed
  - Summary: 7 passed, 0 failed, 0 skipped
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj`
  - Result: Passed
  - Summary: 334 passed, 0 failed, 0 skipped

## Remaining Open Requirements In Scope
- None

## Risks Or Follow-Up Notes
- The new helper intentionally models only the Appendix B packet-size profiles exercised by the selected RFC 9001 requirements.
- CCM limits are represented as `double` values because the RFC uses half-power limits (`2^26.5` and `2^21.5`).
- Unsupported AEAD or packet-size-profile combinations return `false` instead of guessing beyond the selected requirements.
