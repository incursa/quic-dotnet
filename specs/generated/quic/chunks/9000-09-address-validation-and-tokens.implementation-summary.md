# 9000-09-address-validation-and-tokens Implementation Summary

## Requirements Completed
- `REQ-QUIC-RFC9000-S8-0001`
- `REQ-QUIC-RFC9000-S8P1-0001`
- `REQ-QUIC-RFC9000-S8P1-0002`
- `REQ-QUIC-RFC9000-S8P1-0003`
- `REQ-QUIC-RFC9000-S8P1-0004`

## Files Changed
- `src/Incursa.Quic/QuicAddressValidation.cs`
- `src/Incursa.Quic/QuicAntiAmplificationBudget.cs`
- `src/Incursa.Quic/PublicAPI.Unshipped.txt`
- `tests/Incursa.Quic.Tests/QuicAddressValidationTests.cs`
- `tests/Incursa.Quic.Tests/QuicAntiAmplificationBudgetTests.cs`

## Tests Added or Updated
- Added negative coverage in `QuicAddressValidationTests.TryGetVersion1InitialDatagramPaddingLength_RejectsNegativeCurrentPayloadLength`.
- Added positive coverage in `QuicAddressValidationTests.TryFormatVersion1InitialDatagramPadding_WritesRepeatedPaddingFrames`.
- Added negative coverage in `QuicAntiAmplificationBudgetTests.TryRegisterReceivedDatagramPayloadBytes_RejectsNegativePayloadLengths`.
- Added positive coverage in `QuicAntiAmplificationBudgetTests.CanSend_TracksTheThreeTimesAmplificationCapUntilValidation`.
- Added positive coverage in `QuicAntiAmplificationBudgetTests.TryRegisterReceivedDatagramPayloadBytes_IgnoresDatagramsThatAreNotUniquelyAttributed`.
- Added positive coverage in `QuicAntiAmplificationBudgetTests.CanSend_AllowsUnlimitedSendingAfterAddressValidation`.

## Tests Run and Results
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicAddressValidationTests|FullyQualifiedName~QuicAntiAmplificationBudgetTests|FullyQualifiedName~QuicVersionNegotiationTests"`
  - `22 passed, 0 failed, 0 skipped`
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj`
  - `236 passed, 0 failed, 0 skipped`

## Remaining Open Requirements In Scope
- `REQ-QUIC-RFC9000-S8P1-0005`
- `REQ-QUIC-RFC9000-S8P1-0006`
- `REQ-QUIC-RFC9000-S8P1-0007`
- `REQ-QUIC-RFC9000-S8P1P1-0001`
- `REQ-QUIC-RFC9000-S8P1P2-0001` through `REQ-QUIC-RFC9000-S8P1P2-0004`
- `REQ-QUIC-RFC9000-S8P1P3-0001` through `REQ-QUIC-RFC9000-S8P1P3-0017`
- `REQ-QUIC-RFC9000-S8P1P4-0001` through `REQ-QUIC-RFC9000-S8P1P4-0012`

## Risks / Follow-up Notes
- `QuicAddressValidation` is a structural helper for the 64-bit entropy MAY-clause; the repo does not yet model entropy assessment beyond connection-ID length plus endpoint choice.
- `QuicAntiAmplificationBudget` enforces the 3x cap in isolation, but the connection send path still needs to wire it into real packet accounting and validation state.
- Retry token provenance, token lifecycle, and PTO-driven probing remain blocked by missing connection-state, timer, and token-cryptography surfaces.
- No reconciliation artifact existed for this chunk, so it was treated as greenfield.
