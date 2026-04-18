# 9001-02-security-and-registry Closeout

## Audit Result
- `clean_with_explicit_blockers`
- Reconciliation artifact: [9001-02-security-and-registry.reconciliation.json](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9001-02-security-and-registry.reconciliation.json)
- Implementation summary: [9001-02-security-and-registry.implementation-summary.json](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9001-02-security-and-registry.implementation-summary.json)

## Scope
- RFC: `9001`
- Section tokens: `S6`, `S7`, `S8`, `S9`, `S10`
- Requirements in scope: `18`

## Outcome
- Implemented and tested: `6`
- Partial: `1`
- Blocked: `9`
- Deferred: `2`
- Silent gaps: `0`
- Stale or wrong requirement IDs in scope: none found

The helper-backed ceiling now includes `REQ-QUIC-RFC9001-S6-0004` as closed by requirement-home proof and `REQ-QUIC-RFC9001-S6-0005` as partial; the remaining S6/S7/S8/S9 items stay blocked or deferred until handshake-confirmation, key-update, and TLS-authentication support exists.

## In-Scope Requirements

### Implemented And Tested
- `REQ-QUIC-RFC9001-S6-0002` `Identify packet protection keys with Key Phase`
  - Code evidence: [QuicShortHeaderPacket.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicShortHeaderPacket.cs), [QuicPacketParser.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicPacketParser.cs)
  - Test evidence: `tests/Incursa.Quic.Tests/QuicShortHeaderPacketTests.cs::TryParseShortHeader_PreservesOpaqueRemainder`, `tests/Incursa.Quic.Tests/QuicPacketParserTests.cs::TryParseHeader_PreservesTheSevenControlBits`, `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs::TryParseShortHeader_PreservesOpaqueRemainder`, `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs::Fuzz_ShortHeaderParsing_RoundTripsValidInputsAndRejectsFixedBitZero`
  - Direct refs: all four tests above carry `REQ-QUIC-RFC9001-S6-0002`
- `REQ-QUIC-RFC9001-S6-0004` `Toggle Key Phase on each update`
  - Code evidence: requirement-home test coverage only.
  - Test evidence: `tests/Incursa.Quic.Tests/RequirementHomes/RFC9001/REQ-QUIC-RFC9001-S6-0004.cs::ActiveClientRuntimeTogglesOutboundKeyPhaseAfterInstallingSuccessorMaterial`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9001/REQ-QUIC-RFC9001-S6-0004.cs::ActiveClientRuntimeRejectsRepeatingTheSameOneRttKeyUpdate`
  - Direct refs: both tests above carry `REQ-QUIC-RFC9001-S6-0004`
- `REQ-QUIC-RFC9001-S8-0001` `Carry QUIC transport parameters`
  - Code evidence: [QuicTransportParametersCodec.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicTransportParametersCodec.cs)
  - Test evidence: `tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs::TryFormatTransportParameters_WritesExactTupleSequence`, `tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs::TryFormatTransportParameters_EmitsActiveConnectionIdLimitWhenSendingAsClient`, `tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs::TryParseTransportParameters_RoundTripsKnownFieldsAndPreferredAddress`, `tests/Incursa.Quic.Tests/QuicTransportParametersFuzzTests.cs::Fuzz_TransportParameters_RoundTripsRepresentativeValuesAndRejectsTruncation`
  - Direct refs: all four tests above carry `REQ-QUIC-RFC9001-S8-0001`
- `REQ-QUIC-RFC9001-S10-0001` `Register quic_transport_parameters at codepoint 57`
  - Code evidence: [QuicTransportParametersCodec.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicTransportParametersCodec.cs) exposes `QuicTransportParametersExtensionType = 57`
  - Test evidence: `tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs::QuicTransportParametersCodec_ExposesTheRegisteredTlsExtensionMetadata`
  - Direct refs: that test carries `REQ-QUIC-RFC9001-S10-0001`
- `REQ-QUIC-RFC9001-S10-0002` `Mark Recommended as Yes`
  - Code evidence: [QuicTransportParametersCodec.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicTransportParametersCodec.cs) exposes `QuicTransportParametersRecommended = true`
  - Test evidence: `tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs::QuicTransportParametersCodec_ExposesTheRegisteredTlsExtensionMetadata`
  - Direct refs: that test carries `REQ-QUIC-RFC9001-S10-0002`
- `REQ-QUIC-RFC9001-S10-0003` `Include CH and EE in TLS 1.3 column`
  - Code evidence: [QuicTransportParametersCodec.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicTransportParametersCodec.cs) exposes `QuicTransportParametersClientHello = true` and `QuicTransportParametersEncryptedExtensions = true`
  - Test evidence: `tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs::QuicTransportParametersCodec_ExposesTheRegisteredTlsExtensionMetadata`
  - Direct refs: that test carries `REQ-QUIC-RFC9001-S10-0003`

### Partially Implemented
- `REQ-QUIC-RFC9001-S6-0005` `Let Key Phase detect key changes`
  - Code evidence: requirement-home test coverage only.
  - Test evidence: `tests/Incursa.Quic.Tests/RequirementHomes/RFC9001/REQ-QUIC-RFC9001-S6-0005.cs::TryOpenProtectedApplicationDataPacket_DetectsTheChangedKeyPhaseWithoutTheTriggeringPacket`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9001/REQ-QUIC-RFC9001-S6-0005.cs::TryOpenProtectedApplicationDataPacket_DoesNotReportAKeyPhaseChangeForPhaseZeroPackets`
  - Direct refs: both tests above carry `REQ-QUIC-RFC9001-S6-0005`
  - Status: partial because the edge boundary is still missing.

### Blocked
- `REQ-QUIC-RFC9001-S6-0001` `Allow key update after handshake confirmation`
  - Remaining gap: the repo still lacks handshake-confirmation state and the 1-RTT key-update subsystem needed to initiate a safe key update.
- `REQ-QUIC-RFC9001-S6-0003` `Initialize Key Phase to zero`
  - Remaining gap: the repo does not yet format 1-RTT packets with a key-update state machine, so the initial Key Phase value is not a live implementation concern yet.
- `REQ-QUIC-RFC9001-S6-0006` `Update keys when Key Phase changes`
  - Remaining gap: the repo does not yet have key-update logic that can swap packet-protection keys when the Key Phase bit changes.
- `REQ-QUIC-RFC9001-S6-0007` `Decrypt the packet with the changed Key Phase`
  - Remaining gap: the repo does not yet implement packet decryption or the changed-Key-Phase recovery path needed by this clause.
- `REQ-QUIC-RFC9001-S6-0008` `Update both endpoints on key update`
  - Remaining gap: the repo does not yet model bilateral key-update propagation between endpoints.
- `REQ-QUIC-RFC9001-S6-0009` `Prohibit TLS KeyUpdate messages`
  - Remaining gap: the repo does not yet have a TLS message-processing surface where outbound KeyUpdate messages could be prohibited.
- `REQ-QUIC-RFC9001-S6-0010` `Treat TLS KeyUpdate as a connection error`
  - Remaining gap: the repo does not yet have TLS alert handling or connection-error orchestration for received KeyUpdate messages.
- `REQ-QUIC-RFC9001-S7-0002` `Fail on Handshake tampering`
  - Remaining gap: the repo still lacks a TLS handshake implementation, so handshake tampering cannot be exercised or detected here.
- `REQ-QUIC-RFC9001-S8-0002` `Authenticate QUIC transport parameters`
  - Remaining gap: the repo still lacks TLS transcript and authentication plumbing, so transport-parameter authentication cannot be proven cryptographically yet.

### Deferred
- `REQ-QUIC-RFC9001-S7-0001` `Use caution with unauthenticated Initial data`
  - Remaining gap: this is policy guidance about unauthenticated Initial data, not a clean executable invariant in the current helper-only surfaces.
- `REQ-QUIC-RFC9001-S9-0001` `Apply TLS security considerations to QUIC`
  - Remaining gap: this is a document-level security-scope rule rather than an executable helper behavior in the current repo.

## Reference Audit
- Source files checked for in-scope requirement IDs: [QuicShortHeaderPacket.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicShortHeaderPacket.cs), [QuicPacketParser.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicPacketParser.cs), [QuicTransportParametersCodec.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicTransportParametersCodec.cs), [QuicTransportParameters.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicTransportParameters.cs), [PublicAPI.Unshipped.txt](C:/src/incursa/quic-dotnet/src/Incursa.Quic/PublicAPI.Unshipped.txt)
- Source requirement refs found: none
- Test files with requirement traits: [QuicShortHeaderPacketTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicShortHeaderPacketTests.cs), [QuicPacketParserTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicPacketParserTests.cs), [QuicHeaderPropertyTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs), [QuicHeaderFuzzTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs), [REQ-QUIC-RFC9001-S6-0004.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/RequirementHomes/RFC9001/REQ-QUIC-RFC9001-S6-0004.cs), [REQ-QUIC-RFC9001-S6-0005.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/RequirementHomes/RFC9001/REQ-QUIC-RFC9001-S6-0005.cs), [QuicTransportParametersTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs), [QuicTransportParametersFuzzTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicTransportParametersFuzzTests.cs)
- Test requirement refs found: `REQ-QUIC-RFC9001-S6-0002`, `REQ-QUIC-RFC9001-S6-0004`, `REQ-QUIC-RFC9001-S6-0005`, `REQ-QUIC-RFC9001-S8-0001`, `REQ-QUIC-RFC9001-S10-0001`, `REQ-QUIC-RFC9001-S10-0002`, `REQ-QUIC-RFC9001-S10-0003`
- Stale or wrong refs found: none

## Verification
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj`
  - Result: Passed
  - Summary: `327 passed, 0 failed, 0 skipped`
- `dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicTransportParametersBenchmarks*"`
  - Result: Passed
  - Summary: `2 benchmarks executed successfully in Dry mode`

## Notes
- The implementation summary was treated as the source of truth because the requested reconciliation artifact was not present on disk.
- The scoped source files do not carry requirement-ID annotations; traceability in this chunk is provided through tests and the helper constants exposed in `QuicTransportParametersCodec`.
- No silent gaps remain in the selected section-token scope.
