# 9000-24-frame-encodings-part-1 Implementation Summary

## Requirements Completed

- `REQ-QUIC-RFC9000-S18-0002`
- `REQ-QUIC-RFC9000-S18-0003`
- `REQ-QUIC-RFC9000-S18-0004`
- `REQ-QUIC-RFC9000-S18-0005`
- `REQ-QUIC-RFC9000-S18-0006`
- `REQ-QUIC-RFC9000-S18P1-0001`
- `REQ-QUIC-RFC9000-S18P1-0002`
- `REQ-QUIC-RFC9000-S18P2-0002`
- `REQ-QUIC-RFC9000-S18P2-0001`
- `REQ-QUIC-RFC9000-S18P2-0004`
- `REQ-QUIC-RFC9000-S18P2-0005`
- `REQ-QUIC-RFC9000-S18P2-0007`
- `REQ-QUIC-RFC9000-S18P2-0008`
- `REQ-QUIC-RFC9000-S18P2-0010`
- `REQ-QUIC-RFC9000-S18P2-0013`
- `REQ-QUIC-RFC9000-S18P2-0015`
- `REQ-QUIC-RFC9000-S18P2-0016`
- `REQ-QUIC-RFC9000-S18P2-0020`
- `REQ-QUIC-RFC9000-S18P2-0021`
- `REQ-QUIC-RFC9000-S18P2-0022`
- `REQ-QUIC-RFC9000-S18P2-0023`
- `REQ-QUIC-RFC9000-S18P2-0028`
- `REQ-QUIC-RFC9000-S18P2-0029`
- `REQ-QUIC-RFC9000-S18P2-0030`
- `REQ-QUIC-RFC9000-S18P2-0031`
- `REQ-QUIC-RFC9000-S18P2-0032`
- `REQ-QUIC-RFC9000-S18P2-0033`
- `REQ-QUIC-RFC9000-S18P2-0035`
- `REQ-QUIC-RFC9000-S18P2-0037`

## Files Changed

- `src/Incursa.Quic/QuicTransportParameterRole.cs`
- `src/Incursa.Quic/QuicPreferredAddress.cs`
- `src/Incursa.Quic/QuicTransportParameters.cs`
- `src/Incursa.Quic/QuicTransportParametersCodec.cs`
- `src/Incursa.Quic/PublicAPI.Unshipped.txt`
- `tests/Incursa.Quic.Tests/QuicTransportParameterTestData.cs`
- `tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs`
- `tests/Incursa.Quic.Tests/QuicTransportParametersFuzzTests.cs`
- `specs/generated/quic/chunks/9000-24-frame-encodings-part-1.implementation-summary.md`
- `specs/generated/quic/chunks/9000-24-frame-encodings-part-1.implementation-summary.json`

## Tests Added Or Updated

- `TryFormatTransportParameters_WritesExactTupleSequence`
- `TryParseTransportParameters_RoundTripsKnownFieldsAndPreferredAddress`
- `TryParseTransportParameters_AcceptsPreferredAddressWithZeroedIpv4Family`
- `TryParseTransportParameters_RejectsTruncatedTupleValue`
- `TryParseTransportParameters_IgnoresReservedGreaseParameters`
- `TryFormatTransportParameters_RejectsServerOnlyParametersWhenSendingAsClient`
- `TryParseTransportParameters_RejectsServerOnlyParametersWhenReceivingAsServer`
- `TryParseTransportParameters_RejectsPreferredAddressWithZeroLengthConnectionId`
- `TryParseTransportParameters_RejectsActiveConnectionIdLimitBelowTwo`
- `TryParseTransportParameters_RejectsTruncatedPreferredAddressValue`
- `Fuzz_TransportParameters_RoundTripsRepresentativeValuesAndRejectsTruncation`

## Tests Run And Results

- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --logger "console;verbosity=minimal"`
- Result: Passed
- Summary: 145 passed, 0 failed, 0 skipped

## Remaining Open Requirements In Scope

- `REQ-QUIC-RFC9000-S18-0001` and `REQ-QUIC-RFC9000-S18-0007` still need TLS `extension_data` integration that this repository does not currently own.
- `REQ-QUIC-RFC9000-S18P2-0007`, `REQ-QUIC-RFC9000-S18P2-0003`, `REQ-QUIC-RFC9000-S18P2-0006`, `REQ-QUIC-RFC9000-S18P2-0009`, `REQ-QUIC-RFC9000-S18P2-0011`, `REQ-QUIC-RFC9000-S18P2-0012`, `REQ-QUIC-RFC9000-S18P2-0014`, `REQ-QUIC-RFC9000-S18P2-0017`, `REQ-QUIC-RFC9000-S18P2-0018`, `REQ-QUIC-RFC9000-S18P2-0019`, `REQ-QUIC-RFC9000-S18P2-0024`, `REQ-QUIC-RFC9000-S18P2-0025`, `REQ-QUIC-RFC9000-S18P2-0026`, `REQ-QUIC-RFC9000-S18P2-0027`, `REQ-QUIC-RFC9000-S18P2-0034`, `REQ-QUIC-RFC9000-S18P2-0036`, and `REQ-QUIC-RFC9000-S18P2-0038` require connection-layer state or error propagation that this codec-only slice does not own.

## Risks And Follow-Up

- The new codec proves wire encoding/decoding and boundary validation, but not the downstream handshake, stream-control, migration, or stateless-reset behaviors those requirements imply.
- `REQ-QUIC-RFC9000-S18P2-0036` and `REQ-QUIC-RFC9000-S18P2-0038` currently stop at parse/format rejection; mapping them to QUIC connection errors remains a later connection-layer task.
- A pre-existing unrelated worktree edit remains in `specs/quic-phase-prompts/Phase-01-Foundation-Wire-Format-and-Packet-Frame-Substrate.md` and was left untouched.
