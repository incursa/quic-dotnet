# RFC 9000 Chunk Implementation Summary: `9000-05-connection-id-management`

## Requirements Completed

- `REQ-QUIC-RFC9000-S5P1P2-0004`: The on-wire RETIRE_CONNECTION_ID signal is now directly traced.
- `REQ-QUIC-RFC9000-S5P1P2-0005`: The no-reuse request is covered at the wire format layer by the RETIRE_CONNECTION_ID frame codec.
- `REQ-QUIC-RFC9000-S5P1P2-0008`: The wire-format Retire Prior To field is now directly traced.
- `REQ-QUIC-RFC9000-S5P2-0001`: Trace coverage was already present from the prior pass; the packet-classification hook is still a direct match for the imported ID.
- `REQ-QUIC-RFC9000-S5P2P2-0001`: The Version Negotiation send helper now gates unsupported versions on the observed datagram size.
- `REQ-QUIC-RFC9000-S5P2P2-0004`: The same helper now covers the "datagram sufficiently long" decision for server responses.
- `REQ-QUIC-RFC9000-S5P2P3-0002`: The preferred_address transport parameter is encoded, parsed, and fuzzed; the remaining migration-policy clauses are tracked separately in this chunk.
- `REQ-QUIC-RFC9000-S5P2P3-0004`: The disable_active_migration transport parameter is directly traced at the wire level.

## Files Changed

- `src/Incursa.Quic/QuicVersionNegotiation.cs`
- `src/Incursa.Quic/PublicAPI.Unshipped.txt`
- `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecPart4FuzzTests.cs`
- `tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs`
- `tests/Incursa.Quic.Tests/QuicTransportParametersFuzzTests.cs`
- `specs/generated/quic/chunks/9000-05-connection-id-management.implementation-summary.md`
- `specs/generated/quic/chunks/9000-05-connection-id-management.implementation-summary.json`

## Tests Added or Updated

- Current-pass test update: `QuicVersionNegotiationTests.cs` now covers the datagram-size-gated Version Negotiation helper.
- Supporting source/API updates: `QuicVersionNegotiation.cs` and `PublicAPI.Unshipped.txt`.
- Carry-forward trace coverage from the previous pass remains in `QuicFrameCodecPart4Tests.cs`, `QuicFrameCodecPart4FuzzTests.cs`, `QuicTransportParametersTests.cs`, and `QuicTransportParametersFuzzTests.cs`.
- Carry-forward trace coverage for `REQ-QUIC-RFC9000-S5P2-0001` remains in `QuicPacketParserTests.cs` and `QuicHeaderPropertyTests.cs` from the prior pass.

## Tests Run and Results

- Command: `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicPacketParserTests|FullyQualifiedName~QuicHeaderPropertyTests|FullyQualifiedName~QuicHeaderFuzzTests|FullyQualifiedName~QuicVersionNegotiationPacketTests|FullyQualifiedName~QuicVersionNegotiationTests|FullyQualifiedName~QuicShortHeaderPacketTests|FullyQualifiedName~QuicFrameCodecPart4Tests|FullyQualifiedName~QuicFrameCodecPart4FuzzTests|FullyQualifiedName~QuicTransportParametersTests|FullyQualifiedName~QuicTransportParametersFuzzTests"`
- Passed: 72
- Failed: 0
- Skipped: 0
- Duration: 168 ms

## Remaining Open Requirements in Scope

### `S5P1P2`

- Open: 13
- `REQ-QUIC-RFC9000-S5P1P2-0001`: No connection-state or CID lifecycle manager exists in this parser/codec slice.
- `REQ-QUIC-RFC9000-S5P1P2-0002`: No connection-state or CID lifecycle manager exists in this parser/codec slice.
- `REQ-QUIC-RFC9000-S5P1P2-0003`: No connection-state or CID lifecycle manager exists in this parser/codec slice.
- `REQ-QUIC-RFC9000-S5P1P2-0006`: No connection-state or CID lifecycle manager exists in this parser/codec slice.
- `REQ-QUIC-RFC9000-S5P1P2-0007`: No connection-state or CID lifecycle manager exists in this parser/codec slice.
- `REQ-QUIC-RFC9000-S5P1P2-0009`: No connection-state or CID lifecycle manager exists in this parser/codec slice.
- `REQ-QUIC-RFC9000-S5P1P2-0010`: No connection-state or CID lifecycle manager exists in this parser/codec slice.
- `REQ-QUIC-RFC9000-S5P1P2-0011`: No connection-state or CID lifecycle manager exists in this parser/codec slice.
- `REQ-QUIC-RFC9000-S5P1P2-0012`: No connection-state or CID lifecycle manager exists in this parser/codec slice.
- `REQ-QUIC-RFC9000-S5P1P2-0013`: No connection-state or CID lifecycle manager exists in this parser/codec slice.
- `REQ-QUIC-RFC9000-S5P1P2-0014`: No connection-state or CID lifecycle manager exists in this parser/codec slice.
- `REQ-QUIC-RFC9000-S5P1P2-0015`: No connection-state or CID lifecycle manager exists in this parser/codec slice.
- `REQ-QUIC-RFC9000-S5P1P2-0016`: No connection-state or CID lifecycle manager exists in this parser/codec slice.

### `S5P2`

- Open: 12
- `REQ-QUIC-RFC9000-S5P2-0002`: No packet association, key-removal, or error-recovery pipeline exists in this parser-centric slice.
- `REQ-QUIC-RFC9000-S5P2-0003`: No packet association, key-removal, or error-recovery pipeline exists in this parser-centric slice.
- `REQ-QUIC-RFC9000-S5P2-0004`: No packet association, key-removal, or error-recovery pipeline exists in this parser-centric slice.
- `REQ-QUIC-RFC9000-S5P2-0005`: No packet association, key-removal, or error-recovery pipeline exists in this parser-centric slice.
- `REQ-QUIC-RFC9000-S5P2-0006`: No packet association, key-removal, or error-recovery pipeline exists in this parser-centric slice.
- `REQ-QUIC-RFC9000-S5P2-0007`: No packet association, key-removal, or error-recovery pipeline exists in this parser-centric slice.
- `REQ-QUIC-RFC9000-S5P2-0008`: No packet association, key-removal, or error-recovery pipeline exists in this parser-centric slice.
- `REQ-QUIC-RFC9000-S5P2-0009`: No packet association, key-removal, or error-recovery pipeline exists in this parser-centric slice.
- `REQ-QUIC-RFC9000-S5P2-0010`: No packet association, key-removal, or error-recovery pipeline exists in this parser-centric slice.
- `REQ-QUIC-RFC9000-S5P2-0011`: No packet association, key-removal, or error-recovery pipeline exists in this parser-centric slice.
- `REQ-QUIC-RFC9000-S5P2-0012`: No packet association, key-removal, or error-recovery pipeline exists in this parser-centric slice.
- `REQ-QUIC-RFC9000-S5P2-0013`: No packet association, key-removal, or error-recovery pipeline exists in this parser-centric slice.

### `S5P2P1`

- Open: 5
- `REQ-QUIC-RFC9000-S5P2P1-0001`: No client-side packet association or version-selection state exists.
- `REQ-QUIC-RFC9000-S5P2P1-0002`: No client-side packet association or version-selection state exists.
- `REQ-QUIC-RFC9000-S5P2P1-0003`: No client-side packet association or version-selection state exists.
- `REQ-QUIC-RFC9000-S5P2P1-0004`: No client-side packet association or version-selection state exists.
- `REQ-QUIC-RFC9000-S5P2P1-0005`: No client-side packet association or version-selection state exists.

### `S5P2P2`

- Open: 8
- `REQ-QUIC-RFC9000-S5P2P2-0002`: No server-side packet acceptance, Version Negotiation send path, or handshake orchestration exists.
- `REQ-QUIC-RFC9000-S5P2P2-0003`: No server-side packet acceptance, Version Negotiation send path, or handshake orchestration exists.
- `REQ-QUIC-RFC9000-S5P2P2-0005`: No server-side packet acceptance, Version Negotiation send path, or handshake orchestration exists.
- `REQ-QUIC-RFC9000-S5P2P2-0006`: No server-side packet acceptance, Version Negotiation send path, or handshake orchestration exists.
- `REQ-QUIC-RFC9000-S5P2P2-0007`: No server-side packet acceptance, Version Negotiation send path, or handshake orchestration exists.
- `REQ-QUIC-RFC9000-S5P2P2-0008`: No server-side packet acceptance, Version Negotiation send path, or handshake orchestration exists.
- `REQ-QUIC-RFC9000-S5P2P2-0009`: No server-side packet acceptance, Version Negotiation send path, or handshake orchestration exists.
- `REQ-QUIC-RFC9000-S5P2P2-0010`: No server-side packet acceptance, Version Negotiation send path, or handshake orchestration exists.

### `S5P2P3`

- Open: 4
- `REQ-QUIC-RFC9000-S5P2P3-0001`: No preferred-address migration or load-balancing runtime exists in this slice.
- `REQ-QUIC-RFC9000-S5P2P3-0003`: No preferred-address migration or load-balancing runtime exists in this slice.
- `REQ-QUIC-RFC9000-S5P2P3-0005`: No preferred-address migration or load-balancing runtime exists in this slice.
- `REQ-QUIC-RFC9000-S5P2P3-0006`: No preferred-address migration or load-balancing runtime exists in this slice.

## Risks or Follow-up Notes

- The remaining work is still concentrated in stateful connection management and packet-processing behavior that this parser/codec slice does not model.
- The current pass also added a small stateless Version Negotiation decision helper that closes the datagram-size gate for the server response path.
- The remaining open requirements still require connection-state and packet-processing machinery that this parser/codec slice does not model.
