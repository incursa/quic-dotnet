# 9000-06-version-negotiation Closeout

## Scope
- RFC: `9000`
- Section tokens: `S6`, `S6P1`, `S6P2`, `S6P3`
- Canonical spec: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Reconciliation artifact: not present for this chunk
- Implementation summary reviewed: `./specs/generated/quic/chunks/9000-06-version-negotiation.implementation-summary.json`

## Requirements In Scope
- `REQ-QUIC-RFC9000-S6-0001` Size the first datagram for multi-version support. Implemented and tested in `src/Incursa.Quic/QuicVersionNegotiation.cs` and `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`.
- `REQ-QUIC-RFC9000-S6-0002` Clients that support multiple QUIC versions SHOULD size the first UDP datagram to the largest minimum datagram size supported. Implemented and tested in `src/Incursa.Quic/QuicVersionNegotiation.cs` and `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`.
- `REQ-QUIC-RFC9000-S6P1-0001` Send Version Negotiation with accepted versions. Implemented and tested in `src/Incursa.Quic/QuicVersionNegotiation.cs`, `src/Incursa.Quic/QuicVersionNegotiationPacket.cs`, and the version-negotiation tests.
- `REQ-QUIC-RFC9000-S6P1-0002` Forbid Version Negotiation responses to Version Negotiation. Implemented and tested in `src/Incursa.Quic/QuicVersionNegotiation.cs` and `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`.
- `REQ-QUIC-RFC9000-S6P1-0003` Limit Version Negotiation volume. Explicitly blocked: no server-side policy exists in the repository to cap how many Version Negotiation packets are sent.
- `REQ-QUIC-RFC9000-S6P2-0001` Reject unsupported Version Negotiation attempts. Implemented and tested in `src/Incursa.Quic/QuicVersionNegotiation.cs` and `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`.
- `REQ-QUIC-RFC9000-S6P2-0002` Client MUST abandon the current connection attempt when the Version Negotiation packet is acceptable under the clause. Implemented and tested in `src/Incursa.Quic/QuicVersionNegotiation.cs` and `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`.
- `REQ-QUIC-RFC9000-S6P2-0003` Discard Version Negotiation after another packet was successfully processed. Implemented and tested in `src/Incursa.Quic/QuicVersionNegotiation.cs` and `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`.
- `REQ-QUIC-RFC9000-S6P2-0004` Discard a Version Negotiation packet that lists the client-selected version. Implemented and tested in `src/Incursa.Quic/QuicVersionNegotiation.cs`, `src/Incursa.Quic/QuicVersionNegotiationPacket.cs`, and the packet tests.
- `REQ-QUIC-RFC9000-S6P3-0001` Use reserved versions to test ignoring. Implemented and tested in `src/Incursa.Quic/QuicVersionNegotiation.cs`, `src/Incursa.Quic/QuicVersionNegotiationPacket.cs`, and the packet tests.
- `REQ-QUIC-RFC9000-S6P3-0002` Use reserved versions to test discarding. Implemented and tested in `src/Incursa.Quic/QuicVersionNegotiation.cs`, `src/Incursa.Quic/QuicVersionNegotiationPacket.cs`, and the packet tests.

## Trace Check
- Test traits were verified on `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`, `tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs`, and `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`.
- Source files were checked for stale `REQ-` annotations in `src/Incursa.Quic/QuicVersionNegotiation.cs`, `src/Incursa.Quic/QuicVersionNegotiationPacket.cs`, and `src/Incursa.Quic/PublicAPI.Unshipped.txt`; none were present.
- No stale or wrong requirement IDs were found in the chunk scope.

## Tests Run
- `dotnet test .\tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --logger "console;verbosity=minimal"`
- Result: `197 passed, 0 failed, 0 skipped`

## Remaining Open Requirements
- `REQ-QUIC-RFC9000-S6P1-0003`

## Risks And Follow-up
- The only open clause is the MAY-level volume-limiting requirement. It needs a server-side rate/volume policy abstraction that the repository does not currently model.
- All other in-scope requirements have implementation and test evidence, and no stale trace IDs were found in the relevant tests or source surfaces.
