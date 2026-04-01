# RFC 9000 Chunk Closeout: `9000-05-connection-id-management`

## Scope

- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- RFC: `9000`
- Section tokens: `S5P1P2, S5P2, S5P2P1, S5P2P2, S5P2P3`

## Audit Result

- Audit result: `clean_with_explicit_deferments`
- No stale requirement IDs remain in scope.
- No requirement-tagged source refs were found under `src/Incursa.Quic`.
- Current test traits use the imported IDs `REQ-QUIC-RFC9000-S5P2-0001`, `REQ-QUIC-RFC9000-S5P1P2-0004`, `REQ-QUIC-RFC9000-S5P1P2-0005`, `REQ-QUIC-RFC9000-S5P1P2-0008`, `REQ-QUIC-RFC9000-S5P2P3-0002`, `REQ-QUIC-RFC9000-S5P2P3-0004`.
- No old->new requirement ID rewrites were needed.
- Every open requirement below carries an explicit blocker note; there are no silent gaps in the scoped set.

## Requirements In Scope

- `S5P1P2`: 16 requirements
- `S5P2`: 13 requirements
- `S5P2P1`: 5 requirements
- `S5P2P2`: 10 requirements
- `S5P2P3`: 6 requirements

Total in scope: **50**
Covered: **6**
Blocked / deferred: **44**
Partial: **0**
Needs review: **0**

## Requirements Completed

- `REQ-QUIC-RFC9000-S5P1P2-0004`: The on-wire RETIRE_CONNECTION_ID signal is now directly traced.
  - Evidence files: tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs, tests/Incursa.Quic.Tests/QuicFrameCodecPart4FuzzTests.cs
  - Tests: tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs, tests/Incursa.Quic.Tests/QuicFrameCodecPart4FuzzTests.cs
- `REQ-QUIC-RFC9000-S5P1P2-0005`: The no-reuse request is covered at the wire format layer by the RETIRE_CONNECTION_ID frame codec.
  - Evidence files: tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs, tests/Incursa.Quic.Tests/QuicFrameCodecPart4FuzzTests.cs
  - Tests: tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs, tests/Incursa.Quic.Tests/QuicFrameCodecPart4FuzzTests.cs
- `REQ-QUIC-RFC9000-S5P1P2-0008`: The wire-format Retire Prior To field is now directly traced.
  - Evidence files: tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs, tests/Incursa.Quic.Tests/QuicFrameCodecPart4FuzzTests.cs
  - Tests: tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs, tests/Incursa.Quic.Tests/QuicFrameCodecPart4FuzzTests.cs
- `REQ-QUIC-RFC9000-S5P2-0001`: Trace coverage was already present from the prior pass; the packet-classification hook is still a direct match for the imported ID.
  - Evidence files: tests/Incursa.Quic.Tests/QuicPacketParserTests.cs, tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs
  - Tests: tests/Incursa.Quic.Tests/QuicPacketParserTests.cs, tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs
- `REQ-QUIC-RFC9000-S5P2P3-0002`: The preferred_address transport parameter is encoded, parsed, and fuzzed; the remaining migration-policy clauses are tracked separately in this chunk.
  - Evidence files: tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs, tests/Incursa.Quic.Tests/QuicTransportParametersFuzzTests.cs
  - Tests: tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs, tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs, tests/Incursa.Quic.Tests/QuicTransportParametersFuzzTests.cs
- `REQ-QUIC-RFC9000-S5P2P3-0004`: The disable_active_migration transport parameter is directly traced at the wire level.
  - Evidence files: tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs, tests/Incursa.Quic.Tests/QuicTransportParametersFuzzTests.cs
  - Tests: tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs, tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs, tests/Incursa.Quic.Tests/QuicTransportParametersFuzzTests.cs

## Reference Audit

- Source roots searched: `C:/src/incursa/quic-dotnet/src/Incursa.Quic`
- Test roots searched: `C:/src/incursa/quic-dotnet/tests`
- In-scope source requirement refs found: none
- In-scope test requirement refs found: REQ-QUIC-RFC9000-S5P2-0001, REQ-QUIC-RFC9000-S5P1P2-0004, REQ-QUIC-RFC9000-S5P1P2-0005, REQ-QUIC-RFC9000-S5P1P2-0008, REQ-QUIC-RFC9000-S5P2P3-0002, REQ-QUIC-RFC9000-S5P2P3-0004
- Stale or wrong refs found: none
- Current canonical in-scope test files: tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs, tests/Incursa.Quic.Tests/QuicFrameCodecPart4FuzzTests.cs, tests/Incursa.Quic.Tests/QuicPacketParserTests.cs, tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs, tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs, tests/Incursa.Quic.Tests/QuicTransportParametersFuzzTests.cs

## Remaining Open Requirements

- `S5P1P2`: `0001-0003`, `0006-0007`, `0009-0016`
- `S5P2`: `0002-0013`
- `S5P2P1`: `0001-0005`
- `S5P2P2`: `0001-0010`
- `S5P2P3`: `0001`, `0003`, `0005-0006`

## Tests Run and Results

- Command: `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicPacketParserTests|FullyQualifiedName~QuicHeaderPropertyTests|FullyQualifiedName~QuicHeaderFuzzTests|FullyQualifiedName~QuicVersionNegotiationPacketTests|FullyQualifiedName~QuicShortHeaderPacketTests|FullyQualifiedName~QuicFrameCodecPart4Tests|FullyQualifiedName~QuicFrameCodecPart4FuzzTests|FullyQualifiedName~QuicTransportParametersTests|FullyQualifiedName~QuicTransportParametersFuzzTests"`
- Result: Passed
- Summary: 62 passed, 0 failed, 0 skipped
- Duration: 162 ms

## Risks / Follow-up Notes

- The remaining work is concentrated in stateful connection management, packet association, and migration behavior that the current parser/codec slice does not model.
- The wire-level pieces in this chunk are now cleanly traced to the imported RFC 9000 IDs.
- No production-source changes were needed in this audit pass; only the closeout artifacts were written.
