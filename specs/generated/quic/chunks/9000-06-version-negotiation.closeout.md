# RFC 9000 Chunk Closeout: `9000-06-version-negotiation`

## Scope

- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- RFC: `9000`
- Section tokens: `S6`, `S6P1`, `S6P2`, `S6P3`
- Reconciliation artifact: not present for this chunk
- Implementation summary reviewed: `./specs/generated/quic/chunks/9000-06-version-negotiation.implementation-summary.json`

## Audit Result

- Audit result: `clean_with_explicit_blockers`
- No stale requirement IDs remain in scope.
- No requirement-tagged source refs were found under `src/Incursa.Quic`.
- Current tests reference only the imported RFC 9000 IDs in scope.
- No old->new requirement ID rewrites were needed.
- The two remaining open requirements both carry explicit blocker notes; there are no silent gaps.

## Requirements In Scope

- `S6`: 2 requirements
- `S6P1`: 3 requirements
- `S6P2`: 4 requirements
- `S6P3`: 2 requirements
- Total in scope: **11**
- Covered: **9**
- Blocked / deferred: **2**
- Partial: **0**
- Needs review: **0**

## Requirements Completed

- `REQ-QUIC-RFC9000-S6P1-0001`: Send Version Negotiation with accepted versions. Evidence files: `src/Incursa.Quic/QuicVersionNegotiation.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`, `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`, `benchmarks/QuicHeaderParsingBenchmarks.cs`. Test files: `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`.
- `REQ-QUIC-RFC9000-S6P1-0002`: Forbid Version Negotiation responses to Version Negotiation. Evidence files: `src/Incursa.Quic/QuicVersionNegotiation.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`, `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`. Test files: `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`.
- `REQ-QUIC-RFC9000-S6P1-0003`: Limit Version Negotiation volume. Evidence files: `src/Incursa.Quic/QuicVersionNegotiation.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`, `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`. Test files: `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`.
- `REQ-QUIC-RFC9000-S6P2-0001`: Reject unsupported Version Negotiation attempts. Evidence files: `src/Incursa.Quic/QuicVersionNegotiation.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`, `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`. Test files: `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`.
- `REQ-QUIC-RFC9000-S6P2-0002`: Client MUST abandon the current connection attempt if it receives a Version Negotiation packet when the predicate says it can. Evidence files: `src/Incursa.Quic/QuicVersionNegotiation.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`, `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`. Test files: `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`.
- `REQ-QUIC-RFC9000-S6P2-0003`: Discard Version Negotiation after another packet has already been processed. Evidence files: `src/Incursa.Quic/QuicVersionNegotiation.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`, `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`. Test files: `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`.
- `REQ-QUIC-RFC9000-S6P2-0004`: Discard a Version Negotiation packet that lists the client-selected version. Evidence files: `src/Incursa.Quic/QuicVersionNegotiation.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`, `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`. Test files: `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`.
- `REQ-QUIC-RFC9000-S6P3-0001`: Use reserved versions to test ignoring. Evidence files: `src/Incursa.Quic/QuicVersionNegotiation.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`, `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`. Test files: `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`.
- `REQ-QUIC-RFC9000-S6P3-0002`: Use reserved versions to test discarding. Evidence files: `tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs`. Test files: `tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs`.

## Remaining Open Requirements

- `REQ-QUIC-RFC9000-S6-0001`: Blocked because the repository still has no outbound UDP datagram assembly or PADDING-based client send surface.
- `REQ-QUIC-RFC9000-S6-0002`: Blocked because the repository still has no first-datagram sender that can add PADDING frames or coalesce packets.

## Reference Audit

- Source roots searched: `C:/src/incursa/quic-dotnet/src/Incursa.Quic`
- Test roots searched: `C:/src/incursa/quic-dotnet/tests`
- In-scope source requirement refs found: none
- In-scope test requirement refs found: `REQ-QUIC-RFC9000-S6-0001`, `REQ-QUIC-RFC9000-S6-0002`, `REQ-QUIC-RFC9000-S6P1-0001`, `REQ-QUIC-RFC9000-S6P1-0002`, `REQ-QUIC-RFC9000-S6P1-0003`, `REQ-QUIC-RFC9000-S6P2-0001`, `REQ-QUIC-RFC9000-S6P2-0002`, `REQ-QUIC-RFC9000-S6P2-0003`, `REQ-QUIC-RFC9000-S6P2-0004`, `REQ-QUIC-RFC9000-S6P3-0001`, `REQ-QUIC-RFC9000-S6P3-0002`
- Stale or wrong refs found: none
- Current in-scope test files: `tests/Incursa.Quic.Tests/QuicVersionNegotiationTests.cs`, `tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`

## Tests Run and Results

- Command: `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicVersionNegotiationTests|FullyQualifiedName~QuicVersionNegotiationPacketTests|FullyQualifiedName~QuicHeaderFuzzTests|FullyQualifiedName~QuicHeaderPropertyTests|FullyQualifiedName~QuicPacketParserTests|FullyQualifiedName~QuicLongHeaderPacketTests"`
- Result: `71 passed, 0 failed, 0 skipped`
- Duration: `163 ms`

## Risks / Follow-up Notes

- The remaining work is confined to the first-datagram send path and PADDING-based client assembly.
- The benchmark source touched in the implementation summary was not exercised by the audit test command.
- All other in-scope requirements have implementation and test evidence, and no stale trace IDs were found in the relevant tests or source surfaces.
