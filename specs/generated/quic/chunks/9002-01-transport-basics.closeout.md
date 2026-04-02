# RFC 9002 Chunk Closeout: `9002-01-transport-basics`

## Scope

- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9002.json`
- RFC: `9002`
- Section tokens: `S2`, `S3`
- Reconciliation artifact reviewed: not present in the repo
- Implementation summary reviewed: `./specs/generated/quic/chunks/9002-01-transport-basics.implementation-summary.json`

## Audit Result

- Audit result: `clean_with_explicit_blockers`
- In-scope requirements: 21 total, 9 implemented and tested, 1 deferred, 11 blocked with explicit notes.
- No stale requirement IDs remain in scope.
- No silent gaps remain in scope.
- Scoped direct requirement refs are test-only in this slice; no in-scope source refs were found under `src/Incursa.Quic`.

## Requirements In Scope

### Implemented and Tested

- `REQ-QUIC-RFC9002-S2-0002` Classify non-control frames as ack-eliciting.
- `REQ-QUIC-RFC9002-S2-0003` Acknowledge ack-eliciting packets promptly.
- `REQ-QUIC-RFC9002-S3-0002` Indicate encryption level in packet headers.
- `REQ-QUIC-RFC9002-S3-0003` Carry packet numbers in packet headers.
- `REQ-QUIC-RFC9002-S3-0004` Map encryption level to packet number space.
- `REQ-QUIC-RFC9002-S3-0008` Permit mixed frame types per packet.
- `REQ-QUIC-RFC9002-S3-0011` Acknowledge all packets.
- `REQ-QUIC-RFC9002-S3-0012` Delay acknowledgment for non-ack-eliciting packets.
- `REQ-QUIC-RFC9002-S3-0017` Suppress direct ACKs for PADDING.

### Deferred

- `REQ-QUIC-RFC9002-S2-0001` Interpret all-caps BCP 14 keywords.

### Blocked

- `REQ-QUIC-RFC9002-S2-0004` Define packets in flight.
- `REQ-QUIC-RFC9002-S3-0001` Attach packet-level headers to transmissions.
- `REQ-QUIC-RFC9002-S3-0005` Prohibit packet number reuse.
- `REQ-QUIC-RFC9002-S3-0006` Send packet numbers monotonically.
- `REQ-QUIC-RFC9002-S3-0007` Allow intentional packet number gaps.
- `REQ-QUIC-RFC9002-S3-0009` Ensure reliable delivery outcome.
- `REQ-QUIC-RFC9002-S3-0010` Allow retransmission in new packets.
- `REQ-QUIC-RFC9002-S3-0013` Shorten CRYPTO acknowledgment timers.
- `REQ-QUIC-RFC9002-S3-0014` Count non-ACK packets toward congestion limits.
- `REQ-QUIC-RFC9002-S3-0015` Treat non-ACK packets as in flight.
- `REQ-QUIC-RFC9002-S3-0016` Count PADDING toward bytes in flight.

## Reference Audit

- Source requirement refs found: none
- Test requirement refs found: `REQ-QUIC-RFC9002-S2-0002`, `REQ-QUIC-RFC9002-S2-0003`, `REQ-QUIC-RFC9002-S3-0001`, `REQ-QUIC-RFC9002-S3-0002`, `REQ-QUIC-RFC9002-S3-0003`, `REQ-QUIC-RFC9002-S3-0004`, `REQ-QUIC-RFC9002-S3-0008`, `REQ-QUIC-RFC9002-S3-0011`, `REQ-QUIC-RFC9002-S3-0012`, `REQ-QUIC-RFC9002-S3-0017`
- Source files checked for requirement IDs: `src/Incursa.Quic/QuicFrameCodec.cs`, `src/Incursa.Quic/QuicPacketParser.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`
- Test files with requirement traits: `tests/Incursa.Quic.Tests/QuicAckGenerationStateTests.cs`, `tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs`, `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs`, `tests/Incursa.Quic.Tests/QuicPacketParserTests.cs`, `tests/Incursa.Quic.Tests/QuicShortHeaderPacketTests.cs`
- Stale or wrong refs found: none

## Tests Reviewed

- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicFrameCodecTests|FullyQualifiedName~QuicPacketParserTests|FullyQualifiedName~QuicLongHeaderPacketTests|FullyQualifiedName~QuicShortHeaderPacketTests|FullyQualifiedName~QuicAckGenerationStateTests"` - `78 passed, 0 failed, 0 skipped`
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj` - `263 passed, 0 failed, 0 skipped`

## Remaining Open Requirements

- `REQ-QUIC-RFC9002-S2-0001`: intentionally deferred; document-level BCP 14 interpretation rule with no executable behavior in this slice.
- `REQ-QUIC-RFC9002-S2-0004`: blocked by missing send, loss, and discard tracking.
- `REQ-QUIC-RFC9002-S3-0001`: blocked by the absence of a transmit/composer surface.
- `REQ-QUIC-RFC9002-S3-0005`: blocked by missing sender-side packet-number allocation state.
- `REQ-QUIC-RFC9002-S3-0006`: blocked by missing sender-side packet-number sequencing.
- `REQ-QUIC-RFC9002-S3-0007`: blocked by missing sender-side packet-number gap policy.
- `REQ-QUIC-RFC9002-S3-0009`: blocked by missing retransmission and loss-detection policy.
- `REQ-QUIC-RFC9002-S3-0010`: blocked by missing retransmission-in-new-packets logic.
- `REQ-QUIC-RFC9002-S3-0013`: blocked by missing CRYPTO-aware ACK timer shortening.
- `REQ-QUIC-RFC9002-S3-0014`: blocked by missing congestion-control accounting for non-ACK packets.
- `REQ-QUIC-RFC9002-S3-0015`: blocked by missing in-flight accounting for non-ACK packets.
- `REQ-QUIC-RFC9002-S3-0016`: blocked by missing bytes-in-flight accounting for PADDING.

## Notes

- The prompt named a reconciliation JSON that does not exist in the repo; this closeout relies on the implementation summary artifact and the scoped repo audit.
- `REQ-QUIC-RFC9002-S3-0001` remains blocked even though tests carry the ID, because the repo still lacks a transmit/composer surface and the current refs only cover parsing and modeling.
- The chunk is trace-consistent for the selected scope and is ready for merge or repo-wide trace/audit follow-up.
