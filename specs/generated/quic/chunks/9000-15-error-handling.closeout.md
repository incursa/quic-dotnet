# 9000-15-error-handling Closeout

## Scope

- RFC: `9000`
- Section tokens: `S11`, `S11P1`, `S11P2`
- Canonical spec: [`SPEC-QUIC-RFC9000.json`](C:/src/incursa/quic-dotnet/specs/requirements/quic/SPEC-QUIC-RFC9000.json)
- Implementation summary: [`9000-15-error-handling.implementation-summary.json`](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9000-15-error-handling.implementation-summary.json)
- Reconciliation artifact: not present at `C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9000-15-error-handling.reconciliation.json`

## Summary

- Requirements in scope: 18
- Covered by implementation or test evidence: 8
- Explicitly deferred or blocked: 10
- Uncovered / silent gaps: 0
- Stale IDs in scope: 0
- Wrong IDs in tests or source refs: 0
- Reconciliation artifact present: no

## Scope Inventory

- `S11`: `RFC9000-S11-P1-S1-R01`, `RFC9000-S11-P2-S1-R01`, `REQ-QUIC-RFC9000-0659`, `REQ-QUIC-RFC9000-0658`, `RFC9000-S11-P3-S2-R01`
- `S11P1`: `RFC9000-S11-1-P1-S1-R01`, `REQ-QUIC-RFC9000-0663`, `REQ-QUIC-RFC9000-S11P1-0003`, `REQ-QUIC-RFC9000-0665`, `REQ-QUIC-RFC9000-S11P1-0005`, `REQ-QUIC-RFC9000-S11P1-0006`, `RFC9000-S11-1-P5-S1-R01`, `RFC9000-S11-1-P5-S3-R01`
- `S11P2`: `REQ-QUIC-RFC9000-S11P2-0001`, `RFC9000-S11-2-P2-S2-R01`, `REQ-QUIC-RFC9000-S11P2-0003`, `REQ-QUIC-RFC9000-S11P2-0004`, `RFC9000-S11-2-P4-S1-R01`

## Evidence

- [`src/Incursa.Quic/QuicFrameCodec.cs`](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicFrameCodec.cs#L72) classifies application `CONNECTION_CLOSE` (`0x1d`) as non-ack-eliciting and parses/formats both transport and application close frames.
- [`src/Incursa.Quic/QuicConnectionCloseFrame.cs`](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicConnectionCloseFrame.cs#L16) exposes the transport/application split and emits the correct wire frame type.
- [`tests/Incursa.Quic.Tests/QuicFrameCodecErrorHandlingTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecErrorHandlingTests.cs#L5) covers positive and negative `CONNECTION_CLOSE` round trips with the in-scope requirement IDs.
- [`tests/Incursa.Quic.Tests/QuicFrameCodecErrorHandlingFuzzTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecErrorHandlingFuzzTests.cs#L5) fuzzes representative transport/application close shapes and truncation rejection.
- [`SPEC-QUIC-RFC9000.json`](C:/src/incursa/quic-dotnet/specs/requirements/quic/SPEC-QUIC-RFC9000.json#L16534) now carries `x_test_refs` for `RFC9000-S11-P3-S2-R01`, and [`RFC9000-S11-P3-S2-R01.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/RFC9000-S11-P3-S2-R01.cs#L1) covers the positive and negative runtime-routing cases for stateless-reset suppression.
- [`tests/Incursa.Quic.Tests/QuicFrameTestData.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameTestData.cs#L83) adds a connection-close frame builder used by the tests.
- The implementation summary reports successful `dotnet test` runs for the targeted frame-codec tests and the full test suite.

## Requirement Coverage

- `RFC9000-S11-P1-S1-R01`: implemented and test-covered by the connection-close round-trip tests.
- `RFC9000-S11-P2-S1-R01`: implemented and test-covered by the connection-close round-trip tests.
- `REQ-QUIC-RFC9000-0659`: implemented and test-covered by the connection-close round-trip tests.
- `REQ-QUIC-RFC9000-0658`: implemented and test-covered by the connection-close round-trip tests.
- `RFC9000-S11-P3-S2-R01`: implemented and test-covered by the new requirement-home proof and canonical `x_test_refs`.
- `RFC9000-S11-1-P1-S1-R01`: implemented and test-covered by the connection-close round-trip tests and the non-ack-eliciting classifier update.
- `REQ-QUIC-RFC9000-0663`: implemented and test-covered by the application-close wire-type handling.
- `REQ-QUIC-RFC9000-S11P1-0003`: implemented and test-covered by the transport-close wire-type handling.
- `REQ-QUIC-RFC9000-0665`: explicitly deferred in the implementation summary because retransmission after termination needs a send path.
- `REQ-QUIC-RFC9000-S11P1-0005`: explicitly deferred in the implementation summary because bounding terminal retransmissions needs connection-lifecycle policy.
- `REQ-QUIC-RFC9000-S11P1-0006`: explicitly deferred in the implementation summary because stateless reset after close needs receive-path and stateful termination logic.
- `RFC9000-S11-1-P5-S1-R01`: explicitly deferred in the implementation summary because invalid Initial discard depends on handshake authentication and packet-processing pipeline.
- `RFC9000-S11-1-P5-S3-R01`: explicitly deferred in the implementation summary because safe discard after revert needs a reversible receive pipeline.
- `REQ-QUIC-RFC9000-S11P2-0001`: explicitly deferred in the implementation summary because RESET_STREAM instigation needs application-protocol and stream-state orchestration.
- `RFC9000-S11-2-P2-S2-R01`: explicitly deferred in the implementation summary because only the application protocol can instigate RESET_STREAM.
- `REQ-QUIC-RFC9000-S11P2-0003`: explicitly deferred in the implementation summary because stream termination policy is owned by the application protocol.
- `REQ-QUIC-RFC9000-S11P2-0004`: explicitly deferred in the implementation summary because STOP_SENDING-driven RESET_STREAM needs an application-protocol callback surface.
- `RFC9000-S11-2-P4-S1-R01`: explicitly deferred in the implementation summary because premature-cancel handling is application-specific.

## Reference Audit

- In-scope source requirement refs found: none.
- In-scope test requirement refs found:
  - [`tests/Incursa.Quic.Tests/QuicFrameCodecErrorHandlingTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecErrorHandlingTests.cs) - `RFC9000-S11-P1-S1-R01`, `RFC9000-S11-P2-S1-R01`, `REQ-QUIC-RFC9000-0659`, `REQ-QUIC-RFC9000-0658`, `RFC9000-S11-1-P1-S1-R01`, `REQ-QUIC-RFC9000-0663`, `REQ-QUIC-RFC9000-S11P1-0003`
  - [`tests/Incursa.Quic.Tests/QuicFrameCodecErrorHandlingFuzzTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecErrorHandlingFuzzTests.cs) - `RFC9000-S11-P1-S1-R01`, `RFC9000-S11-P2-S1-R01`, `REQ-QUIC-RFC9000-0659`, `REQ-QUIC-RFC9000-0658`, `RFC9000-S11-1-P1-S1-R01`, `REQ-QUIC-RFC9000-0663`, `REQ-QUIC-RFC9000-S11P1-0003`
  - [`tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/RFC9000-S11-P3-S2-R01.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/RFC9000-S11-P3-S2-R01.cs) - `RFC9000-S11-P3-S2-R01`
- Stale or wrong in-scope requirement refs found: none.
- Out-of-scope stale/wrong requirement refs found:
  - [`tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs#L42) carries `REQ-QUIC-RFC9000-S10P1P1-0001` on the classifier test, but that ID is the RFC 9000 liveness-probe clause, not the S11 error-handling clause.
- Some test methods carry deferred IDs because they exercise adjacent helper behavior; those IDs remain deferred in this closeout and are not counted as completed.

## Conclusion

This chunk is trace-consistent for its selected scope. The implemented S11 and S11P1 requirements have direct code and test evidence, `RFC9000-S11-P3-S2-R01` is now closed by the requirement-home proof plus canonical spec xrefs, the S11P2 requirements are explicitly deferred in the implementation summary, and there are no silent gaps inside the selected section tokens.

One out-of-scope stale test tag remains in [`QuicFrameCodecTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs#L42); it should be retagged if the repo wants that classifier test to carry the error-handling trace instead of the older liveness-probe ID.
