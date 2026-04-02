# RFC 9000 Chunk Closeout: `9000-03-flow-control`

## Scope

Source: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
RFC: `9000`
Section tokens: `S4`, `S4P1`, `S4P2`, `S4P4`, `S4P5`, `S4P6`

Selection rule: include only requirements whose IDs match RFC `9000` and whose section token is exactly one of the selected tokens.

## Audit Result

- The requested reconciliation JSON was not present at the path in the prompt, so the audit was reconciled against the canonical spec, the implementation summary, and live repo search.
- No stale requirement IDs remain in the scoped tests after correcting the accidental RFC 9001 tags in `QuicFrameCodecPart3Tests.cs` and `QuicFrameCodecFuzzTests.cs`.
- No requirement-tagged source refs were found under `src/Incursa.Quic`.
- Sixteen scoped requirements have direct test evidence.
- Thirty-four scoped requirements remain explicitly deferred with blocker notes in the implementation summary.
- No silent gaps remain in scope.

## Requirements Covered

- `REQ-QUIC-RFC9000-S4-0004`: CRYPTO frames remain outside stream-style flow control and round-trip independently; coverage is carried by `QuicFrameCodecPart3Tests` and `QuicFrameCodecFuzzTests`.
- `REQ-QUIC-RFC9000-S4-0005`: the crypto buffer helper enforces its own capacity and overflow behavior; coverage is carried by `QuicCryptoBufferTests`.
- `REQ-QUIC-RFC9000-S4P1-0005` through `REQ-QUIC-RFC9000-S4P1-0009`: transport-parameter limits and MAX frame coverage are wired through `QuicTransportParametersTests`, `QuicTransportParametersFuzzTests`, `QuicFrameCodecPart3Tests`, and `QuicFrameCodecFuzzTests`.
- `REQ-QUIC-RFC9000-S4P1-0014`: blocked-sender signaling coverage is carried by `QuicFrameCodecPart4Tests` and `QuicFrameCodecPart4FuzzTests`.
- `REQ-QUIC-RFC9000-S4P5-0002` through `REQ-QUIC-RFC9000-S4P5-0003`: STREAM FIN and RESET_STREAM final-size wire coverage is carried by `QuicStreamFrameTests`, `QuicStreamFuzzTests`, and `QuicFrameCodecTests`.
- `REQ-QUIC-RFC9000-S4P6-0003` through `REQ-QUIC-RFC9000-S4P6-0007`: initial stream limits, MAX_STREAMS encoding, and oversized-value rejection are covered by `QuicTransportParametersTests`, `QuicTransportParametersFuzzTests`, `QuicFrameCodecPart3Tests`, and `QuicFrameCodecFuzzTests`.
- `REQ-QUIC-RFC9000-S4P6-0012`: STREAMS_BLOCKED encoding is covered by `QuicFrameCodecPart4Tests` and `QuicFrameCodecPart4FuzzTests`.

## Requirements Deferred

- `REQ-QUIC-RFC9000-S4-0001` through `REQ-QUIC-RFC9000-S4-0003`: blocked because the repository still lacks the connection-scoped flow-control and stream-admission state machine needed to enforce the section.
- `REQ-QUIC-RFC9000-S4P1-0001` through `REQ-QUIC-RFC9000-S4P1-0004`: blocked because sender/receiver flow-control enforcement against per-stream and connection-wide credit is not implemented yet.
- `REQ-QUIC-RFC9000-S4P1-0010` through `REQ-QUIC-RFC9000-S4P1-0013`: blocked because cumulative connection-byte tracking, monotonic MAX-frame handling, and flow-control violation reporting are still missing.
- `REQ-QUIC-RFC9000-S4P1-0015`: blocked because no periodic blocked-sender signaling policy exists for live flow-control state.
- `REQ-QUIC-RFC9000-S4P2-0001` through `REQ-QUIC-RFC9000-S4P2-0005`: blocked because the autotuning and early-credit advertisement policy is not present on top of the current stream-state slice.
- `REQ-QUIC-RFC9000-S4P4-0001` through `REQ-QUIC-RFC9000-S4P4-0004`: blocked because RESET_STREAM lifecycle tracking and opposite-direction preservation are still absent.
- `REQ-QUIC-RFC9000-S4P5-0001`: blocked because stream final-size state is not yet shared across STREAM FIN and RESET_STREAM paths.
- `REQ-QUIC-RFC9000-S4P5-0004` through `REQ-QUIC-RFC9000-S4P5-0008`: blocked because immutable final-size tracking, connection-level accounting, and beyond-final-size error reporting are still missing.
- `REQ-QUIC-RFC9000-S4P6-0001` through `REQ-QUIC-RFC9000-S4P6-0002`: blocked because inbound stream-open accounting and stream-ID limit enforcement are not present.
- `REQ-QUIC-RFC9000-S4P6-0008` through `REQ-QUIC-RFC9000-S4P6-0011`: blocked because connection-wide stream-limit tracking, STREAM_LIMIT_ERROR handling, and monotonic MAX_STREAMS processing are still absent.
- `REQ-QUIC-RFC9000-S4P6-0013`: blocked because the policy for advertising more stream credit without waiting for STREAMS_BLOCKED is not implemented yet.

## Reference Audit

- Source requirement refs found: none.
- Test requirement refs found for the implemented slice: `REQ-QUIC-RFC9000-S4-0004`, `REQ-QUIC-RFC9000-S4-0005`, `REQ-QUIC-RFC9000-S4P1-0005`, `REQ-QUIC-RFC9000-S4P1-0006`, `REQ-QUIC-RFC9000-S4P1-0007`, `REQ-QUIC-RFC9000-S4P1-0008`, `REQ-QUIC-RFC9000-S4P1-0009`, `REQ-QUIC-RFC9000-S4P1-0014`, `REQ-QUIC-RFC9000-S4P5-0002`, `REQ-QUIC-RFC9000-S4P5-0003`, `REQ-QUIC-RFC9000-S4P6-0003`, `REQ-QUIC-RFC9000-S4P6-0004`, `REQ-QUIC-RFC9000-S4P6-0005`, `REQ-QUIC-RFC9000-S4P6-0006`, `REQ-QUIC-RFC9000-S4P6-0007`, and `REQ-QUIC-RFC9000-S4P6-0012`.
- Stale requirement refs found: none after correction.
- The accidental RFC 9001 tags in `QuicFrameCodecPart3Tests.cs` and `QuicFrameCodecFuzzTests.cs` were corrected to the RFC 9000 flow-control ID `REQ-QUIC-RFC9000-S4-0004`.

## Files Changed

- `tests/Incursa.Quic.Tests/QuicFrameCodecPart3Tests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs`

## Tests Run

- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --no-restore`
- Result: `298 passed, 0 failed, 0 skipped`
