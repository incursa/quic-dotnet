# Chunk Closeout: 9000-27-frame-encodings-part-4

## Scope
- Requirements in scope: 66
- Implementation-summary entries: 66
- Spec/summary diff: none
- Reconciliation artifact: not present for this chunk

## Requirements Completed

### Implemented and tested (36)
- DATA_BLOCKED: `REQ-QUIC-RFC9000-S19P12-0003`.. `REQ-QUIC-RFC9000-S19P12-0006`
- STREAM_DATA_BLOCKED: `REQ-QUIC-RFC9000-S19P13-0003`.. `REQ-QUIC-RFC9000-S19P13-0008`
- STREAMS_BLOCKED: `REQ-QUIC-RFC9000-S19P14-0002`, `REQ-QUIC-RFC9000-S19P14-0004`.. `REQ-QUIC-RFC9000-S19P14-0008`
- NEW_CONNECTION_ID: `REQ-QUIC-RFC9000-S19P15-0002`.. `REQ-QUIC-RFC9000-S19P15-0010`, `REQ-QUIC-RFC9000-S19P15-0012`, `REQ-QUIC-RFC9000-S19P15-0013`
- RETIRE_CONNECTION_ID: `REQ-QUIC-RFC9000-S19P16-0004`.. `REQ-QUIC-RFC9000-S19P16-0006`
- PATH_CHALLENGE: `REQ-QUIC-RFC9000-S19P17-0002`.. `REQ-QUIC-RFC9000-S19P17-0005`
- PATH_RESPONSE: `REQ-QUIC-RFC9000-S19P18-0001`.. `REQ-QUIC-RFC9000-S19P18-0002`

### Partially implemented (4)
- `REQ-QUIC-RFC9000-S19P14-0009`: Codec rejects oversize stream-limit values, but the connection-layer STREAM_LIMIT_ERROR / FRAME_ENCODING_ERROR mapping is still deferred.
- `REQ-QUIC-RFC9000-S19P15-0011`: Codec rejects invalid CID lengths, but the repository does not yet surface a connection-layer FRAME_ENCODING_ERROR.
- `REQ-QUIC-RFC9000-S19P15-0019`: Codec validates Retire Prior To <= Sequence Number, but peer CID-retirement bookkeeping is not present in this slice.
- `REQ-QUIC-RFC9000-S19P15-0020`: Codec rejects Retire Prior To values greater than Sequence Number, but the connection-layer FRAME_ENCODING_ERROR mapping is still deferred.

These are codec-level validations or frame-level invariants that are implemented now, but the corresponding connection-layer error classification or peer-state bookkeeping remains deferred.

### Blocked / deferred (26)
- Flow-control sender behavior: `REQ-QUIC-RFC9000-S19P12-0001`, `REQ-QUIC-RFC9000-S19P12-0002`
- Send-only stream handling: `REQ-QUIC-RFC9000-S19P13-0001`, `REQ-QUIC-RFC9000-S19P13-0002`
- Stream-opening accounting: `REQ-QUIC-RFC9000-S19P14-0001`, `REQ-QUIC-RFC9000-S19P14-0003`
- Connection-ID lifecycle and duplicate tracking: `REQ-QUIC-RFC9000-S19P15-0001`, `REQ-QUIC-RFC9000-S19P15-0014`.. `REQ-QUIC-RFC9000-S19P15-0023`
- Peer-issued CID lifecycle and destination-CID checks: `REQ-QUIC-RFC9000-S19P16-0001`, `REQ-QUIC-RFC9000-S19P16-0002`, `REQ-QUIC-RFC9000-S19P16-0003`, `REQ-QUIC-RFC9000-S19P16-0007`.. `REQ-QUIC-RFC9000-S19P16-0011`
- Path validation response generation: `REQ-QUIC-RFC9000-S19P17-0001`, `REQ-QUIC-RFC9000-S19P17-0006`
- Path validation comparison/state: `REQ-QUIC-RFC9000-S19P18-0003`

## Trace Audit
- Tests carrying in-scope requirement traits:
  - `tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs`
  - `tests/Incursa.Quic.Tests/QuicFrameCodecPart4FuzzTests.cs`
- In-scope test traits found: 40 requirement IDs
- Out-of-scope requirement traits found in tests: 0
- No stale requirement IDs remain in scope.
- No code-side requirement refs or XML-comment refs were found under `src/Incursa.Quic`.

## Tests Run
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --logger "console;verbosity=minimal"`
- Result: 188 passed, 0 failed, 0 skipped

## Closeout
- The scope matches the implementation-summary one-for-one.
- All implemented requirements have test traits.
- Remaining items are explicit partials or blockers, not silent gaps.
