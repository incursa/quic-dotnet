# RFC 9221 QUIC DATAGRAM SpecTrace Plan

This plan describes the trace-first path for adding RFC 9221 QUIC DATAGRAM support.
It is an implementation planning artifact, not a canonical requirement source.
Canonical behavior must land in JSON artifacts under `specs/requirements/quic`,
`specs/architecture/quic`, `specs/work-items/quic`, and
`specs/verification/quic` before protocol code is implemented.

## Current State

- `specs/requirements/quic/REQUIREMENT-GAPS.md` no longer carries an RFC 9221 transport-floor gap once the requirement family is trace-clean; higher-level HTTP Datagram and MASQUE work stays in separate gap-ledger entries.
- No `SPEC-QUIC-RFC9221.json` artifact exists yet.
- No RFC 9221 local corpus file exists in this checkout, even though `specs/requirements/quic/README.md` mentions a future RFC corpus.
- `QuicTransportParameters` and `QuicTransportParametersCodec` currently model RFC 9000 transport parameters only.
- `QuicFrameCodec` currently handles RFC 9000 frame types and does not parse or format RFC 9221 DATAGRAM frame types `0x30` and `0x31`.
- `QuicConnectionSendDatagramEffect` means "send a UDP datagram containing a QUIC packet"; it is not an RFC 9221 application DATAGRAM frame.
- `QuicApplicationSendQueue` is stream-oriented and needs either a separate datagram send queue or a widened application-send model.

## Source Inputs

- RFC 9221: <https://datatracker.ietf.org/doc/html/rfc9221>
- RFC 9000 transport parameter and frame processing: `specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- RFC 9001 0-RTT and 1-RTT protection: `specs/requirements/quic/SPEC-QUIC-RFC9001.json`
- RFC 9002 ACK and congestion behavior: `specs/requirements/quic/SPEC-QUIC-RFC9002.json`
- Gap ledger: close the RFC 9221 transport-floor entry when the canonical artifacts, focused proof, generated coverage, and benchmark evidence are all present

## Artifact Plan

Create these canonical JSON artifacts before code changes:

- `specs/requirements/quic/SPEC-QUIC-RFC9221.json`
- `specs/architecture/quic/ARC-QUIC-RFC9221-0001.json`
- `specs/work-items/quic/WI-QUIC-RFC9221-0001.json`
- `specs/verification/quic/VER-QUIC-RFC9221-0001.json`

Update these existing surfaces in the same trace slice:

- `specs/requirements/quic/README.md`
- `specs/requirements/quic/REQUIREMENT-GAPS.md`
- Any generated QUIC coverage outputs produced by the repo-local generation script
- Requirement-home tests under `tests/Incursa.Quic.Tests/RequirementHomes/RFC9221/`
- Permanent benchmark entries under `benchmarks/README.md` when benchmark code lands

## Requirement Slices

### Slice 1: Transport Parameter Negotiation

Candidate requirements:

- `REQ-QUIC-RFC9221-S3-0001`: An endpoint that supports receiving DATAGRAM frames MUST advertise `max_datagram_frame_size` transport parameter `0x20`.
- `REQ-QUIC-RFC9221-S3-0002`: The `max_datagram_frame_size` value MUST represent the maximum complete DATAGRAM frame size, including frame type, length, and payload.
- `REQ-QUIC-RFC9221-S3-0003`: The absence of `max_datagram_frame_size` MUST be treated as value `0`, meaning DATAGRAM frames are unsupported.
- `REQ-QUIC-RFC9221-S3-0004`: An endpoint MUST NOT send DATAGRAM frames before receiving a non-zero peer `max_datagram_frame_size`.
- `REQ-QUIC-RFC9221-S3-0005`: An endpoint MUST NOT send a DATAGRAM frame larger than the peer-advertised `max_datagram_frame_size`.
- `REQ-QUIC-RFC9221-S3-0006`: An endpoint that receives a DATAGRAM frame without having advertised DATAGRAM support MUST close the connection with `PROTOCOL_VIOLATION`.
- `REQ-QUIC-RFC9221-S3-0007`: An endpoint that receives a DATAGRAM frame larger than its advertised `max_datagram_frame_size` MUST close the connection with `PROTOCOL_VIOLATION`.
- `REQ-QUIC-RFC9221-S3-0008`: The `max_datagram_frame_size` limit MUST be unidirectional.
- `REQ-QUIC-RFC9221-S3-0009`: A client that stores DATAGRAM 0-RTT state MUST validate that the server's new `max_datagram_frame_size` is greater than or equal to the stored value.
- `REQ-QUIC-RFC9221-S3-0010`: A client that detects a lower resumed server `max_datagram_frame_size` for stored 0-RTT DATAGRAM state MUST close the connection with `PROTOCOL_VIOLATION`.
- `REQ-QUIC-RFC9221-S3-0011`: Application protocol configuration MUST define behavior when peer DATAGRAM support is absent.

Implementation notes:

- Add `MaxDatagramFrameSize` to `QuicTransportParameters`.
- Add codec constant `0x20` and parse/format support in `QuicTransportParametersCodec`.
- Preserve unknown transport-parameter behavior already expected by RFC 9000, but reject duplicate `0x20` through the existing duplicate-detection path.
- Keep the default as absence/null in the data model and expose an effective value helper that returns `0`.
- Treat recommended value `65535` as guidance, not a hard requirement, unless a repo-local API option chooses it by default.

Proof:

- Positive tests for parse/format round-trip, default absence, advertised non-zero value, and unidirectional local/peer interpretation.
- Negative tests for duplicate parameter encoding, malformed varints, oversized received DATAGRAM frames, and sending before peer support.
- 0-RTT tests should be deferred or marked blocked if the current dormant 0-RTT gate remains closed.
- Fuzz `QuicTransportParametersCodec` with `0x20` values included.
- Benchmark transport-parameter parse/format impact if the benchmark suite already covers transport parameters.

### Slice 2: DATAGRAM Frame Codec

Candidate requirements:

- `REQ-QUIC-RFC9221-S4-0001`: DATAGRAM frame type values MUST be accepted only in the `0x30..0x31` range.
- `REQ-QUIC-RFC9221-S4-0002`: The least significant bit of the DATAGRAM frame type MUST indicate whether a Length field is present.
- `REQ-QUIC-RFC9221-S4-0003`: A DATAGRAM frame with type `0x30` MUST treat Datagram Data as extending to the end of the QUIC packet payload.
- `REQ-QUIC-RFC9221-S4-0004`: A DATAGRAM frame with type `0x31` MUST parse a variable-length integer Length field before Datagram Data.
- `REQ-QUIC-RFC9221-S4-0005`: The DATAGRAM frame codec MUST allow zero-length Datagram Data.
- `REQ-QUIC-RFC9221-S4-0006`: The DATAGRAM frame codec MUST reject truncated Length fields and Length values that exceed the remaining packet payload.

Implementation notes:

- Add a `QuicDatagramFrame` model with `FrameType`, optional `Length`, and owned payload bytes.
- Add `TryParseDatagramFrame` and `TryFormatDatagramFrame` to `QuicFrameCodec`.
- Keep `0x30` formatting available for last-frame-in-packet only; prefer `0x31` when coalescing with later frames.
- Ensure generic frame scanning can classify `0x30` and `0x31` as ack-eliciting.

Proof:

- Positive tests for `0x30`, `0x31`, empty payloads, one-byte and multi-byte varint lengths, and round-tripping.
- Negative tests for invalid type values, truncated varints, declared length beyond payload, and destination buffer too small.
- Fuzz tests for parse boundaries and arbitrary payload lengths.
- Benchmarks for parse/format hot paths under `benchmarks/`.

### Slice 3: Receive Path Semantics

Candidate requirements:

- `REQ-QUIC-RFC9221-S5-0001`: A valid received DATAGRAM frame SHOULD be delivered to the application immediately when the endpoint can process and store it.
- `REQ-QUIC-RFC9221-S5-0002`: DATAGRAM frame payloads MUST be treated as connection-scoped application data rather than stream-associated data.
- `REQ-QUIC-RFC9221-S5-0003`: QUIC transport MUST leave DATAGRAM payload multiplexing semantics to the application protocol.
- `REQ-QUIC-RFC9221-S5-0004`: A receiver MAY drop DATAGRAM frames when it cannot process or store the payload.
- `REQ-QUIC-RFC9221-S6-0001`: Received DATAGRAM application data MUST only be accepted from packets protected with 0-RTT or 1-RTT keys.

Implementation notes:

- Add a runtime event/effect or delivery callback that is explicitly named for application DATAGRAM frames to avoid confusion with UDP send effects.
- Do not attach received DATAGRAM frames to `QuicConnectionStreamState`.
- Decide whether receive backpressure is a bounded queue, drop policy, or immediate callback. Record that decision in `ARC-QUIC-RFC9221-0001.json`.
- Reuse existing packet protection level classification to reject any DATAGRAM carried outside 0-RTT or 1-RTT packet contexts.

Proof:

- Positive tests for 1-RTT delivery and, if enabled, 0-RTT delivery.
- Negative tests for Initial/Handshake packet contexts, unsupported local DATAGRAM parameter, oversized frames, and malformed frame payloads.
- Edge tests for empty payload, large accepted payload at the configured limit, and receiver drop behavior.
- Requirement-home tests must prove connection-scoped delivery without stream ID coupling.

### Slice 4: Send Path And Application API

Candidate requirements:

- `REQ-QUIC-RFC9221-S5-0005`: When an application sends a datagram over a QUIC connection, QUIC SHOULD send the DATAGRAM frame as soon as congestion control and packet assembly permit.
- `REQ-QUIC-RFC9221-S5-0006`: DATAGRAM frames MAY be coalesced with other QUIC frames.
- `REQ-QUIC-RFC9221-S5-0007`: DATAGRAM frames MUST NOT be fragmented across QUIC packets.
- `REQ-QUIC-RFC9221-S5-0008`: Application-facing send logic MUST expose the currently usable maximum DATAGRAM payload size after applying peer frame size, `max_udp_payload_size`, and path MTU constraints.
- `REQ-QUIC-RFC9221-S5P1-0001`: QUIC implementations SHOULD expose relative prioritization for DATAGRAM frames against other DATAGRAM frames and QUIC streams.

Implementation notes:

- Add a datagram-specific send request model separate from `PendingApplicationSendRequest`, or widen the existing queue with an explicit send kind.
- Include datagram priority in the scheduler so stream writes and DATAGRAM frames can be ordered deterministically.
- Packet assembly must reject payloads that cannot fit in one packet after headers and protection overhead.
- Do not reuse `QuicConnectionSendDatagramEffect` naming for RFC 9221 payloads; if a new effect is needed, name it `QuicConnectionApplicationDatagramReceivedEffect` or similar.

Proof:

- Positive tests for sending after peer support, coalescing with stream/PING frames, priority ordering, and max-payload reporting.
- Negative tests for sending before peer support, sending above peer limit, and attempting fragmentation.
- Edge tests around exact fit, one byte over fit, and reduced path MTU.
- Benchmarks for scheduler selection and frame formatting.

### Slice 5: ACK, Loss, And Congestion Behavior

Candidate requirements:

- `REQ-QUIC-RFC9221-S5P2-0001`: DATAGRAM frames MUST be treated as ack-eliciting.
- `REQ-QUIC-RFC9221-S5P2-0002`: DATAGRAM frames MUST NOT be retransmitted by transport loss recovery.
- `REQ-QUIC-RFC9221-S5P2-0003`: A receiver SHOULD support delayed ACKs for packets containing only DATAGRAM frames within `max_ack_delay`.
- `REQ-QUIC-RFC9221-S5P2-0004`: A sender MAY notify the application when it believes a DATAGRAM frame was lost.
- `REQ-QUIC-RFC9221-S5P2-0005`: A sender MAY notify the application when a packet carrying a DATAGRAM frame is acknowledged.
- `REQ-QUIC-RFC9221-S5P2-0006`: DATAGRAM acknowledgment notification MUST NOT be treated as proof that the receiver application processed the payload.
- `REQ-QUIC-RFC9221-S5P3-0001`: DATAGRAM frames MUST NOT contribute to stream-level or connection-wide flow-control limits.
- `REQ-QUIC-RFC9221-S5P4-0001`: DATAGRAM frames MUST be subject to QUIC congestion control.
- `REQ-QUIC-RFC9221-S5P4-0002`: When congestion control does not allow sending a DATAGRAM frame, the sender MUST delay it or drop it without transmission.

Implementation notes:

- Update packet metadata to remember that a sent packet contains DATAGRAM frames without scheduling retransmission payload.
- Wire DATAGRAM-only packets through existing ACK delay and PTO paths as ack-eliciting packets.
- Keep optional loss/ack application notifications out of the first implementation unless a stable API is defined.
- Do not debit stream or connection flow-control counters for DATAGRAM payload bytes.

Proof:

- Positive tests for ack-eliciting classification, delayed ACK scheduling, and congestion-window gating.
- Negative tests proving no retransmission of lost DATAGRAM payloads and no flow-control debit.
- Edge tests for mixed packets containing DATAGRAM plus retransmittable frames.
- Recovery-focused requirement homes should reference both RFC 9221 requirements and the relevant RFC 9002 behavior where trace links require it.

### Slice 6: Security And 0-RTT Boundaries

Candidate requirements:

- `REQ-QUIC-RFC9221-S6-0002`: DATAGRAM application data sent by this implementation MUST be protected with 0-RTT or 1-RTT keys.
- `REQ-QUIC-RFC9221-S6-0003`: Application protocols that permit DATAGRAM in 0-RTT MUST define an acceptable 0-RTT use profile before enabling that behavior.
- `REQ-QUIC-RFC9221-S3-0012`: Server acceptance of 0-RTT DATAGRAM state MUST advertise a `max_datagram_frame_size` greater than or equal to the value associated with the accepted ticket.

Implementation notes:

- If 0-RTT remains dormant in this repo, keep DATAGRAM 0-RTT requirements authored but mark their implementation work item as deferred or blocked by the existing 0-RTT gate.
- Do not allow a public API toggle to enable 0-RTT DATAGRAM behavior without an application profile artifact.
- Keep security text in requirements and architecture; do not hide it in comments or tests.

Proof:

- Positive 1-RTT protection proof is required for the first supported implementation.
- 0-RTT proof is required before any 0-RTT DATAGRAM support is enabled.
- Negative tests must reject unprotected or wrong-encryption-level DATAGRAM attempts.

## Recommended Execution Order

1. Add `SPEC-QUIC-RFC9221.json` with requirements for RFC 9221 sections 3 through 6 and upstream refs to the official RFC URLs.
2. Add `ARC-QUIC-RFC9221-0001.json` defining the DATAGRAM frame model, transport-parameter state, send queue, receive delivery, congestion interaction, and 0-RTT boundary.
3. Add `WI-QUIC-RFC9221-0001.json` for the RFC 9221 transport floor, with optional application ack/loss callbacks, HTTP Datagram adapter behavior, and 0-RTT transmission kept outside the initial closure unless explicitly implemented.
4. Add `VER-QUIC-RFC9221-0001.json` with positive, negative, fuzz, and benchmark evidence requirements before touching runtime code.
5. Implement transport-parameter parse/format support.
6. Implement DATAGRAM frame parse/format support.
7. Implement receive-side validation and application delivery.
8. Implement send-side queueing, sizing, and packet assembly.
9. Integrate ACK, recovery, and congestion metadata without retransmitting DATAGRAM payloads.
10. Add public or internal API surfaces only after the runtime contract is proven.
11. Regenerate coverage/trace outputs and close the RFC 9221 gap only after linked requirements, architecture, work item, verification, tests, fuzzing, and benchmarks exist.

## Verification Commands

Use these as the minimum closure commands for the trace slice:

```powershell
pwsh -NoProfile -File scripts/Validate-SpecTraceJson.ps1 -RepoRoot . -Profiles core
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~RFC9221|Requirement=REQ-QUIC-RFC9221"
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicTransportParameters|FullyQualifiedName~QuicFrameCodec|FullyQualifiedName~Datagram"
dotnet run --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --filter "*Datagram*" --job Dry
```

If `dotnet test --project` fails with `MSB1001`, use the project path as the positional argument as shown above.

## Out Of Scope For The RFC 9221 Transport Floor

- HTTP/3 datagrams, capsules, CONNECT-UDP, and MASQUE behavior.
- Public support claims beyond the traced 1-RTT QUIC DATAGRAM transport floor.
- Application-level DATAGRAM payload multiplexing semantics.
- Optional application-facing DATAGRAM ack/loss notification callbacks unless explicitly accepted in later architecture.
- 0-RTT DATAGRAM support while the repo's early-data gate remains closed.

## Closeout Criteria

- `SPEC-QUIC-RFC9221.json` exists and all requirements have stable upstream refs.
- `ARC-QUIC-RFC9221-0001.json`, `WI-QUIC-RFC9221-0001.json`, and `VER-QUIC-RFC9221-0001.json` reciprocally link the requirement set.
- The RFC 9221 gap is closed with evidence; HTTP Datagrams, CONNECT-UDP, MASQUE, application ACK/loss callbacks, and 0-RTT DATAGRAM transmission stay separate future work.
- Requirement-home tests exist under `tests/Incursa.Quic.Tests/RequirementHomes/RFC9221/`.
- Wire-facing codec fuzz tests and benchmarks exist for DATAGRAM frame handling.
- Core SpecTrace validation passes.
- Focused RFC9221 tests pass.
- Any broader suite failures are reported separately and not used to claim RFC9221 support.
