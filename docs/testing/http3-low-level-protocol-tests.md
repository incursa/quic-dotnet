# Low-Level HTTP/3 Protocol Tests

This document tracks malformed HTTP/3 sequences that normal clients do not emit. The automated checks live in `Http3LowLevelProtocolTests` and use a custom test client over the HTTP/3 frame, stream-dispatch, QPACK, and header-validation seams.

These tests are conformance/triage evidence. They do not by themselves prove complete RFC 9114 or RFC 9204 support.

Case identifiers used by the automated custom client:

- `DATA before HEADERS`
- `Two SETTINGS frames`
- `SETTINGS on request stream`
- `HEADERS on control stream`
- `Invalid frame length`
- `Unknown frame type`
- `Reserved frame type`
- `Malformed pseudo-header order`
- `Uppercase header field name`
- `Invalid content-length`
- `Server-initiated bidirectional stream`
- `Duplicate control streams`
- `Client-sent PUSH_PROMISE`
- `Unadvertised PUSH_PROMISE`

## h3i Examples

`h3i` is useful when a live peer must receive intentionally malformed HTTP/3 traffic. The h3i crate exposes an action model that can send HTTP/3 frames on arbitrary streams in arbitrary order, including illegal sequences. Some cases are easier to express with h3i library actions than as a one-line CLI command.

Practical h3i-style examples:

```text
# Invalid content-length: send HEADERS with content-length: 5, then DATA with 4 bytes.
# h3i library action shape:
# - Action::SendHeadersFrame { stream_id: 0, headers: [":method", ":scheme", ":authority", ":path", "content-length: 5"] }
# - Action::SendFrame { stream_id: 0, frame: DATA("test"), fin_stream: true }
# - Action::Wait for response HEADERS or connection close
```

```text
# DATA before HEADERS:
# - Action::SendFrame { stream_id: 0, frame: DATA("x"), fin_stream: false }
# - Expect H3_FRAME_UNEXPECTED connection close.
```

```text
# HEADERS on control stream:
# - Open client-initiated unidirectional stream.
# - Write stream type 0x00 (control stream).
# - Send SETTINGS.
# - Send HEADERS.
# - Expect H3_FRAME_UNEXPECTED connection close.
```

```text
# Duplicate control stream:
# - Open client-initiated unidirectional stream with stream type 0x00.
# - Open a second client-initiated unidirectional stream with stream type 0x00.
# - Expect H3_STREAM_CREATION_ERROR connection close.
```

The repo-local custom tests cover the same expected outcomes without depending on h3i installation or live QUIC scheduling.

## Expected Outcomes

| Case | RFC section | Expected outcome | Automated test |
| --- | --- | --- | --- |
| Send DATA before HEADERS | RFC 9114 Sections 4.1, 8.1 | `H3_FRAME_UNEXPECTED` | `LowLevelMalformedSequencesProduceExpectedOutcomes` |
| Send two SETTINGS frames | RFC 9114 Section 7.2.4 | `H3_FRAME_UNEXPECTED` | `LowLevelMalformedSequencesProduceExpectedOutcomes` |
| Send SETTINGS on a request stream | RFC 9114 Sections 6.1, 7.2.4 | `H3_FRAME_UNEXPECTED` | `LowLevelMalformedSequencesProduceExpectedOutcomes` |
| Send HEADERS on a control stream | RFC 9114 Sections 6.2.1, 7.2.2 | `H3_FRAME_UNEXPECTED` | `LowLevelMalformedSequencesProduceExpectedOutcomes` |
| Send invalid frame length | RFC 9114 Section 7.1 | `H3_FRAME_ERROR` | `LowLevelMalformedSequencesProduceExpectedOutcomes` |
| Send unknown frame types | RFC 9114 Section 9 | Ignored / no HTTP/3 error | `LowLevelMalformedSequencesProduceExpectedOutcomes` |
| Send reserved frame types | RFC 9114 Sections 7.2.8, 9 | Ignored / no HTTP/3 error | `LowLevelMalformedSequencesProduceExpectedOutcomes` |
| Send malformed pseudo-header order | RFC 9114 Sections 4.1.2, 4.3 | `H3_MESSAGE_ERROR` | `LowLevelMalformedSequencesProduceExpectedOutcomes` |
| Send uppercase header field names | RFC 9114 Sections 4.1.2, 4.2 | `H3_MESSAGE_ERROR` | `LowLevelMalformedSequencesProduceExpectedOutcomes` |
| Send invalid content-length | RFC 9114 Section 4.1.2 | `H3_MESSAGE_ERROR` | `LowLevelMalformedSequencesProduceExpectedOutcomes` |
| Open a server-initiated bidirectional stream | RFC 9114 Section 6.1 | `H3_STREAM_CREATION_ERROR` | `LowLevelMalformedSequencesProduceExpectedOutcomes` |
| Open duplicate control streams | RFC 9114 Section 6.2.1 | `H3_STREAM_CREATION_ERROR` | `LowLevelMalformedSequencesProduceExpectedOutcomes` |
| Send client-to-server PUSH_PROMISE | RFC 9114 Section 7.2.5 | `H3_FRAME_UNEXPECTED` | `LowLevelMalformedSequencesProduceExpectedOutcomes` |
| Receive PUSH_PROMISE before client MAX_PUSH_ID opt-in | RFC 9114 Sections 4.6, 7.2.5, 7.2.7 | `H3_ID_ERROR` | `LowLevelMalformedSequencesProduceExpectedOutcomes` |

## Follow-Up

- Promote any live h3i regression into an RFC 9114 or RFC 9204 protocol-owned requirement before changing support claims.
- Keep unknown and reserved frame handling explicit so greasing behavior is not accidentally converted into a protocol error.
