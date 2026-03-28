# QUIC Requirement Gaps

Use this file to record missing, ambiguous, or blocked QUIC requirements before implementation starts.

## How To Use This File

1. Record the RFC or source reference.
2. State the ambiguity or missing behavior directly.
3. Name the impacted future `SPEC-...` file if it is known.
4. Keep the gap open until the canonical requirement text exists.

## Open Gaps

- None for this slice.

## Resolved Gaps

- Source: RFC 8999 short-header packet form
  Gap: RFC 8999 says a short-header packet carries a destination connection ID immediately after the first byte, but it does not encode the destination connection ID length, so a generic parser cannot infer a unique byte boundary without version-specific context.
  Needed decision: Decide whether the version-independent short-header model will preserve the post-first-byte bytes as an opaque remainder, require version-specific parsing hooks, or use another deterministic boundary rule.
  Affected spec slice: [`SPEC-QUIC-HDR`](./SPEC-QUIC-HDR.md)
  Resolution: Preserve the bytes after the first byte as an opaque remainder in `QuicShortHeaderPacket`; defer version-specific boundary handling to later parsing layers.

- Source: RFC 9000 Sections 12.3 through 12.5 and 19.8
  Gap: Those sections describe packet-number-space lifecycle, packet-number reuse, duplicate suppression, frame-policy markings, and stream-frame internals that require connection-state context beyond the byte-oriented packet/frame container slice.
  Needed decision: Defer those semantics to later stateful packet-processing and stream-frame specs rather than fold them into the current packet/frame container slice.
  Affected spec slice: [`SPEC-QUIC-PKT-FRM`](./SPEC-QUIC-PKT-FRM.md)
  Resolution: The current packet/frame slice stops at packet delimitation, coalesced packet preservation, and generic frame-container validation.

- Source: RFC 9000 Sections 2.1 and 19.8 stream-management semantics
  Gap: Stream identifier reuse, out-of-order stream opening, `STREAM_STATE_ERROR` handling, and flow-control enforcement depend on connection state and stream accounting that are beyond the byte-oriented parser slice.
  Needed decision: Defer those behaviors to a later stateful stream-management specification rather than fold them into the current stream-identifier and STREAM-frame parsing slice.
  Affected spec slice: [`SPEC-QUIC-STRM`](./SPEC-QUIC-STRM.md)
  Resolution: The current stream slice covers stream identifier classification and STREAM frame byte shape only.
