# QUIC Requirement Gaps

Use this file to record missing, ambiguous, or blocked QUIC requirements before implementation starts.

## How To Use This File

1. Record the RFC or source reference.
2. State the ambiguity or missing behavior directly.
3. Name the impacted future `SPEC-...` file if it is known.
4. Keep the gap open until the canonical requirement text exists.

## Open Gaps

- Source: RFC 9000 Sections 12.2, 12.3, and 17.1 through 17.3
  Gap: Section 12 says which packet forms carry a Length field, when packet numbers are present, and which packet forms are terminal inside a datagram, but the concrete byte locations and reduced encodings for Length and Packet Number fields depend on the packet-format sections in Section 17.
  Needed decision: Capture the Section 17 packet-format requirements before implementing full coalesced-datagram slicing or packet-number decoding beyond version-independent header recognition.
  Affected spec slices: [`SPEC-QUIC-PKT-FRM`](./SPEC-QUIC-PKT-FRM.md), [`SPEC-QUIC-PKT-NUM`](./SPEC-QUIC-PKT-NUM.md)

- Source: RFC 9000 Section 12.1 with RFC 9001
  Gap: Section 12.1 provides only the packet-protection overview. The concrete key schedule, AEAD inputs, header-protection removal, and authentication rules still belong to QUIC-TLS and have not yet been turned into canonical repository requirements.
  Needed decision: Add a later QUIC-TLS-backed packet-protection specification before implementing cryptographic packet protection or unprotection.
  Affected spec slice: [`SPEC-QUIC-PKT-PROT`](./SPEC-QUIC-PKT-PROT.md)

- Source: RFC 9000 Section 12.4 Table 3 and Section 19
  Gap: Section 12 now captures the generic frame-container rules and packet-placement rules, but the concrete body semantics for non-STREAM frames still need dedicated frame-specific requirement slices.
  Needed decision: Add Section 19 requirement slices one frame family at a time before implementing body parsing for ACK, CRYPTO, CONNECTION_CLOSE, and the remaining frame types.
  Affected spec slices: [`SPEC-QUIC-PKT-FRM`](./SPEC-QUIC-PKT-FRM.md), future `SPEC-QUIC-FRM-*` artifacts

## Resolved Gaps

- Source: RFC 8999 short-header packet form
  Gap: RFC 8999 says a short-header packet carries a destination connection ID immediately after the first byte, but it does not encode the destination connection ID length, so a generic parser cannot infer a unique byte boundary without version-specific context.
  Needed decision: Decide whether the version-independent short-header model will preserve the post-first-byte bytes as an opaque remainder, require version-specific parsing hooks, or use another deterministic boundary rule.
  Affected spec slice: [`SPEC-QUIC-HDR`](./SPEC-QUIC-HDR.md)
  Resolution: Preserve the bytes after the first byte as an opaque remainder in `QuicShortHeaderPacket`; defer version-specific boundary handling to later parsing layers.

- Source: RFC 9000 Sections 2.1 and 19.8 stream-management semantics
  Gap: Stream identifier reuse, out-of-order stream opening, `STREAM_STATE_ERROR` handling, and flow-control enforcement depend on connection state and stream accounting that are beyond the byte-oriented parser slice.
  Needed decision: Defer those behaviors to a later stateful stream-management specification rather than fold them into the current stream-identifier and STREAM-frame parsing slice.
  Affected spec slice: [`SPEC-QUIC-STRM`](./SPEC-QUIC-STRM.md)
  Resolution: The current stream slice covers stream identifier classification and STREAM frame byte shape only.
