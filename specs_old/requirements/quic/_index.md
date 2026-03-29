# QUIC Requirements

This folder holds the canonical QUIC requirement slices for the repository.

## Current Artifacts

- [`SPEC-QUIC-HDR.md`](./SPEC-QUIC-HDR.md): version-independent packet header parsing and validation
- [`SPEC-QUIC-PKT-PROT.md`](./SPEC-QUIC-PKT-PROT.md): packet forms and the Section 12 protection overview
- [`SPEC-QUIC-PKT-NUM.md`](./SPEC-QUIC-PKT-NUM.md): packet numbers, packet-number spaces, and duplicate-suppression rules
- [`SPEC-QUIC-PKT-FRM.md`](./SPEC-QUIC-PKT-FRM.md): datagram coalescing, generic frame containers, and frame-placement rules
- [`SPEC-QUIC-VINT.md`](./SPEC-QUIC-VINT.md): QUIC variable-length integer decoding
- [`SPEC-QUIC-STRM.md`](./SPEC-QUIC-STRM.md): stream identifiers and STREAM frame parsing
- [`REQUIREMENT-GAPS.md`](./REQUIREMENT-GAPS.md): open questions and ambiguous QUIC behaviors

Start with [`REQUIREMENT-GAPS.md`](./REQUIREMENT-GAPS.md) when a behavior is missing or still ambiguous.
