# QUIC Requirements

This directory holds the QUIC requirement slice for the repository.

## Current Artifacts

- [`SPEC-QUIC-RFC8999.md`](SPEC-QUIC-RFC8999.md): version-independent packet invariants
- [`SPEC-QUIC-RFC9000.md`](SPEC-QUIC-RFC9000.md): QUIC transport requirements
- [`SPEC-QUIC-RFC9001.md`](SPEC-QUIC-RFC9001.md): QUIC TLS and packet-protection requirements
- [`SPEC-QUIC-RFC9002.md`](SPEC-QUIC-RFC9002.md): QUIC loss-detection and congestion-control requirements
- [`SPEC-QUIC-HDR.md`](SPEC-QUIC-HDR.md): the current header-parsing slice
- [`REQUIREMENT-GAPS.md`](REQUIREMENT-GAPS.md): the local gap ledger

## Notes

- Keep new QUIC work traceable to a stable `SPEC-...` file before implementation.
- Use the gap ledger when a source rule is unclear or needs an explicit decision record.
