---
workbench:
  type: specification
  workItems: []
  codeRefs: []
  pathHistory: []
  path: /specs/requirements/quic/README.md
---

# QUIC Requirements

This directory holds the QUIC requirement slice for the repository.
Each canonical artifact is authored in `.json`.

## Current Artifacts

- [`SPEC-QUIC-RFC8999.json`](SPEC-QUIC-RFC8999.json): canonical RFC 8999 invariants source
- [`SPEC-QUIC-RFC9000.json`](SPEC-QUIC-RFC9000.json): canonical RFC 9000 transport source
- [`SPEC-QUIC-RFC9001.json`](SPEC-QUIC-RFC9001.json): canonical RFC 9001 TLS source
- [`SPEC-QUIC-RFC9002.json`](SPEC-QUIC-RFC9002.json): canonical RFC 9002 recovery source
- [`REQUIREMENT-GAPS.md`](REQUIREMENT-GAPS.md): the local gap ledger

## Notes

- Keep new QUIC work traceable to a stable `SPEC-...` file before implementation.
- Use the gap ledger when a source rule is unclear or needs an explicit decision record.
- RFC 8999 now carries the shared header-invariant slice.
