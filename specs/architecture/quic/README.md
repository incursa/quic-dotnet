---
workbench:
  type: architecture
  workItems: []
  codeRefs: []
  pathHistory: []
  path: /specs/architecture/quic/README.md
---

# QUIC Architecture

This directory holds design artifacts for the QUIC slice.
Each canonical artifact is authored in `.json`.

## Current Artifacts

- [`ARC-QUIC-RFC8999-0001.json`](ARC-QUIC-RFC8999-0001.json): canonical RFC 8999 design source
- [`ARC-QUIC-RFC9000-0001.json`](ARC-QUIC-RFC9000-0001.json): canonical RFC 9000 design source
- [`ARC-QUIC-RFC9001-0001.json`](ARC-QUIC-RFC9001-0001.json): canonical RFC 9001 design source
- [`ARC-QUIC-RFC9002-0001.json`](ARC-QUIC-RFC9002-0001.json): canonical RFC 9002 design source
- [`ARC-QUIC-CRT-0001.json`](ARC-QUIC-CRT-0001.json): canonical CRT design source
- [`ARC-QUIC-CRT-0002.json`](ARC-QUIC-CRT-0002.json): canonical CRT deadline-scheduling design source
- [`ARC-QUIC-CRT-0002.json`](ARC-QUIC-CRT-0002.json): canonical CRT deadline-scheduler design source

## Notes

- Keep the design layer focused on satisfaction paths, invariants, and tradeoffs.
- RFC 8999 carries the shared header-invariant architecture slice.
