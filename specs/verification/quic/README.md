---
workbench:
  type: verification
  workItems: []
  codeRefs: []
  pathHistory: []
  path: /specs/verification/quic/README.md
---

# QUIC Verification

This directory holds verification artifacts for the QUIC slice.
Each canonical artifact is authored in `.json`.

## Current Artifacts

- [`VER-QUIC-RFC8999-0001.json`](VER-QUIC-RFC8999-0001.json): canonical RFC 8999 verification source
- [`VER-QUIC-RFC9000-0001.json`](VER-QUIC-RFC9000-0001.json): canonical RFC 9000 verification source
- [`VER-QUIC-RFC9001-0001.json`](VER-QUIC-RFC9001-0001.json): canonical RFC 9001 verification source
- [`VER-QUIC-RFC9002-0001.json`](VER-QUIC-RFC9002-0001.json): canonical RFC 9002 verification source

## Notes

- Keep verification artifacts homogeneous in status.
- Split artifacts when the requirements they cover do not share the same outcome.
- RFC 8999 carries the shared header-invariant verification slice.
