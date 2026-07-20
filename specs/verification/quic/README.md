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
- [`VER-QUIC-CRT-0001.json`](VER-QUIC-CRT-0001.json): canonical CRT verification source
- [`VER-QUIC-CRT-0002.json`](VER-QUIC-CRT-0002.json): canonical CRT deadline-scheduling verification source
- [`VER-QUIC-CRT-0003.json`](VER-QUIC-CRT-0003.json): canonical CRT endpoint-ingress verification source
- [`VER-QUIC-CRT-0004.json`](VER-QUIC-CRT-0004.json): canonical CRT lifecycle and idle-timeout verification source

## Notes

- Keep verification artifacts homogeneous in status.
- Split artifacts when the requirements they cover do not share the same outcome.
- RFC 8999 carries the shared header-invariant verification slice.
