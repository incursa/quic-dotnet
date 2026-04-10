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

- [`ARC-QUIC-INT-0001.json`](ARC-QUIC-INT-0001.json): canonical interop harness boundary design source
- [`ARC-QUIC-RFC8999-0001.json`](ARC-QUIC-RFC8999-0001.json): canonical RFC 8999 design source
- [`ARC-QUIC-RFC9000-0001.json`](ARC-QUIC-RFC9000-0001.json): canonical RFC 9000 design source
- [`ARC-QUIC-RFC9001-0001.json`](ARC-QUIC-RFC9001-0001.json): canonical RFC 9001 design source
- [`ARC-QUIC-RFC9002-0001.json`](ARC-QUIC-RFC9002-0001.json): canonical RFC 9002 design source
- [`ARC-QUIC-CRT-0001.json`](ARC-QUIC-CRT-0001.json): canonical CRT design source
- [`ARC-QUIC-CRT-0002.json`](ARC-QUIC-CRT-0002.json): canonical CRT deadline-scheduling design source
- [`ARC-QUIC-CRT-0003.json`](ARC-QUIC-CRT-0003.json): canonical CRT endpoint-ingress design source
- [`ARC-QUIC-CRT-0004.json`](ARC-QUIC-CRT-0004.json): canonical CRT lifecycle and idle-timeout design source
- [`ARC-QUIC-CRT-0005.json`](ARC-QUIC-CRT-0005.json): canonical CRT path-state and migration design source
- [`ARC-QUIC-CRT-0006.json`](ARC-QUIC-CRT-0006.json): canonical CRT TLS-bridge, diagnostics, and sender/recovery design source
- [`ARC-QUIC-CRT-0008.json`](ARC-QUIC-CRT-0008.json): canonical CRT managed TLS 1.3 handshake-crypto design source
- [`ARC-QUIC-CRT-0009.json`](ARC-QUIC-CRT-0009.json): canonical CRT client certificate-acceptance policy design source
- [`ARC-QUIC-CRT-0010.json`](ARC-QUIC-CRT-0010.json): canonical CRT server-role crypto-floor design source
- [`ARC-QUIC-CRT-0011.json`](ARC-QUIC-CRT-0011.json): canonical CRT server-role EncryptedExtensions continuation design source
- [`ARC-QUIC-CRT-0012.json`](ARC-QUIC-CRT-0012.json): canonical CRT server-role Certificate continuation design source
- [`ARC-QUIC-INT-0001.json`](ARC-QUIC-INT-0001.json): canonical interop-harness adapter design source

## Notes

- Keep the design layer focused on satisfaction paths, invariants, and tradeoffs.
- RFC 8999 carries the shared header-invariant architecture slice.
