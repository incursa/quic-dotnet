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

- [`VER-QUIC-INT-0001.json`](VER-QUIC-INT-0001.json): canonical interop harness foundation verification source
- [`VER-QUIC-INT-0002.json`](VER-QUIC-INT-0002.json): canonical interop endpoint-host shell verification source
- [`VER-QUIC-RFC8999-0001.json`](VER-QUIC-RFC8999-0001.json): canonical RFC 8999 verification source
- [`VER-QUIC-RFC9000-0001.json`](VER-QUIC-RFC9000-0001.json): canonical RFC 9000 verification source
- [`VER-QUIC-RFC9001-0001.json`](VER-QUIC-RFC9001-0001.json): canonical RFC 9001 verification source
- [`VER-QUIC-RFC9002-0001.json`](VER-QUIC-RFC9002-0001.json): canonical RFC 9002 verification source
- [`VER-QUIC-CRT-0001.json`](VER-QUIC-CRT-0001.json): canonical CRT verification source
- [`VER-QUIC-CRT-0002.json`](VER-QUIC-CRT-0002.json): canonical CRT deadline-scheduling verification source
- [`VER-QUIC-CRT-0003.json`](VER-QUIC-CRT-0003.json): canonical CRT endpoint-ingress verification source
- [`VER-QUIC-CRT-0004.json`](VER-QUIC-CRT-0004.json): canonical CRT lifecycle and idle-timeout verification source
- [`VER-QUIC-CRT-0005.json`](VER-QUIC-CRT-0005.json): canonical CRT path-state and migration verification source
- [`VER-QUIC-CRT-0006.json`](VER-QUIC-CRT-0006.json): canonical CRT TLS-bridge, diagnostics, and sender/recovery verification source
- [`VER-QUIC-CRT-0008.json`](VER-QUIC-CRT-0008.json): canonical CRT managed TLS 1.3 handshake-crypto verification source
- [`VER-QUIC-CRT-0009.json`](VER-QUIC-CRT-0009.json): canonical CRT client certificate-acceptance policy verification source
- [`VER-QUIC-CRT-0010.json`](VER-QUIC-CRT-0010.json): canonical CRT server-role crypto-floor verification source
- [`VER-QUIC-CRT-0011.json`](VER-QUIC-CRT-0011.json): canonical CRT server-role EncryptedExtensions continuation verification source
- [`VER-QUIC-CRT-0012.json`](VER-QUIC-CRT-0012.json): canonical CRT server-role Certificate continuation verification source
- [`VER-QUIC-CRT-0013.json`](VER-QUIC-CRT-0013.json): canonical CRT server-role CertificateVerify continuation verification source
- [`VER-QUIC-CRT-0014.json`](VER-QUIC-CRT-0014.json): canonical CRT server-role Finished continuation verification source
- [`VER-QUIC-CRT-0015.json`](VER-QUIC-CRT-0015.json): canonical CRT server-role inbound client Finished proof verification source
- [`VER-QUIC-CRT-0017.json`](VER-QUIC-CRT-0017.json): canonical CRT server-role 1-RTT publication verification source
- [`VER-QUIC-CRT-0018.json`](VER-QUIC-CRT-0018.json): canonical CRT trim and Native AOT compatibility verification source
- [`VER-QUIC-CRT-0019.json`](VER-QUIC-CRT-0019.json): canonical CRT client-role 1-RTT readiness verification source
- [`VER-QUIC-API-0001.json`](VER-QUIC-API-0001.json): canonical public API surface verification source
- [`VER-QUIC-API-0002.json`](VER-QUIC-API-0002.json): canonical initial stream-capacity callback verification source

## Notes

- Keep verification artifacts homogeneous in status.
- Split artifacts when the requirements they cover do not share the same outcome.
- RFC 8999 carries the shared header-invariant verification slice.
