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
- [`VER-QUIC-INT-0003.json`](VER-QUIC-INT-0003.json): canonical interop one-stream transfer boundary verification source
- [`VER-QUIC-INT-0004.json`](VER-QUIC-INT-0004.json): canonical interop post-handshake stream open/accept verification source
- [`VER-QUIC-INT-0005.json`](VER-QUIC-INT-0005.json): canonical interop retry child-process verification source
- [`VER-QUIC-INT-0006.json`](VER-QUIC-INT-0006.json): canonical local interop-runner execution-report helper verification source
- [`VER-QUIC-INT-0007.json`](VER-QUIC-INT-0007.json): canonical local harness preflight planning and localhost smoke verification source
- [`VER-QUIC-INT-0008.json`](VER-QUIC-INT-0008.json): canonical interop runner multiconnect sequential dispatch verification source
- [`VER-QUIC-RFC8999-0001.json`](VER-QUIC-RFC8999-0001.json): canonical RFC 8999 verification source
- [`VER-QUIC-RFC9000-0001.json`](VER-QUIC-RFC9000-0001.json): canonical RFC 9000 verification source
- [`VER-QUIC-RFC9000-0002.json`](VER-QUIC-RFC9000-0002.json): canonical RFC 9000 migration address-validation token emission verification source
- [`VER-QUIC-RFC9000-0003.json`](VER-QUIC-RFC9000-0003.json): canonical RFC 9000 multi-version stateless reset generation verification source
- [`VER-QUIC-RFC9000-0004.json`](VER-QUIC-RFC9000-0004.json): canonical RFC 9000 PMTU discovery path-state verification source
- [`VER-QUIC-RFC9000-0005.json`](VER-QUIC-RFC9000-0005.json): canonical RFC 9000 migration path probing and recovery reset verification source
- [`VER-QUIC-RFC9000-0006.json`](VER-QUIC-RFC9000-0006.json): canonical RFC 9000 DPLPMTUD probe-tracking verification source
- [`VER-QUIC-RFC9000-0007.json`](VER-QUIC-RFC9000-0007.json): canonical RFC 9000 STREAMS_BLOCKED runtime emission verification source
- [`VER-QUIC-RFC9001-0001.json`](VER-QUIC-RFC9001-0001.json): canonical RFC 9001 verification source
- [`VER-QUIC-RFC9001-0002.json`](VER-QUIC-RFC9001-0002.json): canonical RFC 9001 TLS KeyUpdate prohibition verification source
- [`VER-QUIC-RFC9001-0003.json`](VER-QUIC-RFC9001-0003.json): canonical RFC 9001 1-RTT Key Update lifecycle verification source
- [`VER-QUIC-RFC9001-0004.json`](VER-QUIC-RFC9001-0004.json): canonical RFC 9001 post-stop stateless reset response matrix verification source
- [`VER-QUIC-RFC9001-0005.json`](VER-QUIC-RFC9001-0005.json): canonical RFC 9001 stateless reset disposition matrix verification source
- [`VER-QUIC-RFC9001-0006.json`](VER-QUIC-RFC9001-0006.json): canonical RFC 9001 repeated epoch ownership verification source
- [`VER-QUIC-RFC9001-0007.json`](VER-QUIC-RFC9001-0007.json): canonical RFC 9001 known stateless reset loop suppression verification source
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
- [`VER-QUIC-CRT-0020.json`](VER-QUIC-CRT-0020.json): canonical CRT retry bootstrap verification source
- [`VER-QUIC-CRT-0021.json`](VER-QUIC-CRT-0021.json): canonical CRT client trust-material and peer-identity validation verification source
- [`VER-QUIC-CRT-0022.json`](VER-QUIC-CRT-0022.json): canonical CRT server client-auth transcript/runtime prerequisite verification source
- [`VER-QUIC-CRT-0024.json`](VER-QUIC-CRT-0024.json): canonical CRT server revocation callback path verification source
- [`VER-QUIC-API-0001.json`](VER-QUIC-API-0001.json): canonical public API surface verification source
- [`VER-QUIC-API-0002.json`](VER-QUIC-API-0002.json): canonical initial stream-capacity callback verification source
- [`VER-QUIC-API-0003.json`](VER-QUIC-API-0003.json): canonical explicit pinned identity and trust-material client-policy verification source
- [`VER-QUIC-API-0004.json`](VER-QUIC-API-0004.json): canonical hostname-based peer identity and trust-anchor verification source
- [`VER-QUIC-API-0005.json`](VER-QUIC-API-0005.json): canonical pending outbound stream open verification source
- [`VER-QUIC-API-0006.json`](VER-QUIC-API-0006.json): canonical public loopback performance-comparison verification source
- [`VER-QUIC-CRT-0025.json`](VER-QUIC-CRT-0025.json): canonical CRT resumption-ticket ownership and early-data gate verification source
- [`VER-QUIC-CRT-0026.json`](VER-QUIC-CRT-0026.json): canonical CRT post-handshake ticket-bearing TLS update seam verification source
- [`VER-QUIC-CRT-0027.json`](VER-QUIC-CRT-0027.json): canonical CRT client-side 1-RTT post-handshake ticket ingress verification source
- [`VER-QUIC-CRT-0028.json`](VER-QUIC-CRT-0028.json): canonical CRT detached resumption-ticket carrier handoff verification source
- [`VER-QUIC-CRT-0029.json`](VER-QUIC-CRT-0029.json): canonical CRT detached resumption-credential material capture verification source
- [`VER-QUIC-CRT-0030.json`](VER-QUIC-CRT-0030.json): canonical CRT client-side ClientHello PSK-attempt verification source
- [`VER-QUIC-CRT-0031.json`](VER-QUIC-CRT-0031.json): canonical CRT client-side ServerHello branch-point verification source
- [`VER-QUIC-CRT-0032.json`](VER-QUIC-CRT-0032.json): canonical CRT core diagnostics sink and per-connection resolution verification source
- [`VER-QUIC-CRT-0033.json`](VER-QUIC-CRT-0033.json): canonical CRT qlog adapter package boundary verification source
- [`VER-QUIC-CRT-0034.json`](VER-QUIC-CRT-0034.json): canonical CRT client-side abbreviated resumption completion verification source
- [`VER-QUIC-CRT-0035.json`](VER-QUIC-CRT-0035.json): canonical CRT host-facing qlog capture and serialization verification source
- [`VER-QUIC-CRT-0036.json`](VER-QUIC-CRT-0036.json): canonical CRT internal early-data prerequisite capture verification source
- [`VER-QUIC-CRT-0037.json`](VER-QUIC-CRT-0037.json): canonical CRT dormant early-data attempt readiness verification source
- [`VER-QUIC-CRT-0038.json`](VER-QUIC-CRT-0038.json): canonical CRT first client-side 0-RTT packet-emission attempt verification source
- [`VER-QUIC-CRT-0039.json`](VER-QUIC-CRT-0039.json): canonical CRT client-side 0-RTT rejection cleanup verification source
- [`VER-QUIC-CRT-0040.json`](VER-QUIC-CRT-0040.json): canonical CRT client-side peer early-data disposition verification source
- [`VER-QUIC-CRT-0041.json`](VER-QUIC-CRT-0041.json): canonical CRT client-side 1-RTT Key Phase observation verification source
- [`VER-QUIC-CRT-0042.json`](VER-QUIC-CRT-0042.json): canonical CRT client-side successor 1-RTT Key Phase install verification source
- [`VER-QUIC-CRT-0043.json`](VER-QUIC-CRT-0043.json): canonical CRT remaining-work program partition and autopilot reset verification source
- [`VER-QUIC-CRT-0044.json`](VER-QUIC-CRT-0044.json): canonical CRT client-side replacement peer Initial reset verification source
- [`VER-QUIC-CRT-0045.json`](VER-QUIC-CRT-0045.json): canonical CRT server-role secp256r1 HelloRetryRequest verification source

## Notes

- Keep verification artifacts homogeneous in status.
- Split artifacts when the requirements they cover do not share the same outcome.
- RFC 8999 carries the shared header-invariant verification slice.
