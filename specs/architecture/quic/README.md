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
- [`ARC-QUIC-INT-0002.json`](ARC-QUIC-INT-0002.json): canonical interop endpoint-host shell design source
- [`ARC-QUIC-INT-0003.json`](ARC-QUIC-INT-0003.json): canonical interop one-stream transfer boundary design source
- [`ARC-QUIC-INT-0004.json`](ARC-QUIC-INT-0004.json): canonical interop post-handshake stream open/accept design source
- [`ARC-QUIC-INT-0005.json`](ARC-QUIC-INT-0005.json): canonical interop retry child-process contract design source
- [`ARC-QUIC-INT-0006.json`](ARC-QUIC-INT-0006.json): canonical local interop-runner execution-report helper design source
- [`ARC-QUIC-INT-0007.json`](ARC-QUIC-INT-0007.json): canonical local harness preflight planning and localhost smoke design source
- [`ARC-QUIC-INT-0008.json`](ARC-QUIC-INT-0008.json): canonical interop runner multiconnect sequential dispatch design source
- [`ARC-QUIC-RFC8999-0001.json`](ARC-QUIC-RFC8999-0001.json): canonical RFC 8999 design source
- [`ARC-QUIC-RFC9000-0001.json`](ARC-QUIC-RFC9000-0001.json): canonical RFC 9000 design source
- [`ARC-QUIC-RFC9000-0002.json`](ARC-QUIC-RFC9000-0002.json): canonical RFC 9000 migration address-validation token emission design source
- [`ARC-QUIC-RFC9000-0003.json`](ARC-QUIC-RFC9000-0003.json): canonical RFC 9000 multi-version stateless reset generation design source
- [`ARC-QUIC-RFC9000-0004.json`](ARC-QUIC-RFC9000-0004.json): canonical RFC 9000 PMTU discovery path-state design source
- [`ARC-QUIC-RFC9000-0005.json`](ARC-QUIC-RFC9000-0005.json): canonical RFC 9000 migration path probing and recovery reset design source
- [`ARC-QUIC-RFC9000-0006.json`](ARC-QUIC-RFC9000-0006.json): canonical RFC 9000 DPLPMTUD probe-tracking design source
- [`ARC-QUIC-RFC9000-0007.json`](ARC-QUIC-RFC9000-0007.json): canonical RFC 9000 STREAMS_BLOCKED runtime emission design source
- [`ARC-QUIC-RFC9000-0008.json`](ARC-QUIC-RFC9000-0008.json): canonical RFC 9000 DATA_BLOCKED runtime emission design source
- [`ARC-QUIC-RFC9000-0009.json`](ARC-QUIC-RFC9000-0009.json): canonical RFC 9000 MAX_DATA and MAX_STREAM_DATA runtime credit publication design source
- [`ARC-QUIC-RFC9000-0010.json`](ARC-QUIC-RFC9000-0010.json): canonical RFC 9000 path validation response and retry design source
- [`ARC-QUIC-RFC9000-0011.json`](ARC-QUIC-RFC9000-0011.json): canonical RFC 9000 ECN ACK count validation design source
- [`ARC-QUIC-RFC9000-0012.json`](ARC-QUIC-RFC9000-0012.json): canonical RFC 9000 ACK_ECN frame-codec design source
- [`ARC-QUIC-RFC9000-0013.json`](ARC-QUIC-RFC9000-0013.json): canonical RFC 9000 NEW_CONNECTION_ID frame-codec design source
- [`ARC-QUIC-RFC9000-0014.json`](ARC-QUIC-RFC9000-0014.json): canonical RFC 9000 connection-ID retransmission reliability design source
- [`ARC-QUIC-RFC9000-0015.json`](ARC-QUIC-RFC9000-0015.json): canonical RFC 9000 ECN-CE immediate ACK scheduling design source
- [`ARC-QUIC-RFC9000-0016.json`](ARC-QUIC-RFC9000-0016.json): canonical RFC 9000 reordering and gap immediate ACK scheduling design source
- [`ARC-QUIC-RFC9000-0017.json`](ARC-QUIC-RFC9000-0017.json): canonical RFC 9000 non-ack-eliciting ACK deferral and inclusion design source
- [`ARC-QUIC-RFC9001-0001.json`](ARC-QUIC-RFC9001-0001.json): canonical RFC 9001 design source
- [`ARC-QUIC-RFC9001-0002.json`](ARC-QUIC-RFC9001-0002.json): canonical RFC 9001 TLS KeyUpdate prohibition design source
- [`ARC-QUIC-RFC9001-0003.json`](ARC-QUIC-RFC9001-0003.json): canonical RFC 9001 1-RTT Key Update lifecycle boundary design source
- [`ARC-QUIC-RFC9001-0004.json`](ARC-QUIC-RFC9001-0004.json): canonical RFC 9001 post-stop stateless reset response matrix design source
- [`ARC-QUIC-RFC9001-0005.json`](ARC-QUIC-RFC9001-0005.json): canonical RFC 9001 stateless reset disposition matrix design source
- [`ARC-QUIC-RFC9001-0006.json`](ARC-QUIC-RFC9001-0006.json): canonical RFC 9001 repeated epoch ownership design source
- [`ARC-QUIC-RFC9001-0007.json`](ARC-QUIC-RFC9001-0007.json): canonical RFC 9001 known stateless reset loop suppression design source
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
- [`ARC-QUIC-CRT-0013.json`](ARC-QUIC-CRT-0013.json): canonical CRT server-role CertificateVerify continuation design source
- [`ARC-QUIC-CRT-0014.json`](ARC-QUIC-CRT-0014.json): canonical CRT server-role Finished continuation design source
- [`ARC-QUIC-CRT-0015.json`](ARC-QUIC-CRT-0015.json): canonical CRT server-role inbound client Finished proof design source
- [`ARC-QUIC-CRT-0017.json`](ARC-QUIC-CRT-0017.json): canonical CRT server-role 1-RTT publication design source
- [`ARC-QUIC-CRT-0018.json`](ARC-QUIC-CRT-0018.json): canonical CRT trim and Native AOT compatibility design source
- [`ARC-QUIC-CRT-0019.json`](ARC-QUIC-CRT-0019.json): canonical CRT client-role 1-RTT readiness design source
- [`ARC-QUIC-CRT-0020.json`](ARC-QUIC-CRT-0020.json): canonical CRT retry bootstrap ownership design source
- [`ARC-QUIC-CRT-0021.json`](ARC-QUIC-CRT-0021.json): canonical CRT client trust-material and peer-identity validation design source
- [`ARC-QUIC-CRT-0022.json`](ARC-QUIC-CRT-0022.json): canonical CRT server client-auth transcript/runtime prerequisite design source
- [`ARC-QUIC-API-0001.json`](ARC-QUIC-API-0001.json): canonical public API boundary design source
- [`ARC-QUIC-API-0002.json`](ARC-QUIC-API-0002.json): canonical initial stream-capacity callback design source
- [`ARC-QUIC-API-0003.json`](ARC-QUIC-API-0003.json): canonical explicit pinned identity and trust-material client-policy design source
- [`ARC-QUIC-API-0004.json`](ARC-QUIC-API-0004.json): canonical hostname-based peer identity and trust-anchor client-policy design source
- [`ARC-QUIC-API-0005.json`](ARC-QUIC-API-0005.json): canonical pending outbound stream open design source
- [`ARC-QUIC-API-0006.json`](ARC-QUIC-API-0006.json): canonical public loopback performance-comparison design source
- [`ARC-QUIC-CRT-0024.json`](ARC-QUIC-CRT-0024.json): canonical CRT server revocation callback path design source
- [`ARC-QUIC-CRT-0025.json`](ARC-QUIC-CRT-0025.json): canonical CRT resumption-ticket ownership and early-data gate design source
- [`ARC-QUIC-CRT-0026.json`](ARC-QUIC-CRT-0026.json): canonical CRT post-handshake ticket-bearing TLS update seam design source
- [`ARC-QUIC-CRT-0027.json`](ARC-QUIC-CRT-0027.json): canonical CRT client-side 1-RTT post-handshake ticket ingress design source
- [`ARC-QUIC-CRT-0028.json`](ARC-QUIC-CRT-0028.json): canonical CRT detached resumption-ticket carrier handoff design source
- [`ARC-QUIC-CRT-0029.json`](ARC-QUIC-CRT-0029.json): canonical CRT detached resumption-credential material capture design source
- [`ARC-QUIC-CRT-0030.json`](ARC-QUIC-CRT-0030.json): canonical CRT client-side ClientHello PSK-attempt design source
- [`ARC-QUIC-CRT-0031.json`](ARC-QUIC-CRT-0031.json): canonical CRT client-side ServerHello branch-point design source
- [`ARC-QUIC-CRT-0032.json`](ARC-QUIC-CRT-0032.json): canonical CRT diagnostics sink and qlog adapter boundary design source
- [`ARC-QUIC-CRT-0033.json`](ARC-QUIC-CRT-0033.json): canonical CRT client-side abbreviated resumption completion design source
- [`ARC-QUIC-CRT-0034.json`](ARC-QUIC-CRT-0034.json): canonical CRT internal early-data prerequisite capture design source
- [`ARC-QUIC-CRT-0035.json`](ARC-QUIC-CRT-0035.json): canonical CRT dormant early-data attempt readiness design source
- [`ARC-QUIC-CRT-0036.json`](ARC-QUIC-CRT-0036.json): canonical CRT client-side 0-RTT packet-emission attempt design source
- [`ARC-QUIC-CRT-0039.json`](ARC-QUIC-CRT-0039.json): canonical CRT client-side 1-RTT Key Phase observation design source
- [`ARC-QUIC-CRT-0040.json`](ARC-QUIC-CRT-0040.json): canonical CRT client-side successor 1-RTT Key Phase install design source
- [`ARC-QUIC-CRT-0041.json`](ARC-QUIC-CRT-0041.json): canonical CRT remaining-work program partition and autopilot reset design source
- [`ARC-QUIC-CRT-0042.json`](ARC-QUIC-CRT-0042.json): canonical CRT client-side replacement peer Initial reset design source
- [`ARC-QUIC-CRT-0043.json`](ARC-QUIC-CRT-0043.json): canonical CRT server-role secp256r1 HelloRetryRequest design source

## Notes

- Keep the design layer focused on satisfaction paths, invariants, and tradeoffs.
- RFC 8999 carries the shared header-invariant architecture slice.
