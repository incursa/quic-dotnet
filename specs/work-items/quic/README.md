# QUIC Work Items

This directory holds QUIC implementation work items.
Each canonical artifact is authored in `.json`.

## Current Artifacts

- [`WI-QUIC-INT-0001.json`](WI-QUIC-INT-0001.json): canonical interop harness foundation work item
- [`WI-QUIC-INT-0002.json`](WI-QUIC-INT-0002.json): canonical interop endpoint-host shell work item
- [`WI-QUIC-INT-0003.json`](WI-QUIC-INT-0003.json): canonical interop one-stream transfer boundary work item
- [`WI-QUIC-INT-0004.json`](WI-QUIC-INT-0004.json): canonical interop post-handshake stream open/accept work item
- [`WI-QUIC-INT-0005.json`](WI-QUIC-INT-0005.json): canonical interop retry child-process work item
- [`WI-QUIC-INT-0006.json`](WI-QUIC-INT-0006.json): canonical local interop-runner execution-report helper work item
- [`WI-QUIC-INT-0007.json`](WI-QUIC-INT-0007.json): canonical local harness preflight planning and localhost smoke work item
- [`WI-QUIC-INT-0008.json`](WI-QUIC-INT-0008.json): canonical interop runner multiconnect sequential dispatch work item
- [`WI-QUIC-RFC8999-0001.json`](WI-QUIC-RFC8999-0001.json): canonical RFC 8999 work-item source
- [`WI-QUIC-RFC9000-0001.json`](WI-QUIC-RFC9000-0001.json): canonical RFC 9000 work-item source
- [`WI-QUIC-RFC9000-0002.json`](WI-QUIC-RFC9000-0002.json): canonical RFC 9000 migration address-validation token emission work-item source
- [`WI-QUIC-RFC9000-0003.json`](WI-QUIC-RFC9000-0003.json): canonical RFC 9000 multi-version stateless reset generation work-item source
- [`WI-QUIC-RFC9000-0004.json`](WI-QUIC-RFC9000-0004.json): canonical RFC 9000 PMTU discovery path-state work-item source
- [`WI-QUIC-RFC9000-0005.json`](WI-QUIC-RFC9000-0005.json): canonical RFC 9000 migration path probing and recovery reset work-item source
- [`WI-QUIC-RFC9000-0006.json`](WI-QUIC-RFC9000-0006.json): canonical RFC 9000 DPLPMTUD probe-tracking work-item source
- [`WI-QUIC-RFC9000-0007.json`](WI-QUIC-RFC9000-0007.json): canonical RFC 9000 STREAMS_BLOCKED runtime emission work-item source
- [`WI-QUIC-RFC9001-0001.json`](WI-QUIC-RFC9001-0001.json): canonical RFC 9001 work-item source
- [`WI-QUIC-RFC9001-0002.json`](WI-QUIC-RFC9001-0002.json): canonical RFC 9001 TLS KeyUpdate prohibition work-item source
- [`WI-QUIC-RFC9001-0003.json`](WI-QUIC-RFC9001-0003.json): canonical RFC 9001 1-RTT Key Update lifecycle work-item source
- [`WI-QUIC-RFC9001-0004.json`](WI-QUIC-RFC9001-0004.json): canonical RFC 9001 post-stop stateless reset response matrix work-item source
- [`WI-QUIC-RFC9002-0001.json`](WI-QUIC-RFC9002-0001.json): canonical RFC 9002 work-item source
- [`WI-QUIC-CRT-0002.json`](WI-QUIC-CRT-0002.json): canonical CRT deadline-scheduling work item
- [`WI-QUIC-CRT-0003.json`](WI-QUIC-CRT-0003.json): canonical CRT endpoint-ingress work item
- [`WI-QUIC-CRT-0004.json`](WI-QUIC-CRT-0004.json): canonical CRT lifecycle and idle-timeout work item
- [`WI-QUIC-CRT-0005.json`](WI-QUIC-CRT-0005.json): canonical CRT path-state and migration work item
- [`WI-QUIC-CRT-0006.json`](WI-QUIC-CRT-0006.json): canonical CRT TLS-bridge, diagnostics, and sender/recovery work item
- [`WI-QUIC-CRT-0008.json`](WI-QUIC-CRT-0008.json): canonical CRT managed TLS 1.3 handshake-crypto work item
- [`WI-QUIC-CRT-0009.json`](WI-QUIC-CRT-0009.json): canonical CRT client certificate-acceptance policy work item
- [`WI-QUIC-CRT-0010.json`](WI-QUIC-CRT-0010.json): canonical CRT server-role crypto-floor work item
- [`WI-QUIC-CRT-0011.json`](WI-QUIC-CRT-0011.json): canonical CRT server-role EncryptedExtensions continuation work item
- [`WI-QUIC-CRT-0012.json`](WI-QUIC-CRT-0012.json): canonical CRT server-role Certificate continuation work item
- [`WI-QUIC-CRT-0013.json`](WI-QUIC-CRT-0013.json): canonical CRT server-role CertificateVerify continuation work item
- [`WI-QUIC-CRT-0014.json`](WI-QUIC-CRT-0014.json): canonical CRT server-role Finished continuation work item
- [`WI-QUIC-CRT-0015.json`](WI-QUIC-CRT-0015.json): canonical CRT server-role inbound client Finished proof work item
- [`WI-QUIC-CRT-0017.json`](WI-QUIC-CRT-0017.json): canonical CRT server-role 1-RTT publication work item
- [`WI-QUIC-CRT-0018.json`](WI-QUIC-CRT-0018.json): canonical CRT trim and Native AOT compatibility work item
- [`WI-QUIC-CRT-0019.json`](WI-QUIC-CRT-0019.json): canonical CRT client-role 1-RTT readiness work item
- [`WI-QUIC-CRT-0020.json`](WI-QUIC-CRT-0020.json): canonical CRT retry bootstrap ownership work item
- [`WI-QUIC-CRT-0021.json`](WI-QUIC-CRT-0021.json): canonical CRT client trust-material and peer-identity validation work item
- [`WI-QUIC-CRT-0022.json`](WI-QUIC-CRT-0022.json): canonical CRT server client-auth transcript/runtime prerequisite work item
- [`WI-QUIC-API-0001.json`](WI-QUIC-API-0001.json): canonical public API surface promotion work item
- [`WI-QUIC-API-0002.json`](WI-QUIC-API-0002.json): canonical initial stream-capacity callback work item
- [`WI-QUIC-API-0003.json`](WI-QUIC-API-0003.json): canonical explicit pinned identity and trust-material client-policy work item
- [`WI-QUIC-API-0004.json`](WI-QUIC-API-0004.json): canonical hostname-based peer identity and trust-anchor work item
- [`WI-QUIC-API-0005.json`](WI-QUIC-API-0005.json): canonical pending outbound stream open work item
- [`WI-QUIC-API-0006.json`](WI-QUIC-API-0006.json): canonical public loopback performance-comparison work item
- [`WI-QUIC-CRT-0024.json`](WI-QUIC-CRT-0024.json): canonical CRT server revocation callback path work item
- [`WI-QUIC-CRT-0025.json`](WI-QUIC-CRT-0025.json): canonical CRT resumption-ticket ownership and early-data gate work item
- [`WI-QUIC-CRT-0026.json`](WI-QUIC-CRT-0026.json): canonical CRT post-handshake ticket-bearing TLS update seam work item
- [`WI-QUIC-CRT-0027.json`](WI-QUIC-CRT-0027.json): canonical CRT client-side 1-RTT post-handshake ticket ingress work item
- [`WI-QUIC-CRT-0028.json`](WI-QUIC-CRT-0028.json): canonical CRT detached resumption-ticket carrier handoff work item
- [`WI-QUIC-CRT-0029.json`](WI-QUIC-CRT-0029.json): canonical CRT detached resumption-credential material capture work item
- [`WI-QUIC-CRT-0030.json`](WI-QUIC-CRT-0030.json): canonical CRT client-side ClientHello PSK-attempt work item
- [`WI-QUIC-CRT-0031.json`](WI-QUIC-CRT-0031.json): canonical CRT client-side ServerHello branch-point work item
- [`WI-QUIC-CRT-0032.json`](WI-QUIC-CRT-0032.json): canonical CRT core diagnostics sink and per-connection resolution work item
- [`WI-QUIC-CRT-0033.json`](WI-QUIC-CRT-0033.json): canonical CRT qlog adapter package boundary work item
- [`WI-QUIC-CRT-0034.json`](WI-QUIC-CRT-0034.json): canonical CRT client-side abbreviated resumption completion work item
- [`WI-QUIC-CRT-0035.json`](WI-QUIC-CRT-0035.json): canonical CRT host-facing qlog capture and serialization work item
- [`WI-QUIC-CRT-0036.json`](WI-QUIC-CRT-0036.json): canonical CRT internal early-data prerequisite capture work item
- [`WI-QUIC-CRT-0037.json`](WI-QUIC-CRT-0037.json): canonical CRT dormant early-data attempt readiness work item
- [`WI-QUIC-CRT-0038.json`](WI-QUIC-CRT-0038.json): canonical CRT first client-side 0-RTT packet-emission attempt work item
- [`WI-QUIC-CRT-0039.json`](WI-QUIC-CRT-0039.json): canonical CRT client-side 0-RTT rejection cleanup work item
- [`WI-QUIC-CRT-0040.json`](WI-QUIC-CRT-0040.json): canonical CRT client-side peer early-data disposition work item
- [`WI-QUIC-CRT-0041.json`](WI-QUIC-CRT-0041.json): canonical CRT client-side 1-RTT Key Phase observation work item
- [`WI-QUIC-CRT-0042.json`](WI-QUIC-CRT-0042.json): canonical CRT client-side successor 1-RTT Key Phase install work item
- [`WI-QUIC-CRT-0043.json`](WI-QUIC-CRT-0043.json): canonical CRT remaining-work program partition and autopilot reset work item
- [`WI-QUIC-CRT-0044.json`](WI-QUIC-CRT-0044.json): canonical CRT client-side replacement peer Initial reset work item
- [`WI-QUIC-CRT-0045.json`](WI-QUIC-CRT-0045.json): canonical CRT server-role secp256r1 HelloRetryRequest work item

## Notes

- Keep work items descriptive of delivery work, not of the normative requirement text itself.
- RFC 8999 carries the shared header-invariant work item slice.
