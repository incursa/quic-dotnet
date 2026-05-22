# QUIC RFC Corpus

This directory contains the vendored QUIC-related RFC text corpus used as source material for trace-first planning.
Canonical requirements still live under `../requirements/quic`.

## Core Trace Floor

- `rfc8999.txt` - QUIC invariants
- `rfc9000.txt` - QUIC transport
- `rfc9001.txt` - QUIC TLS
- `rfc9002.txt` - QUIC loss detection and congestion control

## Later QUIC-Related RFC Texts

- `rfc9114.txt` - HTTP/3
- `rfc9204.txt` - QPACK
- `rfc9220.txt` - WebSockets over HTTP/3
- `rfc9221.txt` - QUIC datagrams
- `rfc9250.txt` - DNS over QUIC
- `rfc9287.txt` - QUIC version negotiation
- `rfc9297.txt` - HTTP Datagrams and the Capsule Protocol
- `rfc9298.txt` - Proxying UDP Datagrams over HTTP
- `rfc9308.txt` - Manageability of the QUIC Transport
- `rfc9312.txt` - Applicability of the QUIC Transport Protocol
- `rfc9368.txt` - Using Early Data in QUIC
- `rfc9369.txt` - QUIC v2
- `rfc9461.txt` - Discovery of Encrypted DNS Resolvers
- `rfc9463.txt` - Discovery of Designated Resolvers
- `rfc9464.txt` - Discovery of Encrypted DNS Servers
- `rfc9484.txt` - Proxying IP in HTTP

The later RFCs are present locally for planning and reference. Their corresponding behavior slices are tracked in `REQUIREMENT-GAPS.md` or will be opened there when the repository commits to them.
