# QUIC Implementation Chunk Manifest

This backlog groups the canonical QUIC requirement surface into Codex-sized implementation chunks. The extracted assembly buckets were used as ordering hints only; the chunk boundaries below are sized for actual implementation and review flow.

## Summary

- Total requirements: 1736
- RFC 8999: 8 requirements, 1 chunk
- RFC 9000: 1443 requirements, 26 chunks
- RFC 9001: 61 requirements, 2 chunks
- RFC 9002: 224 requirements, 5 chunks
- Priority legend: `P0` foundation and existing-slice reconciliation, `P1` core transport work, `P2` greenfield or late-stage support work.

## First Wave

- `RFC8999-01`: RFC 8999 Section 5.1 long-header invariants (8 reqs) - prefixes `S5P1`
- `RFC9000-01`: RFC 9000 Sections 2-2.4 stream abstractions, stream IDs, and STREAM-frame semantics (44 reqs) - prefixes `S2, S2P1, S2P2, S2P3, S2P4`
- `RFC9000-15`: RFC 9000 Sections 15-17.2 version numbers, varints, and packet-header wire format (53 reqs) - prefixes `S15, S16, S17, S17P1, S17P2`
- `RFC9000-16`: RFC 9000 Sections 17.2.1-17.2.2 Version Negotiation and Initial packet headers (46 reqs) - prefixes `S17P2P1, S17P2P2`
- `RFC9000-18`: RFC 9000 Sections 17.3-17.4 short-header packet type and spin-bit observability (34 reqs) - prefixes `S17P3, S17P3P1, S17P4`
- `RFC9000-21`: RFC 9000 Sections 19.4-19.8 RESET_STREAM, STOP_SENDING, CRYPTO, and STREAM frame formats (64 reqs) - prefixes `S19P4, S19P5, S19P6, S19P7, S19P8`

## Second Wave

- `RFC9000-02`: RFC 9000 Sections 3-3.5 stream state machines (66 reqs) - prefixes `S3, S3P1, S3P2, S3P3, S3P4, S3P5`
- `RFC9000-03`: RFC 9000 Sections 4-4.6 stream operations and flow control (50 reqs) - prefixes `S4, S4P1, S4P2, S4P4, S4P5, S4P6`
- `RFC9000-04`: RFC 9000 Sections 5-5.2.3 connection IDs, packet classification, and Version Negotiation entry points (94 reqs) - prefixes `S5, S5P1, S5P1P1, S5P1P2, S5P2, S5P2P1, S5P2P2, S5P2P3`
- `RFC9000-05`: RFC 9000 Sections 5.3-7 connection establishment, version negotiation, and TLS handshake integration (78 reqs) - prefixes `S5P3, S6, S6P1, S6P2, S6P3, S7, S7P2, S7P3, S7P4, S7P4P1, S7P4P2, S7P5`
- `RFC9000-06`: RFC 9000 Section 8 address validation and anti-amplification (63 reqs) - prefixes `S8, S8P1, S8P1P1, S8P1P2, S8P1P3, S8P1P4, S8P2, S8P2P1, S8P2P2, S8P2P3, S8P2P4`
- `RFC9000-07`: RFC 9000 Sections 9-9.3.3 connection migration initiation and path validation (40 reqs) - prefixes `S9, S9P1, S9P2, S9P3, S9P3P1, S9P3P2, S9P3P3`
- `RFC9000-08`: RFC 9000 Sections 9.4-9.7 migrated-path accounting and preferred-address handling (61 reqs) - prefixes `S9P4, S9P5, S9P6, S9P6P1, S9P6P2, S9P6P3, S9P7`
- `RFC9000-09`: RFC 9000 Sections 10-10.2.3 idle timeout, closing, and draining (52 reqs) - prefixes `S10, S10P1, S10P1P1, S10P1P2, S10P2, S10P2P1, S10P2P2, S10P2P3`
- `RFC9000-10`: RFC 9000 Sections 10.3-10.3.3 stateless reset generation and validation (55 reqs) - prefixes `S10P3, S10P3P1, S10P3P2, S10P3P3`
- `RFC9000-11`: RFC 9000 Sections 11-12.5 error signaling and packet-protection rules (78 reqs) - prefixes `S11, S11P1, S11P2, S12P1, S12P2, S12P3, S12P4, S12P5`
- `RFC9000-12`: RFC 9000 Sections 13-13.2.7 packet acknowledgment processing (54 reqs) - prefixes `S13, S13P1, S13P2, S13P2P1, S13P2P2, S13P2P3, S13P2P4, S13P2P5, S13P2P6, S13P2P7`
- `RFC9000-13`: RFC 9000 Sections 13.3-13.4.2.2 retransmission loss signaling and ECN validation (69 reqs) - prefixes `S13P3, S13P4, S13P4P1, S13P4P2, S13P4P2P1, S13P4P2P2`
- `RFC9000-14`: RFC 9000 Section 14 datagram sizing and PMTU discovery (40 reqs) - prefixes `S14, S14P1, S14P2, S14P2P1, S14P3, S14P4`
- `RFC9000-17`: RFC 9000 Sections 17.2.3-17.2.5.3 0-RTT, Handshake, and Retry packet types (85 reqs) - prefixes `S17P2P3, S17P2P4, S17P2P5, S17P2P5P1, S17P2P5P2, S17P2P5P3`
- `RFC9000-19`: RFC 9000 Sections 18-18.2 transport parameter encoding (47 reqs) - prefixes `S18, S18P1, S18P2`
- `RFC9000-20`: RFC 9000 Sections 19.1-19.3.2 PADDING, PING, and ACK frame formats (47 reqs) - prefixes `S19P1, S19P2, S19P3, S19P3P1, S19P3P2`
- `RFC9000-22`: RFC 9000 Sections 19.9-19.14 flow-control frame formats (58 reqs) - prefixes `S19P10, S19P11, S19P12, S19P13, S19P14, S19P9`
- `RFC9000-23`: RFC 9000 Sections 19.15-19.18 connection-ID and path-probe frames (43 reqs) - prefixes `S19P15, S19P16, S19P17, S19P18`
- `RFC9000-24`: RFC 9000 Sections 19.19-19.21 connection close, handshake done, and frame encoding rules (36 reqs) - prefixes `S19P19, S19P20, S19P21`
- `RFC9000-25`: RFC 9000 Sections 20-21.12 transport error codes and security considerations (34 reqs) - prefixes `S20P1, S20P2, S21P10, S21P11, S21P12, S21P1P1P1, S21P2, S21P3, S21P4, S21P5, S21P5P3, S21P5P6, S21P6, S21P7, S21P9`
- `RFC9000-26`: RFC 9000 Section 22 IANA registry rules and codepoints (52 reqs) - prefixes `S22P1P1, S22P1P2, S22P1P3, S22P1P4, S22P2, S22P3, S22P4, S22P5`
- `RFC9001-01`: RFC 9001 Sections 2-5 TLS packet protection, CRYPTO delivery, and key derivation (34 reqs) - prefixes `S2, S3, S4, S5`
- `RFC9001-02`: RFC 9001 Sections 6-10 and Appendix B key update, security considerations, and AEAD limits (27 reqs) - prefixes `S10, S6, S7, S8, S9, SB, SBP1P1, SBP1P2, SBP2`
- `RFC9002-01`: RFC 9002 Sections 2-5.3 ack-eliciting packets, packets in flight, and RTT estimation (46 reqs) - prefixes `S2, S3, S5, S5P1, S5P2, S5P3`
- `RFC9002-02`: RFC 9002 Sections 6-6.4 loss detection and PTO scheduling (55 reqs) - prefixes `S6, S6P1, S6P1P1, S6P1P2, S6P2, S6P2P1, S6P2P2, S6P2P2P1, S6P2P3, S6P2P4, S6P3, S6P4`
- `RFC9002-03`: RFC 9002 Sections 7-7.8 congestion control, ECN, and persistent congestion (46 reqs) - prefixes `S7, S7P1, S7P2, S7P3P1, S7P3P2, S7P3P3, S7P4, S7P5, S7P6, S7P6P1, S7P6P2, S7P7, S7P8`
- `RFC9002-04`: RFC 9002 Appendix A pseudocode and recovery bookkeeping (49 reqs) - prefixes `SAP1, SAP10, SAP11, SAP1P1, SAP2, SAP4, SAP5, SAP6, SAP7, SAP8, SAP9`
- `RFC9002-05`: RFC 9002 Appendix B congestion-control constants and window updates (28 reqs) - prefixes `SBP1, SBP2, SBP3, SBP4, SBP5, SBP6, SBP7, SBP8, SBP9`

## Parallelization Plan

- `track-wire-format` in `quic/foundation-wire-format`: RFC8999-01, RFC9000-15, RFC9000-16, RFC9000-18
  - Own the packet-header and version/varint foundation in one branch so the long-header parser, version-negotiation logic, and short-header parser can move together without merge churn.
- `track-stream-core` in `quic/stream-core`: RFC9000-01, RFC9000-21
  - Own the stream-ID and STREAM-frame surface in a separate branch from the packet-header work; this keeps the existing stream parser/test slice isolated.
- `track-transport-core` in `quic/transport-core`: RFC9000-02, RFC9000-03, RFC9000-04, RFC9000-05, RFC9000-06, RFC9000-07, RFC9000-08, RFC9000-09, RFC9000-10, RFC9000-11, RFC9000-12, RFC9000-13, RFC9000-14, RFC9000-17, RFC9000-19, RFC9000-20, RFC9000-22, RFC9000-23, RFC9000-24, RFC9000-25, RFC9000-26
  - Run the remaining RFC 9000 transport slices sequentially in one worktree once the foundation branch lands; most of these chunks touch shared transport state or frame-handling code.
- `track-tls-protection` in `quic/tls-protection`: RFC9001-01, RFC9001-02
  - Keep the RFC 9001 packet-protection work isolated from the transport core so the TLS-specific code can be reviewed on its own after the packet-format primitives stabilize.
- `track-loss-recovery` in `quic/loss-recovery`: RFC9002-01, RFC9002-02, RFC9002-03, RFC9002-04, RFC9002-05
  - Run RFC 9002 as its own recovery branch after the ACK and packet-accounting slices are stable; the sections are algorithmically dependent and should stay sequential within one worktree.

## Chunk Manifest

### RFC 8999

- `RFC8999-01` | RFC 8999 | `RFC 8999 Section 5.1 long-header invariants` | 8 reqs | prefixes `S5P1` | priority `P0` | parallel `yes` | impl `yes` | tests `yes`
  - Dependencies: Foundation slice. It anchors the version-independent long-header layout used by the existing parser tests.
  - Note: Direct overlap with the current long-header parser and header tests.

### RFC 9000

- `RFC9000-01` | RFC 9000 | `RFC 9000 Sections 2-2.4 stream abstractions, stream IDs, and STREAM-frame semantics` | 44 reqs | prefixes `S2, S2P1, S2P2, S2P3, S2P4` | priority `P0` | parallel `yes` | impl `yes` | tests `yes`
  - Dependencies: Foundation slice for stream identity and stream payload parsing. It can move alongside the packet-header branch because it owns different code paths.
  - Note: Direct overlap with the existing stream-id and STREAM-frame parser/tests.
- `RFC9000-02` | RFC 9000 | `RFC 9000 Sections 3-3.5 stream state machines` | 66 reqs | prefixes `S3, S3P1, S3P2, S3P3, S3P4, S3P5` | priority `P1` | parallel `no` | impl `no` | tests `no`
  - Dependencies: Depends on the stream abstraction slice and on flow-control decisions from Section 4.
  - Note: Greenfield state-machine work.
- `RFC9000-03` | RFC 9000 | `RFC 9000 Sections 4-4.6 stream operations and flow control` | 50 reqs | prefixes `S4, S4P1, S4P2, S4P4, S4P5, S4P6` | priority `P1` | parallel `no` | impl `no` | tests `no`
  - Dependencies: Build after the stream abstraction and state-machine chunks because the operation surface depends on both.
  - Note: Greenfield flow-control work.
- `RFC9000-04` | RFC 9000 | `RFC 9000 Sections 5-5.2.3 connection IDs, packet classification, and Version Negotiation entry points` | 94 reqs | prefixes `S5, S5P1, S5P1P1, S5P1P2, S5P2, S5P2P1, S5P2P2, S5P2P3` | priority `P1` | parallel `no` | impl `unknown` | tests `yes`
  - Dependencies: Should follow the packet-header foundation because the semantics assume long-header parsing and version visibility.
  - Note: Partial overlap with the existing packet-header and version-negotiation parser/tests; CID policy remains greenfield.
- `RFC9000-05` | RFC 9000 | `RFC 9000 Sections 5.3-7 connection establishment, version negotiation, and TLS handshake integration` | 78 reqs | prefixes `S5P3, S6, S6P1, S6P2, S6P3, S7, S7P2, S7P3, S7P4, S7P4P1, S7P4P2, S7P5` | priority `P1` | parallel `no` | impl `no` | tests `no`
  - Dependencies: Depends on connection identity, addressability, and packet-header primitives from earlier chunks.
  - Note: Greenfield connection-establishment and TLS coordination work.
- `RFC9000-06` | RFC 9000 | `RFC 9000 Section 8 address validation and anti-amplification` | 63 reqs | prefixes `S8, S8P1, S8P1P1, S8P1P2, S8P1P3, S8P1P4, S8P2, S8P2P1, S8P2P2, S8P2P3, S8P2P4` | priority `P1` | parallel `yes` | impl `no` | tests `no`
  - Dependencies: Depends on the connection-establishment chunk and on the packet-size primitives used to enforce amplification limits.
  - Note: Greenfield address-validation logic.
- `RFC9000-07` | RFC 9000 | `RFC 9000 Sections 9-9.3.3 connection migration initiation and path validation` | 40 reqs | prefixes `S9, S9P1, S9P2, S9P3, S9P3P1, S9P3P2, S9P3P3` | priority `P1` | parallel `yes` | impl `no` | tests `no`
  - Dependencies: Depends on address validation and the migration-aware connection model from the earlier connection chunks.
  - Note: Greenfield migration-path logic.
- `RFC9000-08` | RFC 9000 | `RFC 9000 Sections 9.4-9.7 migrated-path accounting and preferred-address handling` | 61 reqs | prefixes `S9P4, S9P5, S9P6, S9P6P1, S9P6P2, S9P6P3, S9P7` | priority `P1` | parallel `yes` | impl `no` | tests `no`
  - Dependencies: Depends on the path-validation and migration state established in the previous migration chunk.
  - Note: Greenfield migration accounting and preferred-address logic.
- `RFC9000-09` | RFC 9000 | `RFC 9000 Sections 10-10.2.3 idle timeout, closing, and draining` | 52 reqs | prefixes `S10, S10P1, S10P1P1, S10P1P2, S10P2, S10P2P1, S10P2P2, S10P2P3` | priority `P1` | parallel `no` | impl `no` | tests `no`
  - Dependencies: Should follow the migration and packet-liveness slices because the closing behavior depends on PTO and validated-path handling.
  - Note: Greenfield connection-lifecycle shutdown work.
- `RFC9000-10` | RFC 9000 | `RFC 9000 Sections 10.3-10.3.3 stateless reset generation and validation` | 55 reqs | prefixes `S10P3, S10P3P1, S10P3P2, S10P3P3` | priority `P1` | parallel `no` | impl `no` | tests `no`
  - Dependencies: Depends on the packet-header and connection-ID primitives that make stateless reset detection possible.
  - Note: Greenfield stateless-reset logic.
- `RFC9000-11` | RFC 9000 | `RFC 9000 Sections 11-12.5 error signaling and packet-protection rules` | 78 reqs | prefixes `S11, S11P1, S11P2, S12P1, S12P2, S12P3, S12P4, S12P5` | priority `P1` | parallel `no` | impl `no` | tests `no`
  - Dependencies: Build after the packet-header foundation because the error and protection rules sit on the same packet model.
  - Note: Greenfield error-signaling and packet-protection policy.
- `RFC9000-12` | RFC 9000 | `RFC 9000 Sections 13-13.2.7 packet acknowledgment processing` | 54 reqs | prefixes `S13, S13P1, S13P2, S13P2P1, S13P2P2, S13P2P3, S13P2P4, S13P2P5, S13P2P6, S13P2P7` | priority `P1` | parallel `no` | impl `no` | tests `no`
  - Dependencies: Prepares the ACK bookkeeping needed by RFC 9002; should land before any recovery work.
  - Note: Greenfield ACK-processing work.
- `RFC9000-13` | RFC 9000 | `RFC 9000 Sections 13.3-13.4.2.2 retransmission loss signaling and ECN validation` | 69 reqs | prefixes `S13P3, S13P4, S13P4P1, S13P4P2, S13P4P2P1, S13P4P2P2` | priority `P1` | parallel `no` | impl `no` | tests `no`
  - Dependencies: Depends on the ACK-processing chunk and feeds directly into loss-recovery logic.
  - Note: Greenfield ECN and loss-signaling work.
- `RFC9000-14` | RFC 9000 | `RFC 9000 Section 14 datagram sizing and PMTU discovery` | 40 reqs | prefixes `S14, S14P1, S14P2, S14P2P1, S14P3, S14P4` | priority `P1` | parallel `yes` | impl `no` | tests `no`
  - Dependencies: Depends on packet-format plumbing and on the packet/ACK model that already exists by this point.
  - Note: Greenfield datagram sizing and PMTU discovery.
- `RFC9000-15` | RFC 9000 | `RFC 9000 Sections 15-17.2 version numbers, varints, and packet-header wire format` | 53 reqs | prefixes `S15, S16, S17, S17P1, S17P2` | priority `P0` | parallel `yes` | impl `yes` | tests `yes`
  - Dependencies: Foundation slice for packet-wire encoding; it should be available before the rest of the header and frame chunks.
  - Note: Direct overlap with the existing varint parser and packet-header tests.
- `RFC9000-16` | RFC 9000 | `RFC 9000 Sections 17.2.1-17.2.2 Version Negotiation and Initial packet headers` | 46 reqs | prefixes `S17P2P1, S17P2P2` | priority `P0` | parallel `no` | impl `yes` | tests `yes`
  - Dependencies: Depends on the packet-header foundation and is the next step after the version/varint chunk.
  - Note: Direct overlap with the existing long-header and version-negotiation tests.
- `RFC9000-17` | RFC 9000 | `RFC 9000 Sections 17.2.3-17.2.5.3 0-RTT, Handshake, and Retry packet types` | 85 reqs | prefixes `S17P2P3, S17P2P4, S17P2P5, S17P2P5P1, S17P2P5P2, S17P2P5P3` | priority `P1` | parallel `no` | impl `unknown` | tests `yes`
  - Dependencies: Depends on the packet-header foundation and the Version Negotiation / Initial packet chunk.
  - Note: Partial overlap with long-header parsing tests; 0-RTT, Handshake, and Retry semantics are greenfield.
- `RFC9000-18` | RFC 9000 | `RFC 9000 Sections 17.3-17.4 short-header packet type and spin-bit observability` | 34 reqs | prefixes `S17P3, S17P3P1, S17P4` | priority `P0` | parallel `yes` | impl `yes` | tests `yes`
  - Dependencies: Depends on the packet-header foundation, but the short-header parser slice already exists in the repo.
  - Note: Direct overlap with the existing short-header parser/tests; spin-bit observability is still greenfield.
- `RFC9000-19` | RFC 9000 | `RFC 9000 Sections 18-18.2 transport parameter encoding` | 47 reqs | prefixes `S18, S18P1, S18P2` | priority `P2` | parallel `yes` | impl `no` | tests `no`
  - Dependencies: Depends on the packet and TLS plumbing, but the transport-parameter encoder itself is a clean standalone slice.
  - Note: Greenfield transport-parameter serialization.
- `RFC9000-20` | RFC 9000 | `RFC 9000 Sections 19.1-19.3.2 PADDING, PING, and ACK frame formats` | 47 reqs | prefixes `S19P1, S19P2, S19P3, S19P3P1, S19P3P2` | priority `P2` | parallel `no` | impl `no` | tests `no`
  - Dependencies: Build after packet-protection and ACK-processing primitives are in place.
  - Note: Greenfield frame-format work.
- `RFC9000-21` | RFC 9000 | `RFC 9000 Sections 19.4-19.8 RESET_STREAM, STOP_SENDING, CRYPTO, and STREAM frame formats` | 64 reqs | prefixes `S19P4, S19P5, S19P6, S19P7, S19P8` | priority `P2` | parallel `yes` | impl `yes` | tests `yes`
  - Dependencies: Depends on the shared frame parser surface and on the stream parser module already present in the repo.
  - Note: Direct overlap with the existing STREAM-frame parser/tests; the non-STREAM frame types remain greenfield.
- `RFC9000-22` | RFC 9000 | `RFC 9000 Sections 19.9-19.14 flow-control frame formats` | 58 reqs | prefixes `S19P10, S19P11, S19P12, S19P13, S19P14, S19P9` | priority `P2` | parallel `no` | impl `no` | tests `no`
  - Dependencies: Should follow the ACK and packet bookkeeping chunks because these frames are tied to flow-control state.
  - Note: Greenfield flow-control frame work.
- `RFC9000-23` | RFC 9000 | `RFC 9000 Sections 19.15-19.18 connection-ID and path-probe frames` | 43 reqs | prefixes `S19P15, S19P16, S19P17, S19P18` | priority `P2` | parallel `no` | impl `no` | tests `no`
  - Dependencies: Depends on the migration and connection-ID chunks because these frames are part of that control plane.
  - Note: Greenfield connection-ID and path-probe frame work.
- `RFC9000-24` | RFC 9000 | `RFC 9000 Sections 19.19-19.21 connection close, handshake done, and frame encoding rules` | 36 reqs | prefixes `S19P19, S19P20, S19P21` | priority `P2` | parallel `no` | impl `no` | tests `no`
  - Dependencies: Depends on the error-handling and packet-protection chunks because these behaviors sit on the shutdown path.
  - Note: Greenfield shutdown-frame and framing-rules work.
- `RFC9000-25` | RFC 9000 | `RFC 9000 Sections 20-21.12 transport error codes and security considerations` | 34 reqs | prefixes `S20P1, S20P2, S21P10, S21P11, S21P12, S21P1P1P1, S21P2, S21P3, S21P4, S21P5, S21P5P3, S21P5P6, S21P6, S21P7, S21P9` | priority `P2` | parallel `yes` | impl `no` | tests `no`
  - Dependencies: Depends on the packet and connection-lifecycle behavior from earlier chunks, but can be implemented as a mostly documentation/policy track.
  - Note: Greenfield security-policy and transport-error guidance.
- `RFC9000-26` | RFC 9000 | `RFC 9000 Section 22 IANA registry rules and codepoints` | 52 reqs | prefixes `S22P1P1, S22P1P2, S22P1P3, S22P1P4, S22P2, S22P3, S22P4, S22P5` | priority `P2` | parallel `yes` | impl `no` | tests `no`
  - Dependencies: Registry policy can run after the frame and transport-codepoint surfaces are stable.
  - Note: Greenfield IANA registry maintenance work.

### RFC 9001

- `RFC9001-01` | RFC 9001 | `RFC 9001 Sections 2-5 TLS packet protection, CRYPTO delivery, and key derivation` | 34 reqs | prefixes `S2, S3, S4, S5` | priority `P1` | parallel `no` | impl `no` | tests `no`
  - Dependencies: Depends on the packet-header and stream/frame plumbing from RFC 9000, especially the packet-number and CRYPTO handling slices.
  - Note: Greenfield TLS/QUIC packet-protection work.
- `RFC9001-02` | RFC 9001 | `RFC 9001 Sections 6-10 and Appendix B key update, security considerations, and AEAD limits` | 27 reqs | prefixes `S10, S6, S7, S8, S9, SB, SBP1P1, SBP1P2, SBP2` | priority `P2` | parallel `no` | impl `no` | tests `no`
  - Dependencies: Depends on the packet-protection chunk and the packet-header / packet-number primitives from RFC 9000.
  - Note: Greenfield key-update and AEAD-limit work.

### RFC 9002

- `RFC9002-01` | RFC 9002 | `RFC 9002 Sections 2-5.3 ack-eliciting packets, packets in flight, and RTT estimation` | 46 reqs | prefixes `S2, S3, S5, S5P1, S5P2, S5P3` | priority `P1` | parallel `no` | impl `no` | tests `no`
  - Dependencies: Depends on packet accounting and ACK-processing from RFC 9000.
  - Note: Greenfield recovery-metric work.
- `RFC9002-02` | RFC 9002 | `RFC 9002 Sections 6-6.4 loss detection and PTO scheduling` | 55 reqs | prefixes `S6, S6P1, S6P1P1, S6P1P2, S6P2, S6P2P1, S6P2P2, S6P2P2P1, S6P2P3, S6P2P4, S6P3, S6P4` | priority `P1` | parallel `no` | impl `no` | tests `no`
  - Dependencies: Depends on the RTT-estimation chunk and on the packet-number-space model from RFC 9000.
  - Note: Greenfield loss-detection engine.
- `RFC9002-03` | RFC 9002 | `RFC 9002 Sections 7-7.8 congestion control, ECN, and persistent congestion` | 46 reqs | prefixes `S7, S7P1, S7P2, S7P3P1, S7P3P2, S7P3P3, S7P4, S7P5, S7P6, S7P6P1, S7P6P2, S7P7, S7P8` | priority `P1` | parallel `no` | impl `no` | tests `no`
  - Dependencies: Depends on the loss-detection chunk and on the ACK/loss bookkeeping that precedes it.
  - Note: Greenfield congestion-control state machine work.
- `RFC9002-04` | RFC 9002 | `RFC 9002 Appendix A pseudocode and recovery bookkeeping` | 49 reqs | prefixes `SAP1, SAP10, SAP11, SAP1P1, SAP2, SAP4, SAP5, SAP6, SAP7, SAP8, SAP9` | priority `P2` | parallel `no` | impl `no` | tests `no`
  - Dependencies: Build after the core RTT, loss, and congestion-control chunks because Appendix A mirrors those algorithms in executable form.
  - Note: Greenfield appendix pseudocode and state-bookkeeping work.
- `RFC9002-05` | RFC 9002 | `RFC 9002 Appendix B congestion-control constants and window updates` | 28 reqs | prefixes `SBP1, SBP2, SBP3, SBP4, SBP5, SBP6, SBP7, SBP8, SBP9` | priority `P2` | parallel `no` | impl `no` | tests `no`
  - Dependencies: Build after the core congestion-control chunk because Appendix B formalizes the window-update rules.
  - Note: Greenfield appendix congestion-control policy work.
