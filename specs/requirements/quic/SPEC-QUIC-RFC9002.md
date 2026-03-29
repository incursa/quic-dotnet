---
artifact_id: SPEC-QUIC-RFC9002
artifact_type: specification
title: QUIC Loss Detection and Congestion Control (RFC 9002)
domain: quic
capability: loss-detection-and-congestion-control
status: draft
owner: quic-maintainers
---

# [`SPEC-QUIC-RFC9002`](./SPEC-QUIC-RFC9002.md) - QUIC Loss Detection and Congestion Control (RFC 9002)

## Purpose

Capture the QUIC loss-detection and congestion-control requirements defined by RFC 9002 as canonical spec-trace clauses.

## Scope

This specification covers the reviewed RFC 9002 extraction outputs, including normative appendix material promoted from the reviewed drafts, and preserves the original RFC section provenance in `Source Refs`.

## Context

RFC 9002 contains both normative behavioral text and pseudocode-oriented appendices. The assembly keeps those clauses in one RFC-level specification while surfacing overlap with RFC 9000 transport recovery rules in generated reports.

## REQ-QUIC-RFC9002-S2-0001 Interpret all-caps BCP 14 keywords
The key words in this document MUST be interpreted as described in BCP 14 when, and only when, they appear in all capitals.

Trace:
- Source Refs:
  - RFC 9002 §2 RFC9002-S2-B2-P1-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-2

## REQ-QUIC-RFC9002-S2-0002 Classify non-control frames as ack-eliciting
Frames other than ACK, PADDING, and CONNECTION_CLOSE MUST be treated as ack-eliciting.

Trace:
- Source Refs:
  - RFC 9002 §2 RFC9002-S2-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-2

## REQ-QUIC-RFC9002-S2-0003 Acknowledge ack-eliciting packets promptly
Packets that contain ack-eliciting frames MUST elicit an ACK from the receiver within the maximum acknowledgment delay.

Trace:
- Source Refs:
  - RFC 9002 §2 RFC9002-S2-B5-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-2

## REQ-QUIC-RFC9002-S2-0004 Define packets in flight
Packets MUST be considered in flight when they are ack-eliciting or contain a PADDING frame and have been sent but are not yet acknowledged, declared lost, or discarded along with old keys.

Trace:
- Source Refs:
  - RFC 9002 §2 RFC9002-S2-B6-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-2

## REQ-QUIC-RFC9002-S3-0001 Attach packet-level headers to transmissions
QUIC transmissions MUST be sent with a packet-level header.

Trace:
- Source Refs:
  - RFC 9002 §3 RFC9002-S3-B2-P1-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-3-1

## REQ-QUIC-RFC9002-S3-0002 Indicate encryption level in packet headers
The packet-level header MUST indicate the encryption level.

Trace:
- Source Refs:
  - RFC 9002 §3 RFC9002-S3-B2-P1-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-3-1

## REQ-QUIC-RFC9002-S3-0003 Carry packet numbers in packet headers
The packet-level header MUST include a packet sequence number.

Trace:
- Source Refs:
  - RFC 9002 §3 RFC9002-S3-B2-P1-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-3-1

## REQ-QUIC-RFC9002-S3-0004 Map encryption level to packet number space
The encryption level MUST indicate the packet number space.

Trace:
- Source Refs:
  - RFC 9002 §3 RFC9002-S3-B2-P1-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-3-1

## REQ-QUIC-RFC9002-S3-0005 Prohibit packet number reuse
Packet numbers MUST NOT repeat within a packet number space for the lifetime of a connection.

Trace:
- Source Refs:
  - RFC 9002 §3 RFC9002-S3-B2-P1-S3
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-3-1

## REQ-QUIC-RFC9002-S3-0006 Send packet numbers monotonically
Packet numbers MUST be sent in monotonically increasing order within a space.

Trace:
- Source Refs:
  - RFC 9002 §3 RFC9002-S3-B2-P1-S4
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-3-1

## REQ-QUIC-RFC9002-S3-0007 Allow intentional packet number gaps
Some packet numbers MAY never be used, leaving intentional gaps.

Trace:
- Source Refs:
  - RFC 9002 §3 RFC9002-S3-B2-P1-S5
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-3-1

## REQ-QUIC-RFC9002-S3-0008 Permit mixed frame types per packet
QUIC packets MAY contain multiple frames of different types.

Trace:
- Source Refs:
  - RFC 9002 §3 RFC9002-S3-B4-P3-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-3-3

## REQ-QUIC-RFC9002-S3-0009 Ensure reliable delivery outcome
Data and frames that need reliable delivery MUST be acknowledged or declared lost.

Trace:
- Source Refs:
  - RFC 9002 §3 RFC9002-S3-B4-P3-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-3-3

## REQ-QUIC-RFC9002-S3-0010 Allow retransmission in new packets
Data and frames that need reliable delivery MUST be sent in new packets as necessary.

Trace:
- Source Refs:
  - RFC 9002 §3 RFC9002-S3-B4-P3-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-3-3

## REQ-QUIC-RFC9002-S3-0011 Acknowledge all packets
All packets MUST be acknowledged.

Trace:
- Source Refs:
  - RFC 9002 §3 RFC9002-S3-B5-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-3-4.1

## REQ-QUIC-RFC9002-S3-0012 Delay acknowledgment for non-ack-eliciting packets
Packets that contain no ack-eliciting frames MUST be acknowledged only along with ack-eliciting packets.

Trace:
- Source Refs:
  - RFC 9002 §3 RFC9002-S3-B5-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-3-4.1

## REQ-QUIC-RFC9002-S3-0013 Shorten CRYPTO acknowledgment timers
Long header packets that contain CRYPTO frames MUST use shorter timers for acknowledgment.

Trace:
- Source Refs:
  - RFC 9002 §3 RFC9002-S3-B6-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-3-4.2

## REQ-QUIC-RFC9002-S3-0014 Count non-ACK packets toward congestion limits
Packets containing frames besides ACK or CONNECTION_CLOSE MUST count toward congestion control limits.

Trace:
- Source Refs:
  - RFC 9002 §3 RFC9002-S3-B7-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-3-4.3

## REQ-QUIC-RFC9002-S3-0015 Treat non-ACK packets as in flight
Packets containing frames besides ACK or CONNECTION_CLOSE MUST be considered in flight.

Trace:
- Source Refs:
  - RFC 9002 §3 RFC9002-S3-B7-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-3-4.3

## REQ-QUIC-RFC9002-S3-0016 Count PADDING toward bytes in flight
Packets containing PADDING frames MUST contribute toward bytes in flight.

Trace:
- Source Refs:
  - RFC 9002 §3 RFC9002-S3-B8-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-3-4.4

## REQ-QUIC-RFC9002-S3-0017 Suppress direct ACKs for PADDING
PADDING frames MUST NOT directly cause an acknowledgment to be sent.

Trace:
- Source Refs:
  - RFC 9002 §3 RFC9002-S3-B8-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-3-4.4

## REQ-QUIC-RFC9002-S5-0001 Compute RTT path values
An endpoint MUST compute min_rtt, smoothed_rtt, and rttvar for each path.

Trace:
- Source Refs:
  - RFC 9002 §5 RFC9002-S5-B2-P1-S3
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5

## REQ-QUIC-RFC9002-S5P1-0001 Gate RTT sample generation
An endpoint MUST generate an RTT sample on receiving an ACK frame only if the largest acknowledged packet number is newly acknowledged and at least one newly acknowledged packet was ack-eliciting.

Trace:
- Source Refs:
  - RFC 9002 §5.1 RFC9002-S5.1-B1-P0-S1
  - RFC 9002 §5.1 RFC9002-S5.1-B3-P0-S1
  - RFC 9002 §5.1 RFC9002-S5.1-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.1

## REQ-QUIC-RFC9002-S5P1-0002 Measure latest RTT from the largest acknowledged packet
latest_rtt MUST equal the time elapsed between when the largest acknowledged packet was sent and when the corresponding ACK was received.

Trace:
- Source Refs:
  - RFC 9002 §5.1 RFC9002-S5.1-B5-P2-S1
  - RFC 9002 §5.1 RFC9002-S5.1-B6-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.1

## REQ-QUIC-RFC9002-S5P1-0003 Use only the largest acknowledged packet
An RTT sample MUST use only the largest acknowledged packet in the received ACK frame.

Trace:
- Source Refs:
  - RFC 9002 §5.1 RFC9002-S5.1-B7-P3-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.1

## REQ-QUIC-RFC9002-S5P1-0004 Skip duplicate RTT updates
An ACK frame SHOULD NOT be used to update RTT estimates if it does not newly acknowledge the largest acknowledged packet.

Trace:
- Source Refs:
  - RFC 9002 §5.1 RFC9002-S5.1-B8-P4-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.1

## REQ-QUIC-RFC9002-S5P1-0005 Require ack-eliciting progress
An RTT sample MUST NOT be generated on receiving an ACK frame that does not newly acknowledge at least one ack-eliciting packet.

Trace:
- Source Refs:
  - RFC 9002 §5.1 RFC9002-S5.1-B9-P5-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.1

## REQ-QUIC-RFC9002-S5P2-0001 Initialize min_rtt from the first sample
min_rtt MUST be set to latest_rtt on the first RTT sample.

Trace:
- Source Refs:
  - RFC 9002 §5.2 RFC9002-S5.2-B3-P2-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.2

## REQ-QUIC-RFC9002-S5P2-0002 Update min_rtt on later samples
On all RTT samples after the first, min_rtt MUST be set to the lesser of min_rtt and latest_rtt.

Trace:
- Source Refs:
  - RFC 9002 §5.2 RFC9002-S5.2-B3-P2-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.2

## REQ-QUIC-RFC9002-S5P2-0003 Compute min_rtt from local observations
An endpoint MUST use only locally observed times when computing min_rtt.

Trace:
- Source Refs:
  - RFC 9002 §5.2 RFC9002-S5.2-B4-P3-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.2

## REQ-QUIC-RFC9002-S5P2-0004 Ignore peer delay in min_rtt
An endpoint MUST NOT adjust min_rtt for acknowledgment delays reported by the peer.

Trace:
- Source Refs:
  - RFC 9002 §5.2 RFC9002-S5.2-B4-P3-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.2

## REQ-QUIC-RFC9002-S5P2-0005 Refresh min_rtt after persistent congestion
Endpoints SHOULD set min_rtt to the newest RTT sample after persistent congestion is established.

Trace:
- Source Refs:
  - RFC 9002 §5.2 RFC9002-S5.2-B6-P5-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.2

## REQ-QUIC-RFC9002-S5P2-0006 Allow opportunistic min_rtt reestablishment
Endpoints MAY reestablish min_rtt at other times in the connection, such as when traffic volume is low and an acknowledgment is received with a low acknowledgment delay.

Trace:
- Source Refs:
  - RFC 9002 §5.2 RFC9002-S5.2-B7-P6-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.2

## REQ-QUIC-RFC9002-S5P2-0007 Avoid over-refreshing min_rtt
Implementations SHOULD NOT refresh the min_rtt value too often.

Trace:
- Source Refs:
  - RFC 9002 §5.2 RFC9002-S5.2-B7-P6-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.2

## REQ-QUIC-RFC9002-S5P3-0001 Use adjusted RTT samples for smoothed RTT
The calculation of smoothed_rtt MUST use RTT samples after adjusting them for acknowledgment delays.

Trace:
- Source Refs:
  - RFC 9002 §5.3 RFC9002-S5.3-B3-P2-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.3

## REQ-QUIC-RFC9002-S5P3-0002 Ignore max_ack_delay before handshake confirmation
The endpoint SHOULD ignore max_ack_delay until the handshake is confirmed.

Trace:
- Source Refs:
  - RFC 9002 §5.3 RFC9002-S5.3-B4-P3-S2
  - RFC 9002 §5.3 RFC9002-S5.3-B7-P6-S1
  - RFC 9002 §5.3 RFC9002-S5.3-B9-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.3

## REQ-QUIC-RFC9002-S5P3-0003 Allow dropping some adjusted samples
Before handshake confirmation, an endpoint MAY ignore an RTT sample if adjusting the sample for acknowledgment delay would make it smaller than min_rtt.

Trace:
- Source Refs:
  - RFC 9002 §5.3 RFC9002-S5.3-B5-P4-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.3

## REQ-QUIC-RFC9002-S5P3-0004 Subtract local decryption delay
When acknowledgment processing is postponed because the corresponding decryption keys are not immediately available, an endpoint SHOULD subtract that local delay from its RTT sample until the handshake is confirmed.

Trace:
- Source Refs:
  - RFC 9002 §5.3 RFC9002-S5.3-B12-P7-S1
  - RFC 9002 §5.3 RFC9002-S5.3-B12-P7-S3
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.3

## REQ-QUIC-RFC9002-S5P3-0005 Initialize the RTT estimator at connection start
An endpoint MUST initialize the RTT estimator during connection establishment and when the estimator is reset during connection migration.

Trace:
- Source Refs:
  - RFC 9002 §5.3 RFC9002-S5.3-B14-P9-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.3

## REQ-QUIC-RFC9002-S5P3-0006 Seed new-path RTT estimation with the initial RTT
Before any RTT samples are available for a new path, or when the estimator is reset, the RTT estimator MUST be initialized using the initial RTT.

Trace:
- Source Refs:
  - RFC 9002 §5.3 RFC9002-S5.3-B14-P9-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.3

## REQ-QUIC-RFC9002-S5P3-0007 Initialize smoothed RTT and variation
When the RTT estimator is initialized, `smoothed_rtt` MUST be set to `kInitialRtt` and `rttvar` to `kInitialRtt / 2`.

Trace:
- Source Refs:
  - RFC 9002 §5.3 RFC9002-S5.3-B15-P10-S1
  - RFC 9002 §5.3 RFC9002-S5.3-B16-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.3

## REQ-QUIC-RFC9002-S5P3-0008 Reset the estimator on the first post-init sample
On the first RTT sample after initialization, `smoothed_rtt` MUST be set to `latest_rtt` and `rttvar` to `latest_rtt / 2`.

Trace:
- Source Refs:
  - RFC 9002 §5.3 RFC9002-S5.3-B18-P12-S1
  - RFC 9002 §5.3 RFC9002-S5.3-B19-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.3

## REQ-QUIC-RFC9002-S5P3-0009 Clamp ACK delay after handshake confirmation
After the handshake is confirmed, an endpoint MUST use the lesser of the acknowledgment delay and the peer's max_ack_delay.

Trace:
- Source Refs:
  - RFC 9002 §5.3 RFC9002-S5.3-B10-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.3

## REQ-QUIC-RFC9002-S5P3-0010 Update RTT estimates on subsequent samples
On subsequent RTT samples, an endpoint MUST set adjusted_rtt to latest_rtt - ack_delay when latest_rtt is at least min_rtt + ack_delay and otherwise set adjusted_rtt to latest_rtt, then update smoothed_rtt to 7/8 of its prior value plus 1/8 of adjusted_rtt and update rttvar to 3/4 of its prior value plus 1/4 of abs(smoothed_rtt - adjusted_rtt).

Trace:
- Source Refs:
  - RFC 9002 §5.3 RFC9002-S5.3-B20-P13-S1
  - RFC 9002 §5.3 RFC9002-S5.3-B21-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.3

## REQ-QUIC-RFC9002-S5P3-0011 Ignore ACK delay for Initial packets
An endpoint MAY ignore the acknowledgment delay for Initial packets.

Trace:
- Source Refs:
  - RFC 9002 §5.3 RFC9002-S5.3-B8-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.3

## REQ-QUIC-RFC9002-S5P3-0012 Bound adjusted RTT by min_rtt
An endpoint MUST NOT subtract the acknowledgment delay from the RTT sample if the resulting value would be smaller than min_rtt.

Trace:
- Source Refs:
  - RFC 9002 §5.3 RFC9002-S5.3-B11-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-5.3

## REQ-QUIC-RFC9002-S6-0001 Separate loss detection by packet number space
Loss detection MUST be separate per packet number space.

Trace:
- Source Refs:
  - RFC 9002 §6 RFC9002-S6-B4-P3-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6

## REQ-QUIC-RFC9002-S6P1-0001 Declare loss only for packets that satisfy the basic loss criteria
A packet MUST be unacknowledged, in flight, and sent before an acknowledged packet before it can be declared lost.

Trace:
- Source Refs:
  - RFC 9002 §6.1 RFC9002-S6.1-B3-P2-S1
  - RFC 9002 §6.1 RFC9002-S6.1-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1

## REQ-QUIC-RFC9002-S6P1-0002 Allow smaller initial reordering thresholds with adaptation
Implementations with adaptive time thresholds MAY start with smaller initial reordering thresholds to minimize recovery latency.

Trace:
- Source Refs:
  - RFC 9002 §6.1 RFC9002-S6.1-B7-P4-S3
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1

## REQ-QUIC-RFC9002-S6P1P1-0001 Recommend a packet threshold of three
The packet reordering threshold SHOULD be 3.

Trace:
- Source Refs:
  - RFC 9002 §6.1.1 RFC9002-S6.1.1-B2-P1-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1.1

## REQ-QUIC-RFC9002-S6P1P1-0002 Avoid packet thresholds below three
Implementations SHOULD NOT use a packet threshold less than 3.

Trace:
- Source Refs:
  - RFC 9002 §6.1.1 RFC9002-S6.1.1-B2-P1-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1.1

## REQ-QUIC-RFC9002-S6P1P2-0001 Declare earlier packets lost after sufficient time
Once a later packet within the same packet number space has been acknowledged, an endpoint SHOULD declare an earlier packet lost if it was sent a threshold amount of time in the past.

Trace:
- Source Refs:
  - RFC 9002 §6.1.2 RFC9002-S6.1.2-B2-P1-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1.2

## REQ-QUIC-RFC9002-S6P1P2-0002 Bound the time threshold by timer granularity
To avoid declaring packets lost too early, the time threshold MUST be at least the local timer granularity.

Trace:
- Source Refs:
  - RFC 9002 §6.1.2 RFC9002-S6.1.2-B2-P1-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1.2

## REQ-QUIC-RFC9002-S6P1P2-0003 Compute the time threshold from RTT and granularity
The time threshold MUST be max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity).

Trace:
- Source Refs:
  - RFC 9002 §6.1.2 RFC9002-S6.1.2-B3-P0-S1
  - RFC 9002 §6.1.2 RFC9002-S6.1.2-B4-P2-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1.2

## REQ-QUIC-RFC9002-S6P1P2-0004 Schedule a timer for the remaining time before declaring loss
If packets sent prior to the largest acknowledged packet cannot yet be declared lost, a timer SHOULD be set for the remaining time.

Trace:
- Source Refs:
  - RFC 9002 §6.1.2 RFC9002-S6.1.2-B4-P2-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1.2

## REQ-QUIC-RFC9002-S6P1P2-0005 Use the recommended packet-threshold multiplier
The RECOMMENDED time threshold multiplier, kTimeThreshold, SHOULD be 9/8.

Trace:
- Source Refs:
  - RFC 9002 §6.1.2 RFC9002-S6.1.2-B8-P4-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1.2

## REQ-QUIC-RFC9002-S6P1P2-0006 Use a one-millisecond timer granularity
The RECOMMENDED timer granularity, kGranularity, SHOULD be 1 millisecond.

Trace:
- Source Refs:
  - RFC 9002 §6.1.2 RFC9002-S6.1.2-B8-P4-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1.2

## REQ-QUIC-RFC9002-S6P1P2-0007 Allow alternative time-threshold experiments
Implementations MAY experiment with absolute thresholds, thresholds from previous connections, adaptive thresholds, or RTT variation.

Trace:
- Source Refs:
  - RFC 9002 §6.1.2 RFC9002-S6.1.2-B9-P5-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1.2

## REQ-QUIC-RFC9002-S6P2-0001 Send probe datagrams on PTO expiration or address-validation uncertainty
A Probe Timeout (PTO) MUST trigger the sending of one or two probe datagrams when ack-eliciting packets are not acknowledged within the expected period of time or when the server may not have validated the client's address.

Trace:
- Source Refs:
  - RFC 9002 §6.2 RFC9002-S6.2-B2-P1-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2

## REQ-QUIC-RFC9002-S6P2-0002 Compute PTO per packet number space
The PTO MUST be computed separately for each packet number space.

Trace:
- Source Refs:
  - RFC 9002 §6.2 RFC9002-S6.2-B3-P2-S1
  - RFC 9002 §6.2 RFC9002-S6.2-B3-P2-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2

## REQ-QUIC-RFC9002-S6P2-0003 Do not infer loss from PTO expiration
A PTO timer expiration MUST NOT cause prior unacknowledged packets to be marked as lost.

Trace:
- Source Refs:
  - RFC 9002 §6.2 RFC9002-S6.2-B4-P3-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2

## REQ-QUIC-RFC9002-S6P2P1-0001 Schedule PTO after ack-eliciting transmission
When an ack-eliciting packet is transmitted, the sender MUST schedule a PTO timer using PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay.

Trace:
- Source Refs:
  - RFC 9002 §6.2.1 RFC9002-S6.2.1-B2-P1-S1
  - RFC 9002 §6.2.1 RFC9002-S6.2.1-B3-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.1

## REQ-QUIC-RFC9002-S6P2P1-0002 Set max_ack_delay to zero for early handshake spaces
When the PTO is armed for the Initial or Handshake packet number spaces, the max_ack_delay in the PTO computation MUST be set to 0.

Trace:
- Source Refs:
  - RFC 9002 §6.2.1 RFC9002-S6.2.1-B5-P3-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.1

## REQ-QUIC-RFC9002-S6P2P1-0003 Keep PTO above granularity
The PTO period MUST be at least kGranularity.

Trace:
- Source Refs:
  - RFC 9002 §6.2.1 RFC9002-S6.2.1-B6-P4-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.1

## REQ-QUIC-RFC9002-S6P2P1-0004 Use the earlier PTO across Initial and Handshake spaces
When ack-eliciting packets in multiple packet number spaces are in flight, the PTO timer MUST be set to the earlier value of the Initial and Handshake packet number spaces.

Trace:
- Source Refs:
  - RFC 9002 §6.2.1 RFC9002-S6.2.1-B7-P5-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.1

## REQ-QUIC-RFC9002-S6P2P1-0005 Defer application-data PTO until handshake confirmation
An endpoint MUST NOT set its PTO timer for the Application Data packet number space until the handshake is confirmed.

Trace:
- Source Refs:
  - RFC 9002 §6.2.1 RFC9002-S6.2.1-B8-P6-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.1

## REQ-QUIC-RFC9002-S6P2P1-0006 Restart PTO on send, acknowledgment, or key discard
A sender SHOULD restart its PTO timer every time an ack-eliciting packet is sent or acknowledged, or when Initial or Handshake keys are discarded.

Trace:
- Source Refs:
  - RFC 9002 §6.2.1 RFC9002-S6.2.1-B9-P7-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.1

## REQ-QUIC-RFC9002-S6P2P1-0007 Increase PTO backoff on timeout
When a PTO timer expires, the PTO backoff MUST be increased, which doubles the PTO period.

Trace:
- Source Refs:
  - RFC 9002 §6.2.1 RFC9002-S6.2.1-B10-P8-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.1

## REQ-QUIC-RFC9002-S6P2P1-0008 Reset PTO backoff on acknowledgment
The PTO backoff factor MUST be reset when an acknowledgment is received.

Trace:
- Source Refs:
  - RFC 9002 §6.2.1 RFC9002-S6.2.1-B10-P8-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.1

## REQ-QUIC-RFC9002-S6P2P1-0009 Suppress PTO-backoff reset on unvalidated Initial acknowledgments
A client that is not yet certain that the server has finished validating its address MUST NOT reset the PTO backoff factor on receiving acknowledgments in Initial packets.

Trace:
- Source Refs:
  - RFC 9002 §6.2.1 RFC9002-S6.2.1-B10-P8-S4
  - RFC 9002 §6.2.1 RFC9002-S6.2.1-B10-P8-S5
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.1

## REQ-QUIC-RFC9002-S6P2P1-0010 Avoid conflicting timers
The PTO timer MUST NOT be set if a timer is set for time-threshold loss detection.

Trace:
- Source Refs:
  - RFC 9002 §6.2.1 RFC9002-S6.2.1-B13-P11-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.1

## REQ-QUIC-RFC9002-S6P2P2-0001 Reuse prior-smoothed RTT on resumed connections
Resumed connections over the same network MAY use the previous connection's final smoothed RTT value as the resumed connection's initial RTT.

Trace:
- Source Refs:
  - RFC 9002 §6.2.2 RFC9002-S6.2.2-B2-P1-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.2

## REQ-QUIC-RFC9002-S6P2P2-0002 Default initial RTT to 333 milliseconds
When no previous RTT is available, the initial RTT SHOULD be set to 333 milliseconds.

Trace:
- Source Refs:
  - RFC 9002 §6.2.2 RFC9002-S6.2.2-B2-P1-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.2

## REQ-QUIC-RFC9002-S6P2P2-0003 Use PATH_CHALLENGE and PATH_RESPONSE timing for initial RTT
A connection MAY use the delay between sending a PATH_CHALLENGE and receiving a PATH_RESPONSE to set the initial RTT for a new path.

Trace:
- Source Refs:
  - RFC 9002 §6.2.2 RFC9002-S6.2.2-B3-P2-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.2

## REQ-QUIC-RFC9002-S6P2P2-0004 Do not treat PATH_CHALLENGE/PATH_RESPONSE delay as an RTT sample
That delay SHOULD NOT be considered an RTT sample.

Trace:
- Source Refs:
  - RFC 9002 §6.2.2 RFC9002-S6.2.2-B3-P2-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.2

## REQ-QUIC-RFC9002-S6P2P2-0005 Reset timers when keys are discarded
When Initial or Handshake keys are discarded, the PTO and loss detection timers MUST be reset.

Trace:
- Source Refs:
  - RFC 9002 §6.2.2 RFC9002-S6.2.2-B4-P3-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.2

## REQ-QUIC-RFC9002-S6P2P2P1-0001 Delay server PTO until address validation traffic arrives
If no additional data can be sent, the server's PTO timer MUST NOT be armed until datagrams have been received from the client.

Trace:
- Source Refs:
  - RFC 9002 §6.2.2.1 RFC9002-S6.2.2.1-B2-P1-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.2.1

## REQ-QUIC-RFC9002-S6P2P2P1-0002 Reset the server PTO when the client sends data
When the server receives a datagram from the client, the amplification limit increases and the server MUST reset the PTO timer.

Trace:
- Source Refs:
  - RFC 9002 §6.2.2.1 RFC9002-S6.2.2.1-B3-P2-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.2.1

## REQ-QUIC-RFC9002-S6P2P2P1-0003 Fire a past-due PTO immediately
If the PTO timer is then set to a time in the past, it MUST be executed immediately.

Trace:
- Source Refs:
  - RFC 9002 §6.2.2.1 RFC9002-S6.2.2.1-B3-P2-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.2.1

## REQ-QUIC-RFC9002-S6P2P2P1-0004 Arm the client PTO before handshake confirmation
The client MUST set the PTO timer if it has not received an acknowledgment for any of its Handshake packets and the handshake is not confirmed, even if there are no packets in flight.

Trace:
- Source Refs:
  - RFC 9002 §6.2.2.1 RFC9002-S6.2.2.1-B4-P3-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.2.1

## REQ-QUIC-RFC9002-S6P2P2P1-0005 Send Handshake probes when keys are available
When the PTO fires, the client MUST send a Handshake packet if it has Handshake keys.

Trace:
- Source Refs:
  - RFC 9002 §6.2.2.1 RFC9002-S6.2.2.1-B4-P3-S3
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.2.1

## REQ-QUIC-RFC9002-S6P2P2P1-0006 Send Initial probes otherwise
When the PTO fires and the client does not have Handshake keys, it MUST send an Initial packet in a UDP datagram with a payload of at least 1200 bytes.

Trace:
- Source Refs:
  - RFC 9002 §6.2.2.1 RFC9002-S6.2.2.1-B4-P3-S3
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.2.1

## REQ-QUIC-RFC9002-S6P2P3-0001 Permit early CRYPTO probes for handshake speedup
To speed up handshake completion under these conditions, an endpoint MAY, for a limited number of times per connection, send a packet containing unacknowledged CRYPTO data earlier than PTO expiry, subject to the address-validation limits.

Trace:
- Source Refs:
  - RFC 9002 §6.2.3 RFC9002-S6.2.3-B3-P2-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.3

## REQ-QUIC-RFC9002-S6P2P4-0001 Probe with at least one ack-eliciting packet
When a PTO timer expires, a sender MUST send at least one ack-eliciting packet in the packet number space as a probe.

Trace:
- Source Refs:
  - RFC 9002 §6.2.4 RFC9002-S6.2.4-B2-P1-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.4

## REQ-QUIC-RFC9002-S6P2P4-0002 Allow two full-sized PTO datagrams
An endpoint MAY send up to two full-sized datagrams containing ack-eliciting packets to avoid an expensive consecutive PTO expiration due to a single lost datagram or to transmit data from multiple packet number spaces.

Trace:
- Source Refs:
  - RFC 9002 §6.2.4 RFC9002-S6.2.4-B2-P1-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.4

## REQ-QUIC-RFC9002-S6P2P4-0003 Keep PTO probe packets ack-eliciting
All probe packets sent on a PTO MUST be ack-eliciting.

Trace:
- Source Refs:
  - RFC 9002 §6.2.4 RFC9002-S6.2.4-B2-P1-S3
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.4

## REQ-QUIC-RFC9002-S6P2P4-0004 Use other packet number spaces for PTO probes
In addition to sending data in the packet number space for which the timer expired, the sender SHOULD send ack-eliciting packets from other packet number spaces with in-flight data, coalescing packets if possible.

Trace:
- Source Refs:
  - RFC 9002 §6.2.4 RFC9002-S6.2.4-B3-P2-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.4

## REQ-QUIC-RFC9002-S6P2P4-0005 Include new data in PTO probes
An endpoint SHOULD include new data in packets that are sent on PTO expiration.

Trace:
- Source Refs:
  - RFC 9002 §6.2.4 RFC9002-S6.2.4-B5-P4-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.4

## REQ-QUIC-RFC9002-S6P2P4-0006 Allow previously sent data in PTO probes
Previously sent data MAY be sent if no new data can be sent.

Trace:
- Source Refs:
  - RFC 9002 §6.2.4 RFC9002-S6.2.4-B5-P4-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.4

## REQ-QUIC-RFC9002-S6P2P4-0007 Allow alternative probe-content strategies
Implementations MAY use alternative strategies for determining the content of probe packets, including sending new or retransmitted data based on the application's priorities.

Trace:
- Source Refs:
  - RFC 9002 §6.2.4 RFC9002-S6.2.4-B5-P4-S3
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.4

## REQ-QUIC-RFC9002-S6P2P4-0008 Send a PING when no probe data exists
When there is no data to send, the sender SHOULD send a PING or other ack-eliciting frame in a single packet, rearming the PTO timer.

Trace:
- Source Refs:
  - RFC 9002 §6.2.4 RFC9002-S6.2.4-B6-P5-S3
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.4

## REQ-QUIC-RFC9002-S6P2P4-0009 Allow declaring in-flight packets lost instead of probing
Instead of sending an ack-eliciting packet, the sender MAY mark any packets still in flight as lost.

Trace:
- Source Refs:
  - RFC 9002 §6.2.4 RFC9002-S6.2.4-B7-P6-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.4

## REQ-QUIC-RFC9002-S6P3-0001 Reject Retry as an acknowledgment
A Retry packet MUST NOT be treated as an acknowledgment.

Trace:
- Source Refs:
  - RFC 9002 §6.3 RFC9002-S6.3-B2-P1-S3
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.3

## REQ-QUIC-RFC9002-S6P3-0002 Reset recovery and congestion state on Retry
Clients that receive a Retry packet MUST reset congestion control and loss recovery state, including any pending timers.

Trace:
- Source Refs:
  - RFC 9002 §6.3 RFC9002-S6.3-B3-P2-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.3

## REQ-QUIC-RFC9002-S6P3-0003 Retain cryptographic handshake state across Retry
Clients MUST retain other connection state, in particular cryptographic handshake messages.

Trace:
- Source Refs:
  - RFC 9002 §6.3 RFC9002-S6.3-B3-P2-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.3

## REQ-QUIC-RFC9002-S6P3-0004 Permit RTT estimation from Retry timing
The client MAY compute an RTT estimate to the server as the time period from when the first Initial packet was sent to when a Retry or Version Negotiation packet is received.

Trace:
- Source Refs:
  - RFC 9002 §6.3 RFC9002-S6.3-B4-P3-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.3

## REQ-QUIC-RFC9002-S6P3-0005 Allow using Retry-derived RTT as the initial RTT
The client MAY use this value in place of its default for the initial RTT estimate.

Trace:
- Source Refs:
  - RFC 9002 §6.3 RFC9002-S6.3-B4-P3-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.3

## REQ-QUIC-RFC9002-S6P4-0001 Discard recovery state when protection keys go away
The sender MUST discard all recovery state associated with packets sent with discarded Initial or Handshake keys.

Trace:
- Source Refs:
  - RFC 9002 §6.4 RFC9002-S6.4-B2-P1-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.4

## REQ-QUIC-RFC9002-S6P4-0002 Remove discarded packets from bytes in flight
The sender MUST remove those packets from the count of bytes in flight.

Trace:
- Source Refs:
  - RFC 9002 §6.4 RFC9002-S6.4-B2-P1-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.4

## REQ-QUIC-RFC9002-S6P4-0003 Discard recovery state for rejected 0-RTT packets
An endpoint MUST discard recovery state for all in-flight 0-RTT packets when 0-RTT is rejected.

Trace:
- Source Refs:
  - RFC 9002 §6.4 RFC9002-S6.4-B4-P3-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.4

## REQ-QUIC-RFC9002-S6P4-0004 Discard secrets as soon as the replacement keys exist
Initial and Handshake secrets MUST be discarded as soon as Handshake and 1-RTT keys are proven to be available to both client and server.

Trace:
- Source Refs:
  - RFC 9002 §6.4 RFC9002-S6.4-B6-P5-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-6.4

## REQ-QUIC-RFC9002-S7-0001 Require alternate controllers to obey RFC 8085
If a sender uses a different controller than the one specified in this document, the chosen controller MUST conform to the congestion-control guidelines in Section 3.1 of RFC 8085.

Trace:
- Source Refs:
  - RFC 9002 §7 RFC9002-S7-B4-P3-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7

## REQ-QUIC-RFC9002-S7-0002 Exclude ACK-only packets from bytes in flight
Packets containing only ACK frames MUST NOT count toward bytes in flight.

Trace:
- Source Refs:
  - RFC 9002 §7 RFC9002-S7-B5-P4-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7

## REQ-QUIC-RFC9002-S7-0003 Exclude ACK-only packets from congestion control
Packets containing only ACK frames MUST NOT be congestion controlled.

Trace:
- Source Refs:
  - RFC 9002 §7 RFC9002-S7-B5-P4-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7

## REQ-QUIC-RFC9002-S7-0004 Allow ACK-only loss signals to influence control
QUIC MAY use loss of ACK-only packets to adjust the congestion controller or the rate of ACK-only packets being sent.

Trace:
- Source Refs:
  - RFC 9002 §7 RFC9002-S7-B5-P4-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7

## REQ-QUIC-RFC9002-S7-0005 Keep congestion control per path
The congestion controller MUST be per path, so packets sent on other paths do not alter the current path's congestion controller.

Trace:
- Source Refs:
  - RFC 9002 §7 RFC9002-S7-B6-P5-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7

## REQ-QUIC-RFC9002-S7-0006 Respect the bytes-in-flight ceiling
An endpoint MUST NOT send a packet if it would cause bytes_in_flight to be larger than the congestion window, unless the packet is sent on a PTO timer expiration or when entering recovery.

Trace:
- Source Refs:
  - RFC 9002 §7 RFC9002-S7-B8-P7-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7

## REQ-QUIC-RFC9002-S7P1-0001 Treat ECN CE as congestion on validated paths
If a path has been validated to support ECN, QUIC MUST treat a CE codepoint in the IP header as a signal of congestion.

Trace:
- Source Refs:
  - RFC 9002 §7.1 RFC9002-S7.1-B2-P1-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.1

## REQ-QUIC-RFC9002-S7P2-0001 Start each connection in slow start
QUIC MUST begin every connection in slow start with the congestion window set to an initial value.

Trace:
- Source Refs:
  - RFC 9002 §7.2 RFC9002-S7.2-B2-P1-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.2

## REQ-QUIC-RFC9002-S7P2-0002 Recommend the initial congestion window
Endpoints SHOULD use an initial congestion window of ten times the maximum datagram size while limiting the window to the larger of 14,720 bytes or twice the maximum datagram size.

Trace:
- Source Refs:
  - RFC 9002 §7.2 RFC9002-S7.2-B2-P1-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.2

## REQ-QUIC-RFC9002-S7P2-0003 Recompute the initial window when datagram size changes
If the maximum datagram size changes during the connection, the initial congestion window SHOULD be recalculated with the new size.

Trace:
- Source Refs:
  - RFC 9002 §7.2 RFC9002-S7.2-B3-P2-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.2

## REQ-QUIC-RFC9002-S7P2-0004 Reset the initial window after handshake-driven MTU reduction
If the maximum datagram size is decreased in order to complete the handshake, the congestion window SHOULD be set to the new initial congestion window.

Trace:
- Source Refs:
  - RFC 9002 §7.2 RFC9002-S7.2-B3-P2-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.2

## REQ-QUIC-RFC9002-S7P2-0005 Recommend a two-packet minimum congestion window
The minimum congestion window SHOULD be 2 * max_datagram_size.

Trace:
- Source Refs:
  - RFC 9002 §7.2 RFC9002-S7.2-B5-P4-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.2

## REQ-QUIC-RFC9002-S7P3P1-0001 Enter recovery on loss or ECN-CE increase
A sender MUST enter a recovery period when it detects packet loss or when the ECN-CE count reported by its peer increases.

Trace:
- Source Refs:
  - RFC 9002 §7.3.1 RFC9002-S7.3.1-B4-P3-S1
  - RFC 9002 §7.3.2 RFC9002-S7.3.2-B2-P1-S1
  - RFC 9002 §7.3.3 RFC9002-S7.3.3-B4-P3-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.3.1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.3.2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.3.3

## REQ-QUIC-RFC9002-S7P3P1-0002 Enter slow start when the window is below threshold
A NewReno sender MUST be considered in slow start any time the congestion window is below the slow start threshold.

Trace:
- Source Refs:
  - RFC 9002 §7.3.1 RFC9002-S7.3.1-B2-P1-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.3.1

## REQ-QUIC-RFC9002-S7P3P1-0003 Increase cwnd by acknowledged bytes in slow start
While a sender is in slow start, the congestion window MUST increase by the number of bytes acknowledged when each acknowledgment is processed.

Trace:
- Source Refs:
  - RFC 9002 §7.3.1 RFC9002-S7.3.1-B3-P2-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.3.1

## REQ-QUIC-RFC9002-S7P3P2-0001 Stay in recovery once entered
A sender that is already in a recovery period MUST stay in that recovery period.

Trace:
- Source Refs:
  - RFC 9002 §7.3.2 RFC9002-S7.3.2-B2-P1-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.3.2

## REQ-QUIC-RFC9002-S7P3P2-0002 Do not reenter recovery while already there
A sender that is already in a recovery period MUST NOT reenter it.

Trace:
- Source Refs:
  - RFC 9002 §7.3.2 RFC9002-S7.3.2-B2-P1-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.3.2

## REQ-QUIC-RFC9002-S7P3P2-0003 Cut the slow start threshold on recovery entry
On entering a recovery period, a sender MUST set the slow start threshold to half the congestion window when loss is detected.

Trace:
- Source Refs:
  - RFC 9002 §7.3.2 RFC9002-S7.3.2-B3-P2-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.3.2

## REQ-QUIC-RFC9002-S7P3P2-0004 Restore congestion window before leaving recovery
The congestion window MUST be set to the reduced value of the slow start threshold before exiting the recovery period.

Trace:
- Source Refs:
  - RFC 9002 §7.3.2 RFC9002-S7.3.2-B3-P2-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.3.2

## REQ-QUIC-RFC9002-S7P3P2-0005 Permit gentler recovery-window reduction
Implementations MAY reduce the congestion window immediately upon entering a recovery period or use other mechanisms, such as Proportional Rate Reduction, to reduce the congestion window more gradually.

Trace:
- Source Refs:
  - RFC 9002 §7.3.2 RFC9002-S7.3.2-B4-P3-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.3.2

## REQ-QUIC-RFC9002-S7P3P2-0006 Hold the congestion window steady during recovery
During a recovery period, the congestion window MUST NOT change in response to new losses or increases in the ECN-CE count.

Trace:
- Source Refs:
  - RFC 9002 §7.3.2 RFC9002-S7.3.2-B5-P4-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.3.2

## REQ-QUIC-RFC9002-S7P3P2-0007 Leave recovery when a recovery-period packet is acknowledged
A recovery period MUST end and the sender enter congestion avoidance when a packet sent during the recovery period is acknowledged.

Trace:
- Source Refs:
  - RFC 9002 §7.3.2 RFC9002-S7.3.2-B6-P5-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.3.2

## REQ-QUIC-RFC9002-S7P3P3-0001 Remain in congestion avoidance only while the window is above the threshold
A NewReno sender MUST be considered in congestion avoidance any time the congestion window is at or above the slow start threshold and not in a recovery period.

Trace:
- Source Refs:
  - RFC 9002 §7.3.3 RFC9002-S7.3.3-B2-P1-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.3.3

## REQ-QUIC-RFC9002-S7P3P3-0002 Limit congestion-avoidance growth to one datagram per acknowledged window
A sender in congestion avoidance MUST limit the increase to the congestion window to at most one maximum datagram size for each congestion window that is acknowledged.

Trace:
- Source Refs:
  - RFC 9002 §7.3.3 RFC9002-S7.3.3-B3-P2-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.3.3

## REQ-QUIC-RFC9002-S7P4-0001 Ignore undecryptable packet loss before keys are available
Endpoints MAY ignore the loss of Handshake, 0-RTT, and 1-RTT packets that might have arrived before the peer had packet protection keys to process those packets.

Trace:
- Source Refs:
  - RFC 9002 §7.4 RFC9002-S7.4-B2-P1-S3
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.4

## REQ-QUIC-RFC9002-S7P4-0002 Do not ignore later packet loss
Endpoints MUST NOT ignore the loss of packets that were sent after the earliest acknowledged packet in a given packet number space.

Trace:
- Source Refs:
  - RFC 9002 §7.4 RFC9002-S7.4-B2-P1-S4
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.4

## REQ-QUIC-RFC9002-S7P5-0001 Do not block probe packets with congestion control
Probe packets MUST NOT be blocked by the congestion controller.

Trace:
- Source Refs:
  - RFC 9002 §7.5 RFC9002-S7.5-B2-P1-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.5

## REQ-QUIC-RFC9002-S7P5-0002 Count probe packets as additional flight
A sender MUST count these packets as being additionally in flight.

Trace:
- Source Refs:
  - RFC 9002 §7.5 RFC9002-S7.5-B2-P1-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.5

## REQ-QUIC-RFC9002-S7P6-0001 Declare persistent congestion when all long-duration packets are lost
When a sender establishes loss of all packets sent over a long enough duration, the network MUST be considered to be experiencing persistent congestion.

Trace:
- Source Refs:
  - RFC 9002 §7.6 RFC9002-S7.6-B2-P1-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.6

## REQ-QUIC-RFC9002-S7P6P1-0001 Compute persistent congestion duration from RTT and max_ack_delay
The persistent congestion duration MUST be computed as (smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay) * kPersistentCongestionThreshold.

Trace:
- Source Refs:
  - RFC 9002 §7.6.1 RFC9002-S7.6.1-B2-P1-S1
  - RFC 9002 §7.6.1 RFC9002-S7.6.1-B3-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.6.1

## REQ-QUIC-RFC9002-S7P6P1-0002 Include max_ack_delay in persistent congestion duration
Unlike PTO computation, this duration MUST include max_ack_delay irrespective of the packet number spaces in which losses are established.

Trace:
- Source Refs:
  - RFC 9002 §7.6.1 RFC9002-S7.6.1-B4-P2-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.6.1

## REQ-QUIC-RFC9002-S7P6P1-0003 Recommend a persistent congestion threshold of three
The RECOMMENDED value for kPersistentCongestionThreshold SHOULD be 3.

Trace:
- Source Refs:
  - RFC 9002 §7.6.1 RFC9002-S7.6.1-B7-P5-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.6.1

## REQ-QUIC-RFC9002-S7P6P2-0001 Establish persistent congestion after the full loss test passes
A sender MUST establish persistent congestion after receipt of an acknowledgment if two ack-eliciting packets are declared lost and the conditions in the following list are all met.

Trace:
- Source Refs:
  - RFC 9002 §7.6.2 RFC9002-S7.6.2-B2-P1-S1
  - RFC 9002 §7.6.2 RFC9002-S7.6.2-B3-P0-S1
  - RFC 9002 §7.6.2 RFC9002-S7.6.2-B4-P0-S1
  - RFC 9002 §7.6.2 RFC9002-S7.6.2-B5-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.6.2

## REQ-QUIC-RFC9002-S7P6P2-0002 Require the two declared-lost packets to be ack-eliciting
Those two packets MUST be ack-eliciting.

Trace:
- Source Refs:
  - RFC 9002 §7.6.2 RFC9002-S7.6.2-B6-P2-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.6.2

## REQ-QUIC-RFC9002-S7P6P2-0003 Delay persistent congestion until at least one RTT sample exists
Persistent congestion SHOULD NOT start until there is at least one RTT sample.

Trace:
- Source Refs:
  - RFC 9002 §7.6.2 RFC9002-S7.6.2-B7-P3-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.6.2

## REQ-QUIC-RFC9002-S7P6P2-0004 Consider packet number spaces when declaring persistent congestion
Persistent congestion SHOULD consider packets sent across packet number spaces.

Trace:
- Source Refs:
  - RFC 9002 §7.6.2 RFC9002-S7.6.2-B8-P4-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.6.2

## REQ-QUIC-RFC9002-S7P6P2-0005 Allow limited packet-number-space state when necessary
A sender that does not have state for all packet number spaces or cannot compare send times across packet number spaces MAY use state for just the packet number space that was acknowledged.

Trace:
- Source Refs:
  - RFC 9002 §7.6.2 RFC9002-S7.6.2-B8-P4-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.6.2

## REQ-QUIC-RFC9002-S7P6P2-0006 Reset cwnd to the minimum on persistent congestion
When persistent congestion is declared, the sender's congestion window MUST be reduced to the minimum congestion window.

Trace:
- Source Refs:
  - RFC 9002 §7.6.2 RFC9002-S7.6.2-B9-P5-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.6.2

## REQ-QUIC-RFC9002-S7P7-0001 Pace all in-flight packets
A sender SHOULD pace sending of all in-flight packets based on input from the congestion controller.

Trace:
- Source Refs:
  - RFC 9002 §7.7 RFC9002-S7.7-B2-P1-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.7

## REQ-QUIC-RFC9002-S7P7-0002 Either pace or cap bursts
Senders MUST either use pacing or limit such bursts.

Trace:
- Source Refs:
  - RFC 9002 §7.7 RFC9002-S7.7-B3-P2-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.7

## REQ-QUIC-RFC9002-S7P7-0003 Limit bursts to the initial congestion window
Senders SHOULD limit bursts to the initial congestion window.

Trace:
- Source Refs:
  - RFC 9002 §7.7 RFC9002-S7.7-B3-P2-S3
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.7

## REQ-QUIC-RFC9002-S7P7-0004 Allow larger bursts when the path can absorb them
A sender with knowledge that the network path can absorb larger bursts MAY use a higher limit.

Trace:
- Source Refs:
  - RFC 9002 §7.7 RFC9002-S7.7-B3-P2-S4
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.7

## REQ-QUIC-RFC9002-S7P7-0005 Do not pace pure ACK packets
Packets containing only ACK frames SHOULD therefore not be paced.

Trace:
- Source Refs:
  - RFC 9002 §7.7 RFC9002-S7.7-B5-P4-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.7

## REQ-QUIC-RFC9002-S7P8-0001 Do not increase cwnd when underutilized
When bytes in flight is smaller than the congestion window and sending is not pacing limited, the congestion window SHOULD NOT be increased in either slow start or congestion avoidance.

Trace:
- Source Refs:
  - RFC 9002 §7.8 RFC9002-S7.8-B2-P1-S3
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.8

## REQ-QUIC-RFC9002-S7P8-0002 Do not call yourself application-limited because of pacing delay
A sender SHOULD NOT consider itself application limited if it would have fully utilized the congestion window without pacing delay.

Trace:
- Source Refs:
  - RFC 9002 §7.8 RFC9002-S7.8-B3-P2-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.8

## REQ-QUIC-RFC9002-S7P8-0003 Allow alternate cwnd-updating mechanisms after underutilization
A sender MAY implement alternative mechanisms to update its congestion window after periods of underutilization, such as those proposed for TCP in RFC 7661.

Trace:
- Source Refs:
  - RFC 9002 §7.8 RFC9002-S7.8-B4-P3-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-7.8

## REQ-QUIC-RFC9002-SAP1-0001 Track ack-eliciting packets until resolution
A QUIC sender MUST track every ack-eliciting packet until the packet is acknowledged or lost.

Trace:
- Source Refs:
  - RFC 9002 §A.1 RFC9002-SA.1-B2-P1-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.1

## REQ-QUIC-RFC9002-SAP1-0002 Index tracked packet state by packet number and crypto context
Implementations MUST be able to access tracked packet information by packet number and crypto context.

Trace:
- Source Refs:
  - RFC 9002 §A.1 RFC9002-SA.1-B2-P1-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.1

## REQ-QUIC-RFC9002-SAP1-0003 Store per-packet recovery fields
Implementations MUST store the per-packet fields needed for loss recovery and congestion control.

Trace:
- Source Refs:
  - RFC 9002 §A.1 RFC9002-SA.1-B2-P1-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.1

## REQ-QUIC-RFC9002-SAP1-0004 Allow retained state for lost packets
An endpoint MAY retain state for a packet after it is declared lost for a limited time to allow for packet reordering.

Trace:
- Source Refs:
  - RFC 9002 §A.1 RFC9002-SA.1-B3-P2-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.1

## REQ-QUIC-RFC9002-SAP1-0005 Track sent packets per packet number space
Sent packets MUST be tracked separately for each packet number space.

Trace:
- Source Refs:
  - RFC 9002 §A.1 RFC9002-SA.1-B4-P3-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.1

## REQ-QUIC-RFC9002-SAP1-0006 Limit ACK processing to one packet number space
ACK processing MUST apply to a single packet number space.

Trace:
- Source Refs:
  - RFC 9002 §A.1 RFC9002-SA.1-B4-P3-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.1

## REQ-QUIC-RFC9002-SAP1P1-0001 Record packet numbers in sent-packet state
The sent-packet record MUST include the packet number of the sent packet.

Trace:
- Source Refs:
  - RFC 9002 §A.1.1 RFC9002-SA.1.1-B2-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.1.1

## REQ-QUIC-RFC9002-SAP1P1-0002 Record ACK-eliciting status in sent-packet state
The sent-packet record MUST include a Boolean that indicates whether the packet is ack-eliciting.

Trace:
- Source Refs:
  - RFC 9002 §A.1.1 RFC9002-SA.1.1-B3-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.1.1

## REQ-QUIC-RFC9002-SAP1P1-0003 Record bytes-in-flight participation in sent-packet state
The sent-packet record MUST include a Boolean that indicates whether the packet counts toward bytes in flight.

Trace:
- Source Refs:
  - RFC 9002 §A.1.1 RFC9002-SA.1.1-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.1.1

## REQ-QUIC-RFC9002-SAP1P1-0004 Record sent bytes in sent-packet state
The sent-packet record MUST include the number of bytes sent in the packet, excluding UDP and IP overhead but including QUIC framing overhead.

Trace:
- Source Refs:
  - RFC 9002 §A.1.1 RFC9002-SA.1.1-B5-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.1.1

## REQ-QUIC-RFC9002-SAP1P1-0005 Record packet send time in sent-packet state
The sent-packet record MUST include the time the packet was sent.

Trace:
- Source Refs:
  - RFC 9002 §A.1.1 RFC9002-SA.1.1-B6-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.1.1

## REQ-QUIC-RFC9002-SAP2-0001 Use the recommended packet-threshold value
kPacketThreshold SHOULD be 3.

Trace:
- Source Refs:
  - RFC 9002 §A.2 RFC9002-SA.2-B3-P0-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.2

## REQ-QUIC-RFC9002-SAP2-0002 Use the recommended time-threshold value
kTimeThreshold SHOULD be 9/8.

Trace:
- Source Refs:
  - RFC 9002 §A.2 RFC9002-SA.2-B4-P0-S3
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.2

## REQ-QUIC-RFC9002-SAP2-0003 Use the recommended timer granularity
kGranularity SHOULD be 1 millisecond.

Trace:
- Source Refs:
  - RFC 9002 §A.2 RFC9002-SA.2-B5-P0-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.2

## REQ-QUIC-RFC9002-SAP2-0004 Use the recommended initial RTT
kInitialRtt SHOULD be 333 milliseconds.

Trace:
- Source Refs:
  - RFC 9002 §A.2 RFC9002-SA.2-B6-P0-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.2

## REQ-QUIC-RFC9002-SAP2-0005 Enumerate the three packet number spaces
The packet number space enumeration MUST include Initial, Handshake, and ApplicationData.

Trace:
- Source Refs:
  - RFC 9002 §A.2 RFC9002-SA.2-B7-P0-S1
  - RFC 9002 §A.2 RFC9002-SA.2-B8-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.2

## REQ-QUIC-RFC9002-SAP4-0001 Initialize loss detection state at connection start
At the beginning of a connection, the loss detection state MUST be initialized by resetting the loss detection timer, setting pto_count to 0, setting latest_rtt to 0, setting smoothed_rtt to kInitialRtt, setting rttvar to kInitialRtt / 2, setting min_rtt to 0, setting first_rtt_sample to 0, and initializing the per-packet-number-space tracking state.

Trace:
- Source Refs:
  - RFC 9002 §A.4 RFC9002-SA.4-B2-P1-S1
  - RFC 9002 §A.4 RFC9002-SA.4-B3-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.4

## REQ-QUIC-RFC9002-SAP5-0001 Store packet metadata when sending
When a packet is sent, the sender MUST store its packet number, send time, ack-eliciting flag, in_flight flag, and sent_bytes in sent_packets[pn_space][packet_number].

Trace:
- Source Refs:
  - RFC 9002 §A.5 RFC9002-SA.5-B2-P1-S1
  - RFC 9002 §A.5 RFC9002-SA.5-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.5

## REQ-QUIC-RFC9002-SAP5-0002 Update last ack-eliciting send time for in-flight ack-eliciting packets
When a sent packet is in flight and ack-eliciting, the sender MUST update time_of_last_ack_eliciting_packet[pn_space] to now().

Trace:
- Source Refs:
  - RFC 9002 §A.5 RFC9002-SA.5-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.5

## REQ-QUIC-RFC9002-SAP5-0003 Account sent bytes and refresh the loss timer on send
When a sent packet is in flight, the sender MUST account for `sent_bytes` in congestion control and set the loss detection timer.

Trace:
- Source Refs:
  - RFC 9002 §A.5 RFC9002-SA.5-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.5

## REQ-QUIC-RFC9002-SAP6-0001 Rearm the loss detection timer when datagram receipt unblocks amplification
If receiving a datagram unblocks the server from anti-amplification limits, the endpoint MUST set the loss detection timer.

Trace:
- Source Refs:
  - RFC 9002 §A.6 RFC9002-SA.6-B2-P1-S1
  - RFC 9002 §A.6 RFC9002-SA.6-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.6

## REQ-QUIC-RFC9002-SAP6-0002 Process an expired timer after amplification blocking
If the loss detection timer would already have expired while the anti-amplification limit was applied, the endpoint MUST process the timeout immediately.

Trace:
- Source Refs:
  - RFC 9002 §A.6 RFC9002-SA.6-B2-P1-S2
  - RFC 9002 §A.6 RFC9002-SA.6-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.6

## REQ-QUIC-RFC9002-SAP7-0001 Update the largest acknowledged packet per space
When an ACK frame is received, the sender MUST update largest_acked_packet[pn_space] to the larger of its current value and ack.largest_acked.

Trace:
- Source Refs:
  - RFC 9002 §A.7 RFC9002-SA.7-B2-P1-S1
  - RFC 9002 §A.7 RFC9002-SA.7-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.7

## REQ-QUIC-RFC9002-SAP7-0002 Remove newly acknowledged packets before further ACK processing
When an ACK frame is received, the sender MUST remove newly acknowledged packets from `sent_packets` and return without further action if there are no newly acknowledged packets.

Trace:
- Source Refs:
  - RFC 9002 §A.7 RFC9002-SA.7-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.7

## REQ-QUIC-RFC9002-SAP7-0003 Update RTT only for newly acknowledged ack-eliciting packets
When the largest newly acknowledged packet is ack.largest_acked and at least one newly acknowledged packet is ack-eliciting, the sender MUST update latest_rtt and then update RTT estimates using ack_delay.

Trace:
- Source Refs:
  - RFC 9002 §A.7 RFC9002-SA.7-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.7

## REQ-QUIC-RFC9002-SAP7-0004 Process ECN and loss state on acknowledgment
When an ACK frame carries ECN information, the sender MUST process it, detect and remove newly lost packets, pass any lost packets to `OnPacketsLost`, and pass newly acknowledged packets to `OnPacketsAcked`.

Trace:
- Source Refs:
  - RFC 9002 §A.7 RFC9002-SA.7-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.7

## REQ-QUIC-RFC9002-SAP7-0005 Reset PTO backoff after validated acknowledgment
If peer address validation is complete, the sender MUST reset pto_count to 0 after processing acknowledgments.

Trace:
- Source Refs:
  - RFC 9002 §A.7 RFC9002-SA.7-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.7

## REQ-QUIC-RFC9002-SAP7-0006 Refresh the loss detection timer after acknowledgment processing
After processing an ACK frame, the sender MUST set the loss detection timer.

Trace:
- Source Refs:
  - RFC 9002 §A.7 RFC9002-SA.7-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.7

## REQ-QUIC-RFC9002-SAP7-0007 Initialize RTT estimation on the first sample
On the first RTT sample, the endpoint MUST set min_rtt to latest_rtt, smoothed_rtt to latest_rtt, rttvar to latest_rtt / 2, and first_rtt_sample to now().

Trace:
- Source Refs:
  - RFC 9002 §A.7 RFC9002-SA.7-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.7

## REQ-QUIC-RFC9002-SAP7-0008 Update min_rtt and cap ack delay after handshake confirmation
On later RTT samples, the endpoint MUST update `min_rtt` to the lesser of `min_rtt` and `latest_rtt`, and after handshake confirmation cap `ack_delay` at `max_ack_delay`.

Trace:
- Source Refs:
  - RFC 9002 §A.7 RFC9002-SA.7-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.7

## REQ-QUIC-RFC9002-SAP7-0009 Update RTT estimates from adjusted RTT samples
On later RTT samples, the endpoint MUST use `latest_rtt - ack_delay` when `latest_rtt` is at least `min_rtt + ack_delay`, otherwise use `latest_rtt`, and then update `rttvar` and `smoothed_rtt` using the weighted averages in the appendix pseudocode.

Trace:
- Source Refs:
  - RFC 9002 §A.7 RFC9002-SA.7-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.7

## REQ-QUIC-RFC9002-SAP8-0001 Return the earliest pending loss time
GetLossTimeAndSpace MUST return the earliest nonzero loss_time across the packet number spaces together with the corresponding packet number space.

Trace:
- Source Refs:
  - RFC 9002 §A.8 RFC9002-SA.8-B5-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.8

## REQ-QUIC-RFC9002-SAP8-0002 Start PTO timing from now when no ack-eliciting packets are in flight
If no ack-eliciting packets are in flight, GetPtoTimeAndSpace MUST start PTO timing from now() + duration and select Handshake when handshake keys exist, otherwise Initial.

Trace:
- Source Refs:
  - RFC 9002 §A.8 RFC9002-SA.8-B5-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.8

## REQ-QUIC-RFC9002-SAP8-0003 Suppress Application Data PTO until handshake confirmation
GetPtoTimeAndSpace MUST skip Application Data until the handshake is confirmed.

Trace:
- Source Refs:
  - RFC 9002 §A.8 RFC9002-SA.8-B5-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.8

## REQ-QUIC-RFC9002-SAP8-0004 Include max_ack_delay and backoff in Application Data PTO
When computing Application Data PTO, the sender MUST include max_ack_delay and exponential backoff.

Trace:
- Source Refs:
  - RFC 9002 §A.8 RFC9002-SA.8-B5-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.8

## REQ-QUIC-RFC9002-SAP8-0005 Complete address validation for servers and validated clients
`PeerCompletedAddressValidation` MUST return true for servers and for clients only after a Handshake ACK has been received or the handshake has been confirmed.

Trace:
- Source Refs:
  - RFC 9002 §A.8 RFC9002-SA.8-B5-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.8

## REQ-QUIC-RFC9002-SAP8-0006 Set or cancel the loss detection timer according to loss and PTO state
`SetLossDetectionTimer` MUST update the timer to the earliest pending loss time when one exists, cancel the timer when the server is at the anti-amplification limit or when no ack-eliciting packets are in flight and peer address validation is complete, and otherwise update the timer to the PTO timeout.

Trace:
- Source Refs:
  - RFC 9002 §A.8 RFC9002-SA.8-B5-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.8

## REQ-QUIC-RFC9002-SAP9-0001 Handle timeout-driven loss detection first
When the loss detection timer expires and an earliest loss time exists, the endpoint MUST detect lost packets in that packet number space, assert that the lost-packet list is nonempty, pass the lost packets to `OnPacketsLost`, refresh the timer, and return.

Trace:
- Source Refs:
  - RFC 9002 §A.9 RFC9002-SA.9-B2-P1-S1
  - RFC 9002 §A.9 RFC9002-SA.9-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.9

## REQ-QUIC-RFC9002-SAP9-0002 Send anti-deadlock probes when nothing is in flight
When no ack-eliciting packets are in flight, the endpoint MUST send a Handshake packet if it has Handshake keys; otherwise send a padded Initial packet.

Trace:
- Source Refs:
  - RFC 9002 §A.9 RFC9002-SA.9-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.9

## REQ-QUIC-RFC9002-SAP9-0003 Use PTO to send data or PING probes
When the timer expires because of PTO rather than loss detection, the sender MUST send new data if available, otherwise retransmit old data, and if neither is available send a single PING frame.

Trace:
- Source Refs:
  - RFC 9002 §A.9 RFC9002-SA.9-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.9

## REQ-QUIC-RFC9002-SAP9-0004 Probe with one or two ack-eliciting packets on PTO
When PTO fires, the sender MUST send one or two ack-eliciting packets in the selected packet number space.

Trace:
- Source Refs:
  - RFC 9002 §A.9 RFC9002-SA.9-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.9

## REQ-QUIC-RFC9002-SAP9-0005 Increase PTO backoff after timeout handling
When PTO fires, the sender MUST increment `pto_count` and refresh the loss detection timer.

Trace:
- Source Refs:
  - RFC 9002 §A.9 RFC9002-SA.9-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.9

## REQ-QUIC-RFC9002-SAP10-0001 Require a known largest acknowledged packet for loss detection
DetectAndRemoveLostPackets MUST only run when largest_acked_packet[pn_space] is known.

Trace:
- Source Refs:
  - RFC 9002 §A.10 RFC9002-SA.10-B2-P1-S1
  - RFC 9002 §A.10 RFC9002-SA.10-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.10

## REQ-QUIC-RFC9002-SAP10-0002 Compute the loss delay from RTT and timer granularity
`DetectAndRemoveLostPackets` MUST compute `loss_delay` as `kTimeThreshold` times the larger of `latest_rtt` and `smoothed_rtt`, and not let `loss_delay` fall below `kGranularity`.

Trace:
- Source Refs:
  - RFC 9002 §A.10 RFC9002-SA.10-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.10

## REQ-QUIC-RFC9002-SAP10-0003 Remove lost packets and schedule future loss marking
`DetectAndRemoveLostPackets` MUST remove packets that are sufficiently old or sufficiently behind the largest acknowledged packet from `sent_packets`, report them lost, and schedule `loss_time` for packets that are not yet lost.

Trace:
- Source Refs:
  - RFC 9002 §A.10 RFC9002-SA.10-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.10

## REQ-QUIC-RFC9002-SAP10-0004 Skip packets beyond the largest acknowledged packet
DetectAndRemoveLostPackets MUST ignore packets whose packet number is greater than largest_acked_packet[pn_space].

Trace:
- Source Refs:
  - RFC 9002 §A.10 RFC9002-SA.10-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.10

## REQ-QUIC-RFC9002-SAP11-0001 Discard packets in the lost space when keys are dropped
When Initial or Handshake keys are discarded, the endpoint MUST discard packets in that space and update loss detection state.

Trace:
- Source Refs:
  - RFC 9002 §A.11 RFC9002-SA.11-B2-P1-S1
  - RFC 9002 §A.11 RFC9002-SA.11-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.11

## REQ-QUIC-RFC9002-SAP11-0002 Remove discarded packets from bytes in flight and sent-packet state
When Initial or Handshake keys are discarded, the sender MUST remove the discarded packets from bytes in flight and clear `sent_packets` for that packet number space.

Trace:
- Source Refs:
  - RFC 9002 §A.11 RFC9002-SA.11-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.11

## REQ-QUIC-RFC9002-SAP11-0003 Reset timer state when keys are discarded
When Initial or Handshake keys are discarded, the sender MUST reset `time_of_last_ack_eliciting_packet[pn_space]`, `loss_time[pn_space]`, and `pto_count`, and set the loss detection timer.

Trace:
- Source Refs:
  - RFC 9002 §A.11 RFC9002-SA.11-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-a.11

## REQ-QUIC-RFC9002-SBP1-0001 Use the recommended loss reduction factor
kLossReductionFactor SHOULD be 0.5.

Trace:
- Source Refs:
  - RFC 9002 §B.1 RFC9002-SB.1-B5-P0-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.1

## REQ-QUIC-RFC9002-SBP1-0002 Use the recommended persistent congestion threshold
kPersistentCongestionThreshold SHOULD be 3.

Trace:
- Source Refs:
  - RFC 9002 §B.1 RFC9002-SB.1-B6-P0-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.1

## REQ-QUIC-RFC9002-SBP2-0001 Set the maximum datagram size from path MTU
The sender MUST set `max_datagram_size` based on its Path Maximum Transmission Unit and not use a value below 1200 bytes.

Trace:
- Source Refs:
  - RFC 9002 §B.2 RFC9002-SB.2-B3-P0-S1
  - RFC 9002 §B.2 RFC9002-SB.2-B3-P0-S4
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.2

## REQ-QUIC-RFC9002-SBP2-0002 Count eligible packets in bytes in flight
bytes_in_flight MUST count sent packets that contain at least one ack-eliciting or PADDING frame and have not been acknowledged or declared lost.

Trace:
- Source Refs:
  - RFC 9002 §B.2 RFC9002-SB.2-B5-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.2

## REQ-QUIC-RFC9002-SBP2-0003 Exclude transport overhead from bytes in flight
bytes_in_flight accounting MUST exclude IP and UDP overhead but include the QUIC header and AEAD overhead.

Trace:
- Source Refs:
  - RFC 9002 §B.2 RFC9002-SB.2-B5-P0-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.2

## REQ-QUIC-RFC9002-SBP2-0004 Exclude ACK-only packets from bytes in flight
Packets containing only ACK frames MUST NOT count toward bytes_in_flight.

Trace:
- Source Refs:
  - RFC 9002 §B.2 RFC9002-SB.2-B5-P0-S3
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.2

## REQ-QUIC-RFC9002-SBP2-0005 Track ECN-CE counters per packet number space
The sender MUST track the highest ECN-CE counter value reported by the peer for each packet number space.

Trace:
- Source Refs:
  - RFC 9002 §B.2 RFC9002-SB.2-B4-P0-S1
  - RFC 9002 §B.2 RFC9002-SB.2-B4-P0-S2
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.2

## REQ-QUIC-RFC9002-SBP3-0001 Initialize congestion control state at connection start
At the beginning of a connection, the congestion control state MUST be initialized by setting congestion_window to kInitialWindow, bytes_in_flight to 0, congestion_recovery_start_time to 0, ssthresh to infinite, and each ECN-CE counter to 0.

Trace:
- Source Refs:
  - RFC 9002 §B.3 RFC9002-SB.3-B2-P1-S1
  - RFC 9002 §B.3 RFC9002-SB.3-B3-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.3

## REQ-QUIC-RFC9002-SBP4-0001 Increase bytes in flight when sending non-ACK packets
Whenever a packet containing non-ACK frames is sent, the sender MUST increase bytes_in_flight by sent_bytes.

Trace:
- Source Refs:
  - RFC 9002 §B.4 RFC9002-SB.4-B2-P1-S1
  - RFC 9002 §B.4 RFC9002-SB.4-B3-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.4

## REQ-QUIC-RFC9002-SBP5-0001 Ignore acknowledgments for packets not in flight
On packet acknowledgment, the sender MUST ignore packets that are not in flight.

Trace:
- Source Refs:
  - RFC 9002 §B.5 RFC9002-SB.5-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.5

## REQ-QUIC-RFC9002-SBP5-0002 Remove acknowledged bytes from bytes in flight
On packet acknowledgment, the sender MUST subtract the packet's sent_bytes from bytes_in_flight.

Trace:
- Source Refs:
  - RFC 9002 §B.5 RFC9002-SB.5-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.5

## REQ-QUIC-RFC9002-SBP5-0003 Suppress window growth when application or flow control is limiting
On packet acknowledgment, the sender MUST NOT increase congestion_window when the sender is application limited or flow-control limited.

Trace:
- Source Refs:
  - RFC 9002 §B.5 RFC9002-SB.5-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.5

## REQ-QUIC-RFC9002-SBP5-0004 Suppress window growth during recovery
On packet acknowledgment, the sender MUST NOT increase congestion_window for packets acknowledged during a recovery period.

Trace:
- Source Refs:
  - RFC 9002 §B.5 RFC9002-SB.5-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.5

## REQ-QUIC-RFC9002-SBP5-0005 Grow the congestion window by acknowledged bytes in slow start
While in slow start, the sender MUST increase congestion_window by the number of acknowledged bytes.

Trace:
- Source Refs:
  - RFC 9002 §B.5 RFC9002-SB.5-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.5

## REQ-QUIC-RFC9002-SBP5-0006 Grow the congestion window proportionally in congestion avoidance
While in congestion avoidance, the sender MUST increase congestion_window by max_datagram_size multiplied by the acknowledged bytes and divided by congestion_window.

Trace:
- Source Refs:
  - RFC 9002 §B.5 RFC9002-SB.5-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.5

## REQ-QUIC-RFC9002-SBP6-0001 Ignore congestion events while already in recovery
If the sender is already in a recovery period, a new congestion event MUST have no effect.

Trace:
- Source Refs:
  - RFC 9002 §B.6 RFC9002-SB.6-B2-P1-S1
  - RFC 9002 §B.6 RFC9002-SB.6-B3-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.6

## REQ-QUIC-RFC9002-SBP6-0002 Enter recovery and reduce the congestion window on a congestion event
When a new congestion event is detected, the sender MUST set `congestion_recovery_start_time` to `now()`, set `ssthresh` to `congestion_window * kLossReductionFactor`, and set `congestion_window` to the larger of `ssthresh` and `kMinimumWindow`.

Trace:
- Source Refs:
  - RFC 9002 §B.6 RFC9002-SB.6-B2-P1-S2
  - RFC 9002 §B.6 RFC9002-SB.6-B3-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.6

## REQ-QUIC-RFC9002-SBP6-0003 Allow one extra packet to speed recovery
When a new congestion event is detected, the sender MAY send one packet to speed up loss recovery.

Trace:
- Source Refs:
  - RFC 9002 §B.6 RFC9002-SB.6-B3-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.6

## REQ-QUIC-RFC9002-SBP7-0001 Treat increased ECN-CE counts as congestion
When the peer-reported ECN-CE counter increases, the sender MUST treat the change as a new congestion event and update the stored ECN-CE counter.

Trace:
- Source Refs:
  - RFC 9002 §B.7 RFC9002-SB.7-B2-P1-S1
  - RFC 9002 §B.7 RFC9002-SB.7-B3-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.7

## REQ-QUIC-RFC9002-SBP7-0002 Use the largest acknowledged packet time for ECN signaling
When signaling congestion from ECN information, the sender MUST use the send time of the largest acknowledged packet in the packet number space.

Trace:
- Source Refs:
  - RFC 9002 §B.7 RFC9002-SB.7-B3-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.7

## REQ-QUIC-RFC9002-SBP8-0001 Remove in-flight lost packets from bytes in flight
When packets are declared lost, the sender MUST remove any in-flight lost packets from bytes_in_flight.

Trace:
- Source Refs:
  - RFC 9002 §B.8 RFC9002-SB.8-B2-P1-S1
  - RFC 9002 §B.8 RFC9002-SB.8-B3-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.8

## REQ-QUIC-RFC9002-SBP8-0002 Trigger congestion response on loss of in-flight packets
If any in-flight packet was lost, the sender MUST invoke the congestion event logic using the latest loss send time.

Trace:
- Source Refs:
  - RFC 9002 §B.8 RFC9002-SB.8-B3-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.8

## REQ-QUIC-RFC9002-SBP8-0003 Defer persistent congestion checks until an RTT sample exists
The sender MUST NOT evaluate persistent congestion until first_rtt_sample is nonzero.

Trace:
- Source Refs:
  - RFC 9002 §B.8 RFC9002-SB.8-B3-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.8

## REQ-QUIC-RFC9002-SBP8-0004 Limit persistent congestion checks to packets sent after the first RTT sample
For persistent congestion testing, the sender MUST consider only packets sent after first_rtt_sample.

Trace:
- Source Refs:
  - RFC 9002 §B.8 RFC9002-SB.8-B3-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.8

## REQ-QUIC-RFC9002-SBP8-0005 Collapse the congestion window on persistent congestion
If persistent congestion is detected, the sender MUST set `congestion_window` to `kMinimumWindow` and reset `congestion_recovery_start_time` to `0`.

Trace:
- Source Refs:
  - RFC 9002 §B.8 RFC9002-SB.8-B3-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.8

## REQ-QUIC-RFC9002-SBP9-0001 Stop counting discarded packets in bytes in flight
When Initial or Handshake keys are discarded, packets in that space MUST no longer count toward bytes_in_flight.

Trace:
- Source Refs:
  - RFC 9002 §B.9 RFC9002-SB.9-B2-P1-S1
  - RFC 9002 §B.9 RFC9002-SB.9-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.9

## REQ-QUIC-RFC9002-SBP9-0002 Remove discarded packets from congestion accounting
When Initial or Handshake keys are discarded, the sender MUST remove the discarded packets from `bytes_in_flight` and clear `sent_packets` for that packet number space.

Trace:
- Source Refs:
  - RFC 9002 §B.9 RFC9002-SB.9-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.9

## REQ-QUIC-RFC9002-SBP9-0003 Reset recovery timers after discarding keys
When Initial or Handshake keys are discarded, the sender MUST reset `time_of_last_ack_eliciting_packet[pn_space]`, `loss_time[pn_space]`, and `pto_count`, and set the loss detection timer.

Trace:
- Source Refs:
  - RFC 9002 §B.9 RFC9002-SB.9-B4-P0-S1
  - https://www.rfc-editor.org/rfc/rfc9002.html#section-b.9
