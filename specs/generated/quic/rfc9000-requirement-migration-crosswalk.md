# RFC9000 Requirement Migration Crosswalk

This crosswalk reflects the clarified migration policy: incoming staged RFC9000 IDs become canonical for clear overlaps. Staged `.stable.json` was used as source data, not published directly.

## Summary
- `live_requirement_count`: 1448
- `staged_requirement_count`: 1641
- `staged_ids_now_live_count`: 396
- `section2_pilot_rename_with_lineage_count`: 8
- `section2_pilot_new_only_count`: 2
- `exact_statement_rename_with_lineage_count`: 379
- `s15_rename_with_lineage_count`: 1
- `s16_rename_with_lineage_count`: 1
- `s16_split_merge_count`: 2
- `remaining_exact_statement_rename_candidates`: 0
- `ambiguous_exact_statement_groups`: 5
- `live_ids_not_in_staged_count`: 1052
- `staged_ids_not_in_live_count`: 1245
- `retired_ledger_count`: 391

## Applied Reports
- `specs/generated/quic/rfc9000-migration-section-2-review.json`
- `specs/generated/quic/rfc9000-migration-exact-statement-renames.json`
- `specs/generated/quic/rfc9000-migration-s15-review.json`
- `specs/generated/quic/rfc9000-migration-s16-review.json`
- `specs/generated/quic/rfc9000-migration-retired-requirements.json`

## Remaining Exact Statement Rename Candidates
None.

## Ambiguous Exact Statement Groups
| Statement | Live IDs | Staged IDs |
|---|---|---|
| MAX_STREAMS frames that do not increase the stream limit MUST be ignored. | `REQ-QUIC-RFC9000-S19P11-0008`, `REQ-QUIC-RFC9000-S4P6-0011` | `REQ-QUIC-RFC9000-0202` |
| Packets containing a zero value for this bit are not valid packets in this version and MUST be discarded. | `REQ-QUIC-RFC9000-S17P2-0015`, `REQ-QUIC-RFC9000-S17P3P1-0014` | `REQ-QUIC-RFC9000-1069` |
| The Length field MUST be encoded as a variable-length integer. | `REQ-QUIC-RFC9000-S17P2P2-0013`, `REQ-QUIC-RFC9000-S17P2P3-0015`, `REQ-QUIC-RFC9000-S17P2P4-0014`, `REQ-QUIC-RFC9000-S19P6-0006` | `REQ-QUIC-RFC9000-0952` |
| The stateless reset token MUST be difficult to guess. | `REQ-QUIC-RFC9000-S10P3-0016`, `REQ-QUIC-RFC9000-S10P3P2-0001` | `REQ-QUIC-RFC9000-0641` |
| The value included prior to protection MUST be set to 0. | `REQ-QUIC-RFC9000-S17P2-0028`, `REQ-QUIC-RFC9000-S17P3P1-0016` | `REQ-QUIC-RFC9000-1072`, `REQ-QUIC-RFC9000-1730` |

## Live IDs Not Present In Staged
Live IDs not present in staged remain for explicit review; they were not guessed or deleted.

| Live ID | Title |
|---|---|
| `REQ-QUIC-RFC9000-S10-0001` | Discard connection state if it does not have a validated path on which it can send packets |
| `REQ-QUIC-RFC9000-S10P1-0001` | To avoid excessively small idle timeout periods, endpoints MUST increase the idle timeout period to be at least three times the current Probe Timeout (PTO) |
| `REQ-QUIC-RFC9000-S10P1-0002` | Silently close on idle timeout |
| `REQ-QUIC-RFC9000-S10P1-0003` | Advertise and compute idle timeout |
| `REQ-QUIC-RFC9000-S10P1-0004` | Commit to immediate close before timeout |
| `REQ-QUIC-RFC9000-S10P1-0006` | Restart idle timer on fresh ack-eliciting send |
| `REQ-QUIC-RFC9000-S10P1P1-0001` | Allow liveness probes |
| `REQ-QUIC-RFC9000-S10P1P2-0002` | Allow deferring idle timeout |
| `RFC9000-S10-2-P5-S2-R01` | These states SHOULD persist for at least three times the current PTO interval as defined in [QUIC-RECOVERY] |
| `RFC9000-S10-2-P6-S2-R01` | That have some alternative means to ensure that late-arriving packets do not induce a response, such as those that are able to close the UDP socket, MAY end these states earlier to allow for faster resource recovery |
| `REQ-QUIC-RFC9000-S10P2-0007` | Close all streams on CONNECTION_CLOSE |
| `REQ-QUIC-RFC9000-S10P2-0008` | Reset open streams implicitly |
| `REQ-QUIC-RFC9000-S10P2-0010` | Enter draining state after receiving close |
| `REQ-QUIC-RFC9000-S10P2-0011` | Close immediately on protocol violation |
| `REQ-QUIC-RFC9000-S10P2-0012` | Permit immediate close after application shutdown |
| `RFC9000-S10-2-1-P4-S1-R01` | An endpoint's selected connection ID and the QUIC version are sufficient information to identify packets for a closing connection |
| `RFC9000-S10-2-1-P5-S2-R01` | To avoid being used for an amplification attack, such endpoints MUST limit the cumulative size of packets it sends to three times the cumulative size of the packets that are received and attributed to the connection |
| `RFC9000-S10-2-1-P5-S3-R01` | To minimize the state that an endpoint maintains for a closing connection, endpoints MAY send the exact same packet in response to any received packet |
| `REQ-QUIC-RFC9000-S10P2P1-0009` | Retain only closing-state essentials |
| `REQ-QUIC-RFC9000-S10P2P2-0001` | While otherwise identical to the closing state, an endpoint in the draining state MUST NOT send any packets |
| `REQ-QUIC-RFC9000-S10P2P2-0002` | That receives a CONNECTION_CLOSE frame MAY send a single packet containing a CONNECTION_CLOSE frame before entering the draining state, using a NO_ERROR code if appropriate |
| `RFC9000-S10-2-2-P2-S2-R01` | Send further packets |
| `REQ-QUIC-RFC9000-S10P2P2-0004` | Enter the draining state from the closing state if it receives a CONNECTION_CLOSE frame, which indicates that the peer is also closing or draining |
| `REQ-QUIC-RFC9000-S10P2P2-0005` | Enter draining on peer close |
| `REQ-QUIC-RFC9000-S10P2P3-0001` | After the handshake is confirmed (see Section 4 |
| `REQ-QUIC-RFC9000-S10P2P3-0002` | However, prior to confirming the handshake, it is possible that more advanced packet protection keys are not available to the peer, so another CONNECTION_CLOSE frame MAY be sent in a packet that uses a lower packet protection level |
| `REQ-QUIC-RFC9000-S10P2P3-0003` | Under these circumstances, a server SHOULD send a CONNECTION_CLOSE frame in both Handshake and Initial packets to ensure that at least one of them is processable by the client |
| `REQ-QUIC-RFC9000-S10P2P3-0004` | Prior to confirming the handshake, a peer might be unable to process 1-RTT packets, so an endpoint SHOULD send a CONNECTION_CLOSE frame in both Handshake and 1-RTT packets |
| `REQ-QUIC-RFC9000-S10P2P3-0005` | Also send a CONNECTION_CLOSE frame in an Initial packet |
| `REQ-QUIC-RFC9000-S10P2P3-0007` | For this reason, endpoints MAY discard packets rather than immediately close if errors are detected in packets that lack authentication |
| `REQ-QUIC-RFC9000-S10P2P3-0008` | Send post-handshake close in 1-RTT |
| `REQ-QUIC-RFC9000-S10P2P3-0009` | Allow lower-protection close before handshake confirmation |
| `REQ-QUIC-RFC9000-S10P2P3-0010` | Close in Handshake and 1-RTT before confirmation |
| `REQ-QUIC-RFC9000-S10P2P3-0011` | Downgrade close type for Initial and Handshake |
| `REQ-QUIC-RFC9000-S10P2P3-0012` | Clear Reason Phrase when downgrading close type |
| `REQ-QUIC-RFC9000-S10P2P3-0013` | Prefer APPLICATION_ERROR when downgrading close type |
| `RFC9000-S10-3-P1-S2-R01` | Send a Stateless Reset in response to receiving a packet that it cannot associate with an active connection |
| `REQ-QUIC-RFC9000-S10P3-0003` | Use a hard-to-guess 16-byte stateless reset token |
| `REQ-QUIC-RFC9000-S10P3-0005` | Use the Figure 10 packet layout for Stateless Reset |
| `REQ-QUIC-RFC9000-S10P3-0006` | Send Stateless Reset as a short-header packet |
| `REQ-QUIC-RFC9000-S10P3-0007` | The remainder of the first byte and an arbitrary number of bytes following it are set to values that SHOULD be indistinguishable from random |
| `REQ-QUIC-RFC9000-S10P3-0008` | Include at least 38 unpredictable bits |
| `REQ-QUIC-RFC9000-S10P3-0009` | Pad packets to keep Stateless Reset hard to distinguish |
| `REQ-QUIC-RFC9000-S10P3-0010` | Make short-packet Stateless Resets one byte shorter |
| `REQ-QUIC-RFC9000-S10P3-0013` | Format Stateless Resets with a short header |
| `REQ-QUIC-RFC9000-S10P3-0014` | Treat any packet ending in a valid reset token as a Stateless Reset |
| `REQ-QUIC-RFC9000-S10P3-0015` | Allow Stateless Reset in response to long-header packets |
| `REQ-QUIC-RFC9000-S10P3-0016` | Make reset tokens hard to guess |
| `REQ-QUIC-RFC9000-S10P3-0017` | Advertise reset tokens in NEW_CONNECTION_ID |
| `REQ-QUIC-RFC9000-S10P3-0018` | Permit server transport-parameter reset tokens |
| `REQ-QUIC-RFC9000-S10P3-0019` | End the connection on received reset |
| `REQ-QUIC-RFC9000-S10P3-0021` | Send reset using the Figure 10 layout |
| `REQ-QUIC-RFC9000-S10P3-0022` | Set fixed bits to 1 |
| `REQ-QUIC-RFC9000-S10P3-0023` | Make leading reset bytes look random |
| `REQ-QUIC-RFC9000-S10P3-0024` | Place the token in the tail |
| `REQ-QUIC-RFC9000-S10P3-0025` | Provide enough unpredictable bits |
| `REQ-QUIC-RFC9000-S10P3-0026` | Use a full UDP datagram |
| `REQ-QUIC-RFC9000-S10P3-0027` | Pad packets to improve reset indistinguishability |
| `REQ-QUIC-RFC9000-S10P3-0028` | Avoid amplification with Stateless Reset |
| `REQ-QUIC-RFC9000-S10P3-0029` | Support all negotiated versions in reset generation |
| `REQ-QUIC-RFC9000-S10P3P1-0001` | Use the trailing 16 bytes to detect Stateless Reset |
| `REQ-QUIC-RFC9000-S10P3P1-0002` | Remember recent stateless reset tokens |
| `REQ-QUIC-RFC9000-S10P3P1-0003` | Compare the remote-address token set to classify Stateless Reset |
| `RFC9000-S10-3-1-P2-S2-R01` | Skip the token check after successful packet processing |
| `RFC9000-S10-3-1-P2-S2-R02` | Always check when the first packet cannot be processed |
| `RFC9000-S10-3-1-P3-S1-R01` | Ignore unused and retired reset tokens |
| `REQ-QUIC-RFC9000-S10P3P1-0007` | Avoid leaking token values during comparison |
| `REQ-QUIC-RFC9000-S10P3P1-0008` | Enter draining on a matching stateless reset token |
| `REQ-QUIC-RFC9000-S10P3P1-0010` | Remember and scope reset tokens |
| `REQ-QUIC-RFC9000-S10P3P2-0001` | Be difficult to guess |
| `REQ-QUIC-RFC9000-S10P3P2-0002` | Truncate the stateless reset token to 16 bytes |
| `RFC9000-S10-3-2-P4-S2-R01` | Use a recoverable connection ID length with static-key tokens |
| `REQ-QUIC-RFC9000-S10P3P2-0004` | Disallow zero-length connection IDs for static-key tokens |
| `RFC9000-S10-3-2-P5-S2-R01` | Do not reuse the connection ID and static key combination |
| `REQ-QUIC-RFC9000-S10P3P2-0008` | Allow duplicate stateless reset tokens to signal protocol violation |
| `REQ-QUIC-RFC9000-S10P3P2-0009` | Allow per-connection random secrets |
| `REQ-QUIC-RFC9000-S10P3P2-0010` | Allow static-key token generation |
| `REQ-QUIC-RFC9000-S10P3P2-0012` | Forbid zero-length connection IDs |
| `REQ-QUIC-RFC9000-S10P3P3-0001` | Keep Stateless Reset smaller than the triggering packet |
| `REQ-QUIC-RFC9000-S10P3P3-0002` | Allow a reset-send limit |
| `RFC9000-S11-P1-S1-R01` | that detects an error SHOULD signal the existence of that error to its peer |
| `RFC9000-S11-P2-S1-R01` | The most appropriate error code (Section 20) SHOULD be included in the frame that signals the error |
| `RFC9000-S11-1-P1-S1-R01` | Errors that result in the connection being unusable, such as an obvious violation of protocol semantics or corruption of state that affects an entire connection, MUST be signaled using a CONNECTION_CLOSE frame (Section 19 |
| `REQ-QUIC-RFC9000-S11P1-0003` | Use CONNECTION_CLOSE type 0x1c for transport errors |
| `REQ-QUIC-RFC9000-S11P1-0005` | Limiting the number of retransmissions and the time over which this final packet is sent limits the effort expended on terminated connections |
| `REQ-QUIC-RFC9000-S11P1-0006` | An endpoint that continues to receive data for a terminated connection MUST attempt the stateless reset process |
| `RFC9000-S11-1-P5-S1-R01` | As the AEAD for Initial packets does not provide strong authentication, an endpoint MAY discard an invalid Initial packet |
| `REQ-QUIC-RFC9000-S11P2-0001` | If an application-level error affects a single stream but otherwise leaves the connection in a recoverable state, the endpoint can send a RESET_STREAM frame (Section 19 |
| `RFC9000-S11-2-P2-S2-R01` | RESET_STREAM MUST only be instigated by the application protocol that uses QUIC |
| `REQ-QUIC-RFC9000-S11P2-0003` | Allow stream termination only by the application protocol |
| `REQ-QUIC-RFC9000-S11P2-0004` | A local instance of the application protocol uses a direct API call, and a remote instance uses the STOP_SENDING frame, which triggers an automatic RESET_STREAM |
| `REQ-QUIC-RFC9000-S12P1-0001` | Version Negotiation packets have no cryptographic protection |
| `REQ-QUIC-RFC9000-S12P1-0002` | Retry packets use an AEAD function [AEAD] to protect against accidental modification |
| `REQ-QUIC-RFC9000-S12P1-0003` | Initial packets use an AEAD function, the keys for which are derived using a value that is visible on the wire |
| `REQ-QUIC-RFC9000-S12P1-0004` | Initial protection exists to ensure that the sender of the packet is on the network path |
| `REQ-QUIC-RFC9000-S12P1-0005` | Any entity that receives an Initial packet from a client can recover the keys that will allow them to both read the contents of the packet and generate Initial packets that will be successfully authenticated at either endpoint |
| `REQ-QUIC-RFC9000-S12P1-0006` | The AEAD also protects Initial packets against accidental modification |
| `REQ-QUIC-RFC9000-S12P1-0007` | The cryptographic handshake ensures that only the communicating endpoints receive the corresponding keys for Handshake, 0-RTT, and 1-RTT packets |
| `REQ-QUIC-RFC9000-S12P2-0002` | The length includes both the Packet Number and Payload fields, both of which are confidentiality protected and initially of unknown length |
| `REQ-QUIC-RFC9000-S12P2-0003` | Using the Length field, a sender can coalesce multiple QUIC packets into one UDP datagram |
| `REQ-QUIC-RFC9000-S12P2-0006` | include multiple frames in a single packet if they are to be sent at the same encryption level, instead of coalescing multiple packets at the same encryption level |
| `RFC9000-S12-2-P5-S2-R01` | Buffer or discard on decryption failure |
| `RFC9000-S12-2-P5-S2-R02` | Continue processing remaining coalesced packets |
| `RFC9000-S12-2-P5-S1-R01` | Process each coalesced packet separately |
| `REQ-QUIC-RFC9000-S12P2-0013` | Retry packets (Section 17 |
| `REQ-QUIC-RFC9000-S12P3-0001` | This number is used in determining the cryptographic nonce for packet protection |
| `REQ-QUIC-RFC9000-S12P3-0002` | maintains a separate packet number for sending and receiving |
| `REQ-QUIC-RFC9000-S12P3-0003` | Version Negotiation (Section 17 |
| `REQ-QUIC-RFC9000-S12P3-0004` | Initial packets can only be sent with Initial packet protection keys and acknowledged in packets that are also Initial packets |
| `REQ-QUIC-RFC9000-S12P3-0005` | Similarly, Handshake packets are sent at the Handshake encryption level and can only be acknowledged in Handshake packets |
| `REQ-QUIC-RFC9000-S12P3-0006` | numbers in each space start at packet number 0 |
| `REQ-QUIC-RFC9000-S12P3-0009` | Allow Stateless Reset after packet-number exhaustion |
| `REQ-QUIC-RFC9000-S12P3-0012` | Duplicate suppression MUST happen after removing packet protection for the reasons described in Section 9 |
| `REQ-QUIC-RFC9000-S12P4-0005` | Keep frames within one packet |
| `REQ-QUIC-RFC9000-S12P4-0007` | A description of this summary is included after the table |
| `REQ-QUIC-RFC9000-S12P4-0008` | Use Frame Type for frame-specific flags in selected frames |
| `REQ-QUIC-RFC9000-S12P4-0010` | Limit Initial and Handshake appearance of CONNECTION_CLOSE type 0x1c |
| `REQ-QUIC-RFC9000-S12P4-0013` | Treat N-marked packets as not ack-eliciting |
| `REQ-QUIC-RFC9000-S12P4-0014` | Exclude C-marked packets from bytes in flight |
| `REQ-QUIC-RFC9000-S12P4-0015` | Allow P-marked packets to probe new paths |
| `REQ-QUIC-RFC9000-S12P4-0016` | Treat F-marked frame contents as flow controlled |
| `REQ-QUIC-RFC9000-S12P4-0017` | Treat unknown frame types as frame encoding errors |
| `REQ-QUIC-RFC9000-S12P4-0018` | Make frames idempotent |
| `REQ-QUIC-RFC9000-S12P4-0019` | That is, a valid frame does not cause undesirable side effects or errors when received more than once |
| `REQ-QUIC-RFC9000-S12P4-0021` | Allow longer-than-necessary frame-type encodings to fail |
| `REQ-QUIC-RFC9000-S12P5-0001` | The rules here generalize those of TLS, in that frames associated with establishing the connection can usually appear in packets in any packet number space, whereas those associated with transferring data can only appear in the application data packet number space |
| `REQ-QUIC-RFC9000-S12P5-0003` | Allow QUIC-layer CONNECTION_CLOSE in any packet number space |
| `REQ-QUIC-RFC9000-S12P5-0004` | Restrict application-error CONNECTION_CLOSE to application data |
| `REQ-QUIC-RFC9000-S12P5-0005` | Allow ACK in any packet number space but only acknowledge within that space |
| `REQ-QUIC-RFC9000-S12P5-0007` | treat receipt of these frames in 0-RTT packets as a connection error of type PROTOCOL_VIOLATION |
| `REQ-QUIC-RFC9000-S13-0001` | Send one or more frames in each QUIC packet |
| `RFC9000-S13-P2-S2-R01` | wait for a short period of time to collect multiple frames before sending a packet that is not maximally packed, to avoid sending out large numbers of small packets |
| `RFC9000-S13-P2-S3-R01` | An implementation MAY use knowledge about application sending behavior or heuristics to determine whether and for how long to wait |
| `REQ-QUIC-RFC9000-S13-0004` | A single QUIC packet can include multiple STREAM frames from one or more streams |
| `REQ-QUIC-RFC9000-S13-0005` | Implementations are advised to include as few streams as necessary in outgoing packets without losing transmission efficiency to underfilled packets |
| `REQ-QUIC-RFC9000-S13P1-0002` | For STREAM frames, this means the data has been enqueued in preparation to be received by the application protocol, but it does not require that data be delivered and consumed |
| `REQ-QUIC-RFC9000-S13P1-0003` | Acknowledge processed packets with ACK frames |
| `REQ-QUIC-RFC9000-S13P2-0002` | Send ACK frames within max_ack_delay only for ack-eliciting packets |
| `REQ-QUIC-RFC9000-S13P2-0003` | Acknowledge non-ack-eliciting packets only for other reasons |
| `REQ-QUIC-RFC9000-S13P2P1-0001` | Acknowledge ack-eliciting packets within max_ack_delay |
| `REQ-QUIC-RFC9000-S13P2P1-0003` | uses the receiver's max_ack_delay value in determining timeouts for timer-based retransmission, as detailed in Section 6 |
| `RFC9000-S13-2-1-P2-R02` | Acknowledge 0-RTT and 1-RTT packets within max_ack_delay |
| `RFC9000-S13-2-1-P2-R01` | Acknowledge Initial and Handshake packets immediately |
| `RFC9000-S13-2-1-P3-R01` | Do not send multiple ACK-only packets in response to one ack-eliciting packet |
| `REQ-QUIC-RFC9000-S13P2P1-0007` | Do not send non-ack-eliciting packets in response to non-ack-eliciting packets |
| `REQ-QUIC-RFC9000-S13P2P1-0008` | Non-ack-eliciting packets are eventually acknowledged when the endpoint sends an ACK frame in response to other events |
| `REQ-QUIC-RFC9000-S13P2P1-0009` | that is only sending ACK frames will not receive acknowledgments from its peer unless those acknowledgments are included in packets with ack-eliciting frames |
| `RFC9000-S13-2-1-P6-S1-R01` | Avoid infinite feedback loops when adding ack-eliciting frames |
| `REQ-QUIC-RFC9000-S13P2P1-0013` | Send ACK frames without delay for out-of-order or gap-detecting packets |
| `REQ-QUIC-RFC9000-S13P2P2-0001` | determines how frequently to send acknowledgments in response to ack-eliciting packets |
| `REQ-QUIC-RFC9000-S13P2P3-0001` | When an ACK frame is sent, one or more ranges of acknowledged packets are included |
| `REQ-QUIC-RFC9000-S13P2P3-0003` | If it does not, then older ranges (those with the smallest packet numbers) are omitted |
| `REQ-QUIC-RFC9000-S13P2P3-0006` | Senders can expect acknowledgments for most packets, but QUIC does not guarantee receipt of an acknowledgment for every packet that the receiver processes |
| `REQ-QUIC-RFC9000-S13P2P3-0008` | Discard ACK ranges when a frame would be too large |
| `REQ-QUIC-RFC9000-S13P2P3-0011` | Retain the largest successfully processed packet number |
| `REQ-QUIC-RFC9000-S13P2P3-0013` | Section 13 |
| `REQ-QUIC-RFC9000-S13P2P4-0001` | In cases with ACK frame loss and reordering, this approach does not guarantee that every acknowledgment is seen by the sender before it is no longer included in the ACK frame |
| `REQ-QUIC-RFC9000-S13P2P5-0001` | Measure intentional acknowledgment delays |
| `REQ-QUIC-RFC9000-S13P2P5-0002` | Encode acknowledgment delay in ACK Delay |
| `RFC9000-S13-2-5-P3-S1-R01` | Report measured delay when it exceeds max_ack_delay |
| `RFC9000-S13-2-6-P1-S1-R01` | Carry ACK frames only in the same packet number space |
| `RFC9000-S13-2-6-P1-S2-R01` | Use 1-RTT for acknowledging 1-RTT packets |
| `REQ-QUIC-RFC9000-S13P2P6-0003` | Acknowledge client 0-RTT packets with 1-RTT packets |
| `REQ-QUIC-RFC9000-S13P2P6-0004` | This can mean that the client is unable to use these acknowledgments if the server cryptographic handshake messages are delayed or lost |
| `RFC9000-S13-2-7-P1-S3-R01` | Send non-PADDING frames periodically to elicit acknowledgments |
| `REQ-QUIC-RFC9000-S13P3-0001` | Do not retransmit lost packets whole |
| `REQ-QUIC-RFC9000-S13P3-0002` | Do not retransmit lost frames whole |
| `REQ-QUIC-RFC9000-S13P3-0003` | Send lost information again in new frames |
| `REQ-QUIC-RFC9000-S13P3-0004` | Use new frames and packets for lost information |
| `REQ-QUIC-RFC9000-S13P3-0005` | Stop resending information once it is acknowledged |
| `REQ-QUIC-RFC9000-S13P3-0007` | Discard CRYPTO data when its packet number space is discarded |
| `REQ-QUIC-RFC9000-S13P3-0008` | Retransmit STREAM data unless RESET_STREAM was sent |
| `REQ-QUIC-RFC9000-S13P3-0009` | Stop needing STREAM frames after RESET_STREAM |
| `REQ-QUIC-RFC9000-S13P3-0010` | Carry the most recent acknowledgments and delay in ACK frames |
| `REQ-QUIC-RFC9000-S13P3-0011` | Retransmit RESET_STREAM until acknowledged or data is acknowledged |
| `REQ-QUIC-RFC9000-S13P3-0013` | Retransmit STOP_SENDING until the stream reaches a terminal state |
| `REQ-QUIC-RFC9000-S13P3-0015` | Send current connection maximum data in MAX_DATA frames |
| `REQ-QUIC-RFC9000-S13P3-0017` | Send current stream data offsets in MAX_STREAM_DATA frames |
| `REQ-QUIC-RFC9000-S13P3-0018` | Send updated MAX_STREAM_DATA values when the frame is lost or the limit changes |
| `REQ-QUIC-RFC9000-S13P3-0019` | Stop sending MAX_STREAM_DATA once the stream is closed or reset |
| `REQ-QUIC-RFC9000-S13P3-0021` | Send updated MAX_STREAMS values when the frame is lost or the limit changes |
| `REQ-QUIC-RFC9000-S13P3-0022` | Carry blocked signals in dedicated frames |
| `REQ-QUIC-RFC9000-S13P3-0023` | Scope blocked signals appropriately |
| `REQ-QUIC-RFC9000-S13P3-0024` | Send a new blocked frame while blocked and the latest frame is lost |
| `REQ-QUIC-RFC9000-S13P3-0025` | Include the blocking limit in blocked frames |
| `REQ-QUIC-RFC9000-S13P3-0029` | Send new connection IDs in NEW_CONNECTION_ID frames and retransmit them if lost |
| `REQ-QUIC-RFC9000-S13P3-0030` | Send retired connection IDs in RETIRE_CONNECTION_ID frames and retransmit them if lost |
| `REQ-QUIC-RFC9000-S13P3-0031` | Compare NEW_TOKEN frames directly for duplicates and reordering |
| `REQ-QUIC-RFC9000-S13P3-0032` | PING and PADDING frames contain no information, so lost PING or PADDING frames do not require repair |
| `REQ-QUIC-RFC9000-S13P3-0034` | prioritize retransmission of data over sending new data, unless priorities specified by the application indicate otherwise |
| `REQ-QUIC-RFC9000-S13P3-0037` | This includes packets that are acknowledged after being declared lost, which can happen in the presence of network reordering |
| `REQ-QUIC-RFC9000-S13P3-0038` | can discard this information after a period of time elapses that adequately allows for reordering, such as a PTO (Section 6 |
| `REQ-QUIC-RFC9000-S13P4-0001` | QUIC endpoints MAY use ECN to detect and respond to network congestion |
| `REQ-QUIC-RFC9000-S13P4-0002` | Check whether the path and peer support ECN before enabling it |
| `REQ-QUIC-RFC9000-S13P4P1-0001` | Do not report ECN counts without ECN support or ECN field access |
| `REQ-QUIC-RFC9000-S13P4P1-0002` | Even if an endpoint does not set an ECT field in packets it sends, the endpoint MUST provide feedback about ECN markings it receives, if these are accessible |
| `REQ-QUIC-RFC9000-S13P4P1-0003` | Failing to report the ECN counts will cause the sender to disable the use of ECN for this connection |
| `REQ-QUIC-RFC9000-S13P4P1-0004` | Update ECN counts when receiving marked IP packets |
| `REQ-QUIC-RFC9000-S13P4P1-0005` | Include ECN counts in subsequent ACK frames |
| `REQ-QUIC-RFC9000-S13P4P1-0006` | Keep separate ECN counts per packet number space |
| `REQ-QUIC-RFC9000-S13P4P1-0007` | Count ECN once per coalesced QUIC packet |
| `REQ-QUIC-RFC9000-S13P4P1-0008` | Count ECN for each packet number space in a coalesced datagram |
| `REQ-QUIC-RFC9000-S13P4P2-0001` | Validate ECN counts per path and disable ECN on errors |
| `REQ-QUIC-RFC9000-S13P4P2-0003` | Watch for ECN-marked packets being lost |
| `REQ-QUIC-RFC9000-S13P4P2-0004` | Validate ECN for each new connection and path change |
| `REQ-QUIC-RFC9000-S13P4P2-0005` | Implementations MAY use other methods defined in RFCs |
| `REQ-QUIC-RFC9000-S13P4P2-0006` | Validate ECN using ECT(1) counts when ECT(1) is used |
| `REQ-QUIC-RFC9000-S13P4P2P1-0001` | Validate ECN counts before using them |
| `REQ-QUIC-RFC9000-S13P4P2P1-0002` | Fail ECN validation when counts are missing for newly acknowledged ECT packets |
| `REQ-QUIC-RFC9000-S13P4P2P1-0003` | This check detects a network element that zeroes the ECN field or a peer that does not report ECN markings |
| `REQ-QUIC-RFC9000-S13P4P2P1-0004` | Fail ECN validation when ECT(0) and CE counts are too small |
| `REQ-QUIC-RFC9000-S13P4P2P1-0005` | Fail ECN validation when ECT(1) and CE counts are too small |
| `REQ-QUIC-RFC9000-S13P4P2P1-0007` | Fail ECN validation when received counts exceed sent counts |
| `REQ-QUIC-RFC9000-S13P4P2P1-0008` | Fail ECN validation for never-applied ECT counts |
| `REQ-QUIC-RFC9000-S13P4P2P2-0001` | Disable ECN when validation fails |
| `REQ-QUIC-RFC9000-S13P4P2P2-0002` | It stops setting the ECT codepoint in IP packets that it sends, assuming that either the network path or the peer does not support ECN |
| `REQ-QUIC-RFC9000-S13P4P2P2-0003` | Even if validation fails, an endpoint MAY revalidate ECN for the same path at any later time in the connection |
| `REQ-QUIC-RFC9000-S13P4P2P2-0004` | Upon successful validation, an endpoint MAY continue to set an ECT codepoint in subsequent packets it sends, with the expectation that the path is ECN capable |
| `RFC9000-S13-4-2-2-P3-S2-R01` | Network routing and path elements can change mid-connection |
| `REQ-QUIC-RFC9000-S14-0002` | The datagram size includes one or more QUIC packet headers and protected payloads, but not the UDP or IP headers |
| `REQ-QUIC-RFC9000-S14-0003` | Define maximum datagram size as the largest UDP payload across a path |
| `REQ-QUIC-RFC9000-S14-0005` | Use PMTUD or DPLPMTUD to discover larger datagram sizes |
| `REQ-QUIC-RFC9000-S14-0006` | Avoid exceeding the max_udp_payload_size once known |
| `REQ-QUIC-RFC9000-S14-0008` | In IPv4 [IPv4], the Don't Fragment (DF) bit MUST be set if possible, to prevent fragmentation on the path |
| `REQ-QUIC-RFC9000-S14-0009` | Treat received datagram size as unauthenticated |
| `RFC9000-S14-1-P1-S1-R01` | Pad Initial datagrams to 1200 bytes |
| `REQ-QUIC-RFC9000-S14P1-0002` | Initial packets can even be coalesced with invalid packets, which a receiver will discard |
| `RFC9000-S14-1-P1-S3-R01` | Pad server Initial datagrams to 1200 bytes |
| `REQ-QUIC-RFC9000-S14P1-0004` | Sending UDP datagrams of this size ensures that the network path supports a reasonable Path Maximum Transmission Unit (PMTU), in both directions |
| `RFC9000-S14-1-P3-S1-R01` | Allow oversized Initial datagrams when the path and peer support them |
| `RFC9000-S14-1-P4-S1-R01` | Discard undersized Initial packets at the server |
| `RFC9000-S14-1-P4-S2-R01` | Allow servers to close on undersized Initial packets |
| `RFC9000-S14-1-P5-S1-R01` | Limit bytes sent before validating the client address |
| `REQ-QUIC-RFC9000-S14P2-0001` | The UDP payload includes one or more QUIC packet headers and protected payloads |
| `REQ-QUIC-RFC9000-S14P2-0002` | The largest UDP payload an endpoint sends at any given time is referred to as the endpoint's maximum datagram size |
| `RFC9000-S14-2-P2-S1-R01` | Use DPLPMTUD or PMTUD to determine support for a desired size |
| `RFC9000-S14-2-P2-S2-R01` | Do not exceed the smallest allowed maximum datagram size without PMTU discovery |
| `REQ-QUIC-RFC9000-S14P2-0005` | Both DPLPMTUD and PMTUD send datagrams that are larger than the current maximum datagram size, referred to as PMTU probes |
| `REQ-QUIC-RFC9000-S14P2-0006` | Size non-PMTU-probe packets to fit within the maximum datagram size |
| `RFC9000-S14-2-P4-S1-R01` | Stop sending packets on a path that cannot support 1200 bytes |
| `RFC9000-S14-2-P5-S2-R01` | Maintain a maximum datagram size per address pair when doing PMTU discovery |
| `RFC9000-S14-2-P6-S1-R01` | Allow conservative maximum datagram size estimates |
| `RFC9000-S14-2-1-P4-S2-R01` | Use the quoted packet to associate ICMP messages with a connection |
| `RFC9000-S14-2-1-P4-S3-R01` | Validate ICMP messages with addresses, ports, and connection IDs |
| `RFC9000-S14-2-1-P5-S1-R01` | Do not increase PMTU based on ICMP messages |
| `REQ-QUIC-RFC9000-S14P3-0001` | DPLPMTUD [DPLPMTUD] relies on tracking loss or acknowledgment of QUIC packets that are carried in PMTU probes |
| `REQ-QUIC-RFC9000-S14P3-0002` | PMTU probes for DPLPMTUD that use the PADDING frame implement "Probing using padding data", as defined in Section 4 |
| `REQ-QUIC-RFC9000-S14P3-0004` | Maintain an MPS per address pair when using DPLPMTUD |
| `REQ-QUIC-RFC9000-S14P4-0001` | Make PMTU probes ack-eliciting |
| `RFC9000-S14-4-P2-S2-R01` | Do not treat PMTU probe loss as congestion |
| `REQ-QUIC-RFC9000-S15-0003` | Identify this specification as version 0x00000001 |
| `REQ-QUIC-RFC9000-S17-0001` | All numeric values MUST be encoded in network byte order (that is, big endian), and all field... |
| `REQ-QUIC-RFC9000-S17P1-0001` | When present in long or short packet headers, they MUST be encoded in 1 to 4 bytes |
| `RFC9000-S17-1-P3-R01` | Prior to receiving an acknowledgment for a packet number space, the full packet number MUST b... |
| `RFC9000-S17-1-P4-R01` | After an acknowledgment is received for a packet number space, the sender MUST use a packet n... |
| `REQ-QUIC-RFC9000-S17P2-0001` | The Header Form field MUST be 1 bits long with value 1 |
| `REQ-QUIC-RFC9000-S17P2-0002` | The Fixed Bit field MUST be 1 bits long with value 1 |
| `REQ-QUIC-RFC9000-S17P2-0003` | The Long Packet Type field MUST be 2 bits long |
| `REQ-QUIC-RFC9000-S17P2-0004` | The Type-Specific Bits field MUST be 4 bits long |
| `REQ-QUIC-RFC9000-S17P2-0005` | The Version field MUST be 32 bits long |
| `REQ-QUIC-RFC9000-S17P2-0006` | The Destination Connection ID Length field MUST be 8 bits long |
| `REQ-QUIC-RFC9000-S17P2-0007` | The Destination Connection ID field MUST be between 0 and 160 bits long |
| `REQ-QUIC-RFC9000-S17P2-0008` | The Source Connection ID Length field MUST be 8 bits long |
| `REQ-QUIC-RFC9000-S17P2-0009` | The Source Connection ID field MUST be between 0 and 160 bits long |
| `REQ-QUIC-RFC9000-S17P2-0010` | Long headers MUST be used for packets that are sent prior to the establishment of 1-RTT keys |
| `REQ-QUIC-RFC9000-S17P2-0011` | Once 1-RTT keys are available, a sender MUST switch to sending packets using the short header... |
| `REQ-QUIC-RFC9000-S17P2-0012` | Packets that use the long header MUST contain the following fields: |
| `REQ-QUIC-RFC9000-S17P2-0013` | The most significant bit (0x80) of byte 0 (the first byte) MUST be set to 1 for long headers |
| `REQ-QUIC-RFC9000-S17P2-0014` | The next bit (0x40) of byte 0 MUST be set to 1, unless the packet is a Version Negotiation pa... |
| `REQ-QUIC-RFC9000-S17P2-0015` | Packets containing a zero value for this bit are not valid packets in this version and MUST b... |
| `REQ-QUIC-RFC9000-S17P2-0016` | The next two bits (those with a mask of 0x30) of byte 0 MUST contain a packet type |
| `REQ-QUIC-RFC9000-S17P2-0017` | This field MUST indicate the version of QUIC that is in use and determines how the rest of th... |
| `REQ-QUIC-RFC9000-S17P2-0019` | This length MUST be encoded as an 8-bit unsigned integer |
| `REQ-QUIC-RFC9000-S17P2-0020` | In QUIC version 1, this value MUST NOT exceed 20 bytes |
| `REQ-QUIC-RFC9000-S17P2-0021` | Endpoints that receive a version 1 long header with a value larger than 20 MUST drop the packet |
| `REQ-QUIC-RFC9000-S17P2-0022` | In order to properly form a Version Negotiation packet, servers SHOULD be able to read longer... |
| `REQ-QUIC-RFC9000-S17P2-0023` | The Destination Connection ID field follows the Destination Connection ID Length field, which... |
| `REQ-QUIC-RFC9000-S17P2-0025` | The Source Connection ID field follows the Source Connection ID Length field, which MUST indi... |
| `REQ-QUIC-RFC9000-S17P2-0026` | While type-specific semantics for this version are described in the following sections, sever... |
| `REQ-QUIC-RFC9000-S17P2-0027` | Two bits (those with a mask of 0x0c) of byte 0 MUST be reserved across multiple packet types |
| `REQ-QUIC-RFC9000-S17P2-0028` | The value included prior to protection MUST be set to 0 |
| `REQ-QUIC-RFC9000-S17P2-0029` | An endpoint MUST treat receipt of a packet that has a non-zero value for these bits after rem... |
| `REQ-QUIC-RFC9000-S17P2-0030` | Discarding such a packet after only removing header protection MAY expose the endpoint to att... |
| `REQ-QUIC-RFC9000-S17P2-0031` | In packet types that MUST contain a Packet Number field, the least significant two bits (thos... |
| `REQ-QUIC-RFC9000-S17P2-0032` | The Packet Number field MUST be field is 1 to 4 bytes long |
| `REQ-QUIC-RFC9000-S17P2-0033` | The length of the Packet Number field MUST be encoded in the Packet Number Length bits of byt... |
| `REQ-QUIC-RFC9000-S17P2P1-0001` | The Version Negotiation packet is a response to a client packet that contains a version that... |
| `REQ-QUIC-RFC9000-S17P2P1-0002` | It MUST only be sent by servers |
| `REQ-QUIC-RFC9000-S17P2P1-0003` | The Header Form field MUST be 1 bits long with value 1 |
| `REQ-QUIC-RFC9000-S17P2P1-0004` | The Unused field MUST be 7 bits long |
| `REQ-QUIC-RFC9000-S17P2P1-0005` | The Version field MUST be 32 bits long with value 0 |
| `REQ-QUIC-RFC9000-S17P2P1-0006` | The Destination Connection ID Length field MUST be 8 bits long |
| `REQ-QUIC-RFC9000-S17P2P1-0007` | The Destination Connection ID field MUST be between 0 and 2040 bits long |
| `REQ-QUIC-RFC9000-S17P2P1-0008` | The Source Connection ID Length field MUST be 8 bits long |
| `REQ-QUIC-RFC9000-S17P2P1-0009` | The Source Connection ID field MUST be between 0 and 2040 bits long |
| `REQ-QUIC-RFC9000-S17P2P1-0010` | The value in the Unused field MUST be set to an arbitrary value by the server |
| `REQ-QUIC-RFC9000-S17P2P1-0012` | Where QUIC might be multiplexed with other protocols (see [RFC7983]), servers SHOULD set the... |
| `REQ-QUIC-RFC9000-S17P2P1-0015` | The value for Source Connection ID MUST be copied from the Destination Connection ID of the r... |
| `REQ-QUIC-RFC9000-S17P2P1-0016` | Version-specific rules for the connection ID therefore MUST NOT influence a decision about wh... |
| `REQ-QUIC-RFC9000-S17P2P1-0018` | It is only sent in response to a packet that MUST indicate an unsupported version; see Sectio... |
| `REQ-QUIC-RFC9000-S17P2P1-0019` | The Version Negotiation packet MUST NOT include the Packet Number and Length fields present i... |
| `REQ-QUIC-RFC9000-S17P2P2-0001` | An Initial packet MUST use long headers with a type value of 0x00 |
| `REQ-QUIC-RFC9000-S17P2P2-0002` | The Header Form field MUST be 1 bits long with value 1 |
| `REQ-QUIC-RFC9000-S17P2P2-0003` | The Fixed Bit field MUST be 1 bits long with value 1 |
| `REQ-QUIC-RFC9000-S17P2P2-0004` | The Long Packet Type field MUST be 2 bits long with value 0 |
| `REQ-QUIC-RFC9000-S17P2P2-0005` | The Reserved Bits field MUST be 2 bits long |
| `REQ-QUIC-RFC9000-S17P2P2-0006` | The Packet Number Length field MUST be 2 bits long |
| `REQ-QUIC-RFC9000-S17P2P2-0007` | The Version field MUST be 32 bits long |
| `REQ-QUIC-RFC9000-S17P2P2-0008` | The Destination Connection ID Length field MUST be 8 bits long |
| `REQ-QUIC-RFC9000-S17P2P2-0009` | The Destination Connection ID field MUST be between 0 and 160 bits long |
| `REQ-QUIC-RFC9000-S17P2P2-0010` | The Source Connection ID Length field MUST be 8 bits long |
| `REQ-QUIC-RFC9000-S17P2P2-0011` | The Source Connection ID field MUST be between 0 and 160 bits long |
| `REQ-QUIC-RFC9000-S17P2P2-0012` | The Token Length field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S17P2P2-0013` | The Length field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S17P2P2-0014` | The Packet Number field MUST be between 8 and 32 bits long |
| `REQ-QUIC-RFC9000-S17P2P2-0015` | The Initial packet MUST contain a long header as well as the Length and Packet Number fields;... |
| `REQ-QUIC-RFC9000-S17P2P2-0016` | The first byte MUST contain the Reserved and Packet Number Length bits; see also Section 17.2 |
| `REQ-QUIC-RFC9000-S17P2P2-0017` | The Token Length field MUST be variable-length integer specifying the length of the Token fie... |
| `REQ-QUIC-RFC9000-S17P2P2-0020` | This protection does not provide confidentiality or integrity against attackers that can obse... |
| `REQ-QUIC-RFC9000-S17P2P2-0021` | The client and server use the Initial packet type for any packet that MUST contain an initial... |
| `REQ-QUIC-RFC9000-S17P2P2-0022` | This MUST include all cases where a new packet containing the initial cryptographic message n... |
| `REQ-QUIC-RFC9000-S17P2P2-0024` | The payload of an Initial packet MUST include a CRYPTO frame (or frames) containing a cryptog... |
| `REQ-QUIC-RFC9000-S17P2P2-0025` | An endpoint that receives an Initial packet containing other frames MAY either discard the pa... |
| `REQ-QUIC-RFC9000-S17P2P2-0026` | The first packet sent by a client always includes a CRYPTO frame that MUST contain the start... |
| `REQ-QUIC-RFC9000-S17P2P3-0001` | A 0-RTT packet MUST use long headers with a type value of 0x01, followed by the Length and Pa... |
| `REQ-QUIC-RFC9000-S17P2P3-0002` | The first byte MUST contain the Reserved and Packet Number Length bits; see Section 17.2 |
| `REQ-QUIC-RFC9000-S17P2P3-0003` | A 0-RTT packet MUST be used to carry "early" data from the client to the server as part of th... |
| `REQ-QUIC-RFC9000-S17P2P3-0004` | As part of the TLS handshake, the server MAY accept or reject this early data |
| `REQ-QUIC-RFC9000-S17P2P3-0005` | The Header Form field MUST be 1 bits long with value 1 |
| `REQ-QUIC-RFC9000-S17P2P3-0006` | The Fixed Bit field MUST be 1 bits long with value 1 |
| `REQ-QUIC-RFC9000-S17P2P3-0007` | The Long Packet Type field MUST be 2 bits long with value 1 |
| `REQ-QUIC-RFC9000-S17P2P3-0008` | The Reserved Bits field MUST be 2 bits long |
| `REQ-QUIC-RFC9000-S17P2P3-0009` | The Packet Number Length field MUST be 2 bits long |
| `REQ-QUIC-RFC9000-S17P2P3-0010` | The Version field MUST be 32 bits long |
| `REQ-QUIC-RFC9000-S17P2P3-0011` | The Destination Connection ID Length field MUST be 8 bits long |
| `REQ-QUIC-RFC9000-S17P2P3-0012` | The Destination Connection ID field MUST be between 0 and 160 bits long |
| `REQ-QUIC-RFC9000-S17P2P3-0013` | The Source Connection ID Length field MUST be 8 bits long |
| `REQ-QUIC-RFC9000-S17P2P3-0014` | The Source Connection ID field MUST be between 0 and 160 bits long |
| `REQ-QUIC-RFC9000-S17P2P3-0015` | The Length field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S17P2P3-0016` | The Packet Number field MUST be between 8 and 32 bits long |
| `REQ-QUIC-RFC9000-S17P2P3-0018` | New packet numbers MUST be used for any new packets that are sent; as described in Section 17... |
| `REQ-QUIC-RFC9000-S17P2P3-0020` | This means that 0-RTT packets MUST NOT contain any response to frames from 1-RTT packets |
| `REQ-QUIC-RFC9000-S17P2P3-0021` | For instance, a client MUST NOT send an ACK frame in a 0-RTT packet, because that can only ac... |
| `REQ-QUIC-RFC9000-S17P2P3-0023` | A server SHOULD treat a violation of remembered limits (Section 7.4.1) as a connection error... |
| `REQ-QUIC-RFC9000-S17P2P4-0001` | A Handshake packet MUST use long headers with a type value of 0x02, followed by the Length an... |
| `REQ-QUIC-RFC9000-S17P2P4-0002` | The first byte MUST contain the Reserved and Packet Number Length bits; see Section 17.2 |
| `REQ-QUIC-RFC9000-S17P2P4-0003` | It MUST be used to carry cryptographic handshake messages and acknowledgments from the server... |
| `REQ-QUIC-RFC9000-S17P2P4-0004` | The Header Form field MUST be 1 bits long with value 1 |
| `REQ-QUIC-RFC9000-S17P2P4-0005` | The Fixed Bit field MUST be 1 bits long with value 1 |
| `REQ-QUIC-RFC9000-S17P2P4-0006` | The Long Packet Type field MUST be 2 bits long with value 2 |
| `REQ-QUIC-RFC9000-S17P2P4-0007` | The Reserved Bits field MUST be 2 bits long |
| `REQ-QUIC-RFC9000-S17P2P4-0008` | The Packet Number Length field MUST be 2 bits long |
| `REQ-QUIC-RFC9000-S17P2P4-0009` | The Version field MUST be 32 bits long |
| `REQ-QUIC-RFC9000-S17P2P4-0010` | The Destination Connection ID Length field MUST be 8 bits long |
| `REQ-QUIC-RFC9000-S17P2P4-0011` | The Destination Connection ID field MUST be between 0 and 160 bits long |
| `REQ-QUIC-RFC9000-S17P2P4-0012` | The Source Connection ID Length field MUST be 8 bits long |
| `REQ-QUIC-RFC9000-S17P2P4-0013` | The Source Connection ID field MUST be between 0 and 160 bits long |
| `REQ-QUIC-RFC9000-S17P2P4-0014` | The Length field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S17P2P4-0015` | The Packet Number field MUST be between 8 and 32 bits long |
| `REQ-QUIC-RFC9000-S17P2P4-0017` | The Destination Connection ID field in a Handshake packet MUST contain a connection ID that i... |
| `REQ-QUIC-RFC9000-S17P2P4-0018` | Handshake packets have their own packet number space, and thus the first Handshake packet sen... |
| `REQ-QUIC-RFC9000-S17P2P4-0019` | The payload of this packet MUST contain CRYPTO frames and could contain PING, PADDING, or ACK... |
| `REQ-QUIC-RFC9000-S17P2P5-0001` | As shown in Figure 18, a Retry packet MUST use a long packet header with a type value of 0x03 |
| `REQ-QUIC-RFC9000-S17P2P5-0002` | It MUST be used by a server that wishes to perform a retry; see Section 8.1 |
| `REQ-QUIC-RFC9000-S17P2P5-0003` | The Header Form field MUST be 1 bits long with value 1 |
| `REQ-QUIC-RFC9000-S17P2P5-0004` | The Fixed Bit field MUST be 1 bits long with value 1 |
| `REQ-QUIC-RFC9000-S17P2P5-0005` | The Long Packet Type field MUST be 2 bits long with value 3 |
| `REQ-QUIC-RFC9000-S17P2P5-0006` | The Unused field MUST be 4 bits long |
| `REQ-QUIC-RFC9000-S17P2P5-0007` | The Version field MUST be 32 bits long |
| `REQ-QUIC-RFC9000-S17P2P5-0008` | The Destination Connection ID Length field MUST be 8 bits long |
| `REQ-QUIC-RFC9000-S17P2P5-0009` | The Destination Connection ID field MUST be between 0 and 160 bits long |
| `REQ-QUIC-RFC9000-S17P2P5-0010` | The Source Connection ID Length field MUST be 8 bits long |
| `REQ-QUIC-RFC9000-S17P2P5-0011` | The Source Connection ID field MUST be between 0 and 160 bits long |
| `REQ-QUIC-RFC9000-S17P2P5-0012` | The Retry Integrity Tag field MUST be 128 bits long |
| `REQ-QUIC-RFC9000-S17P2P5-0013` | A Retry packet MUST NOT contain any protected fields |
| `REQ-QUIC-RFC9000-S17P2P5-0014` | The value in the Unused field is set to an arbitrary value by the server; a client MUST ignor... |
| `REQ-QUIC-RFC9000-S17P2P5-0015` | In addition to the fields from the long header, it MUST contain these additional fields: |
| `REQ-QUIC-RFC9000-S17P2P5-0016` | An opaque token that the server MAY use to validate the client's address |
| `REQ-QUIC-RFC9000-S17P2P5P1-0001` | The server MUST include a connection ID of its choice in the Source Connection ID field |
| `RFC9000-S17-2-5-1-P2-S1-R01` | This value MUST NOT be equal to the Destination Connection ID field of the packet sent by the... |
| `RFC9000-S17-2-5-1-P2-S2-R01` | A client MUST discard a Retry packet that contains a Source Connection ID field that is ident... |
| `RFC9000-S17-2-5-1-P2-S3-R01` | The client MUST use the value from the Source Connection ID field of the Retry packet in the... |
| `REQ-QUIC-RFC9000-S17P2P5P1-0006` | A server MAY either discard or buffer 0-RTT packets that it receives |
| `RFC9000-S17-2-5-2-P2-R01` | Clients MUST discard Retry packets that have a Retry Integrity Tag that cannot be validated;... |
| `REQ-QUIC-RFC9000-S17P2P5P2-0005` | The client responds to a Retry packet with an Initial packet that MUST include the provided R... |
| `REQ-QUIC-RFC9000-S17P2P5P2-0006` | A client MUST set the Destination Connection ID field of this Initial packet to the value fro... |
| `REQ-QUIC-RFC9000-S17P2P5P2-0007` | It also MUST set the Token field to the token provided in the Retry packet |
| `REQ-QUIC-RFC9000-S17P2P5P2-0008` | The client MUST NOT change the Source Connection ID because the server could include the conn... |
| `REQ-QUIC-RFC9000-S17P2P5P2-0009` | A Retry packet does not include a packet number and MUST NOT be explicitly acknowledged by a... |
| `REQ-QUIC-RFC9000-S17P2P5P3-0001` | Subsequent Initial packets from the client MUST include the connection ID and token values fr... |
| `REQ-QUIC-RFC9000-S17P2P5P3-0002` | The client copies the Source Connection ID field from the Retry packet to the Destination Con... |
| `REQ-QUIC-RFC9000-S17P2P5P3-0007` | In particular, 0-RTT packets MUST contain confidential information that will most likely be r... |
| `REQ-QUIC-RFC9000-S17P3-0001` | This version of QUIC defines a single packet type that MUST use the short packet header |
| `REQ-QUIC-RFC9000-S17P3P1-0002` | It MUST be used after the version and 1-RTT keys are negotiated |
| `REQ-QUIC-RFC9000-S17P3P1-0003` | The Header Form field MUST be 1 bits long with value 0 |
| `REQ-QUIC-RFC9000-S17P3P1-0004` | The Fixed Bit field MUST be 1 bits long with value 1 |
| `REQ-QUIC-RFC9000-S17P3P1-0005` | The Spin Bit field MUST be 1 bits long |
| `REQ-QUIC-RFC9000-S17P3P1-0006` | The Reserved Bits field MUST be 2 bits long |
| `REQ-QUIC-RFC9000-S17P3P1-0007` | The Key Phase field MUST be 1 bits long |
| `REQ-QUIC-RFC9000-S17P3P1-0008` | The Packet Number Length field MUST be 2 bits long |
| `REQ-QUIC-RFC9000-S17P3P1-0009` | The Destination Connection ID field MUST be between 0 and 160 bits long |
| `REQ-QUIC-RFC9000-S17P3P1-0010` | The Packet Number field MUST be between 8 and 32 bits long |
| `REQ-QUIC-RFC9000-S17P3P1-0011` | 1-RTT packets MUST contain the following fields: |
| `REQ-QUIC-RFC9000-S17P3P1-0012` | The most significant bit (0x80) of byte 0 MUST be set to 0 for the short header |
| `REQ-QUIC-RFC9000-S17P3P1-0013` | The next bit (0x40) of byte 0 MUST be set to 1 |
| `REQ-QUIC-RFC9000-S17P3P1-0014` | Packets containing a zero value for this bit are not valid packets in this version and MUST b... |
| `REQ-QUIC-RFC9000-S17P3P1-0016` | The value included prior to protection MUST be set to 0 |
| `REQ-QUIC-RFC9000-S17P3P1-0018` | Discarding such a packet after only removing header protection MAY expose the endpoint to att... |
| `REQ-QUIC-RFC9000-S17P3P1-0019` | The next bit (0x04) of byte 0 MUST indicate the key phase, which allows a recipient of a pack... |
| `REQ-QUIC-RFC9000-S17P3P1-0021` | The Packet Number field MUST be Packet Number field is 1 to 4 bytes long |
| `REQ-QUIC-RFC9000-S17P3P1-0022` | The length of the Packet Number field MUST be encoded in Packet Number Length field |
| `REQ-QUIC-RFC9000-S17P3P1-0023` | 1-RTT packets always MUST include a 1-RTT protected payload |
| `REQ-QUIC-RFC9000-S17P4-0001` | On-path observers MAY measure the time between two spin bit toggle events to estimate the end... |
| `REQ-QUIC-RFC9000-S17P4-0002` | The spin bit MUST only be present in 1-RTT packets, since it is possible to measure the initi... |
| `RFC9000-S17-4-P3-S1-R01` | An endpoint that does not support this feature MUST disable it, as defined below |
| `RFC9000-S17-4-P4-S2-R01` | Even when the spin bit is not disabled by the administrator, endpoints MUST disable their use... |
| `REQ-QUIC-RFC9000-S17P4-0008` | If the spin bit is enabled for the connection, the endpoint maintains a spin value for each n... |
| `REQ-QUIC-RFC9000-S17P4-0009` | When a server receives a 1-RTT packet that increases the highest packet number seen by the se... |
| `REQ-QUIC-RFC9000-S18-0002` | They MUST be encoded as a sequence of transport parameters, as shown in Figure 20: |
| `REQ-QUIC-RFC9000-S18-0003` | Each transport parameter MUST be encoded as an (identifier, length, value) tuple, as shown in... |
| `REQ-QUIC-RFC9000-S18-0004` | The Transport Parameter ID field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S18-0005` | The Transport Parameter Length field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S18-0007` | QUIC MUST encode transport parameters into a sequence of bytes, which is then included in the... |
| `REQ-QUIC-RFC9000-S18P1-0001` | Transport parameters with an identifier of the form 31 * N + 27 for integer values of N MUST... |
| `REQ-QUIC-RFC9000-S18P1-0002` | These transport parameters have no semantics and MAY carry arbitrary values |
| `REQ-QUIC-RFC9000-S18P2-0001` | This transport parameter MUST only be sent by a server |
| `REQ-QUIC-RFC9000-S18P2-0002` | The maximum idle timeout is a value in milliseconds that MUST be encoded as an integer; see (... |
| `REQ-QUIC-RFC9000-S18P2-0003` | A stateless reset token MUST be used in verifying a stateless reset; see Section 10.3 |
| `REQ-QUIC-RFC9000-S18P2-0004` | Allow servers to send stateless_reset_token |
| `REQ-QUIC-RFC9000-S18P2-0005` | Forbid clients from sending stateless_reset_token |
| `REQ-QUIC-RFC9000-S18P2-0006` | A server that does not send this transport parameter MUST NOT use stateless reset (Section 10... |
| `REQ-QUIC-RFC9000-S18P2-0007` | UDP datagrams with payloads larger than this limit MUST NOT be likely to be processed by the... |
| `REQ-QUIC-RFC9000-S18P2-0008` | The initial maximum data parameter is an integer value that contains the initial value for th... |
| `REQ-QUIC-RFC9000-S18P2-0009` | This MUST be equivalent to sending a MAX_DATA (Section 19.9) for the connection immediately a... |
| `REQ-QUIC-RFC9000-S18P2-0010` | The initial maximum bidirectional streams parameter is an integer value that MUST contain the... |
| `REQ-QUIC-RFC9000-S18P2-0011` | If this parameter is absent or zero, the peer MUST NOT open bidirectional streams until a MAX... |
| `REQ-QUIC-RFC9000-S18P2-0012` | Setting this parameter MUST be equivalent to sending a MAX_STREAMS (Section 19.11) of the cor... |
| `REQ-QUIC-RFC9000-S18P2-0013` | The initial maximum unidirectional streams parameter is an integer value that MUST contain th... |
| `REQ-QUIC-RFC9000-S18P2-0014` | If this parameter is absent or zero, the peer MUST NOT open unidirectional streams until a MA... |
| `REQ-QUIC-RFC9000-S18P2-0015` | This value SHOULD include the receiver's expected delays in alarms firing |
| `REQ-QUIC-RFC9000-S18P2-0016` | The disable active migration transport parameter is included if the endpoint MUST NOT support... |
| `REQ-QUIC-RFC9000-S18P2-0017` | An endpoint that receives this transport parameter MUST NOT use a new local address when send... |
| `REQ-QUIC-RFC9000-S18P2-0018` | This transport parameter MUST NOT prohibit connection migration after a client has acted on a... |
| `REQ-QUIC-RFC9000-S18P2-0019` | The server's preferred address MUST be used to effect a change in server address at the end o... |
| `REQ-QUIC-RFC9000-S18P2-0024` | The Connection ID field and the Stateless Reset Token field MUST contain an alternative conne... |
| `REQ-QUIC-RFC9000-S18P2-0026` | Similarly, a server MUST NOT include a zero-length connection ID in this transport parameter |
| `REQ-QUIC-RFC9000-S18P2-0028` | The IPv4 Address field MUST be 32 bits long |
| `REQ-QUIC-RFC9000-S18P2-0029` | The IPv4 Port field MUST be 16 bits long |
| `REQ-QUIC-RFC9000-S18P2-0030` | The IPv6 Address field MUST be 128 bits long |
| `REQ-QUIC-RFC9000-S18P2-0031` | The IPv6 Port field MUST be 16 bits long |
| `REQ-QUIC-RFC9000-S18P2-0032` | The Connection ID Length field MUST be 8 bits long |
| `REQ-QUIC-RFC9000-S18P2-0033` | The Stateless Reset Token field MUST be 128 bits long |
| `REQ-QUIC-RFC9000-S18P2-0034` | This value MUST include the connection ID received during the handshake, that received in the... |
| `REQ-QUIC-RFC9000-S18P2-0038` | A server MUST treat receipt of any of these transport parameters as a connection error of typ... |
| `REQ-QUIC-RFC9000-S19P1-0002` | PADDING frames MAY be used to increase the size of a packet |
| `REQ-QUIC-RFC9000-S19P1-0003` | Padding MAY be used to increase an Initial packet to the minimum required size or to provide... |
| `REQ-QUIC-RFC9000-S19P1-0004` | PADDING frames are formatted as shown in Figure 23, which shows that PADDING frames MUST have... |
| `REQ-QUIC-RFC9000-S19P1-0005` | That is, a PADDING frame MUST consist of the single byte that identifies the frame as a PADDI... |
| `REQ-QUIC-RFC9000-S19P1-0006` | The Type field MUST be encoded as a variable-length integer with value 0x00 |
| `REQ-QUIC-RFC9000-S19P10-0001` | A MAX_STREAM_DATA frame (type=0x11) MUST be used in flow control to inform a peer of the maxi... |
| `REQ-QUIC-RFC9000-S19P10-0002` | A MAX_STREAM_DATA frame MAY be sent for streams in the "Recv" state; see Section 3.2 |
| `REQ-QUIC-RFC9000-S19P10-0005` | The Type field MUST be encoded as a variable-length integer with value 0x11 |
| `REQ-QUIC-RFC9000-S19P10-0006` | The Stream ID field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P10-0007` | The Maximum Stream Data field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P10-0008` | MAX_STREAM_DATA frames MUST contain the following fields: |
| `REQ-QUIC-RFC9000-S19P10-0009` | The Stream ID field MUST be stream ID of the affected stream, encoded as a variable-length in... |
| `REQ-QUIC-RFC9000-S19P10-0010` | A variable-length integer indicating the maximum amount of data that MAY be sent on the ident... |
| `REQ-QUIC-RFC9000-S19P10-0011` | Loss or reordering can mean that the largest received offset on a stream MAY be greater than... |
| `REQ-QUIC-RFC9000-S19P10-0014` | This MUST include violations of remembered limits in Early Data; see Section 7.4.1 |
| `REQ-QUIC-RFC9000-S19P11-0001` | The Type field MUST be encoded as a variable-length integer with value 0x12..0x13 |
| `REQ-QUIC-RFC9000-S19P11-0002` | The Maximum Streams field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P11-0003` | MAX_STREAMS frames MUST contain the following field: |
| `REQ-QUIC-RFC9000-S19P11-0004` | A count of the cumulative number of streams of the corresponding type that MAY be opened over... |
| `REQ-QUIC-RFC9000-S19P11-0005` | This value MUST NOT exceed 260, as it is not possible to encode stream IDs larger than 262-1 |
| `REQ-QUIC-RFC9000-S19P11-0006` | Receipt of a frame that permits opening of a stream larger than this limit MUST be treated as... |
| `REQ-QUIC-RFC9000-S19P11-0007` | Loss or reordering MAY cause an endpoint to receive a MAX_STREAMS frame with a lower stream l... |
| `REQ-QUIC-RFC9000-S19P11-0008` | MAX_STREAMS frames that do not increase the stream limit MUST be ignored |
| `REQ-QUIC-RFC9000-S19P11-0011` | This MUST include violations of remembered limits in Early Data; see Section 7.4.1 |
| `REQ-QUIC-RFC9000-S19P11-0012` | Note that these frames (and the corresponding transport parameters) MUST NOT describe the num... |
| `REQ-QUIC-RFC9000-S19P12-0001` | A sender SHOULD send a DATA_BLOCKED frame (type=0x14) when it wishes to send data but is unab... |
| `REQ-QUIC-RFC9000-S19P12-0002` | DATA_BLOCKED frames MAY be used as input to tuning of flow control algorithms; see Section 4.2 |
| `REQ-QUIC-RFC9000-S19P12-0003` | The Type field MUST be encoded as a variable-length integer with value 0x14 |
| `REQ-QUIC-RFC9000-S19P12-0004` | The Maximum Data field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P12-0005` | DATA_BLOCKED frames MUST contain the following field: |
| `REQ-QUIC-RFC9000-S19P12-0006` | The Maximum Data field MUST be variable-length integer indicating the connection-level limit... |
| `REQ-QUIC-RFC9000-S19P13-0003` | The Type field MUST be encoded as a variable-length integer with value 0x15 |
| `REQ-QUIC-RFC9000-S19P13-0004` | The Stream ID field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P13-0005` | The Maximum Stream Data field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P13-0006` | STREAM_DATA_BLOCKED frames MUST contain the following fields: |
| `REQ-QUIC-RFC9000-S19P13-0007` | The Stream ID field MUST be variable-length integer indicating the stream that is blocked due... |
| `REQ-QUIC-RFC9000-S19P13-0008` | The Maximum Stream Data field MUST be variable-length integer indicating the offset of the st... |
| `REQ-QUIC-RFC9000-S19P14-0001` | A sender SHOULD send a STREAMS_BLOCKED frame (type=0x16 or 0x17) when it wishes to open a str... |
| `REQ-QUIC-RFC9000-S19P14-0002` | A STREAMS_BLOCKED frame of type 0x16 MUST be used to indicate reaching the bidirectional stre... |
| `REQ-QUIC-RFC9000-S19P14-0003` | A STREAMS_BLOCKED frame MUST NOT open the stream, but informs the peer that a new stream was... |
| `REQ-QUIC-RFC9000-S19P14-0004` | The Type field MUST be encoded as a variable-length integer with value 0x16..0x17 |
| `REQ-QUIC-RFC9000-S19P14-0005` | The Maximum Streams field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P14-0006` | STREAMS_BLOCKED frames MUST contain the following field: |
| `REQ-QUIC-RFC9000-S19P14-0007` | The Maximum Streams field MUST be variable-length integer indicating the maximum number of st... |
| `REQ-QUIC-RFC9000-S19P14-0008` | This value MUST NOT exceed 260, as it is not possible to encode stream IDs larger than 262-1 |
| `REQ-QUIC-RFC9000-S19P14-0009` | Receipt of a frame that encodes a larger stream ID MUST be treated as a connection error of t... |
| `REQ-QUIC-RFC9000-S19P15-0001` | An endpoint sends a NEW_CONNECTION_ID frame (type=0x18) to provide its peer with alternative... |
| `REQ-QUIC-RFC9000-S19P15-0002` | The Type field MUST be encoded as a variable-length integer with value 0x18 |
| `REQ-QUIC-RFC9000-S19P15-0003` | The Sequence Number field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P15-0004` | The Retire Prior To field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P15-0005` | The Length field MUST be 8 bits long |
| `REQ-QUIC-RFC9000-S19P15-0006` | The Connection ID field MUST be between 8 and 160 bits long |
| `REQ-QUIC-RFC9000-S19P15-0007` | The Stateless Reset Token field MUST be 128 bits long |
| `REQ-QUIC-RFC9000-S19P15-0008` | NEW_CONNECTION_ID frames MUST contain the following fields: |
| `REQ-QUIC-RFC9000-S19P15-0009` | Retire Prior To field |
| `REQ-QUIC-RFC9000-S19P15-0010` | The Length field MUST be 8-bit unsigned integer containing the length of the connection ID |
| `REQ-QUIC-RFC9000-S19P15-0011` | Values less than 1 and greater than 20 are invalid and MUST be treated as a connection error... |
| `REQ-QUIC-RFC9000-S19P15-0012` | The Connection ID field MUST be connection ID of the specified length |
| `REQ-QUIC-RFC9000-S19P15-0013` | A 128-bit value that will be used for a stateless reset when the associated connection ID MUS... |
| `REQ-QUIC-RFC9000-S19P15-0016` | Receipt of the same frame multiple times MUST NOT be treated as a connection error |
| `REQ-QUIC-RFC9000-S19P15-0017` | A receiver MAY use the sequence number supplied in the NEW_CONNECTION_ID frame to handle rece... |
| `REQ-QUIC-RFC9000-S19P15-0021` | Once a sender MUST indicate a Retire Prior To value, smaller values sent in subsequent NEW_CO... |
| `REQ-QUIC-RFC9000-S19P16-0001` | An endpoint sends a RETIRE_CONNECTION_ID frame (type=0x19) to MUST indicate that it will no l... |
| `REQ-QUIC-RFC9000-S19P16-0002` | This MUST include the connection ID provided during the handshake |
| `REQ-QUIC-RFC9000-S19P16-0003` | New connection IDs MAY be delivered to a peer using the NEW_CONNECTION_ID frame (Section 19.15) |
| `REQ-QUIC-RFC9000-S19P16-0004` | The Type field MUST be encoded as a variable-length integer with value 0x19 |
| `REQ-QUIC-RFC9000-S19P16-0005` | The Sequence Number field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P16-0006` | RETIRE_CONNECTION_ID frames MUST contain the following field: |
| `REQ-QUIC-RFC9000-S19P16-0007` | Receipt of a RETIRE_CONNECTION_ID frame containing a sequence number greater than any previou... |
| `REQ-QUIC-RFC9000-S19P16-0009` | The peer MAY treat this as a connection error of type PROTOCOL_VIOLATION |
| `REQ-QUIC-RFC9000-S19P16-0010` | An endpoint MUST NOT send this frame if it was provided with a zero-length connection ID by i... |
| `REQ-QUIC-RFC9000-S19P17-0001` | Endpoints MAY use PATH_CHALLENGE frames (type=0x1a) to check reachability to the peer and for... |
| `REQ-QUIC-RFC9000-S19P17-0002` | The Type field MUST be encoded as a variable-length integer with value 0x1a |
| `REQ-QUIC-RFC9000-S19P17-0003` | The Data field MUST be 64 bits long |
| `REQ-QUIC-RFC9000-S19P17-0004` | PATH_CHALLENGE frames MUST contain the following field: |
| `REQ-QUIC-RFC9000-S19P17-0005` | This 8-byte field MUST contain arbitrary data |
| `REQ-QUIC-RFC9000-S19P17-0006` | The recipient of this frame MUST generate a PATH_RESPONSE frame (Section 19.18) containing th... |
| `REQ-QUIC-RFC9000-S19P18-0001` | The Type field MUST be encoded as a variable-length integer with value 0x1b |
| `REQ-QUIC-RFC9000-S19P18-0002` | The Data field MUST be 64 bits long |
| `REQ-QUIC-RFC9000-S19P18-0003` | If the content of a PATH_RESPONSE frame does not match the content of a PATH_CHALLENGE frame... |
| `REQ-QUIC-RFC9000-S19P19-0001` | The CONNECTION_CLOSE frame with a type of 0x1c MUST be used to signal errors at only the QUIC... |
| `REQ-QUIC-RFC9000-S19P19-0002` | The CONNECTION_CLOSE frame with a type of 0x1d MUST be used to signal an error with the appli... |
| `REQ-QUIC-RFC9000-S19P19-0003` | The Type field MUST be encoded as a variable-length integer with value 0x1c..0x1d |
| `REQ-QUIC-RFC9000-S19P19-0004` | The Error Code field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P19-0005` | The Frame Type field MUST be encoded as a variable-length integer when present |
| `REQ-QUIC-RFC9000-S19P19-0006` | The Reason Phrase Length field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P19-0007` | CONNECTION_CLOSE frames MUST contain the following fields: |
| `REQ-QUIC-RFC9000-S19P19-0008` | A variable-length integer that MUST indicate the reason for closing this connection |
| `REQ-QUIC-RFC9000-S19P19-0010` | A CONNECTION_CLOSE frame of type 0x1d MUST use codes defined by the application protocol; see... |
| `REQ-QUIC-RFC9000-S19P19-0011` | The Frame Type field MUST be variable-length integer encoding the type of frame that triggere... |
| `REQ-QUIC-RFC9000-S19P19-0012` | A value of 0 (equivalent to the mention of the PADDING frame) MUST be used when the frame typ... |
| `REQ-QUIC-RFC9000-S19P19-0014` | The Reason Phrase Length field MUST be variable-length integer specifying the length of the r... |
| `REQ-QUIC-RFC9000-S19P19-0015` | Because a CONNECTION_CLOSE frame MUST NOT be split between packets, any limits on packet size... |
| `REQ-QUIC-RFC9000-S19P19-0016` | This MAY be zero length if the sender chooses not to give details beyond the Error Code value |
| `REQ-QUIC-RFC9000-S19P19-0017` | This SHOULD be a UTF-8 encoded string [RFC3629], though the frame does not carry information,... |
| `REQ-QUIC-RFC9000-S19P19-0018` | The application-specific variant of CONNECTION_CLOSE (type 0x1d) MAY only be sent using 0-RTT... |
| `REQ-QUIC-RFC9000-S19P2-0001` | Endpoints MAY use PING frames (type=0x01) to verify that their peers are still alive or to ch... |
| `REQ-QUIC-RFC9000-S19P2-0002` | PING frames are formatted as shown in Figure 24, which shows that PING frames MUST have no co... |
| `REQ-QUIC-RFC9000-S19P2-0003` | The Type field MUST be encoded as a variable-length integer with value 0x01 |
| `REQ-QUIC-RFC9000-S19P2-0004` | The PING frame MAY be used to keep a connection alive when an application or application prot... |
| `REQ-QUIC-RFC9000-S19P20-0001` | The server MUST use a HANDSHAKE_DONE frame (type=0x1e) to signal confirmation of the handshak... |
| `REQ-QUIC-RFC9000-S19P20-0002` | HANDSHAKE_DONE frames are formatted as shown in Figure 44, which shows that HANDSHAKE_DONE fr... |
| `REQ-QUIC-RFC9000-S19P20-0003` | The Type field MUST be encoded as a variable-length integer with value 0x1e |
| `REQ-QUIC-RFC9000-S19P20-0004` | A HANDSHAKE_DONE frame MAY only be sent by the server |
| `REQ-QUIC-RFC9000-S19P21-0002` | An endpoint therefore needs to understand the syntax of all frames before it MAY successfully... |
| `REQ-QUIC-RFC9000-S19P21-0003` | This allows for efficient encoding of frames, but it means that an endpoint MUST NOT send a f... |
| `REQ-QUIC-RFC9000-S19P21-0011` | An IANA registry MUST be used to manage the assignment of frame types; see Section 22.4 |
| `REQ-QUIC-RFC9000-S19P3-0001` | Handle ACK frame types 0x02 and 0x03 |
| `REQ-QUIC-RFC9000-S19P3-0002` | The ACK frame MUST contain one or more ACK Ranges |
| `REQ-QUIC-RFC9000-S19P3-0003` | If the frame type is 0x03, ACK frames also MUST contain the cumulative count of QUIC packets... |
| `RFC9000-S19-3-P1-S1-R02` | Use ECN information to manage congestion state |
| `REQ-QUIC-RFC9000-S19P3-0005` | Once acknowledged, a packet MUST remain acknowledged, even if it does not appear in a future... |
| `REQ-QUIC-RFC9000-S19P3-0006` | Packets from different packet number spaces MAY be identified using the same numeric value |
| `REQ-QUIC-RFC9000-S19P3-0009` | The Type field MUST be encoded as a variable-length integer with value 0x02..0x03 |
| `REQ-QUIC-RFC9000-S19P3-0010` | The Largest Acknowledged field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P3-0011` | The ACK Delay field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P3-0012` | The ACK Range Count field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P3-0013` | The First ACK Range field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P3-0014` | ACK frames MUST contain the following fields: |
| `REQ-QUIC-RFC9000-S19P3-0015` | The Largest Acknowledged field MUST be variable-length integer representing the largest packe... |
| `REQ-QUIC-RFC9000-S19P3-0016` | Unlike the packet number in the QUIC long or short header, the value in an ACK frame MUST NOT... |
| `REQ-QUIC-RFC9000-S19P3-0017` | The ACK Delay field MUST be variable-length integer encoding the acknowledgment delay in micr... |
| `REQ-QUIC-RFC9000-S19P3-0018` | The ACK Range Count field MUST be variable-length integer specifying the number of ACK Range... |
| `REQ-QUIC-RFC9000-S19P3-0019` | The First ACK Range field MUST be variable-length integer indicating the number of contiguous... |
| `REQ-QUIC-RFC9000-S19P3-0020` | MUST contain additional ranges of packets that are alternately not acknowledged (Gap) and ack... |
| `REQ-QUIC-RFC9000-S19P3P1-0002` | ACK Ranges MAY be repeated |
| `REQ-QUIC-RFC9000-S19P3P1-0003` | The Gap field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P3P1-0004` | The ACK Range Length field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P3P1-0005` | The Gap field MUST be variable-length integer indicating the number of contiguous unacknowled... |
| `REQ-QUIC-RFC9000-S19P3P1-0006` | The ACK Range Length field MUST be variable-length integer indicating the number of contiguou... |
| `REQ-QUIC-RFC9000-S19P3P1-0008` | Larger ACK Range values MUST indicate a larger range, with corresponding lower values for the... |
| `REQ-QUIC-RFC9000-S19P3P1-0010` | If any computed packet number is negative, an endpoint MUST generate a connection error of ty... |
| `REQ-QUIC-RFC9000-S19P3P2-0001` | The ACK frame MUST use the least significant bit of the type value (that is, type 0x03) to in... |
| `REQ-QUIC-RFC9000-S19P3P2-0002` | The ECT0 Count field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P3P2-0003` | The ECT1 Count field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P3P2-0004` | The ECN-CE Count field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P3P2-0005` | The ECT0 Count field MUST be variable-length integer representing the total number of packets... |
| `REQ-QUIC-RFC9000-S19P3P2-0006` | The ECT1 Count field MUST be variable-length integer representing the total number of packets... |
| `REQ-QUIC-RFC9000-S19P3P2-0007` | The ECN-CE Count field MUST be variable-length integer representing the total number of packe... |
| `REQ-QUIC-RFC9000-S19P4-0002` | A receiver of RESET_STREAM MAY discard any data that it already received on that stream |
| `REQ-QUIC-RFC9000-S19P4-0004` | The Type field MUST be encoded as a variable-length integer with value 0x04 |
| `REQ-QUIC-RFC9000-S19P4-0005` | The Stream ID field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P4-0006` | The Application Protocol Error Code field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P4-0007` | The Final Size field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P4-0008` | RESET_STREAM frames MUST contain the following fields: |
| `REQ-QUIC-RFC9000-S19P4-0009` | The Stream ID field MUST be variable-length integer encoding of the stream ID of the stream b... |
| `REQ-QUIC-RFC9000-S19P4-0010` | A variable-length integer containing the application protocol error code (see Section 20.2) t... |
| `REQ-QUIC-RFC9000-S19P4-0011` | The Final Size field MUST be variable-length integer indicating the final size of the stream... |
| `REQ-QUIC-RFC9000-S19P5-0001` | An endpoint MUST use a STOP_SENDING frame (type=0x05) to communicate that incoming data is be... |
| `REQ-QUIC-RFC9000-S19P5-0002` | A STOP_SENDING frame MAY be sent for streams in the "Recv" or "Size Known" states; see Sectio... |
| `REQ-QUIC-RFC9000-S19P5-0005` | The Type field MUST be encoded as a variable-length integer with value 0x05 |
| `REQ-QUIC-RFC9000-S19P5-0006` | The Stream ID field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P5-0007` | The Application Protocol Error Code field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P5-0008` | STOP_SENDING frames MUST contain the following fields: |
| `REQ-QUIC-RFC9000-S19P5-0009` | The Stream ID field MUST be variable-length integer carrying the stream ID of the stream bein... |
| `REQ-QUIC-RFC9000-S19P5-0010` | The Application Protocol Error Code field MUST be variable-length integer containing the appl... |
| `REQ-QUIC-RFC9000-S19P6-0002` | It MAY be sent in all packet types except 0-RTT |
| `REQ-QUIC-RFC9000-S19P6-0003` | CRYPTO frames are functionally identical to STREAM frames, except that they MUST NOT bear a s... |
| `REQ-QUIC-RFC9000-S19P6-0004` | The Type field MUST be encoded as a variable-length integer with value 0x06 |
| `REQ-QUIC-RFC9000-S19P6-0005` | The Offset field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P6-0006` | The Length field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P6-0007` | CRYPTO frames MUST contain the following fields: |
| `REQ-QUIC-RFC9000-S19P6-0008` | The Offset field MUST be variable-length integer specifying the byte offset in the stream for... |
| `REQ-QUIC-RFC9000-S19P6-0009` | The Length field MUST be variable-length integer specifying the length of the Crypto Data fie... |
| `REQ-QUIC-RFC9000-S19P6-0010` | The largest offset delivered on a stream -- the sum of the offset and data length -- MUST NOT... |
| `REQ-QUIC-RFC9000-S19P6-0012` | Unlike STREAM frames, which MUST include a stream ID indicating to which stream the data belo... |
| `REQ-QUIC-RFC9000-S19P6-0013` | The stream MUST NOT have an explicit end, so CRYPTO frames do not have a FIN bit |
| `REQ-QUIC-RFC9000-S19P7-0001` | The Type field MUST be encoded as a variable-length integer with value 0x07 |
| `REQ-QUIC-RFC9000-S19P7-0002` | The Token Length field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P7-0003` | NEW_TOKEN frames MUST contain the following fields: |
| `REQ-QUIC-RFC9000-S19P7-0004` | The Token Length field MUST be variable-length integer specifying the length of the token in... |
| `REQ-QUIC-RFC9000-S19P7-0005` | An opaque blob that the client MAY use with a future Initial packet |
| `REQ-QUIC-RFC9000-S19P7-0008` | A client might receive multiple NEW_TOKEN frames that MUST contain the same token value if pa... |
| `REQ-QUIC-RFC9000-S19P8-0001` | The OFF bit (0x04) in the frame type MUST be set to indicate that there is an Offset field pr... |
| `REQ-QUIC-RFC9000-S19P8-0002` | When set to 0, the Offset field is absent and the Stream Data starts at an offset of 0 (that... |
| `REQ-QUIC-RFC9000-S19P8-0003` | The LEN bit (0x02) in the frame type MUST be set to indicate that there is a Length field pre... |
| `REQ-QUIC-RFC9000-S19P8-0004` | If this bit MUST be set to 0, the Length field is absent and the Stream Data field extends to... |
| `REQ-QUIC-RFC9000-S19P8-0005` | If this bit MUST be set to 1, the Length field is present |
| `REQ-QUIC-RFC9000-S19P8-0006` | The FIN bit (0x01) MUST indicate that the frame marks the end of the stream |
| `REQ-QUIC-RFC9000-S19P8-0008` | The Type field MUST be encoded as a variable-length integer with value 0x08..0x0f |
| `REQ-QUIC-RFC9000-S19P8-0009` | The Stream ID field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P8-0010` | The Offset field MUST be encoded as a variable-length integer when present |
| `REQ-QUIC-RFC9000-S19P8-0011` | The Length field MUST be encoded as a variable-length integer when present |
| `REQ-QUIC-RFC9000-S19P8-0012` | STREAM frames MUST contain the following fields: |
| `REQ-QUIC-RFC9000-S19P8-0013` | The Stream ID field MUST be variable-length integer indicating the stream ID of the stream; s... |
| `REQ-QUIC-RFC9000-S19P8-0014` | The Offset field MUST be variable-length integer specifying the byte offset in the stream for... |
| `REQ-QUIC-RFC9000-S19P8-0015` | This field is present when the OFF bit MUST be set to 1 |
| `REQ-QUIC-RFC9000-S19P8-0016` | The Length field MUST be variable-length integer specifying the length of the Stream Data fie... |
| `REQ-QUIC-RFC9000-S19P8-0017` | This field is present when the LEN bit MUST be set to 1 |
| `REQ-QUIC-RFC9000-S19P8-0018` | When the LEN bit MUST be set to 0, the Stream Data field consumes all the remaining bytes in... |
| `REQ-QUIC-RFC9000-S19P8-0019` | The largest offset delivered on a stream -- the sum of the offset and data length -- MUST NOT... |
| `REQ-QUIC-RFC9000-S19P8-0020` | Receipt of a frame that exceeds this limit MUST be treated as a connection error of type FRAM... |
| `REQ-QUIC-RFC9000-S19P9-0001` | A MAX_DATA frame (type=0x10) MUST be used in flow control to inform the peer of the maximum a... |
| `REQ-QUIC-RFC9000-S19P9-0002` | The Type field MUST be encoded as a variable-length integer with value 0x10 |
| `REQ-QUIC-RFC9000-S19P9-0003` | The Maximum Data field MUST be encoded as a variable-length integer |
| `REQ-QUIC-RFC9000-S19P9-0004` | MAX_DATA frames MUST contain the following field: |
| `REQ-QUIC-RFC9000-S19P9-0005` | A variable-length integer indicating the maximum amount of data that MAY be sent on the entir... |
| `REQ-QUIC-RFC9000-S19P9-0006` | The sum of the final sizes on all streams -- including streams in terminal states -- MUST NOT... |
| `REQ-QUIC-RFC9000-S19P9-0008` | This MUST include violations of remembered limits in Early Data; see Section 7.4.1 |
| `REQ-QUIC-RFC9000-S2-0003` | Allow streams to be long-lived |
| `REQ-QUIC-RFC9000-S20P1-0001` | This section lists the defined QUIC transport error codes that MAY be used in a CONNECTION_CL... |
| `REQ-QUIC-RFC9000-S20P1-0002` | An endpoint MUST use this with CONNECTION_CLOSE to signal that the connection is being closed... |
| `REQ-QUIC-RFC9000-S20P1-0003` | The endpoint encountered an internal error and MUST NOT continue with the connection |
| `REQ-QUIC-RFC9000-S20P1-0004` | An endpoint has received more data in CRYPTO frames than it MAY buffer |
| `REQ-QUIC-RFC9000-S20P1-0005` | An endpoint is unlikely to receive a CONNECTION_CLOSE frame carrying this code except when th... |
| `REQ-QUIC-RFC9000-S20P1-0006` | A range of 256 values is reserved for carrying error codes specific to the cryptographic hand... |
| `REQ-QUIC-RFC9000-S20P1-0007` | Codes for errors occurring when TLS MUST be used for the cryptographic handshake are describe... |
| `REQ-QUIC-RFC9000-S20P1-0008` | Absent either of these conditions, error codes MUST be used to identify a general function of... |
| `REQ-QUIC-RFC9000-S20P2-0001` | Application protocol error codes MUST be used for the RESET_STREAM frame (Section 19.4), the... |
| `REQ-QUIC-RFC9000-S21P10-0001` | If duplicate packets are discarded by a receiver, an attacker will MUST race the duplicate pa... |
| `RFC9000-S21-11-P2-R01` | To defend against this style of denial of service, endpoints that share a static key for stat... |
| `RFC9000-S21-11-P3-R01` | More generally, servers MUST NOT generate a stateless reset if a connection with the correspo... |
| `REQ-QUIC-RFC9000-S21P12-0001` | Keep Version Negotiation packets free of downgrade prevention mechanisms |
| `REQ-QUIC-RFC9000-S21P1P1P1-0001` | Use address validation to confirm receipt capability |
| `REQ-QUIC-RFC9000-S21P1P1P1-0002` | Limit bytes sent to unvalidated addresses |
| `REQ-QUIC-RFC9000-S21P2-0001` | Disallow address change during handshake |
| `REQ-QUIC-RFC9000-S21P2-0002` | Discard packets that cannot be authenticated |
| `RFC9000-S21-3-P2-R01` | Servers SHOULD provide mitigations for this attack by limiting the usage and lifetime of addr... |
| `RFC9000-S21-4-P1-S2-R01` | An endpoint MAY skip packet numbers when sending packets to detect this behavior |
| `REQ-QUIC-RFC9000-S21P5-0001` | For request forgery to be effective, an attacker MUST be able to influence what packets the p... |
| `RFC9000-S21-5-P7-S2-R01` | QUIC servers SHOULD NOT be deployed in networks that do not deploy ingress filtering [BCP38]... |
| `RFC9000-S21-5-3-P2-R01` | A client MUST NOT send non-probing frames to a preferred address prior to validating that add... |
| `RFC9000-S21-5-6-P4-S1-R01` | Endpoints MAY choose to reduce the risk of request forgery by not including values from NEW_T... |
| `REQ-QUIC-RFC9000-S21P5P6-0005` | Endpoints MAY choose to avoid sending datagrams to these ports or not send datagrams that mat... |
| `RFC9000-S21-6-P2-R01` | QUIC deployments SHOULD provide mitigations for the Slowloris attacks, such as increasing the... |
| `RFC9000-S21-9-P4-R01` | While there are legitimate uses for all messages, implementations SHOULD track cost of proces... |
| `RFC9000-S21-9-P4-R02` | Endpoints MAY respond to this condition with a connection error or by dropping packets |
| `REQ-QUIC-RFC9000-S22P1P1-0001` | Require only codepoint value and contact information for provisional registration requests |
| `REQ-QUIC-RFC9000-S22P1P1-0002` | Require Expert Review for provisional registrations |
| `REQ-QUIC-RFC9000-S22P1P1-0003` | Include a Date field in provisional registrations |
| `REQ-QUIC-RFC9000-S22P1P1-0004` | Allow provisional date updates without expert review |
| `REQ-QUIC-RFC9000-S22P1P1-0005` | Include provisional registration support fields |
| `REQ-QUIC-RFC9000-S22P1P1-0006` | Define the Value field |
| `REQ-QUIC-RFC9000-S22P1P1-0007` | Define the Status field |
| `REQ-QUIC-RFC9000-S22P1P1-0008` | Define the Specification field |
| `REQ-QUIC-RFC9000-S22P1P1-0009` | Define the Date field |
| `REQ-QUIC-RFC9000-S22P1P1-0010` | Define the Change Controller field |
| `REQ-QUIC-RFC9000-S22P1P1-0011` | Define the Contact field |
| `REQ-QUIC-RFC9000-S22P1P1-0012` | Define the Notes field |
| `REQ-QUIC-RFC9000-S22P1P1-0014` | Do not require Date when requesting registration |
| `RFC9000-S22-1-2-P1-R01` | New requests for codepoints from QUIC registries SHOULD use a randomly selected codepoint tha... |
| `REQ-QUIC-RFC9000-S22P1P2-0003` | Reserve first unassigned codepoint for Standards Action |
| `REQ-QUIC-RFC9000-S22P1P2-0004` | Allow early codepoint assignment for selected values |
| `RFC9000-S22-1-2-P3-R01` | For codepoints that are encoded in variable-length integers (Section 16), such as frame types... |
| `RFC9000-S22-1-2-P4-S2-R01` | IANA MUST allocate the selected codepoint if the codepoint is unassigned and the requirements... |
| `REQ-QUIC-RFC9000-S22P1P4-0001` | Use Specification Required for permanent registrations |
| `REQ-QUIC-RFC9000-S22P1P4-0002` | Verify the specification for permanent registrations |
| `REQ-QUIC-RFC9000-S22P1P4-0003` | The creation of a registry MAY specify additional constraints on permanent registrations |
| `RFC9000-S22-1-4-P2-R01` | The creation of a registry MAY identify a range of codepoints where registrations are governe... |
| `REQ-QUIC-RFC9000-S22P1P4-0005` | Do not block provisional registrations with stricter permanent requirements |
| `REQ-QUIC-RFC9000-S22P1P4-0007` | Assign document registrations permanent status |
| `REQ-QUIC-RFC9000-S22P1P4-0008` | Record the change controller and contact for document registrations |
| `REQ-QUIC-RFC9000-S22P2-0001` | Assign codepoint 0x00000001 |
| `RFC9000-S22-2-P4-S1-R02` | Exclude reserved version-pattern codepoints from listings |
| `RFC9000-S22-2-P4-S1-R01` | Protect reserved version-pattern codepoints |
| `REQ-QUIC-RFC9000-S22P3-0001` | Use Specification Required for transport parameters |
| `REQ-QUIC-RFC9000-S22P3-0002` | Use stricter policy for low transport-parameter codepoints |
| `RFC9000-S22-3-P3-R01` | Include Parameter Name for transport parameters |
| `REQ-QUIC-RFC9000-S22P3-0004` | Define Parameter Name |
| `REQ-QUIC-RFC9000-S22P4-0001` | Use Specification Required for frame types |
| `REQ-QUIC-RFC9000-S22P4-0002` | Use stricter policy for low frame-type codepoints |
| `REQ-QUIC-RFC9000-S22P4-0003` | Include Frame Type Name for frame types |
| `REQ-QUIC-RFC9000-S22P4-0004` | Define Frame Type Name |
| `REQ-QUIC-RFC9000-S22P4-0005` | In addition to the advice in Section 22.1, specifications for new permanent registrations SHO... |
| `REQ-QUIC-RFC9000-S22P4-0006` | Describe frame field semantics in specifications |
| `REQ-QUIC-RFC9000-S22P5-0001` | Use Specification Required for transport error codes |
| `REQ-QUIC-RFC9000-S22P5-0002` | Use stricter policy for low transport error codepoints |
| `REQ-QUIC-RFC9000-S22P5-0003` | Include Code and Description for transport error codes |
| `REQ-QUIC-RFC9000-S22P5-0004` | Define Code |
| `REQ-QUIC-RFC9000-S22P5-0005` | Define Description |
| `REQ-QUIC-RFC9000-S2P1-0001` | Constrain unidirectional stream direction |
| `REQ-QUIC-RFC9000-S2P1-0002` | Constrain bidirectional stream direction |
| `REQ-QUIC-RFC9000-S2P1-0003` | Identify streams by stream ID |
| `REQ-QUIC-RFC9000-S2P1-0008` | Use the low bit to identify stream initiator |
| `REQ-QUIC-RFC9000-S2P1-0009` | Use even IDs for client-initiated streams |
| `REQ-QUIC-RFC9000-S2P1-0010` | Use odd IDs for server-initiated streams |
| `REQ-QUIC-RFC9000-S2P1-0011` | Use the second low bit to distinguish stream direction |
| `REQ-QUIC-RFC9000-S2P1-0012` | Start each stream space at its minimum value |
| `REQ-QUIC-RFC9000-S2P1-0014` | Open lower-numbered streams when a stream ID is used out of order |
| `REQ-QUIC-RFC9000-S2P2-0001` | Encapsulate application data in STREAM frames |
| `REQ-QUIC-RFC9000-S2P2-0004` | Buffer out-of-order stream data until it can be delivered in order |
| `RFC9000-S2-2-P3-S1-R01` | Allow optional out-of-order delivery to applications |
| `REQ-QUIC-RFC9000-S2P2-0006` | Permit discarded received data |
| `RFC9000-S2-2-P4-S2-R01` | Keep retransmitted stream data stable at the same offset |
| `REQ-QUIC-RFC9000-S2P2-0009` | Expose streams as ordered byte streams only |
| `REQ-QUIC-RFC9000-S2P3-0001` | Avoid a built-in prioritization exchange |
| `REQ-QUIC-RFC9000-S2P3-0003` | Use application priority information for resource allocation |
| `REQ-QUIC-RFC9000-S2P4-0001` | Provide the stream operations described here |
| `REQ-QUIC-RFC9000-S2P4-0002` | Allow protocol-specific implementations to expose only needed operations |
| `REQ-QUIC-RFC9000-S2P4-0003` | Allow writing data after reserving flow control credit |
| `REQ-QUIC-RFC9000-S2P4-0004` | Allow clean stream termination |
| `REQ-QUIC-RFC9000-S2P4-0005` | Allow abrupt stream termination |
| `REQ-QUIC-RFC9000-S2P4-0006` | Allow reading data |
| `REQ-QUIC-RFC9000-S2P4-0007` | Allow aborting stream reads |
| `REQ-QUIC-RFC9000-S2P4-0008` | Allow stream state-change notifications |
| `REQ-QUIC-RFC9000-S3-0001` | Choose the correct state machine for unidirectional streams |
| `REQ-QUIC-RFC9000-S3-0002` | Use both state machines for bidirectional streams |
| `REQ-QUIC-RFC9000-S3-0003` | Allow alternate stream state machines with consistent behavior |
| `REQ-QUIC-RFC9000-S3P1-0001` | Treat Ready as a newly created sendable stream |
| `REQ-QUIC-RFC9000-S3P1-0002` | Permit buffering in Ready |
| `REQ-QUIC-RFC9000-S3P1-0003` | Enter Send state on first outbound stream frame |
| `REQ-QUIC-RFC9000-S3P1-0004` | Allow deferred stream ID allocation |
| `REQ-QUIC-RFC9000-S3P1-0005` | Start peer-initiated bidirectional senders in Ready |
| `REQ-QUIC-RFC9000-S3P1-0006` | Transmit and retransmit in Send |
| `REQ-QUIC-RFC9000-S3P1-0007` | Respect peer flow control while sending |
| `REQ-QUIC-RFC9000-S3P1-0010` | Restrict Data Sent retransmissions |
| `REQ-QUIC-RFC9000-S3P1-0011` | Stop flow control checks in Data Sent |
| `REQ-QUIC-RFC9000-S3P1-0012` | Allow ignoring MAX_STREAM_DATA in Data Sent |
| `REQ-QUIC-RFC9000-S3P1-0013` | Enter Data Recvd after all data is acknowledged |
| `REQ-QUIC-RFC9000-S3P1-0014` | Allow application abandonment of stream transmission |
| `REQ-QUIC-RFC9000-S3P1-0015` | Send RESET_STREAM when abandoning transmission |
| `REQ-QUIC-RFC9000-S3P1-0016` | Permit RESET_STREAM as the first frame |
| `REQ-QUIC-RFC9000-S3P1-0017` | Enter Reset Recvd after RESET_STREAM is acknowledged |
| `REQ-QUIC-RFC9000-S3P2-0001` | Do not track unobservable sending-part states |
| `REQ-QUIC-RFC9000-S3P2-0002` | Track data delivery to the application |
| `REQ-QUIC-RFC9000-S3P2-0005` | Start receiving parts in Recv |
| `REQ-QUIC-RFC9000-S3P2-0006` | Enter Recv when the peer-side sending part opens |
| `REQ-QUIC-RFC9000-S3P2-0007` | Open bidirectional streams on peer flow-control or stop-sending frames |
| `REQ-QUIC-RFC9000-S3P2-0008` | Interpret MAX_STREAM_DATA on an unopened stream as peer opening |
| `REQ-QUIC-RFC9000-S3P2-0009` | Interpret STOP_SENDING on an unopened stream as a peer desire to stop reception |
| `REQ-QUIC-RFC9000-S3P2-0010` | Allow reordered peer flow-control or stop-sending frames |
| `REQ-QUIC-RFC9000-S3P2-0013` | Buffer received stream data for ordered delivery |
| `REQ-QUIC-RFC9000-S3P2-0014` | Advertise more receive credit as data is consumed |
| `REQ-QUIC-RFC9000-S3P2-0015` | Recognize final size when FIN arrives |
| `REQ-QUIC-RFC9000-S3P2-0016` | Enter Size Known after FIN |
| `REQ-QUIC-RFC9000-S3P2-0018` | Discard further stream frames after all data is received |
| `REQ-QUIC-RFC9000-S3P2-0020` | Enter Data Read after delivery to the application |
| `REQ-QUIC-RFC9000-S3P2-0021` | Enter Reset Recvd on RESET_STREAM in Recv or Size Known |
| `REQ-QUIC-RFC9000-S3P2-0023` | Remain in Data Recvd when RESET_STREAM is suppressed |
| `REQ-QUIC-RFC9000-S3P2-0024` | Enter Reset Read after the application receives reset notification |
| `REQ-QUIC-RFC9000-S3P3-0001` | Forbid terminal-state transmit frames |
| `RFC9000-S3-3-P2-S2-R01` | Forbid post-reset transmission of STREAM frames |
| `REQ-QUIC-RFC9000-S3P3-0003` | Allow delayed receipt of state-changing frames |
| `REQ-QUIC-RFC9000-S3P3-0004` | Limit MAX_STREAM_DATA to Recv |
| `REQ-QUIC-RFC9000-S3P3-0005` | Allow STOP_SENDING except after reset reception |
| `REQ-QUIC-RFC9000-S3P3-0006` | Allow delayed receipt of receiver-side frames |
| `REQ-QUIC-RFC9000-S3P4-0001` | Compose bidirectional streams from send and receive parts |
| `REQ-QUIC-RFC9000-S3P4-0002` | Allow composite stream-state representations |
| `REQ-QUIC-RFC9000-S3P4-0003` | Require acknowledgment before closed-state transitions in the example mapping |
| `REQ-QUIC-RFC9000-S3P5-0001` | Allow aborting stream reads with an application error code |
| `RFC9000-S3-5-P2-S1-R01` | Signal aborting reads with STOP_SENDING |
| `REQ-QUIC-RFC9000-S3P5-0003` | Count data after STOP_SENDING toward flow control |
| `REQ-QUIC-RFC9000-S3P5-0004` | Treat STOP_SENDING as a request for RESET_STREAM |
| `REQ-QUIC-RFC9000-S3P5-0005` | Send RESET_STREAM after receiving STOP_SENDING in Ready or Send |
| `RFC9000-S3-5-P4-S3-R01` | Permit deferred RESET_STREAM in Data Sent |
| `RFC9000-S3-5-P4-S4-R01` | Prefer RESET_STREAM over retransmission after loss |
| `RFC9000-S3-5-P5-S1-R01` | Copy STOP_SENDING error codes when sending RESET_STREAM |
| `RFC9000-S3-5-P5-S2-R01` | Allow ignoring later RESET_STREAM error codes |
| `REQ-QUIC-RFC9000-S3P5-0011` | Repeat STOP_SENDING after loss |
| `REQ-QUIC-RFC9000-S3P5-0012` | Allow RESET_STREAM to terminate one direction of a bidirectional stream |
| `REQ-QUIC-RFC9000-S3P5-0013` | Allow STOP_SENDING to encourage prompt opposite-direction termination |
| `REQ-QUIC-RFC9000-S4-0001` | Flow-control streams and the whole connection |
| `REQ-QUIC-RFC9000-S4-0002` | Limit bytes on streams and across the connection |
| `REQ-QUIC-RFC9000-S4P1-0001` | Use limit-based flow control |
| `REQ-QUIC-RFC9000-S4P1-0002` | Limit per-stream receive buffer use |
| `REQ-QUIC-RFC9000-S4P1-0006` | Advertise larger flow-control limits with MAX frames |
| `REQ-QUIC-RFC9000-S4P1-0009` | Advertise larger connection limits with MAX_DATA |
| `REQ-QUIC-RFC9000-S4P1-0011` | Ignore smaller advertised limits |
| `RFC9000-S4-2-P2-S1-R01` | Allow repeated or early credit advertisements |
| `REQ-QUIC-RFC9000-S4P2-0002` | Allow autotuning of flow-control credit |
| `REQ-QUIC-RFC9000-S4P2-0003` | Send flow-control frames opportunistically |
| `REQ-QUIC-RFC9000-S4P2-0004` | Do not require blocked senders to signal blocking |
| `REQ-QUIC-RFC9000-S4P4-0001` | Tear down state and ignore later data after RESET_STREAM |
| `REQ-QUIC-RFC9000-S4P4-0002` | Terminate only one direction on RESET_STREAM |
| `REQ-QUIC-RFC9000-S4P5-0001` | Communicate final size reliably |
| `REQ-QUIC-RFC9000-S4P5-0002` | Use STREAM FIN to carry final size |
| `REQ-QUIC-RFC9000-S4P5-0003` | Use RESET_STREAM Final Size to carry final size |
| `REQ-QUIC-RFC9000-S4P5-0007` | Treat final-size changes as errors |
| `RFC9000-S4-5-P5-S2-R01` | Treat data beyond final size as an error |
| `REQ-QUIC-RFC9000-S4P6-0001` | Limit the cumulative number of incoming streams |
| `REQ-QUIC-RFC9000-S4P6-0002` | Restrict stream IDs to the advertised limit |
| `REQ-QUIC-RFC9000-S4P6-0003` | Set initial stream limits in transport parameters |
| `REQ-QUIC-RFC9000-S4P6-0004` | Advertise later stream limits with MAX_STREAMS |
| `REQ-QUIC-RFC9000-S4P6-0005` | Apply separate limits by stream direction |
| `RFC9000-S4-6-P2-S1-R01` | Close on oversized stream-count values in transport parameters |
| `REQ-QUIC-RFC9000-S4P6-0007` | Close on oversized stream-count values in frames |
| `REQ-QUIC-RFC9000-S4P6-0010` | Ignore smaller advertised stream limits |
| `REQ-QUIC-RFC9000-S4P6-0011` | Ignore non-increasing MAX_STREAMS frames |
| `REQ-QUIC-RFC9000-S5-0001` | Treat a QUIC connection as shared client-server state |
| `REQ-QUIC-RFC9000-S5-0002` | Start every connection with a handshake phase |
| `REQ-QUIC-RFC9000-S5-0003` | Use the handshake to confirm willingness and establish parameters |
| `REQ-QUIC-RFC9000-S5-0004` | Allow limited connection use during the handshake |
| `REQ-QUIC-RFC9000-S5-0005` | Allow 0-RTT client data before server response |
| `REQ-QUIC-RFC9000-S5-0006` | Do not provide replay protection for 0-RTT |
| `REQ-QUIC-RFC9000-S5-0007` | Allow server data before final handshake messages |
| `REQ-QUIC-RFC9000-S5-0008` | Use connection IDs to enable migration |
| `REQ-QUIC-RFC9000-S5P1-0001` | Assign each connection a set of CIDs |
| `REQ-QUIC-RFC9000-S5P1-0002` | Let endpoints choose peer-used connection IDs |
| `REQ-QUIC-RFC9000-S5P1-0003` | Use CIDs to survive address changes |
| `REQ-QUIC-RFC9000-S5P1-0004` | Make CID selection routable and recognizable |
| `REQ-QUIC-RFC9000-S5P1-0005` | Use multiple CIDs for privacy |
| `REQ-QUIC-RFC9000-S5P1-0008` | Include CID fields in long headers |
| `REQ-QUIC-RFC9000-S5P1-0009` | Include only the destination CID in short headers |
| `REQ-QUIC-RFC9000-S5P1-0010` | Know the short-header destination CID length |
| `REQ-QUIC-RFC9000-S5P1-0011` | Allow load balancers to agree on CID handling |
| `REQ-QUIC-RFC9000-S5P1-0012` | Echo client CIDs in Version Negotiation |
| `REQ-QUIC-RFC9000-S5P1-0014` | Avoid concurrent zero-length-CID connections on the same address tuple |
| `REQ-QUIC-RFC9000-S5P1P1-0001` | Associate each CID with a sequence number |
| `REQ-QUIC-RFC9000-S5P1P1-0005` | Use NEW_CONNECTION_ID for additional CIDs |
| `REQ-QUIC-RFC9000-S5P1P1-0007` | Do not sequence the first client-selected CID or Retry-provided CID |
| `REQ-QUIC-RFC9000-S5P1P1-0008` | Accept packets carrying an issued CID for the connection lifetime |
| `REQ-QUIC-RFC9000-S5P1P1-0009` | Treat active CIDs as valid at any time |
| `RFC9000-S5-1-1-P4-S3-R01` | Do not exceed the peer's active CID limit |
| `RFC9000-S5-1-1-P4-S4-R01` | Allow temporary CID excess only with immediate retirement requirements |
| `RFC9000-S5-1-1-P5-S2-R01` | Close on too many active CIDs |
| `RFC9000-S5-1-1-P6-S3-R01` | Allow limiting the total number of issued CIDs |
| `RFC9000-S5-1-1-P6-S4-R01` | Allow limiting CID issuance to reduce per-path state |
| `RFC9000-S5-1-1-P7-S1-R01` | Keep enough peer-usable CIDs for migration |
| `REQ-QUIC-RFC9000-S5P1P2-0002` | Consume CIDs in response to migration |
| `REQ-QUIC-RFC9000-S5P1P2-0003` | Maintain a set of peer-issued CIDs |
| `REQ-QUIC-RFC9000-S5P1P2-0004` | Retire a CID by sending RETIRE_CONNECTION_ID |
| `REQ-QUIC-RFC9000-S5P1P2-0005` | Make RETIRE_CONNECTION_ID a no-reuse request |
| `REQ-QUIC-RFC9000-S5P1P2-0008` | Prompt peer retirement with an increased Retire Prior To |
| `REQ-QUIC-RFC9000-S5P1P2-0009` | Continue accepting retired CIDs until the peer retires them |
| `RFC9000-S5-1-2-P6-S2-R01` | Track at least twice the active CID limit |
| `REQ-QUIC-RFC9000-S5P1P2-0015` | Allow treating excessive unretired CIDs as an error |
| `REQ-QUIC-RFC9000-S5P2-0001` | Classify incoming packets on receipt |
| `REQ-QUIC-RFC9000-S5P2-0002` | Allow existing-connection association or new server connections |
| `REQ-QUIC-RFC9000-S5P2-0003` | Try to associate packets with an existing connection |
| `REQ-QUIC-RFC9000-S5P2-0004` | Process packets that match the existing CID |
| `REQ-QUIC-RFC9000-S5P2-0006` | Allow fragile zero-length-CID matching strategies |
| `REQ-QUIC-RFC9000-S5P2-0007` | Allow Stateless Reset for unattributed packets |
| `REQ-QUIC-RFC9000-S5P2-0008` | Discard packets inconsistent with connection state |
| `REQ-QUIC-RFC9000-S5P2-0009` | Discard packets with a different protocol version |
| `REQ-QUIC-RFC9000-S5P2-0010` | Discard packets if packet protection cannot be removed |
| `REQ-QUIC-RFC9000-S5P2-0012` | Generate a connection error on pre-error processing |
| `REQ-QUIC-RFC9000-S5P2-0013` | Revert changes made while processing weakly protected invalid packets |
| `REQ-QUIC-RFC9000-S5P2P1-0001` | Match client packets by client-selected CID |
| `REQ-QUIC-RFC9000-S5P2P1-0003` | Discard packets that do not match an existing client connection |
| `REQ-QUIC-RFC9000-S5P2P1-0004` | Allow clients to drop or buffer not-yet-decryptable packets |
| `RFC9000-S5-2-2-P1-S1-R01` | Send Version Negotiation for large unsupported packets |
| `RFC9000-S5-2-2-P2-S4-R01` | Prefer Version Negotiation when possible |
| `REQ-QUIC-RFC9000-S5P2P2-0005` | Match supported-version packets by connection ID or address tuple |
| `RFC9000-S5-2-2-P6-S2-R01` | Ignore premature Handshake packets from clients |
| `REQ-QUIC-RFC9000-S5P2P3-0001` | Allow out-of-band forwarding for simple load balancers |
| `REQ-QUIC-RFC9000-S5P2P3-0002` | Allow preferred-address migration for dedicated server addresses |
| `REQ-QUIC-RFC9000-S5P2P3-0003` | Allow clients to decline preferred addresses |
| `REQ-QUIC-RFC9000-S5P2P3-0006` | Avoid stateless reset oracles in simple load balancing |
| `REQ-QUIC-RFC9000-S5P3-0001` | Allow clients to open connections |
| `REQ-QUIC-RFC9000-S5P3-0002` | Allow clients to enable Early Data |
| `REQ-QUIC-RFC9000-S5P3-0003` | Allow clients to learn Early Data acceptance |
| `REQ-QUIC-RFC9000-S5P3-0004` | Allow servers to listen for connections |
| `REQ-QUIC-RFC9000-S5P3-0005` | Allow servers to embed application data in resumption tickets |
| `REQ-QUIC-RFC9000-S5P3-0006` | Allow servers to use resumption-ticket data for Early Data decisions |
| `REQ-QUIC-RFC9000-S5P3-0007` | Allow configuring initial stream counts |
| `REQ-QUIC-RFC9000-S5P3-0008` | Allow receive-buffer control via flow control limits |
| `REQ-QUIC-RFC9000-S5P3-0009` | Allow handshake status queries |
| `REQ-QUIC-RFC9000-S5P3-0010` | Allow connection liveness maintenance |
| `REQ-QUIC-RFC9000-S5P3-0011` | Allow immediate connection close |
| `REQ-QUIC-RFC9000-S6-0002` | Clients that support multiple QUIC versions SHOULD ensure that the first UDP datagram they send is sized to the largest of the minimum datagram sizes from all versions they support, using PADDING frames (Section 19 |
| `REQ-QUIC-RFC9000-0284` | Send Version Negotiation with accepted versions |
| `REQ-QUIC-RFC9000-S6P2-0001` | Reject unsupported Version Negotiation attempts |
| `RFC9000-S6-2-P2-R01` | That supports only this version of QUIC MUST abandon the current connection attempt if it receives a Version Negotiation packet, with the following two exceptions |
| `RFC9000-S6-3-P2-R01` | Use reserved versions to test ignoring |
| `RFC9000-S6-3-P2-S2-R01` | Use reserved versions to test discarding |
| `REQ-QUIC-RFC9000-S7-0001` | Provide the following properties: |
| `REQ-QUIC-RFC9000-S7-0002` | Provide authenticated key exchange |
| `REQ-QUIC-RFC9000-S7-0003` | Always authenticate the server |
| `REQ-QUIC-RFC9000-S7-0004` | Allow optional client authentication |
| `REQ-QUIC-RFC9000-S7-0005` | Produce distinct keys per connection |
| `REQ-QUIC-RFC9000-S7-0006` | Use handshake keys for 0-RTT and 1-RTT protection |
| `REQ-QUIC-RFC9000-S7-0007` | Authenticate transport parameter exchange |
| `REQ-QUIC-RFC9000-S7-0008` | Protect server transport parameters |
| `REQ-QUIC-RFC9000-S7-0009` | Authenticate application protocol negotiation |
| `REQ-QUIC-RFC9000-S7P2-0002` | Use Source Connection ID to select the peer-facing Destination Connection ID |
| `REQ-QUIC-RFC9000-S7P2-0004` | Use an unpredictable client Destination Connection ID |
| `REQ-QUIC-RFC9000-S7P2-0007` | Populate the client Source Connection ID |
| `RFC9000-S7-2-P8-S1-R01` | Change the Destination Connection ID it uses for sending packets in response to only the first received Initial or Retry packet |
| `REQ-QUIC-RFC9000-S7P2-0013` | Allow further Destination Connection ID changes only from NEW_CONNECTION_ID frames |
| `RFC9000-S7-2-P8-S3-R02` | Discard subsequent Initial packets with a different Source Connection ID |
| `REQ-QUIC-RFC9000-S7P3-0001` | Authenticate connection ID choices through transport parameters |
| `REQ-QUIC-RFC9000-S7P3-0003` | Echo the client Initial Destination Connection ID in original_destination_connection_id |
| `REQ-QUIC-RFC9000-S7P3-0004` | Echo the Retry Source Connection ID when Retry is used |
| `RFC9000-S7-3-P3-S1-R01` | The values provided by a peer for these transport parameters MUST match the values that an endpoint used in the Destination and Source Connection ID fields of Initial packets that it sent (and received, for servers) |
| `RFC9000-S7-3-P4-S1-R01` | Treat the absence of the initial_source_connection_id transport parameter from either endpoint or the absence of the original_destination_connection_id transport parameter from the server as a connection error of type TRANSPORT_PARAMETER_ERROR |
| `REQ-QUIC-RFC9000-S7P3-0008` | Treat the following as a connection error of type TRANSPORT_PARAMETER_ERROR or PROTOCOL_VIOLATION: |
| `RFC9000-S7-4-1-P3-S1-R01` | The definition of a new transport parameter (Section 7 |
| `RFC9000-S7-4-1-P4-S1-R01` | Use remembered values for the following parameters: ack_delay_exponent, max_ack_delay, initial_source_connection_id, original_destination_connection_id, preferred_address, retry_source_connection_id, and stateless_reset_token |
| `RFC9000-S7-4-1-P6-R01` | If 0-RTT data is accepted by the server, the server MUST NOT reduce any limits or alter any values that might be violated by the client with its 0-RTT data |
| `RFC9000-S7-4-1-P6-S1-R01` | In particular, a server that accepts 0-RTT data MUST NOT set values for the following parameters (Section 18 |
| `REQ-QUIC-RFC9000-S7P4P1-0010` | Do not use updated transport-parameter values in 0-RTT |
| `REQ-QUIC-RFC9000-S7P4P1-0012` | Allow 0-RTT only with remembered transport parameters |
| `RFC9000-S7-5-P2-S2-R01` | Choose to allow more data to be buffered during the handshake |
| `REQ-QUIC-RFC9000-S7P5-0004` | Once the handshake completes, if an endpoint is unable to buffer all data in a CRYPTO frame, it MAY discard that CRYPTO frame and all CRYPTO frames received in the future, or it MAY close the connection with a CRYPTO_BUFFER_EXCEEDED error code |
| `RFC9000-S7-5-P4-S2-R01` | Containing discarded CRYPTO frames MUST be acknowledged because the packet has been received and processed by the transport even though the CRYPTO frame was discarded |
| `RFC9000-S8-P2-S2-R01` | Limit sending to unvalidated addresses |
| `RFC9000-S8-1-P2-R01` | Additionally, an endpoint MAY consider the peer address validated if the peer uses a connection ID chosen by the endpoint and the connection ID contains at least 64 bits of entropy |
| `RFC9000-S8-1-P4-R01` | Prior to validating the client address, servers MUST NOT send more than three times as many bytes as the number of bytes they have received |
| `RFC9000-S8-1-P4-S2-R01` | For the purposes of avoiding amplification prior to address validation, servers MUST count all of the payload bytes received in datagrams that are uniquely attributed to a single connection |
| `RFC9000-S8-1-P6-S3-R01` | To prevent this deadlock, clients MUST send a packet on a Probe Timeout (PTO) |
| `REQ-QUIC-RFC9000-S8P1-0006` | Specifically, the client MUST send an Initial packet in a UDP datagram that contains at least 1200 bytes if it does not have Handshake keys, and otherwise send a Handshake packet |
| `RFC9000-S8-1-P6-S3-R01` | Probe on PTO to avoid handshake deadlock |
| `REQ-QUIC-RFC9000-S8P1P2-0001` | This token MUST be repeated by the client in all Initial packets it sends for that connection after it receives the Retry packet |
| `REQ-QUIC-RFC9000-S8P1P2-0002` | Instead, the server SHOULD immediately close (Section 10 |
| `REQ-QUIC-RFC9000-S8P1P2-0003` | Validate Retry token returns |
| `REQ-QUIC-RFC9000-S8P1P2-0004` | Close on invalid Retry tokens |
| `RFC9000-S8-1-3-P1-S1-R01` | Provide clients with an address validation token during one connection that can be used on a subsequent connection |
| `RFC9000-S8-1-3-P2-S3-R01` | Include the token in all Initial packets it sends, unless a Retry replaces the token with a newer one |
| `RFC9000-S8-1-3-P3-S2-R01` | Thus, a token SHOULD have an expiration time, which could be either an explicit expiration time or an issued timestamp that can be used to dynamically calculate the expiration time |
| `RFC9000-S8-1-3-P4-S1-R01` | Issued with NEW_TOKEN MUST NOT include information that would allow values to be linked by an observer to the connection on which it was issued |
| `RFC9000-S8-1-3-P4-S3-R01` | Ensure that every NEW_TOKEN frame it sends is unique across all clients, with the exception of those sent to repair losses of previously sent NEW_TOKEN frames |
| `RFC9000-S8-1-3-P4-S4-R01` | Information that allows the server to distinguish between tokens from Retry and NEW_TOKEN MAY be accessible to entities other than the server |
| `RFC9000-S8-1-3-P6-S4-R01` | Include a token that is not applicable to the server that it is connecting to, unless the client has the knowledge that the server that issued the token and the server the client is connecting to are jointly managing the tokens |
| `REQ-QUIC-RFC9000-S8P1P3-0012` | In comparison, a token obtained in a Retry packet MUST be used immediately during the connection attempt and cannot be used in subsequent connection attempts |
| `RFC9000-S8-1-3-P8-S1-R01` | Reuse a token from a NEW_TOKEN frame for different connection attempts |
| `RFC9000-S8-1-3-P10-S1-R01` | When a server receives an Initial packet with an address validation token, it MUST attempt to validate the token, unless it has already completed address validation |
| `RFC9000-S8-1-3-P10-S2-R01` | If the token is invalid, then the server SHOULD proceed as if the client did not have a validated address, including potentially sending a Retry packet |
| `REQ-QUIC-RFC9000-S8P1P3-0017` | Clients MAY use tokens obtained on one connection for any connection attempt using the same version |
| `RFC9000-S8-1-4-P2-S2-R01` | For this design to work, the token MUST be covered by integrity protection against modification or falsification by clients |
| `REQ-QUIC-RFC9000-S8P1P4-0005` | If the client IP address has changed, the server MUST adhere to the anti-amplification limit |
| `REQ-QUIC-RFC9000-S8P1P4-0006` | To protect against such attacks, servers MUST ensure that replay of tokens is prevented or limited |
| `RFC9000-S8-1-4-P5-S3-R01` | Servers SHOULD ensure that tokens sent in Retry packets are only accepted for a short time, as they are returned immediately by clients |
| `REQ-QUIC-RFC9000-S8P1P4-0008` | Tokens that are provided in NEW_TOKEN frames (Section 19 |
| `REQ-QUIC-RFC9000-S8P1P4-0009` | Servers are encouraged to allow tokens to be used only once, if possible |
| `REQ-QUIC-RFC9000-S8P1P4-0010` | Make address-validation tokens hard to guess and integrity protected |
| `REQ-QUIC-RFC9000-S8P1P4-0012` | Protect against token replay |
| `RFC9000-S8-2-1-P2-S1-R01` | Send multiple PATH_CHALLENGE frames to guard against packet loss |
| `RFC9000-S8-2-1-P2-S2-R01` | However, an endpoint SHOULD NOT send multiple PATH_CHALLENGE frames in a single packet |
| `RFC9000-S8-2-1-P4-S1-R01` | Use unpredictable data in every PATH_CHALLENGE frame so that it can associate the peer's response with the corresponding PATH_CHALLENGE |
| `RFC9000-S8-2-1-P5-S1-R01` | Expand datagrams that contain a PATH_CHALLENGE frame to at least the smallest allowed maximum datagram size of 1200 bytes, unless the anti-amplification limit for the path does not permit sending a datagram of this size |
| `RFC9000-S8-2-1-P6-S1-R01` | To ensure that the path MTU is large enough, the endpoint MUST perform a second path validation by sending a PATH_CHALLENGE frame in a datagram of at least 1200 bytes |
| `RFC9000-S8-2-1-P7-S1-R01` | Unlike other cases where datagrams are expanded, endpoints MUST NOT discard datagrams that appear to be too small when they contain PATH_CHALLENGE or PATH_RESPONSE |
| `REQ-QUIC-RFC9000-S8P2P1-0008` | Use PATH_CHALLENGE to validate a path |
| `RFC9000-S8-2-2-P1-S1-R01` | On receiving a PATH_CHALLENGE frame, an endpoint MUST respond by echoing the data contained in the PATH_CHALLENGE frame in a PATH_RESPONSE frame |
| `RFC9000-S8-2-2-P1-S2-R01` | Delay transmission of a packet containing a PATH_RESPONSE frame unless constrained by congestion control |
| `RFC9000-S8-2-2-P2-S3-R01` | This requirement MUST NOT be enforced by the endpoint that initiates path validation, as that would enable an attack on migration |
| `RFC9000-S8-2-2-P3-S1-R01` | Expand datagrams that contain a PATH_RESPONSE frame to at least the smallest allowed maximum datagram size of 1200 bytes |
| `RFC9000-S8-2-2-P3-S3-R01` | However, an endpoint MUST NOT expand the datagram containing the PATH_RESPONSE if the resulting data exceeds the anti-amplification limit |
| `REQ-QUIC-RFC9000-S8P2P2-0007` | Send more than one PATH_RESPONSE frame in response to one PATH_CHALLENGE frame |
| `RFC9000-S8-2-3-P2-S3-R01` | However, the endpoint MUST initiate another path validation with an expanded datagram to verify that the path supports the required MTU |
| `REQ-QUIC-RFC9000-S8P2P4-0002` | That has no valid network path to its peer MAY signal this using the NO_VIABLE_PATH connection error, noting that this is only possible if the network path exists but does not support the required MTU (Section 14) |
| `REQ-QUIC-RFC9000-S8P2P4-0003` | Signal no viable path when appropriate |
| `REQ-QUIC-RFC9000-S9-0002` | If the peer sent the disable_active_migration transport parameter, an endpoint also MUST NOT send packets (including probing packets |
| `REQ-QUIC-RFC9000-S9-0008` | Forbid migration before handshake confirmation |
| `REQ-QUIC-RFC9000-S9-0009` | Respect Disable Active Migration |
| `REQ-QUIC-RFC9000-S9-0010` | Validate Peer Address Changes |
| `REQ-QUIC-RFC9000-S9-0012` | Discard Packets from Unknown Server Addresses |
| `REQ-QUIC-RFC9000-S9P1-0001` | Probe for peer reachability from a new local address using path validation (Section 8 |
| `REQ-QUIC-RFC9000-S9P1-0002` | Probe New Local Addresses Before Migration |
| `REQ-QUIC-RFC9000-S9P2-0003` | Reset Congestion State on Migration |
| `REQ-QUIC-RFC9000-S9P2-0004` | Retain State for Port-Only Changes |
| `REQ-QUIC-RFC9000-S9P2-0005` | Validate ECN Capability After Migration |
| `REQ-QUIC-RFC9000-S9P3-0001` | If the recipient permits the migration, it MUST send subsequent packets to the new peer address and MUST initiate path validation (Section 8 |
| `RFC9000-S9-3-P4-S1-R01` | Allow data on an unvalidated peer address |
| `REQ-QUIC-RFC9000-S9P3-0003` | Protect unvalidated peer-address traffic |
| `RFC9000-S9-3-P4-S2-R01` | Skip validation of a peer address if that address has been seen recently |
| `RFC9000-S9-3-P7-S1-R01` | After verifying a new client address, the server SHOULD send new address validation tokens (Section 8) to the client |
| `REQ-QUIC-RFC9000-S9P3-0007` | Initiate Path Validation After Permitting Migration |
| `REQ-QUIC-RFC9000-S9P3-0009` | Protect Against Address-Spoofing Attacks |
| `REQ-QUIC-RFC9000-S9P3-0010` | Allow Abandoning Other Path Validation |
| `REQ-QUIC-RFC9000-S9P3P1-0001` | Limit Sending Until Address Validation |
| `REQ-QUIC-RFC9000-S9P3P2-0001` | To protect the connection from failing due to such a spurious migration, an endpoint MUST revert to using the last validated peer address when validation of a new peer address fails |
| `REQ-QUIC-RFC9000-S9P3P2-0003` | For instance, an endpoint MAY send a Stateless Reset in response to any further incoming packets |
| `REQ-QUIC-RFC9000-S9P3P2-0004` | Revert to the Last Validated Peer Address |
| `REQ-QUIC-RFC9000-S9P3P2-0005` | Allow Stateless Reset After Silent Close |
| `REQ-QUIC-RFC9000-S9P3P3-0004` | Use Heuristics for Attack Detection |
| `RFC9000-S9-4-P1-S2-R01` | Sent on the old path MUST NOT contribute to congestion control or RTT estimation for the new path |
| `RFC9000-S9-4-P2-S1-R01` | Use updated congestion state only after confirming the peer address |
| `REQ-QUIC-RFC9000-S9P4-0003` | Retain congestion state for port-only changes |
| `REQ-QUIC-RFC9000-S9P4-0004` | Keep ACK coverage across multiple paths |
| `REQ-QUIC-RFC9000-S9P4-0005` | Retain State for Port-Only Peer Changes |
| `REQ-QUIC-RFC9000-S9P4-0007` | Allow Probe-Packet Loss Exceptions |
| `REQ-QUIC-RFC9000-S9P4-0008` | Allow a Separate PATH_CHALLENGE Timer |
| `REQ-QUIC-RFC9000-S9P4-0009` | Allow Retrying PATH_CHALLENGE on Timeout |
| `RFC9000-S9-4-P5-S4-R02` | Do Not Make the PATH_CHALLENGE Timer More Aggressive |
| `RFC9000-S9-5-P2-R01` | At any time, endpoints MAY change the Destination Connection ID they transmit with to a value that has not been used on another path |
| `RFC9000-S9-5-P4-R01` | Prevent connection-id reuse across destination addresses |
| `REQ-QUIC-RFC9000-S9P5-0004` | Due to network changes outside the control of its peer, an endpoint might receive packets from a new source address with the same Destination Connection ID field value, in which case it MAY continue to use the current connection ID with the new remote address while still sending from the same local address |
| `REQ-QUIC-RFC9000-S9P5-0005` | Limit use of the zero-length connection ID for migration |
| `REQ-QUIC-RFC9000-S9P5-0006` | Keep address changes infrequent |
| `REQ-QUIC-RFC9000-S9P5-0007` | Provide new connection IDs before peers migrate |
| `REQ-QUIC-RFC9000-S9P5-0008` | Keep Provided Connection IDs Unlinkable |
| `REQ-QUIC-RFC9000-S9P5-0009` | Allow Reuse with the Same Local Address |
| `REQ-QUIC-RFC9000-S9P6-0001` | If a client receives packets from a new server address when the client has not initiated a migration to that address, the client SHOULD discard these packets |
| `REQ-QUIC-RFC9000-S9P6-0002` | Discard Unexpected Server-Address Packets |
| `REQ-QUIC-RFC9000-S9P6P1-0001` | Servers MAY communicate a preferred address of each address family (IPv4 and IPv6) to allow clients to pick the one most suited to their network attachment |
| `REQ-QUIC-RFC9000-S9P6P1-0002` | Once the handshake is confirmed, the client SHOULD select one of the two addresses provided by the server and initiate path validation (see Section 8 |
| `REQ-QUIC-RFC9000-S9P6P1-0003` | Begin sending packets to the new server address after successful validation |
| `REQ-QUIC-RFC9000-S9P6P1-0004` | Discontinue use of the old server address after successful validation |
| `RFC9000-S9-6-1-P4-S2-R01` | Keep using the original server address after failed validation |
| `REQ-QUIC-RFC9000-S9P6P1-0006` | Convey a Preferred Address in the TLS Handshake |
| `REQ-QUIC-RFC9000-S9P6P1-0007` | Allow Per-Family Preferred Addresses |
| `REQ-QUIC-RFC9000-S9P6P1-0009` | Use an Unused Active Connection ID for Preferred-Address Migration |
| `REQ-QUIC-RFC9000-S9P6P1-0010` | Move Future Packets to the New Server Address After Validation |
| `REQ-QUIC-RFC9000-S9P6P2-0001` | That migrates to a preferred address MUST validate the address it chooses before migrating |
| `REQ-QUIC-RFC9000-S9P6P2-0006` | Do not use preferred-address values for other connections |
| `REQ-QUIC-RFC9000-S9P6P2-0007` | Use these for other connections, including connections that are resumed from the current connection |
| `REQ-QUIC-RFC9000-S9P6P2-0009` | Respond to PATH_CHALLENGE with PATH_RESPONSE |
| `REQ-QUIC-RFC9000-S9P6P2-0010` | Move Exclusively to the Preferred Address After Validation |
| `REQ-QUIC-RFC9000-S9P6P2-0011` | Restrict Preferred-Address Values to the Current Connection |
| `REQ-QUIC-RFC9000-S9P6P3-0005` | Servers SHOULD initiate path validation to the client's new address upon receiving a probe packet from a different address |
| `REQ-QUIC-RFC9000-S9P6P3-0007` | Keep preferred-address connection IDs path-agnostic |
| `REQ-QUIC-RFC9000-S9P6P3-0008` | Use the preferred-address connection ID on any path |
| `REQ-QUIC-RFC9000-S9P6P3-0009` | Protect Preferred-Address Traffic from Attacks |
| `REQ-QUIC-RFC9000-S9P7-0001` | That send data using IPv6 SHOULD apply an IPv6 flow label in compliance with [RFC6437], unless the local API does not allow setting IPv6 flow labels |
| `REQ-QUIC-RFC9000-S9P7-0002` | The flow label generation MUST be designed to minimize the chances of linkability with a previously used flow label, as a stable flow label would enable correlating activity on multiple paths |
| `REQ-QUIC-RFC9000-S9P7-0003` | Apply IPv6 Flow Labels |
| `REQ-QUIC-RFC9000-S9P7-0004` | Minimize Flow-Label Linkability |

## Staged IDs Not Present In Live
Staged IDs not present in live are candidate new-only requirements or replacements requiring semantic review.

| Staged ID | Title |
|---|---|
| `REQ-QUIC-RFC9000-0001` | Authenticate packet contents |
| `REQ-QUIC-RFC9000-0002` | Encrypt packet contents |
| `REQ-QUIC-RFC9000-0003` | Streams are ordered byte sequences |
| `REQ-QUIC-RFC9000-0004` | Bidirectional streams allow both endpoints to send |
| `REQ-QUIC-RFC9000-0005` | Unidirectional streams allow one endpoint to send |
| `REQ-QUIC-RFC9000-0006` | Bound data sent with credit |
| `REQ-QUIC-RFC9000-0007` | Limit stream creation with credit |
| `REQ-QUIC-RFC9000-0008` | Connections are not bound to one path |
| `REQ-QUIC-RFC9000-0009` | Migration uses connection identifiers |
| `REQ-QUIC-RFC9000-0010` | Client-only migration in version 1 |
| `REQ-QUIC-RFC9000-0011` | Graceful shutdown |
| `REQ-QUIC-RFC9000-0012` | Immediate teardown on errors |
| `REQ-QUIC-RFC9000-0013` | Stateless termination after state loss |
| `REQ-QUIC-RFC9000-0014` | Timeout negotiation |
| `REQ-QUIC-RFC9000-0015` | QUIC packet definition |
| `REQ-QUIC-RFC9000-0016` | Multiple QUIC packets per datagram |
| `REQ-QUIC-RFC9000-0017` | Ack-eliciting packet definition |
| `REQ-QUIC-RFC9000-0018` | Ack-eliciting packets prompt acknowledgments |
| `REQ-QUIC-RFC9000-0029` | Carry data in one direction |
| `REQ-QUIC-RFC9000-0030` | Identify streams with numeric IDs |
| `REQ-QUIC-RFC9000-0035` | Least significant bit identifies stream initiator |
| `REQ-QUIC-RFC9000-0036` | Client-initiated streams use even IDs |
| `REQ-QUIC-RFC9000-0037` | Server-initiated streams use odd IDs |
| `REQ-QUIC-RFC9000-0038` | Second least significant bit distinguishes stream direction |
| `REQ-QUIC-RFC9000-0039` | Two low bits identify one of four stream types |
| `REQ-QUIC-RFC9000-0040` | 0x00 maps to client-initiated bidirectional streams |
| `REQ-QUIC-RFC9000-0041` | 0x01 maps to server-initiated bidirectional streams |
| `REQ-QUIC-RFC9000-0042` | 0x02 maps to client-initiated unidirectional streams |
| `REQ-QUIC-RFC9000-0043` | 0x03 maps to server-initiated unidirectional streams |
| `REQ-QUIC-RFC9000-0044` | Stream spaces start at their minimum values |
| `REQ-QUIC-RFC9000-0046` | Out-of-order stream IDs open lower-numbered streams |
| `REQ-QUIC-RFC9000-0049` | Buffer out-of-order stream data |
| `REQ-QUIC-RFC9000-0050` | Optionally deliver stream data out of order |
| `REQ-QUIC-RFC9000-0051` | Allow discarding already received data |
| `REQ-QUIC-RFC9000-0053` | Keep duplicate stream data stable |
| `REQ-QUIC-RFC9000-0054` | Treat streams as byte-stream abstractions only |
| `REQ-QUIC-RFC9000-0055` | Do not preserve STREAM frame boundaries |
| `REQ-QUIC-RFC9000-0058` | Write data after reserving flow control credit |
| `REQ-QUIC-RFC9000-0059` | End stream with FIN |
| `REQ-QUIC-RFC9000-0060` | Reset non-terminal stream |
| `REQ-QUIC-RFC9000-0061` | Abort stream reading and request closure |
| `REQ-QUIC-RFC9000-0062` | Request stream state-change notifications |
| `REQ-QUIC-RFC9000-0063` | Use the correct state machine for unidirectional streams |
| `REQ-QUIC-RFC9000-0064` | Use both state machines for bidirectional streams |
| `REQ-QUIC-RFC9000-0065` | Opening either side opens bidirectional streams in both directions |
| `REQ-QUIC-RFC9000-0066` | Off-path attacker cannot block client migration |
| `REQ-QUIC-RFC9000-0067` | Off-path attacker cannot close connection after handshake |
| `REQ-QUIC-RFC9000-0068` | Enter Data Recvd after all ACKs |
| `REQ-QUIC-RFC9000-0069` | Enter Data Sent on STREAM with FIN |
| `REQ-QUIC-RFC9000-0070` | Enter Reset Recvd on ACK |
| `REQ-QUIC-RFC9000-0071` | Enter Reset Sent from Data Sent on RESET_STREAM |
| `REQ-QUIC-RFC9000-0072` | Enter Reset Sent from Ready on RESET_STREAM |
| `REQ-QUIC-RFC9000-0073` | Enter Reset Sent from Send on RESET_STREAM |
| `REQ-QUIC-RFC9000-0074` | Enter Send on STREAM or STREAM_DATA_BLOCKED |
| `REQ-QUIC-RFC9000-0075` | Application opens initiated sending part |
| `REQ-QUIC-RFC9000-0076` | Ready state accepts application data |
| `REQ-QUIC-RFC9000-0077` | First STREAM causes Send |
| `REQ-QUIC-RFC9000-0078` | Peer-initiated bidirectional streams start Ready |
| `REQ-QUIC-RFC9000-0079` | Send state transmits stream data in STREAM frames |
| `REQ-QUIC-RFC9000-0080` | Process MAX_STREAM_DATA frames |
| `REQ-QUIC-RFC9000-0081` | Respect peer flow control limits |
| `REQ-QUIC-RFC9000-0084` | Retransmit only as needed in Data Sent |
| `REQ-QUIC-RFC9000-0085` | Omit STREAM_DATA_BLOCKED in Data Sent |
| `REQ-QUIC-RFC9000-0086` | Skip flow control checks in Data Sent |
| `REQ-QUIC-RFC9000-0087` | Ignore MAX_STREAM_DATA in Data Sent |
| `REQ-QUIC-RFC9000-0088` | Enter Data Recvd after all data is acknowledged |
| `REQ-QUIC-RFC9000-0089` | Make Data Recvd terminal |
| `REQ-QUIC-RFC9000-0090` | Send RESET_STREAM after abandonment or STOP_SENDING |
| `REQ-QUIC-RFC9000-0091` | Transition to Reset Sent on RESET_STREAM |
| `REQ-QUIC-RFC9000-0092` | Allow first-frame RESET_STREAM |
| `REQ-QUIC-RFC9000-0093` | Transition to Reset Sent on first-frame RESET_STREAM |
| `REQ-QUIC-RFC9000-0094` | Enter Reset Recvd after RESET_STREAM acknowledgment |
| `REQ-QUIC-RFC9000-0095` | Make Reset Recvd terminal |
| `REQ-QUIC-RFC9000-0096` | Do not track unobservable sending states |
| `REQ-QUIC-RFC9000-0099` | Create receiving part when bidirectional sending part is created |
| `REQ-QUIC-RFC9000-0100` | Create receiving part when higher-numbered stream is created |
| `REQ-QUIC-RFC9000-0101` | Enter Data Read after application reads all data |
| `REQ-QUIC-RFC9000-0102` | Enter Data Recvd after all data arrives |
| `REQ-QUIC-RFC9000-0103` | Enter Reset Read after application reads reset |
| `REQ-QUIC-RFC9000-0104` | Enter Reset Recvd on RESET_STREAM |
| `REQ-QUIC-RFC9000-0105` | Enter Size Known on STREAM with FIN |
| `REQ-QUIC-RFC9000-0106` | Start receiving part in Recv |
| `REQ-QUIC-RFC9000-0107` | Treat MAX_STREAM_DATA on unopened streams as peer-opened |
| `REQ-QUIC-RFC9000-0108` | Interpret STOP_SENDING on unopened streams as peer-cancelled |
| `REQ-QUIC-RFC9000-0111` | Learn final stream size on STREAM FIN |
| `REQ-QUIC-RFC9000-0112` | Stop sending MAX_STREAM_DATA in Size Known |
| `REQ-QUIC-RFC9000-0114` | Discard stream frames after all data is received |
| `REQ-QUIC-RFC9000-0116` | Enter Data Read after delivery |
| `REQ-QUIC-RFC9000-0117` | Treat Data Read as terminal |
| `REQ-QUIC-RFC9000-0118` | Enter Reset Recvd on RESET_STREAM in Recv or Size Known |
| `REQ-QUIC-RFC9000-0119` | Allow delivery after RESET_STREAM reception |
| `REQ-QUIC-RFC9000-0121` | Allow RESET_STREAM suppression when data is already buffered |
| `REQ-QUIC-RFC9000-0122` | Suppressing RESET_STREAM leaves the receiver in Data Recvd |
| `REQ-QUIC-RFC9000-0123` | Transition to Reset Read on reset signal |
| `REQ-QUIC-RFC9000-0124` | Treat Reset Read as terminal |
| `REQ-QUIC-RFC9000-0125` | Stream state-affecting frames are limited to three types |
| `REQ-QUIC-RFC9000-0126` | Terminal stream states forbid state-affecting sender frames |
| `REQ-QUIC-RFC9000-0127` | Reset-sent and terminal states forbid STREAM frames |
| `REQ-QUIC-RFC9000-0128` | MAX_STREAM_DATA is sent only in Recv |
| `REQ-QUIC-RFC9000-0129` | STOP_SENDING is permitted before reset receipt |
| `REQ-QUIC-RFC9000-0130` | Require acknowledgment before closed or half-closed transitions |
| `REQ-QUIC-RFC9000-0131` | Map closed state from data received and data read |
| `REQ-QUIC-RFC9000-0132` | Map closed state from data received and reset read |
| `REQ-QUIC-RFC9000-0133` | Map closed state from reset sent and data read |
| `REQ-QUIC-RFC9000-0134` | Map closed state from reset sent and reset read |
| `REQ-QUIC-RFC9000-0135` | Map half-closed local state from data received |
| `REQ-QUIC-RFC9000-0136` | Map half-closed local state from reset sent |
| `REQ-QUIC-RFC9000-0137` | Map half-closed remote state from data read |
| `REQ-QUIC-RFC9000-0138` | Map half-closed remote state from reset read |
| `REQ-QUIC-RFC9000-0139` | Map idle composite state |
| `REQ-QUIC-RFC9000-0140` | Map open composite state |
| `REQ-QUIC-RFC9000-0141` | Define idle stream state |
| `REQ-QUIC-RFC9000-0142` | Allow aborting reads with an application error |
| `REQ-QUIC-RFC9000-0143` | Signal STOP_SENDING for Recv or Size Known |
| `REQ-QUIC-RFC9000-0144` | Allow discarding STREAM frames after STOP_SENDING |
| `REQ-QUIC-RFC9000-0145` | Count STREAM frames after STOP_SENDING |
| `REQ-QUIC-RFC9000-0146` | Send RESET_STREAM in Ready or Send after STOP_SENDING |
| `REQ-QUIC-RFC9000-0147` | Allow deferring RESET_STREAM in Data Sent |
| `REQ-QUIC-RFC9000-0148` | Prefer RESET_STREAM when outstanding data is lost |
| `REQ-QUIC-RFC9000-0149` | Allow any application error code in RESET_STREAM |
| `REQ-QUIC-RFC9000-0150` | Copy STOP_SENDING error code to RESET_STREAM |
| `REQ-QUIC-RFC9000-0151` | Ignore RESET_STREAM error code after STOP_SENDING |
| `REQ-QUIC-RFC9000-0153` | Retransmit lost STOP_SENDING frames |
| `REQ-QUIC-RFC9000-0154` | Avoid STOP_SENDING after stream completion |
| `REQ-QUIC-RFC9000-0155` | Control data across all streams |
| `REQ-QUIC-RFC9000-0156` | Control data on each stream |
| `REQ-QUIC-RFC9000-0160` | Advertise receive limits |
| `REQ-QUIC-RFC9000-0161` | Limit stream flow control |
| `REQ-QUIC-RFC9000-0165` | Advertise larger connection limits |
| `REQ-QUIC-RFC9000-0166` | Advertise larger stream limits |
| `REQ-QUIC-RFC9000-0169` | Define MAX_DATA aggregate offset |
| `REQ-QUIC-RFC9000-0171` | Smaller advertised limits are not errors |
| `REQ-QUIC-RFC9000-0172` | Smaller advertised limits have no effect |
| `REQ-QUIC-RFC9000-0175` | Block at the flow-control limit |
| `REQ-QUIC-RFC9000-0178` | Allow repeated limit updates |
| `REQ-QUIC-RFC9000-0179` | Allow blocked sender to omit flow-control frames |
| `REQ-QUIC-RFC9000-0181` | Account stream credit for connection-level flow control |
| `REQ-QUIC-RFC9000-0182` | Ignore data after RESET_STREAM |
| `REQ-QUIC-RFC9000-0183` | Tear down stream state on RESET_STREAM |
| `REQ-QUIC-RFC9000-0184` | Reset one stream direction abruptly |
| `REQ-QUIC-RFC9000-0187` | Final size equals consumed flow-control credit |
| `REQ-QUIC-RFC9000-0188` | Communicate final size reliably |
| `REQ-QUIC-RFC9000-0189` | Define final size from STREAM FIN fields |
| `REQ-QUIC-RFC9000-0190` | Carry final size in RESET_STREAM |
| `REQ-QUIC-RFC9000-0191` | Know the final size when the stream state becomes known |
| `REQ-QUIC-RFC9000-0195` | Respond with FINAL_SIZE_ERROR on final-size change |
| `REQ-QUIC-RFC9000-0196` | Treat data at or beyond final size as FINAL_SIZE_ERROR |
| `REQ-QUIC-RFC9000-0197` | Do not open streams at or beyond the concurrency limit |
| `REQ-QUIC-RFC9000-0198` | Close on oversized MAX_STREAMS frame |
| `REQ-QUIC-RFC9000-0199` | Close on oversized max_streams transport parameter |
| `REQ-QUIC-RFC9000-0202` | Ignore non-increasing MAX_STREAMS frames |
| `REQ-QUIC-RFC9000-0205` | Allow server application data before final handshake messages |
| `REQ-QUIC-RFC9000-0206` | Authenticated packet integrity |
| `REQ-QUIC-RFC9000-0207` | Select connection IDs that support routing and identification |
| `REQ-QUIC-RFC9000-0210` | Include destination connection ID in long headers |
| `REQ-QUIC-RFC9000-0211` | Include source connection ID in long headers |
| `REQ-QUIC-RFC9000-0212` | Short headers include only the destination connection ID |
| `REQ-QUIC-RFC9000-0213` | Short headers omit the explicit length |
| `REQ-QUIC-RFC9000-0214` | Echo client-selected connection IDs in Version Negotiation packets |
| `REQ-QUIC-RFC9000-0216` | Forbid concurrent zero-length CID connections on the same address and port |
| `REQ-QUIC-RFC9000-0218` | Associate sequence numbers with connection IDs |
| `REQ-QUIC-RFC9000-0223` | First destination connection ID is unnumbered |
| `REQ-QUIC-RFC9000-0224` | Retry-provided connection IDs are unnumbered |
| `REQ-QUIC-RFC9000-0225` | Accept packets carrying issued connection IDs |
| `REQ-QUIC-RFC9000-0226` | Active connection IDs are valid at any time |
| `REQ-QUIC-RFC9000-0227` | Issued and unretired connection IDs are active |
| `REQ-QUIC-RFC9000-0230` | Do not exceed peer connection ID limit |
| `REQ-QUIC-RFC9000-0231` | Send connection IDs above a peer limit when retirement is required |
| `REQ-QUIC-RFC9000-0232` | Close when active connection IDs exceed the advertised limit |
| `REQ-QUIC-RFC9000-0235` | Limit connection ID issuance to reduce per-path state |
| `REQ-QUIC-RFC9000-0236` | Limit the total number of connection IDs issued per connection |
| `REQ-QUIC-RFC9000-0237` | Keep enough connection IDs available for migration |
| `REQ-QUIC-RFC9000-0241` | Maintain peer connection IDs |
| `REQ-QUIC-RFC9000-0242` | Retire connection IDs before removing them from use |
| `REQ-QUIC-RFC9000-0243` | Make RETIRE_CONNECTION_ID frames retire the CID and request replacement |
| `REQ-QUIC-RFC9000-0246` | Use increased Retire Prior To to retire connection IDs |
| `REQ-QUIC-RFC9000-0250` | Track sufficient RETIRE_CONNECTION_ID frames |
| `REQ-QUIC-RFC9000-0252` | Treat excess unretired connection IDs as a connection error |
| `REQ-QUIC-RFC9000-0254` | Process packets for existing connections |
| `REQ-QUIC-RFC9000-0256` | Send Stateless Reset for unattributable packets |
| `REQ-QUIC-RFC9000-0257` | Discard inconsistent packets for matched connections |
| `REQ-QUIC-RFC9000-0259` | Revert or error on early packet processing |
| `REQ-QUIC-RFC9000-0260` | Destination Connection ID matches client selection |
| `REQ-QUIC-RFC9000-0262` | Discard packets that do not match a connection |
| `REQ-QUIC-RFC9000-0263` | Drop or buffer packets before key computation |
| `REQ-QUIC-RFC9000-0266` | Send Version Negotiation for unsupported versions |
| `REQ-QUIC-RFC9000-0268` | Allow different semantics in first unsupported-version packet |
| `REQ-QUIC-RFC9000-0269` | Respond with Version Negotiation packets |
| `REQ-QUIC-RFC9000-0270` | Match supported-version packets to connections |
| `REQ-QUIC-RFC9000-0274` | Ignore Handshake packets before a server response |
| `REQ-QUIC-RFC9000-0276` | Use preferred_address to request connection migration |
| `REQ-QUIC-RFC9000-0279` | Avoid stateless reset oracle in simple load balancing |
| `REQ-QUIC-RFC9000-0280` | Send Version Negotiation packets for new-connection attempts |
| `REQ-QUIC-RFC9000-0282` | Omit Version Negotiation on undersized datagrams |
| `REQ-QUIC-RFC9000-0283` | Include accepted versions in Version Negotiation packets |
| `REQ-QUIC-RFC9000-0284` | Respond with Version Negotiation for unacceptable versions |
| `REQ-QUIC-RFC9000-0287` | Authenticate the server |
| `REQ-QUIC-RFC9000-0288` | Optionally authenticate the client |
| `REQ-QUIC-RFC9000-0289` | Produce distinct and unrelated keys per connection |
| `REQ-QUIC-RFC9000-0290` | Use keying material for 0-RTT and 1-RTT packet protection |
| `REQ-QUIC-RFC9000-0291` | Support authenticated application protocol negotiation |
| `REQ-QUIC-RFC9000-0292` | Allow CRYPTO frames in multiple packet number spaces |
| `REQ-QUIC-RFC9000-0294` | Permit application data exchange after handshake completion |
| `REQ-QUIC-RFC9000-0296` | Use the cryptographic handshake after address validation |
| `REQ-QUIC-RFC9000-0297` | Carry the cryptographic handshake in Initial and Handshake packets |
| `REQ-QUIC-RFC9000-0298` | Coalesce multiple QUIC packets into one UDP datagram |
| `REQ-QUIC-RFC9000-0299` | Client sends 1-RTT packets in the same packet number space |
| `REQ-QUIC-RFC9000-0300` | Server acknowledges 0-RTT data in 1-RTT packets |
| `REQ-QUIC-RFC9000-0301` | Destination Connection ID provides consistent routing |
| `REQ-QUIC-RFC9000-0302` | Long header contains two connection IDs |
| `REQ-QUIC-RFC9000-0303` | Recipient chooses the Destination Connection ID |
| `REQ-QUIC-RFC9000-0304` | Source Connection ID sets the peer Destination Connection ID |
| `REQ-QUIC-RFC9000-0306` | Source Connection ID specifies destination connection ID |
| `REQ-QUIC-RFC9000-0308` | Client uses an unpredictable destination connection ID before server contact |
| `REQ-QUIC-RFC9000-0311` | Use first Initial DCID to determine Initial packet keys |
| `REQ-QUIC-RFC9000-0312` | Change Initial packet keys after Retry |
| `REQ-QUIC-RFC9000-0313` | Populate Source Connection ID with a client-chosen value |
| `REQ-QUIC-RFC9000-0314` | Set Source Connection ID Length to indicate the length |
| `REQ-QUIC-RFC9000-0318` | Change the destination connection ID only for the first Initial or Retry packet |
| `REQ-QUIC-RFC9000-0320` | Limit later destination connection ID changes to NEW_CONNECTION_ID values |
| `REQ-QUIC-RFC9000-0321` | Authenticate handshake connection IDs through transport parameters |
| `REQ-QUIC-RFC9000-0322` | Include the first received Initial Destination CID in transport parameters |
| `REQ-QUIC-RFC9000-0324` | Include the Retry packet Source CID in transport parameters |
| `REQ-QUIC-RFC9000-0325` | Match transport parameter values to the endpoint's Initial packet connection IDs |
| `REQ-QUIC-RFC9000-0327` | Treat missing initial_source_connection_id as transport parameter error |
| `REQ-QUIC-RFC9000-0328` | Treat missing original_destination_connection_id as transport parameter error |
| `REQ-QUIC-RFC9000-0329` | Treat missing retry_source_connection_id after Retry as connection error |
| `REQ-QUIC-RFC9000-0330` | Treat retry_source_connection_id without Retry as connection error |
| `REQ-QUIC-RFC9000-0331` | Treat mismatched Initial packet connection ID values as connection error |
| `REQ-QUIC-RFC9000-0333` | Validate peer transport parameter values |
| `REQ-QUIC-RFC9000-0337` | Apply client handshake transport parameters to all offered application protocols |
| `REQ-QUIC-RFC9000-0338` | Store server transport parameters with session tickets |
| `REQ-QUIC-RFC9000-0339` | Use stored transport parameters when attempting 0-RTT |
| `REQ-QUIC-RFC9000-0340` | Apply remembered transport parameters until handshake completion and 1-RTT traffic |
| `REQ-QUIC-RFC9000-0341` | Use handshake transport parameters after handshake completion |
| `REQ-QUIC-RFC9000-0342` | Specify 0-RTT storage behavior for new transport parameters |
| `REQ-QUIC-RFC9000-0343` | Client may omit unprocessable transport parameters |
| `REQ-QUIC-RFC9000-0344` | Do not use remembered 0-RTT parameter values |
| `REQ-QUIC-RFC9000-0347` | Do not lower remembered 0-RTT limit values |
| `REQ-QUIC-RFC9000-0349` | Update sending stream flow control after handshake |
| `REQ-QUIC-RFC9000-0352` | Do not use updated transport parameters in 0-RTT |
| `REQ-QUIC-RFC9000-0354` | Apply handshake-updated transport parameters only to 1-RTT packets |
| `REQ-QUIC-RFC9000-0355` | Keep remembered flow control limits in 0-RTT |
| `REQ-QUIC-RFC9000-0358` | Disable optional features when transport parameters are absent |
| `REQ-QUIC-RFC9000-0359` | Discard unknown transport parameters and retry 0-RTT later |
| `REQ-QUIC-RFC9000-0360` | Maintain out-of-order CRYPTO buffer |
| `REQ-QUIC-RFC9000-0362` | Allow larger handshake CRYPTO buffers |
| `REQ-QUIC-RFC9000-0363` | Allow buffer size to vary during connection |
| `REQ-QUIC-RFC9000-0364` | Temporarily expand handshake buffer |
| `REQ-QUIC-RFC9000-0366` | Close when post-handshake CRYPTO buffering is exceeded |
| `REQ-QUIC-RFC9000-0367` | Discard excess post-handshake CRYPTO frames |
| `REQ-QUIC-RFC9000-0368` | Acknowledge packets containing discarded CRYPTO frames |
| `REQ-QUIC-RFC9000-0369` | Limit sends to unvalidated addresses |
| `REQ-QUIC-RFC9000-0370` | Treat Handshake-keyed packets as Initial confirmation |
| `REQ-QUIC-RFC9000-0371` | Allow validation after Handshake packet processing |
| `REQ-QUIC-RFC9000-0372` | Allow validation with high-entropy endpoint-chosen CID |
| `REQ-QUIC-RFC9000-0373` | Use first Initial DCID for server validation |
| `REQ-QUIC-RFC9000-0374` | Limit server amplification before address validation |
| `REQ-QUIC-RFC9000-0376` | Send PTO packet based on handshake-key availability |
| `REQ-QUIC-RFC9000-0377` | Use an Initial-packet token for address validation |
| `REQ-QUIC-RFC9000-0378` | Deliver validation token via Retry or NEW_TOKEN |
| `REQ-QUIC-RFC9000-0379` | Apply congestion controller send limits |
| `REQ-QUIC-RFC9000-0380` | Client constrained only by congestion controller |
| `REQ-QUIC-RFC9000-0382` | Request address validation with Retry |
| `REQ-QUIC-RFC9000-0383` | Repeat Retry token in Initial packets |
| `REQ-QUIC-RFC9000-0384` | Do not send another Retry after retry token |
| `REQ-QUIC-RFC9000-0385` | Refuse or permit after retry token |
| `REQ-QUIC-RFC9000-0386` | Use Retry to defer connection-establishment costs |
| `REQ-QUIC-RFC9000-0387` | Close invalid Retry token connections |
| `REQ-QUIC-RFC9000-0388` | Avoid closing period without connection state |
| `REQ-QUIC-RFC9000-0389` | Provide address validation tokens |
| `REQ-QUIC-RFC9000-0390` | Use NEW_TOKEN for validation tokens |
| `REQ-QUIC-RFC9000-0391` | Include future-connection token in Initial packets |
| `REQ-QUIC-RFC9000-0394` | Give NEW_TOKEN tokens an expiration time |
| `REQ-QUIC-RFC9000-0395` | Prevent linkable information in NEW_TOKEN tokens |
| `REQ-QUIC-RFC9000-0396` | Keep NEW_TOKEN frames unique across clients |
| `REQ-QUIC-RFC9000-0397` | Token-disambiguation information may be accessible externally |
| `REQ-QUIC-RFC9000-0398` | NEW_TOKEN tokens apply to authoritative servers |
| `REQ-QUIC-RFC9000-0400` | Do not send tokens to non-applicable servers |
| `REQ-QUIC-RFC9000-0402` | Do not reuse Retry tokens in later attempts |
| `REQ-QUIC-RFC9000-0403` | Use Retry tokens immediately |
| `REQ-QUIC-RFC9000-0404` | Do not reuse NEW_TOKEN tokens across attempts |
| `REQ-QUIC-RFC9000-0405` | Reuse tokens across same-version connection attempts |
| `REQ-QUIC-RFC9000-0406` | Ignore unrelated connection properties when selecting a token |
| `REQ-QUIC-RFC9000-0408` | Protect tokens from client modification or falsification |
| `REQ-QUIC-RFC9000-0411` | Allow NEW_TOKEN tokens to suppress Retry |
| `REQ-QUIC-RFC9000-0413` | Prevent or limit token replay |
| `REQ-QUIC-RFC9000-0414` | Limit Retry token acceptance lifetime |
| `REQ-QUIC-RFC9000-0415` | Reject repeated acceptance of NEW_TOKEN tokens |
| `REQ-QUIC-RFC9000-0416` | Allow client-specific token data |
| `REQ-QUIC-RFC9000-0417` | Prefer single-use tokens when possible |
| `REQ-QUIC-RFC9000-0418` | Test reachability between specific addresses |
| `REQ-QUIC-RFC9000-0419` | Confirm packets on a path are received by the peer |
| `REQ-QUIC-RFC9000-0420` | Prevent spoofed source addresses during migration |
| `REQ-QUIC-RFC9000-0421` | Do not validate return-direction sendability |
| `REQ-QUIC-RFC9000-0422` | Do not use acknowledgments for return path validation |
| `REQ-QUIC-RFC9000-0423` | Determine reachability independently per path direction |
| `REQ-QUIC-RFC9000-0424` | Allow path validation at any time |
| `REQ-QUIC-RFC9000-0426` | Allow PADDING with PATH_CHALLENGE for PMTUD |
| `REQ-QUIC-RFC9000-0427` | Allow PATH_CHALLENGE with PATH_RESPONSE |
| `REQ-QUIC-RFC9000-0428` | Use a new connection ID for probes from a new local address |
| `REQ-QUIC-RFC9000-0429` | Send NEW_CONNECTION_ID and PATH_CHALLENGE together when permitted |
| `REQ-QUIC-RFC9000-0430` | Allow simultaneous probing of multiple paths |
| `REQ-QUIC-RFC9000-0431` | Limit simultaneous probe paths by available connection IDs |
| `REQ-QUIC-RFC9000-0432` | Initiate path validation with PATH_CHALLENGE |
| `REQ-QUIC-RFC9000-0433` | Allow multiple PATH_CHALLENGE frames |
| `REQ-QUIC-RFC9000-0434` | Avoid multiple PATH_CHALLENGE frames per packet |
| `REQ-QUIC-RFC9000-0436` | Use unpredictable PATH_CHALLENGE payloads |
| `REQ-QUIC-RFC9000-0437` | Expand PATH_CHALLENGE datagrams to 1200 bytes |
| `REQ-QUIC-RFC9000-0438` | Do not validate path MTU when expansion is blocked |
| `REQ-QUIC-RFC9000-0439` | Perform second path validation with PATH_CHALLENGE |
| `REQ-QUIC-RFC9000-0440` | Retain datagrams carrying PATH_CHALLENGE or PATH_RESPONSE |
| `REQ-QUIC-RFC9000-0441` | Echo PATH_CHALLENGE data in PATH_RESPONSE |
| `REQ-QUIC-RFC9000-0442` | Send PATH_RESPONSE without delay unless congested |
| `REQ-QUIC-RFC9000-0444` | Do not enforce received-path response requirement during initiation |
| `REQ-QUIC-RFC9000-0445` | Expand PATH_RESPONSE datagrams to 1200 bytes |
| `REQ-QUIC-RFC9000-0446` | Do not expand PATH_RESPONSE datagrams beyond the anti-amplification limit |
| `REQ-QUIC-RFC9000-0448` | Validate matching PATH_RESPONSE data |
| `REQ-QUIC-RFC9000-0449` | Let any valid PATH_RESPONSE confirm the challenged path |
| `REQ-QUIC-RFC9000-0450` | Treat undersized challenged datagrams as validating only the path |
| `REQ-QUIC-RFC9000-0451` | Retry path validation with an expanded datagram for MTU checks |
| `REQ-QUIC-RFC9000-0452` | Do not validate path based on ACKs for PATH_CHALLENGE packets |
| `REQ-QUIC-RFC9000-0453` | Fail path validation only when validation is abandoned |
| `REQ-QUIC-RFC9000-0455` | Timer value for failed path validation |
| `REQ-QUIC-RFC9000-0456` | Path validation requires a PATH_RESPONSE |
| `REQ-QUIC-RFC9000-0457` | Abandoned path validation marks the path unusable |
| `REQ-QUIC-RFC9000-0458` | No available paths |
| `REQ-QUIC-RFC9000-0459` | NO_VIABLE_PATH signaling |
| `REQ-QUIC-RFC9000-0461` | Respect disable_active_migration when sending packets |
| `REQ-QUIC-RFC9000-0466` | Clients initiate connection migration |
| `REQ-QUIC-RFC9000-0469` | Probe new local addresses before migration |
| `REQ-QUIC-RFC9000-0470` | Failed path validation leaves the path unusable |
| `REQ-QUIC-RFC9000-0471` | Path validation failure does not end the connection by itself |
| `REQ-QUIC-RFC9000-0472` | Classify only probing-frame packets as probing packets |
| `REQ-QUIC-RFC9000-0473` | Classify packets with any other frame as non-probing packets |
| `REQ-QUIC-RFC9000-0474` | Migrate by sending non-probing frames from the new local address |
| `REQ-QUIC-RFC9000-0477` | Reset congestion control and RTT estimate on migration |
| `REQ-QUIC-RFC9000-0478` | Validate ECN capability on migration |
| `REQ-QUIC-RFC9000-0479` | Treat a non-probing frame from a new address as migration |
| `REQ-QUIC-RFC9000-0480` | Initiate path validation when migration is permitted |
| `REQ-QUIC-RFC9000-0482` | Do not send on a new path without an unused connection ID |
| `REQ-QUIC-RFC9000-0484` | Validate new peer address |
| `REQ-QUIC-RFC9000-0485` | Limit sending to unvalidated peer addresses |
| `REQ-QUIC-RFC9000-0486` | May refrain from limiting sending rate after skipping validation |
| `REQ-QUIC-RFC9000-0487` | May abandon other path validation after switching the send address |
| `REQ-QUIC-RFC9000-0489` | Drop original packet as duplicate |
| `REQ-QUIC-RFC9000-0490` | Spoofed packet appears to come from migrating connection |
| `REQ-QUIC-RFC9000-0491` | Fail source address validation after spurious migration |
| `REQ-QUIC-RFC9000-0492` | Revert to last validated peer address |
| `REQ-QUIC-RFC9000-0493` | Trigger another migration on higher packet numbers |
| `REQ-QUIC-RFC9000-0494` | Abandon spurious migration validation |
| `REQ-QUIC-RFC9000-0496` | Send Stateless Reset on further packets |
| `REQ-QUIC-RFC9000-0497` | Discard genuine packet as duplicate |
| `REQ-QUIC-RFC9000-0500` | Succeed with probing packets when the path is viable but no longer desired |
| `REQ-QUIC-RFC9000-0501` | Time out validation when the path is no longer viable |
| `REQ-QUIC-RFC9000-0503` | Migrate back to the original path when the genuine packet arrives first |
| `REQ-QUIC-RFC9000-0504` | Exclude old-path packets from congestion control |
| `REQ-QUIC-RFC9000-0505` | Exclude old-path packets from RTT estimation |
| `REQ-QUIC-RFC9000-0506` | Reset congestion controller on confirmed new address |
| `REQ-QUIC-RFC9000-0507` | Reset RTT estimator on confirmed new address |
| `REQ-QUIC-RFC9000-0508` | May retain congestion control state on port-only change |
| `REQ-QUIC-RFC9000-0509` | May retain RTT estimate on port-only change |
| `REQ-QUIC-RFC9000-0511` | Allow probe packet exceptions |
| `REQ-QUIC-RFC9000-0512` | Do not make timer more aggressive |
| `REQ-QUIC-RFC9000-0514` | Change Destination Connection ID to an unused value |
| `REQ-QUIC-RFC9000-0516` | Do not reuse a connection ID across multiple destination addresses |
| `REQ-QUIC-RFC9000-0517` | Continue using the current connection ID after receiving packets from a new source address |
| `REQ-QUIC-RFC9000-0521` | No mid-connection migration to a new server address |
| `REQ-QUIC-RFC9000-0522` | Discard packets from an unexpected new server address |
| `REQ-QUIC-RFC9000-0523` | Convey preferred address in TLS handshake |
| `REQ-QUIC-RFC9000-0524` | Optionally communicate preferred addresses by address family |
| `REQ-QUIC-RFC9000-0526` | Construct packets with a previously unused active connection ID |
| `REQ-QUIC-RFC9000-0527` | Switch to the new server address after successful path validation |
| `REQ-QUIC-RFC9000-0528` | Continue using the original address when path validation fails |
| `REQ-QUIC-RFC9000-0530` | Respond to PATH_CHALLENGE with PATH_RESPONSE |
| `REQ-QUIC-RFC9000-0533` | Switch non-probing packets to the preferred address |
| `REQ-QUIC-RFC9000-0536` | Restrict preferred_address validity to the connection |
| `REQ-QUIC-RFC9000-0537` | Prohibit reuse of preferred_address values across connections |
| `REQ-QUIC-RFC9000-0544` | Preferred-address connection IDs are not address-specific |
| `REQ-QUIC-RFC9000-0546` | Apply IPv6 flow labels when sending IPv6 data |
| `REQ-QUIC-RFC9000-0547` | Minimize flow-label linkability |
| `REQ-QUIC-RFC9000-0549` | Close idle connections after the minimum timeout |
| `REQ-QUIC-RFC9000-0550` | Compute effective idle timeout from advertised values |
| `REQ-QUIC-RFC9000-0551` | Initiate immediate close before abandoning an advertised idle timeout |
| `REQ-QUIC-RFC9000-0553` | Restart idle timer on the first ack-eliciting send after receive |
| `REQ-QUIC-RFC9000-0555` | Send liveness probes near PTO expiry |
| `REQ-QUIC-RFC9000-0556` | Send periodic PINGs while deferring idle timeout |
| `REQ-QUIC-RFC9000-0557` | PING packets restart the idle timeout |
| `REQ-QUIC-RFC9000-0558` | PING acknowledgments restart the idle timeout |
| `REQ-QUIC-RFC9000-0559` | PING frames elicit acknowledgments |
| `REQ-QUIC-RFC9000-0561` | Idle timeout after negotiated silence |
| `REQ-QUIC-RFC9000-0563` | Close streams and implicitly reset open streams on CONNECTION_CLOSE |
| `REQ-QUIC-RFC9000-0565` | Enter draining state after receiving CONNECTION_CLOSE |
| `REQ-QUIC-RFC9000-0566` | Use CONNECTION_CLOSE with application-supplied error code to signal closure |
| `REQ-QUIC-RFC9000-0567` | Persist closing and draining states for three PTO intervals |
| `REQ-QUIC-RFC9000-0568` | End closing or draining states early when late packets cannot trigger a response |
| `REQ-QUIC-RFC9000-0573` | Retain enough information to generate CONNECTION_CLOSE packets in closing state |
| `REQ-QUIC-RFC9000-0574` | Retain enough information to identify connection packets in closing state |
| `REQ-QUIC-RFC9000-0577` | Discard other connection state for a closing connection |
| `REQ-QUIC-RFC9000-0578` | Ignore received frames while closing |
| `REQ-QUIC-RFC9000-0581` | Limit closing-state amplification when packet protection keys are discarded |
| `REQ-QUIC-RFC9000-0582` | Reuse the same packet while closing |
| `REQ-QUIC-RFC9000-0584` | Enter draining state on CONNECTION_CLOSE |
| `REQ-QUIC-RFC9000-0585` | Do not send packets while draining |
| `REQ-QUIC-RFC9000-0586` | Allow one CONNECTION_CLOSE response before draining |
| `REQ-QUIC-RFC9000-0587` | Allow draining from closing on CONNECTION_CLOSE |
| `REQ-QUIC-RFC9000-0588` | End draining when closing state would have ended |
| `REQ-QUIC-RFC9000-0589` | Use highest available packet protection for CONNECTION_CLOSE |
| `REQ-QUIC-RFC9000-0590` | Send CONNECTION_CLOSE in 1-RTT after handshake confirmation |
| `REQ-QUIC-RFC9000-0591` | Allow lower-protection CONNECTION_CLOSE before handshake confirmation |
| `REQ-QUIC-RFC9000-0592` | Send CONNECTION_CLOSE in Handshake and Initial packets when client handshake keys are unknown |
| `REQ-QUIC-RFC9000-0593` | Send CONNECTION_CLOSE in Handshake and 1-RTT packets before handshake confirmation |
| `REQ-QUIC-RFC9000-0594` | Send CONNECTION_CLOSE in Initial packets before handshake confirmation |
| `REQ-QUIC-RFC9000-0596` | Clear Reason Phrase when converting to 0x1c |
| `REQ-QUIC-RFC9000-0597` | Use APPLICATION_ERROR when converting to 0x1c |
| `REQ-QUIC-RFC9000-0598` | Coalesce CONNECTION_CLOSE frames into one UDP datagram |
| `REQ-QUIC-RFC9000-0599` | Allow CONNECTION_CLOSE in Initial packets |
| `REQ-QUIC-RFC9000-0600` | Discard unauthenticated packets instead of immediately closing |
| `REQ-QUIC-RFC9000-0601` | Do not enter closing state before establishing state |
| `REQ-QUIC-RFC9000-0602` | No closing or draining state without connection state |
| `REQ-QUIC-RFC9000-0603` | Send stateless reset for an unassociated packet |
| `REQ-QUIC-RFC9000-0605` | Stateless reset token size |
| `REQ-QUIC-RFC9000-0606` | End the connection on Stateless Reset |
| `REQ-QUIC-RFC9000-0608` | Issue stateless reset tokens in NEW_CONNECTION_ID |
| `REQ-QUIC-RFC9000-0609` | Allow servers to issue stateless_reset_token during the handshake |
| `REQ-QUIC-RFC9000-0611` | Include stateless reset token |
| `REQ-QUIC-RFC9000-0612` | Include unpredictable bits |
| `REQ-QUIC-RFC9000-0613` | Set Stateless Reset fixed bits |
| `REQ-QUIC-RFC9000-0614` | Start with first two header bits |
| `REQ-QUIC-RFC9000-0615` | Use entire UDP datagram |
| `REQ-QUIC-RFC9000-0616` | Set remainder bytes to random-like values |
| `REQ-QUIC-RFC9000-0617` | Place stateless reset token in last 16 bytes |
| `REQ-QUIC-RFC9000-0618` | Appear as a short-header packet to other entities |
| `REQ-QUIC-RFC9000-0619` | Pad packets beyond the requested connection ID length |
| `REQ-QUIC-RFC9000-0620` | Keep short Stateless Resets one byte shorter |
| `REQ-QUIC-RFC9000-0621` | Add unpredictable bytes when expansion may be larger |
| `REQ-QUIC-RFC9000-0624` | Format Stateless Resets as short-header packets |
| `REQ-QUIC-RFC9000-0625` | Treat packets ending in a valid stateless reset token as Stateless Reset |
| `REQ-QUIC-RFC9000-0626` | Allow Stateless Reset on long-header packets |
| `REQ-QUIC-RFC9000-0627` | Do not derive Stateless Reset DCID from short headers |
| `REQ-QUIC-RFC9000-0628` | Generate resets for all supported versions |
| `REQ-QUIC-RFC9000-0630` | Remember stateless reset tokens for recently sent datagrams |
| `REQ-QUIC-RFC9000-0631` | Exclude unused or retired reset tokens |
| `REQ-QUIC-RFC9000-0632` | Include reset tokens from NEW_CONNECTION_ID and transport parameters |
| `REQ-QUIC-RFC9000-0633` | Identify stateless reset by remote-address tokens |
| `REQ-QUIC-RFC9000-0634` | Optionally compare every inbound datagram |
| `REQ-QUIC-RFC9000-0635` | Skip the check after successful processing |
| `REQ-QUIC-RFC9000-0636` | Perform stateless-reset comparison on unassociated or undecryptable first packets |
| `REQ-QUIC-RFC9000-0637` | Do not check unused or retired connection IDs for stateless reset tokens |
| `REQ-QUIC-RFC9000-0638` | Compare stateless reset tokens without leaking token value |
| `REQ-QUIC-RFC9000-0641` | Make stateless reset tokens difficult to guess |
| `REQ-QUIC-RFC9000-0642` | Use a single static key across connections |
| `REQ-QUIC-RFC9000-0643` | Truncate stateless reset token output to 16 bytes |
| `REQ-QUIC-RFC9000-0645` | Take the connection ID from the received packet |
| `REQ-QUIC-RFC9000-0646` | Require a recoverable connection ID length |
| `REQ-QUIC-RFC9000-0647` | Disallow zero-length connection IDs |
| `REQ-QUIC-RFC9000-0648` | Use each stateless reset token once |
| `REQ-QUIC-RFC9000-0649` | Do not reuse the connection ID and static key combination |
| `REQ-QUIC-RFC9000-0652` | Permit comparing new values against prior values |
| `REQ-QUIC-RFC9000-0653` | Permit treating duplicate values as protocol violations |
| `REQ-QUIC-RFC9000-0654` | Make stateless resets indistinguishable without the token |
| `REQ-QUIC-RFC9000-0655` | Keep sent stateless resets smaller than the triggering packet |
| `REQ-QUIC-RFC9000-0656` | Signal detected errors to the peer |
| `REQ-QUIC-RFC9000-0657` | Include the most appropriate error code in the signaling frame |
| `REQ-QUIC-RFC9000-0660` | Avoid stateless reset for errors that can use close or reset stream frames |
| `REQ-QUIC-RFC9000-0662` | Signal unusable connection errors with CONNECTION_CLOSE |
| `REQ-QUIC-RFC9000-0664` | Signal transport errors with frame type 0x1c |
| `REQ-QUIC-RFC9000-0666` | Discard invalid Initial packets |
| `REQ-QUIC-RFC9000-0667` | Allow Initial packet discard despite required connection errors |
| `REQ-QUIC-RFC9000-0669` | Send RESET_STREAM for recoverable single-stream application errors |
| `REQ-QUIC-RFC9000-0670` | Restrict RESET_STREAM instigation to the application protocol |
| `REQ-QUIC-RFC9000-0671` | Reserve stream termination to the application protocol |
| `REQ-QUIC-RFC9000-0672` | Local cancellation uses direct API |
| `REQ-QUIC-RFC9000-0673` | Remote cancellation uses STOP_SENDING |
| `REQ-QUIC-RFC9000-0675` | Long header packet types |
| `REQ-QUIC-RFC9000-0676` | Use long header during connection establishment |
| `REQ-QUIC-RFC9000-0677` | Use version-independent packet for version negotiation |
| `REQ-QUIC-RFC9000-0678` | Use short header after 1-RTT keys are available |
| `REQ-QUIC-RFC9000-0679` | Version Negotiation packets are unprotected |
| `REQ-QUIC-RFC9000-0680` | Retry packets use AEAD protection |
| `REQ-QUIC-RFC9000-0681` | Initial packets use AEAD with visible-value key derivation |
| `REQ-QUIC-RFC9000-0683` | Prefer multiple frames in one packet at the same encryption level |
| `REQ-QUIC-RFC9000-0687` | Keep coalesced packets separate and complete |
| `REQ-QUIC-RFC9000-0688` | Acknowledge coalesced packets separately |
| `REQ-QUIC-RFC9000-0689` | Process each coalesced packet individually |
| `REQ-QUIC-RFC9000-0690` | Discard or buffer on decryption failure |
| `REQ-QUIC-RFC9000-0691` | Process remaining packets after decryption failure |
| `REQ-QUIC-RFC9000-0692` | Retry, Version Negotiation, and short-header packets cannot be coalesced |
| `REQ-QUIC-RFC9000-0693` | Retry, Version Negotiation, and short-header packets omit Length fields |
| `REQ-QUIC-RFC9000-0694` | Packet number range |
| `REQ-QUIC-RFC9000-0695` | Separate send and receive packet numbers |
| `REQ-QUIC-RFC9000-0696` | Reduced packet numbers are encoded in 1 to 4 bytes |
| `REQ-QUIC-RFC9000-0697` | Version Negotiation and Retry packets omit packet numbers |
| `REQ-QUIC-RFC9000-0698` | Initial packets use the Initial space |
| `REQ-QUIC-RFC9000-0699` | Handshake packets use the Handshake space |
| `REQ-QUIC-RFC9000-0700` | 0-RTT packets use the application data space |
| `REQ-QUIC-RFC9000-0701` | 1-RTT packets use the application data space |
| `REQ-QUIC-RFC9000-0702` | Use different protection keys per packet type |
| `REQ-QUIC-RFC9000-0703` | Acknowledge Initial packets only in Initial packets |
| `REQ-QUIC-RFC9000-0704` | Send Initial packets with Initial packet protection keys |
| `REQ-QUIC-RFC9000-0705` | Acknowledge Handshake packets only in Handshake packets |
| `REQ-QUIC-RFC9000-0706` | Send Handshake packets at the Handshake encryption level |
| `REQ-QUIC-RFC9000-0707` | Start packet numbers at zero |
| `REQ-QUIC-RFC9000-0711` | Permit Stateless Reset after packet-number exhaustion |
| `REQ-QUIC-RFC9000-0713` | Run duplicate suppression after removing packet protection |
| `REQ-QUIC-RFC9000-0714` | Represent packet payloads as complete frames after protection removal |
| `REQ-QUIC-RFC9000-0719` | Frames stay within one packet |
| `REQ-QUIC-RFC9000-0721` | Table 3 frame types respect packet limits |
| `REQ-QUIC-RFC9000-0722` | Table 3 frame types use listed values |
| `REQ-QUIC-RFC9000-0723` | Specific frames carry flags in the Frame Type field |
| `REQ-QUIC-RFC9000-0725` | Restrict Initial and Handshake packets to CONNECTION_CLOSE |
| `REQ-QUIC-RFC9000-0728` | Packets marked N are not ack-eliciting |
| `REQ-QUIC-RFC9000-0729` | Exclude C-marked packets from bytes in flight |
| `REQ-QUIC-RFC9000-0730` | Packets marked P can probe new paths |
| `REQ-QUIC-RFC9000-0731` | Frames marked F are flow controlled |
| `REQ-QUIC-RFC9000-0732` | Treat unknown frame types as FRAME_ENCODING_ERROR |
| `REQ-QUIC-RFC9000-0733` | Make valid frames idempotent |
| `REQ-QUIC-RFC9000-0735` | Longer encodings may be treated as PROTOCOL_VIOLATION |
| `REQ-QUIC-RFC9000-0737` | QUIC-layer CONNECTION_CLOSE frames allowed in any packet number space |
| `REQ-QUIC-RFC9000-0738` | Application-error CONNECTION_CLOSE frames limited to application data packet number space |
| `REQ-QUIC-RFC9000-0739` | ACK frames allowed in any packet number space |
| `REQ-QUIC-RFC9000-0740` | ACK frames only acknowledge packets from the same packet number space |
| `REQ-QUIC-RFC9000-0742` | Servers may treat receipt of prohibited 0-RTT frames as PROTOCOL_VIOLATION |
| `REQ-QUIC-RFC9000-0743` | Require at least one frame per packet |
| `REQ-QUIC-RFC9000-0744` | Wait briefly to collect frames |
| `REQ-QUIC-RFC9000-0745` | Use heuristics to choose wait time |
| `REQ-QUIC-RFC9000-0746` | Interleave STREAM frames for multiplexing |
| `REQ-QUIC-RFC9000-0747` | Allow multiple STREAM frames per packet |
| `REQ-QUIC-RFC9000-0748` | Block only streams carried in the lost packet |
| `REQ-QUIC-RFC9000-0750` | Enqueue STREAM data for application receipt |
| `REQ-QUIC-RFC9000-0751` | Acknowledge fully processed packets |
| `REQ-QUIC-RFC9000-0754` | Limit delayed ACKs to ack-eliciting packets |
| `REQ-QUIC-RFC9000-0755` | Only acknowledge non-ack-eliciting packets for other ACKs |
| `REQ-QUIC-RFC9000-0757` | Acknowledge ack-eliciting packets within max_ack_delay |
| `REQ-QUIC-RFC9000-0759` | Use peer max_ack_delay for retransmission timeouts |
| `REQ-QUIC-RFC9000-0760` | Limit ACK-only packet responses |
| `REQ-QUIC-RFC9000-0761` | Do not send non-ack-eliciting packets in response |
| `REQ-QUIC-RFC9000-0762` | Eventually acknowledge non-ack-eliciting packets |
| `REQ-QUIC-RFC9000-0765` | Do not make all otherwise non-ack-eliciting packets ack-eliciting |
| `REQ-QUIC-RFC9000-0766` | Occasionally add ack-eliciting frames to elicit acknowledgments |
| `REQ-QUIC-RFC9000-0767` | Generate and send ACK frames without delay on reordered or gap-detected ack-eliciting packets |
| `REQ-QUIC-RFC9000-0769` | Discard all ACK ranges |
| `REQ-QUIC-RFC9000-0770` | Retain the largest processed packet number |
| `REQ-QUIC-RFC9000-0772` | Save Largest Acknowledged when sending ACK frames |
| `REQ-QUIC-RFC9000-0773` | Stop acknowledging packets at or below a sent Largest Acknowledged value |
| `REQ-QUIC-RFC9000-0774` | Send occasional ack-eliciting frames |
| `REQ-QUIC-RFC9000-0775` | Allow at least 1 RTT of reordering without ACK frame loss |
| `REQ-QUIC-RFC9000-0776` | Continue making forward progress despite spurious retransmissions |
| `REQ-QUIC-RFC9000-0777` | Measure intentional acknowledgment delays |
| `REQ-QUIC-RFC9000-0778` | Encode acknowledgment delay in ACK Delay |
| `REQ-QUIC-RFC9000-0781` | Report large measured acknowledgment delay |
| `REQ-QUIC-RFC9000-0782` | Acknowledge 0-RTT packets with 1-RTT keys |
| `REQ-QUIC-RFC9000-0783` | Treat PADDING packets as in flight |
| `REQ-QUIC-RFC9000-0784` | Only-padding packets consume congestion window |
| `REQ-QUIC-RFC9000-0785` | Only-padding packets do not generate acknowledgments |
| `REQ-QUIC-RFC9000-0786` | Send non-padding frames periodically |
| `REQ-QUIC-RFC9000-0787` | Retransmit lost information |
| `REQ-QUIC-RFC9000-0788` | Stop retransmission when acknowledged |
| `REQ-QUIC-RFC9000-0790` | Discard CRYPTO data when keys are discarded |
| `REQ-QUIC-RFC9000-0791` | Retransmit STREAM data unless reset |
| `REQ-QUIC-RFC9000-0792` | ACK frames carry ack delay |
| `REQ-QUIC-RFC9000-0793` | ACK frames carry acknowledgments |
| `REQ-QUIC-RFC9000-0794` | Retransmit RESET_STREAM until completion |
| `REQ-QUIC-RFC9000-0796` | Retransmit STOP_SENDING until receiver is done |
| `REQ-QUIC-RFC9000-0798` | Send current maximum data in MAX_DATA frames |
| `REQ-QUIC-RFC9000-0800` | Send current maximum stream data in MAX_STREAM_DATA frames |
| `REQ-QUIC-RFC9000-0801` | Avoid sending MAX_STREAM_DATA frames too often |
| `REQ-QUIC-RFC9000-0802` | Resend MAX_STREAM_DATA on loss or limit update |
| `REQ-QUIC-RFC9000-0803` | Stop sending MAX_STREAM_DATA frames in closed states |
| `REQ-QUIC-RFC9000-0805` | Avoid sending MAX_STREAMS frames too often |
| `REQ-QUIC-RFC9000-0806` | Resend MAX_STREAMS on loss or limit update |
| `REQ-QUIC-RFC9000-0807` | Carry blocked signals in dedicated frames |
| `REQ-QUIC-RFC9000-0808` | Make DATA_BLOCKED connection-scoped |
| `REQ-QUIC-RFC9000-0809` | Make STREAMS_BLOCKED type-scoped |
| `REQ-QUIC-RFC9000-0810` | Make STREAM_DATA_BLOCKED stream-scoped |
| `REQ-QUIC-RFC9000-0811` | Retransmit blocked-limit frames only while blocked |
| `REQ-QUIC-RFC9000-0812` | Include the blocking limit in blocked frames |
| `REQ-QUIC-RFC9000-0817` | Discard retransmission information after reordering delay or memory limit |
| `REQ-QUIC-RFC9000-0819` | Reduce sending rate in response to reported congestion |
| `REQ-QUIC-RFC9000-0820` | Determine path ECN support before enabling ECN |
| `REQ-QUIC-RFC9000-0821` | Determine peer ECN reporting before enabling ECN |
| `REQ-QUIC-RFC9000-0822` | Do not report ECN counts without ECN support or field access |
| `REQ-QUIC-RFC9000-0823` | Provide ECN feedback when accessible |
| `REQ-QUIC-RFC9000-0824` | Count received ECN codepoints |
| `REQ-QUIC-RFC9000-0825` | Include ECN counts in subsequent ACK frames |
| `REQ-QUIC-RFC9000-0826` | Maintain separate acknowledgment state per packet number space |
| `REQ-QUIC-RFC9000-0827` | Maintain separate ECN counts per packet number space |
| `REQ-QUIC-RFC9000-0829` | Disable ECN when validation errors are detected |
| `REQ-QUIC-RFC9000-0830` | Validate ECN counts per network path |
| `REQ-QUIC-RFC9000-0832` | Detect ECN validation failure from lost ECT-marked packets |
| `REQ-QUIC-RFC9000-0833` | Attempt ECN validation on active migration |
| `REQ-QUIC-RFC9000-0834` | Attempt ECN validation on new connections |
| `REQ-QUIC-RFC9000-0835` | Attempt ECN validation when switching to the preferred address |
| `REQ-QUIC-RFC9000-0836` | Allow RFC-defined ECN methods |
| `REQ-QUIC-RFC9000-0837` | Use ECT(1) counts for ECN validation |
| `REQ-QUIC-RFC9000-0838` | Validate ECN counts before use |
| `REQ-QUIC-RFC9000-0839` | Compare ECN counts against the last successfully processed ACK frame |
| `REQ-QUIC-RFC9000-0840` | Validate ECN count increases against newly acknowledged markings |
| `REQ-QUIC-RFC9000-0841` | Fail validation when ECN counts are missing |
| `REQ-QUIC-RFC9000-0842` | Fail validation when ECN count increases are insufficient |
| `REQ-QUIC-RFC9000-0843` | Fail validation when ECT(1) counts are insufficient |
| `REQ-QUIC-RFC9000-0844` | Allow ECN counts to exceed acknowledged packets |
| `REQ-QUIC-RFC9000-0846` | Fail validation when received ECN counts exceed sent packet counts |
| `REQ-QUIC-RFC9000-0847` | Disable ECN when validation fails |
| `REQ-QUIC-RFC9000-0848` | Allow ECN revalidation later in the connection |
| `REQ-QUIC-RFC9000-0849` | Allow continued ECN marking after successful validation |
| `REQ-QUIC-RFC9000-0850` | Disable ECN when validation later fails |
| `REQ-QUIC-RFC9000-0852` | Define datagram size as UDP payload size |
| `REQ-QUIC-RFC9000-0853` | Datagram size excludes UDP and IP headers |
| `REQ-QUIC-RFC9000-0854` | Datagram size includes QUIC packet headers and protected payloads |
| `REQ-QUIC-RFC9000-0855` | Define maximum datagram size by path-supported UDP payload |
| `REQ-QUIC-RFC9000-0858` | Set the IPv4 DF bit when possible |
| `REQ-QUIC-RFC9000-0859` | Treat datagram size as unauthenticated |
| `REQ-QUIC-RFC9000-0860` | Allow discarding datagrams that do not meet size constraints |
| `REQ-QUIC-RFC9000-0861` | Do not close connections on invalid datagram sizes |
| `REQ-QUIC-RFC9000-0862` | Expand Initial datagrams to 1200 bytes |
| `REQ-QUIC-RFC9000-0863` | Expand server Initial datagrams to 1200 bytes |
| `REQ-QUIC-RFC9000-0864` | Allow Initial datagrams above 1200 bytes |
| `REQ-QUIC-RFC9000-0865` | Discard undersized Initial packets |
| `REQ-QUIC-RFC9000-0866` | Allow immediate close for undersized Initial packets |
| `REQ-QUIC-RFC9000-0867` | Limit bytes sent before address validation |
| `REQ-QUIC-RFC9000-0868` | Use DPLPMTUD or PMTUD to determine path support |
| `REQ-QUIC-RFC9000-0869` | Avoid oversized datagrams without PMTU discovery |
| `REQ-QUIC-RFC9000-0870` | Size non-probe packets within the maximum datagram size |
| `REQ-QUIC-RFC9000-0871` | Stop sending packets when PMTU cannot support 1200 bytes |
| `REQ-QUIC-RFC9000-0873` | Maintain a maximum datagram size per address pair |
| `REQ-QUIC-RFC9000-0874` | Allow a more conservative maximum datagram size computation |
| `REQ-QUIC-RFC9000-0875` | Track loss or acknowledgment of PMTU probe packets |
| `REQ-QUIC-RFC9000-0876` | Use PADDING-frame probes as DPLPMTUD probing using padding data |
| `REQ-QUIC-RFC9000-0878` | Maintain MPS per local and remote IP address pair |
| `REQ-QUIC-RFC9000-0879` | Enter DPLPMTUD BASE after handshake completion |
| `REQ-QUIC-RFC9000-0880` | Do not implement CONFIRMATION_TIMER in SEARCH_COMPLETE |
| `REQ-QUIC-RFC9000-0881` | Validate ICMP PTB before using PTB information |
| `REQ-QUIC-RFC9000-0882` | Validate ICMP messages with packetization-layer information |
| `REQ-QUIC-RFC9000-0883` | PMTU probes are ack-eliciting |
| `REQ-QUIC-RFC9000-0884` | Do not treat PMTU probe loss as congestion |
| `REQ-QUIC-RFC9000-0885` | Consume congestion window for PMTU probes |
| `REQ-QUIC-RFC9000-0886` | Do not acknowledge long header packets after handshake completion |
| `REQ-QUIC-RFC9000-0887` | Do not decrypt long header packets after handshake completion |
| `REQ-QUIC-RFC9000-0888` | Exclude Source Connection ID from non-long-header packets |
| `REQ-QUIC-RFC9000-0889` | Include Source Connection ID in long header packets |
| `REQ-QUIC-RFC9000-0890` | Coalesce long and short header packets into a PMTU probe |
| `REQ-QUIC-RFC9000-0891` | Acknowledge the short-header packet when a PMTU probe reaches the endpoint |
| `REQ-QUIC-RFC9000-0892` | Ignore the long-header packet when a PMTU probe reaches the endpoint |
| `REQ-QUIC-RFC9000-0893` | Allow PMTU probe packets to be invalid |
| `REQ-QUIC-RFC9000-0894` | Allow PMTU probe packets to be sent without current use |
| `REQ-QUIC-RFC9000-0904` | Smaller values use fewer bytes |
| `REQ-QUIC-RFC9000-0909` | Use 00 for 1-byte encodings |
| `REQ-QUIC-RFC9000-0910` | Use 01 for 2-byte encodings |
| `REQ-QUIC-RFC9000-0911` | Use 10 for 4-byte encodings |
| `REQ-QUIC-RFC9000-0912` | Use 11 for 8-byte encodings |
| `REQ-QUIC-RFC9000-0917` | Encode numeric values in big-endian order |
| `REQ-QUIC-RFC9000-0918` | Measure field sizes in bits |
| `REQ-QUIC-RFC9000-0919` | Constrain packet numbers to 62 bits |
| `REQ-QUIC-RFC9000-0920` | Encode packet numbers in 1 to 4 bytes |
| `REQ-QUIC-RFC9000-0921` | Use only the least significant packet-number bits |
| `REQ-QUIC-RFC9000-0922` | Protect encoded packet numbers |
| `REQ-QUIC-RFC9000-0923` | Include the full packet number before acknowledgment |
| `REQ-QUIC-RFC9000-0924` | Packet number encoding size lower bound after acknowledgment |
| `REQ-QUIC-RFC9000-0926` | Remove packet-number protection before recovery |
| `REQ-QUIC-RFC9000-0927` | Reconstruct the full packet number from significant bits |
| `REQ-QUIC-RFC9000-0928` | Decode packet number by nearest expected value |
| `REQ-QUIC-RFC9000-0929` | Define next expected packet number |
| `REQ-QUIC-RFC9000-0930` | Encode long-header packet fields |
| `REQ-QUIC-RFC9000-0931` | Set long-header fixed bit |
| `REQ-QUIC-RFC9000-0932` | Set long-header form bit |
| `REQ-QUIC-RFC9000-0933` | Switch to short header after 1-RTT keys |
| `REQ-QUIC-RFC9000-0934` | Discard packets with zero fixed bit |
| `REQ-QUIC-RFC9000-0935` | Encode long packet type in byte 0 |
| `REQ-QUIC-RFC9000-0936` | Interpret type-specific bits by packet type |
| `REQ-QUIC-RFC9000-0937` | Place QUIC Version after the first byte |
| `REQ-QUIC-RFC9000-0938` | Use QUIC Version to interpret protocol fields |
| `REQ-QUIC-RFC9000-0940` | Encode Destination Connection ID length as 8 bits |
| `REQ-QUIC-RFC9000-0941` | Limit version 1 Destination Connection ID length to 20 bytes |
| `REQ-QUIC-RFC9000-0942` | Drop version 1 long headers with oversized Destination Connection ID lengths |
| `REQ-QUIC-RFC9000-0943` | Read longer connection IDs for Version Negotiation |
| `REQ-QUIC-RFC9000-0945` | Encode Source Connection ID length as 8 bits |
| `REQ-QUIC-RFC9000-0946` | Limit Source Connection ID Length in version 1 |
| `REQ-QUIC-RFC9000-0947` | Drop oversized version 1 long headers |
| `REQ-QUIC-RFC9000-0948` | Source Connection ID field placement |
| `REQ-QUIC-RFC9000-0949` | Treat reserved-bit packets as protocol errors |
| `REQ-QUIC-RFC9000-0950` | Encode packet number length in byte 0 |
| `REQ-QUIC-RFC9000-0951` | Protect packet number length bits |
| `REQ-QUIC-RFC9000-0952` | Encode Length as variable-length integer |
| `REQ-QUIC-RFC9000-0953` | Length equals remainder of packet |
| `REQ-QUIC-RFC9000-0954` | Constrain packet number size to 1 to 4 bytes |
| `REQ-QUIC-RFC9000-0955` | Protect packet number with header protection |
| `REQ-QUIC-RFC9000-0956` | Packet payload contains frames |
| `REQ-QUIC-RFC9000-0957` | Protect packet payload with packet protection |
| `REQ-QUIC-RFC9000-0958` | Keep Version Negotiation packets version independent |
| `REQ-QUIC-RFC9000-0959` | Identify Version Negotiation packets from Version zero |
| `REQ-QUIC-RFC9000-0960` | Send Version Negotiation packets only for unsupported versions |
| `REQ-QUIC-RFC9000-0961` | Version Negotiation packets are sent only by servers |
| `REQ-QUIC-RFC9000-0962` | Include Supported Version fields |
| `REQ-QUIC-RFC9000-0963` | Preserve the Version Negotiation field order |
| `REQ-QUIC-RFC9000-0964` | Set the Header Form bit |
| `REQ-QUIC-RFC9000-0965` | Size the connection ID fields |
| `REQ-QUIC-RFC9000-0966` | Size the connection ID length fields |
| `REQ-QUIC-RFC9000-0967` | Size the Unused field |
| `REQ-QUIC-RFC9000-0968` | Set the Unused field arbitrarily |
| `REQ-QUIC-RFC9000-0970` | Set the Unused field MSB when multiplexing |
| `REQ-QUIC-RFC9000-0973` | Copy Source Connection ID from the received Destination Connection ID |
| `REQ-QUIC-RFC9000-0974` | Ignore version-specific connection ID rules when deciding to send |
| `REQ-QUIC-RFC9000-0975` | Version Negotiation packet carries supported versions list |
| `REQ-QUIC-RFC9000-0977` | Version Negotiation packet omits Length field |
| `REQ-QUIC-RFC9000-0978` | Version Negotiation packet omits Packet Number field |
| `REQ-QUIC-RFC9000-0979` | Version Negotiation packet consumes a UDP datagram |
| `REQ-QUIC-RFC9000-0981` | Initial packet field layout |
| `REQ-QUIC-RFC9000-0982` | Initial packet first-byte values |
| `REQ-QUIC-RFC9000-0983` | Token length field definition |
| `REQ-QUIC-RFC9000-0984` | Token length when absent |
| `REQ-QUIC-RFC9000-0987` | Token field value source |
| `REQ-QUIC-RFC9000-0988` | Initial packet type selection |
| `REQ-QUIC-RFC9000-0989` | Respond to a client Initial with the first server Initial |
| `REQ-QUIC-RFC9000-0991` | Include handshake or ACK material in Initial payloads |
| `REQ-QUIC-RFC9000-0992` | Handling Initial packets with other frames |
| `REQ-QUIC-RFC9000-0993` | Include CRYPTO data in the client's first packet |
| `REQ-QUIC-RFC9000-0994` | Start the first CRYPTO frame at offset 0 |
| `REQ-QUIC-RFC9000-0995` | Align later Initial CRYPTO offsets with first-flight size |
| `REQ-QUIC-RFC9000-0996` | Continue the cryptographic handshake in later Initial packets |
| `REQ-QUIC-RFC9000-0997` | Stop client Initial processing after sending the first Handshake packet |
| `REQ-QUIC-RFC9000-0998` | Stop server Initial processing after receiving the first Handshake packet |
| `REQ-QUIC-RFC9000-0999` | Discard initial packet protection keys |
| `REQ-QUIC-RFC9000-1000` | Discard recovery and congestion state |
| `REQ-QUIC-RFC9000-1001` | Include reserved bits in the first byte |
| `REQ-QUIC-RFC9000-1002` | Use long headers for 0-RTT packets |
| `REQ-QUIC-RFC9000-1003` | Accept or reject 0-RTT early data |
| `REQ-QUIC-RFC9000-1004` | Define the 0-RTT packet header layout |
| `REQ-QUIC-RFC9000-1005` | Share packet number space with 1-RTT |
| `REQ-QUIC-RFC9000-1007` | Use new packet numbers for new packets |
| `REQ-QUIC-RFC9000-1008` | Delay 0-RTT acknowledgments until handshake completion |
| `REQ-QUIC-RFC9000-1010` | Forbid ACK frames in 0-RTT packets |
| `REQ-QUIC-RFC9000-1012` | Place reserved and packet-number-length bits in the first byte |
| `REQ-QUIC-RFC9000-1013` | Use long headers and packet type 0x02 |
| `REQ-QUIC-RFC9000-1014` | Define the Handshake packet wire format |
| `REQ-QUIC-RFC9000-1016` | Populate the Destination Connection ID from the recipient |
| `REQ-QUIC-RFC9000-1017` | Populate the Source Connection ID from the sender |
| `REQ-QUIC-RFC9000-1019` | Discard Handshake CRYPTO data when handshake keys are discarded |
| `REQ-QUIC-RFC9000-1020` | Stop retransmitting Handshake CRYPTO data when handshake keys are discarded |
| `REQ-QUIC-RFC9000-1021` | Use the Retry packet long header type |
| `REQ-QUIC-RFC9000-1022` | Carry a server-created address validation token in Retry packets |
| `REQ-QUIC-RFC9000-1023` | Include the Retry packet unused field |
| `REQ-QUIC-RFC9000-1024` | Lay out the remaining Retry packet fields in order |
| `REQ-QUIC-RFC9000-1025` | Retry packets contain no protected fields |
| `REQ-QUIC-RFC9000-1026` | Allow arbitrary Retry packet unused bits |
| `REQ-QUIC-RFC9000-1027` | Ignore Retry packet unused bits |
| `REQ-QUIC-RFC9000-1028` | Set Retry DCID from the client's Initial SCID |
| `REQ-QUIC-RFC9000-1029` | Set Retry SCID to a server-chosen ID |
| `REQ-QUIC-RFC9000-1030` | Require Retry SCID to differ from the client's DCID |
| `REQ-QUIC-RFC9000-1031` | Discard Retry packets that reuse the Initial DCID |
| `REQ-QUIC-RFC9000-1032` | Use Retry SCID as later DCID |
| `REQ-QUIC-RFC9000-1038` | Discard unvalidated Retry packets |
| `REQ-QUIC-RFC9000-1040` | Respond to Retry with Initial |
| `REQ-QUIC-RFC9000-1041` | Copy Retry source CID into Initial destination CID |
| `REQ-QUIC-RFC9000-1042` | Change Initial keys when Destination Connection ID changes |
| `REQ-QUIC-RFC9000-1043` | Set Initial token from Retry packet |
| `REQ-QUIC-RFC9000-1044` | Preserve source CID on Retry response |
| `REQ-QUIC-RFC9000-1045` | Retry packets cannot be explicitly acknowledged |
| `REQ-QUIC-RFC9000-1046` | Retry packets have no packet number |
| `REQ-QUIC-RFC9000-1047` | Copy Retry Source Connection ID into Destination Connection ID |
| `REQ-QUIC-RFC9000-1048` | Copy Retry token to subsequent Initial packets |
| `REQ-QUIC-RFC9000-1049` | Keep first-Initial restrictions after Retry |
| `REQ-QUIC-RFC9000-1054` | Preserve 0-RTT protection keys after Retry |
| `REQ-QUIC-RFC9000-1056` | Copy connection IDs into transport parameters |
| `REQ-QUIC-RFC9000-1057` | Validate connection IDs per Section 7.3 |
| `REQ-QUIC-RFC9000-1058` | Single short-header packet type |
| `REQ-QUIC-RFC9000-1060` | Include destination connection ID field |
| `REQ-QUIC-RFC9000-1061` | Include key phase bit |
| `REQ-QUIC-RFC9000-1062` | Include packet number field |
| `REQ-QUIC-RFC9000-1063` | Include packet number length field |
| `REQ-QUIC-RFC9000-1064` | Include packet payload |
| `REQ-QUIC-RFC9000-1065` | Include reserved bits |
| `REQ-QUIC-RFC9000-1066` | Include spin bit |
| `REQ-QUIC-RFC9000-1067` | Set header form bit to 0 |
| `REQ-QUIC-RFC9000-1068` | Set fixed bit to 1 |
| `REQ-QUIC-RFC9000-1069` | Discard packets with zero fixed bit |
| `REQ-QUIC-RFC9000-1070` | Define the spin bit in byte 0 |
| `REQ-QUIC-RFC9000-1072` | Zero reserved bits before protection |
| `REQ-QUIC-RFC9000-1074` | Indicate key phase in byte 0 |
| `REQ-QUIC-RFC9000-1076` | Protect packet number length bits with header protection |
| `REQ-QUIC-RFC9000-1077` | Destination Connection ID chosen by recipient |
| `REQ-QUIC-RFC9000-1078` | Packet Number field length |
| `REQ-QUIC-RFC9000-1079` | Packet number protected with header protection |
| `REQ-QUIC-RFC9000-1080` | Packet Number Length encodes packet number length |
| `REQ-QUIC-RFC9000-1081` | 1-RTT packets include protected payload |
| `REQ-QUIC-RFC9000-1082` | Short header header form bit and DCID are version-independent |
| `REQ-QUIC-RFC9000-1083` | Short header remaining fields are version-specific |
| `REQ-QUIC-RFC9000-1084` | Spin bit only in 1-RTT packets |
| `REQ-QUIC-RFC9000-1085` | Spin bit is optional |
| `REQ-QUIC-RFC9000-1086` | Disable unsupported spin bit |
| `REQ-QUIC-RFC9000-1087` | Endpoint decides spin bit state independently |
| `REQ-QUIC-RFC9000-1089` | Random spin-bit disablement floor |
| `REQ-QUIC-RFC9000-1092` | Randomize disabled spin bit value |
| `REQ-QUIC-RFC9000-1093` | Maintain per-path spin values |
| `REQ-QUIC-RFC9000-1094` | Set spin bit from stored path value |
| `REQ-QUIC-RFC9000-1095` | Initialize spin value to zero |
| `REQ-QUIC-RFC9000-1096` | Track highest peer packet number per path |
| `REQ-QUIC-RFC9000-1097` | Update server spin value on new client packet |
| `REQ-QUIC-RFC9000-1099` | Reset spin value when connection ID changes |
| `REQ-QUIC-RFC9000-1101` | Encode transport parameters as a sequence |
| `REQ-QUIC-RFC9000-1102` | Encode transport parameters as tuples |
| `REQ-QUIC-RFC9000-1104` | Include transport parameter bytes in handshake |
| `REQ-QUIC-RFC9000-1105` | Reserve 31 * N + 27 transport parameter identifiers |
| `REQ-QUIC-RFC9000-1106` | Integer transport parameters use variable-length integer encoding |
| `REQ-QUIC-RFC9000-1107` | Absent transport parameters default to zero |
| `REQ-QUIC-RFC9000-1108` | original_destination_connection_id comes from the first client Initial |
| `REQ-QUIC-RFC9000-1109` | original_destination_connection_id is server-only |
| `REQ-QUIC-RFC9000-1110` | max_idle_timeout is encoded as an integer in milliseconds |
| `REQ-QUIC-RFC9000-1111` | Disable idle timeout when both endpoints omit it or set it to zero |
| `REQ-QUIC-RFC9000-1112` | stateless_reset_token is 16 bytes |
| `REQ-QUIC-RFC9000-1113` | stateless_reset_token is used to verify stateless reset |
| `REQ-QUIC-RFC9000-1114` | Clients must not send stateless_reset_token |
| `REQ-QUIC-RFC9000-1115` | Servers may send stateless_reset_token |
| `REQ-QUIC-RFC9000-1116` | Servers that omit stateless_reset_token cannot use stateless reset |
| `REQ-QUIC-RFC9000-1117` | max_udp_payload_size limits received UDP payload size |
| `REQ-QUIC-RFC9000-1118` | Default max UDP payload size |
| `REQ-QUIC-RFC9000-1119` | Maximum UDP payload size floor |
| `REQ-QUIC-RFC9000-1120` | Constrain datagram size with max_udp_payload_size |
| `REQ-QUIC-RFC9000-1121` | Define initial_max_data transport parameter |
| `REQ-QUIC-RFC9000-1122` | Treat the limit as MAX_DATA after handshake |
| `REQ-QUIC-RFC9000-1123` | Define initial_max_stream_data_bidi_local |
| `REQ-QUIC-RFC9000-1124` | Define initial_max_stream_data_bidi_remote |
| `REQ-QUIC-RFC9000-1125` | Define initial_max_stream_data_uni |
| `REQ-QUIC-RFC9000-1126` | Apply initial_max_stream_data_uni to newly created unidirectional streams |
| `REQ-QUIC-RFC9000-1127` | Scope initial_max_stream_data_uni to client transport parameters |
| `REQ-QUIC-RFC9000-1128` | Scope initial_max_stream_data_uni to server transport parameters |
| `REQ-QUIC-RFC9000-1129` | Define initial_max_streams_bidi semantics |
| `REQ-QUIC-RFC9000-1130` | Block bidirectional streams when limit is absent |
| `REQ-QUIC-RFC9000-1131` | Define initial_max_streams_uni semantics |
| `REQ-QUIC-RFC9000-1132` | Block unidirectional streams when limit is absent |
| `REQ-QUIC-RFC9000-1133` | Define ack_delay_exponent semantics |
| `REQ-QUIC-RFC9000-1134` | Default ack_delay_exponent to 3 when absent |
| `REQ-QUIC-RFC9000-1135` | Reject ack_delay_exponent values above 20 |
| `REQ-QUIC-RFC9000-1136` | Define max_ack_delay semantics |
| `REQ-QUIC-RFC9000-1137` | Include expected alarm delays in max_ack_delay |
| `REQ-QUIC-RFC9000-1138` | Default max_ack_delay to 25 ms when absent |
| `REQ-QUIC-RFC9000-1139` | Reject max_ack_delay values at or above 2^14 |
| `REQ-QUIC-RFC9000-1140` | Advertise disable_active_migration when active migration is unsupported |
| `REQ-QUIC-RFC9000-1141` | Prevent new local addresses after disable_active_migration |
| `REQ-QUIC-RFC9000-1142` | Preferred address does not prohibit migration |
| `REQ-QUIC-RFC9000-1143` | Preferred address parameter is zero length |
| `REQ-QUIC-RFC9000-1144` | Preferred address is server-sent only |
| `REQ-QUIC-RFC9000-1148` | IPv4 address precedes IPv4 port |
| `REQ-QUIC-RFC9000-1149` | IPv6 address precedes IPv6 port |
| `REQ-QUIC-RFC9000-1150` | Connection ID length describes following field |
| `REQ-QUIC-RFC9000-1152` | Preferred address fields use sequence number 1 |
| `REQ-QUIC-RFC9000-1153` | Preferred address fields match NEW_CONNECTION_ID syntax and semantics |
| `REQ-QUIC-RFC9000-1155` | Preferred addresses must not carry zero-length connection IDs |
| `REQ-QUIC-RFC9000-1159` | Suppress NEW_CONNECTION_ID frames when using zero-length connection IDs |
| `REQ-QUIC-RFC9000-1160` | Map initial stream data limits to MAX_STREAM_DATA |
| `REQ-QUIC-RFC9000-1161` | Default initial stream data limits to 0 when absent |
| `REQ-QUIC-RFC9000-1163` | Treat forbidden server-only transport parameters as errors |
| `REQ-QUIC-RFC9000-1164` | Use PADDING frames to enlarge packets |
| `REQ-QUIC-RFC9000-1165` | Use PADDING frames for Initial packet sizing |
| `REQ-QUIC-RFC9000-1166` | Use PADDING frames for traffic-analysis protection |
| `REQ-QUIC-RFC9000-1167` | PADDING frame is a single-byte encoding |
| `REQ-QUIC-RFC9000-1168` | PADDING frame type value |
| `REQ-QUIC-RFC9000-1169` | PING frame type value |
| `REQ-QUIC-RFC9000-1170` | Acknowledge packets containing PING frames |
| `REQ-QUIC-RFC9000-1171` | ACK frames carry ACK Ranges |
| `REQ-QUIC-RFC9000-1172` | ACK Ranges identify acknowledged packets |
| `REQ-QUIC-RFC9000-1173` | ACK frames with ECN report cumulative marks |
| `REQ-QUIC-RFC9000-1174` | Properly handle both ACK frame types |
| `REQ-QUIC-RFC9000-1175` | Use ECN information to manage congestion state |
| `REQ-QUIC-RFC9000-1176` | Retain acknowledged packets |
| `REQ-QUIC-RFC9000-1178` | ACK frames stay within a packet number space |
| `REQ-QUIC-RFC9000-1180` | VN and Retry packets are implicitly acknowledged |
| `REQ-QUIC-RFC9000-1181` | ACK frame ECN counts are optional |
| `REQ-QUIC-RFC9000-1182` | ACK frame field order |
| `REQ-QUIC-RFC9000-1183` | ACK frame type values |
| `REQ-QUIC-RFC9000-1184` | Largest Acknowledged field meaning |
| `REQ-QUIC-RFC9000-1185` | ACK frame values are not truncated |
| `REQ-QUIC-RFC9000-1186` | Decode ACK delay with exponent scaling |
| `REQ-QUIC-RFC9000-1187` | Encode ACK delay as a varint |
| `REQ-QUIC-RFC9000-1188` | Define ACK Range Count as a varint |
| `REQ-QUIC-RFC9000-1189` | Define the first ACK range as a varint |
| `REQ-QUIC-RFC9000-1190` | Derive the smallest acknowledged packet from the first range |
| `REQ-QUIC-RFC9000-1191` | Alternate gaps and ACK ranges |
| `REQ-QUIC-RFC9000-1193` | Bind range element counts to ACK Range Count |
| `REQ-QUIC-RFC9000-1194` | Define Gap as a varint |
| `REQ-QUIC-RFC9000-1195` | Define ACK Range Length as a varint |
| `REQ-QUIC-RFC9000-1196` | Use relative integer encoding for ACK range values |
| `REQ-QUIC-RFC9000-1197` | ACK ranges encode preceding packets |
| `REQ-QUIC-RFC9000-1199` | Map larger ACK range values to larger packet ranges |
| `REQ-QUIC-RFC9000-1200` | Compute smallest ACK range value from the largest |
| `REQ-QUIC-RFC9000-1201` | Treat ACK ranges as inclusive packet intervals |
| `REQ-QUIC-RFC9000-1202` | Derive each ACK range largest value from prior gaps and lengths |
| `REQ-QUIC-RFC9000-1204` | Encode gap length as one less than the packet count |
| `REQ-QUIC-RFC9000-1206` | Stop STREAM transmission after RESET_STREAM |
| `REQ-QUIC-RFC9000-1207` | Discard received data after RESET_STREAM |
| `REQ-QUIC-RFC9000-1209` | RESET_STREAM frame format |
| `REQ-QUIC-RFC9000-1210` | Encode RESET_STREAM stream ID |
| `REQ-QUIC-RFC9000-1210001` | Recover Initial packet keys at the receiving entity |
| `REQ-QUIC-RFC9000-1210002` | Protect non-Initial packets with handshake keys |
| `REQ-QUIC-RFC9000-1210003` | Limit packet keys to the communicating endpoints |
| `REQ-QUIC-RFC9000-1210004` | Apply header-protection confidentiality to packet numbers |
| `REQ-QUIC-RFC9000-1210005` | Increase packet numbers within a packet number space |
| `REQ-QUIC-RFC9000-1211` | Encode RESET_STREAM application error code |
| `REQ-QUIC-RFC9000-1212` | Encode RESET_STREAM final size |
| `REQ-QUIC-RFC9000-1213` | Use STOP_SENDING to signal discarded incoming data |
| `REQ-QUIC-RFC9000-1214` | STOP_SENDING requests transmission stop |
| `REQ-QUIC-RFC9000-1215` | Allow STOP_SENDING on Recv or Size Known streams |
| `REQ-QUIC-RFC9000-1218` | Encode STOP_SENDING payload fields in order |
| `REQ-QUIC-RFC9000-1219` | Set STOP_SENDING frame type to 0x05 |
| `REQ-QUIC-RFC9000-1220` | Define STOP_SENDING Stream ID field |
| `REQ-QUIC-RFC9000-1220007` | Make Length cover packet number and payload fields |
| `REQ-QUIC-RFC9000-1220008` | Learn payload length after header protection removal |
| `REQ-QUIC-RFC9000-1220009` | Allow packet coalescing using the Length field |
| `REQ-QUIC-RFC9000-1221` | Define STOP_SENDING application error code field |
| `REQ-QUIC-RFC9000-1223` | Prohibit CRYPTO frames in 0-RTT packets |
| `REQ-QUIC-RFC9000-1224` | Provide an in-order byte stream with CRYPTO frames |
| `REQ-QUIC-RFC9000-1225` | Exclude flow control from CRYPTO frames |
| `REQ-QUIC-RFC9000-1226` | Omit end-of-stream marker from CRYPTO frames |
| `REQ-QUIC-RFC9000-1227` | Omit optional length marker from CRYPTO frames |
| `REQ-QUIC-RFC9000-1228` | Omit optional offset marker from CRYPTO frames |
| `REQ-QUIC-RFC9000-1229` | Omit stream identifier from CRYPTO frames |
| `REQ-QUIC-RFC9000-1230` | Encode CRYPTO fields in order |
| `REQ-QUIC-RFC9000-1231` | Set CRYPTO frame type to 0x06 |
| `REQ-QUIC-RFC9000-1232` | CRYPTO Offset field |
| `REQ-QUIC-RFC9000-1233` | CRYPTO Length field |
| `REQ-QUIC-RFC9000-1234` | CRYPTO flow starts at offset 0 |
| `REQ-QUIC-RFC9000-1235` | Separate CRYPTO flows per encryption level |
| `REQ-QUIC-RFC9000-1236` | CRYPTO stream offset limit |
| `REQ-QUIC-RFC9000-1238` | CRYPTO frames have no FIN bit |
| `REQ-QUIC-RFC9000-1239` | NEW_TOKEN Token field order |
| `REQ-QUIC-RFC9000-1240` | NEW_TOKEN Token Length field encoding |
| `REQ-QUIC-RFC9000-1241` | NEW_TOKEN Type field value |
| `REQ-QUIC-RFC9000-1242` | Define the Token Length field semantics |
| `REQ-QUIC-RFC9000-1247` | Have STREAM frames carry stream data |
| `REQ-QUIC-RFC9000-1248` | Have STREAM frames implicitly create streams |
| `REQ-QUIC-RFC9000-1249` | Constrain STREAM frame type values |
| `REQ-QUIC-RFC9000-1250` | Map STREAM type low-order bits to present fields |
| `REQ-QUIC-RFC9000-1251` | Include Offset field when OFF bit is set |
| `REQ-QUIC-RFC9000-1252` | Omit Offset field when OFF bit is clear |
| `REQ-QUIC-RFC9000-1253` | Start stream data at offset 0 when OFF bit is clear |
| `REQ-QUIC-RFC9000-1254` | Include Length field when LEN bit is set |
| `REQ-QUIC-RFC9000-1255` | Extend Stream Data to end of packet when LEN bit is clear |
| `REQ-QUIC-RFC9000-1256` | Omit Length field when LEN bit is clear |
| `REQ-QUIC-RFC9000-1257` | Mark end of stream with FIN bit |
| `REQ-QUIC-RFC9000-1258` | Compute final stream size from offset and length |
| `REQ-QUIC-RFC9000-1260` | STREAM frame Stream ID encoding |
| `REQ-QUIC-RFC9000-1261` | STREAM frame Offset encoding |
| `REQ-QUIC-RFC9000-1262` | STREAM frame Length encoding |
| `REQ-QUIC-RFC9000-1263` | STREAM frame Stream Data payload |
| `REQ-QUIC-RFC9000-1264` | Use zero-length STREAM data to indicate the next byte offset |
| `REQ-QUIC-RFC9000-1265` | Assign offset zero to the first stream byte |
| `REQ-QUIC-RFC9000-1266` | Cap delivered stream offset at 2^62-1 |
| `REQ-QUIC-RFC9000-1267` | Treat oversized stream offsets as connection errors |
| `REQ-QUIC-RFC9000-1268` | Include the Maximum Data field in MAX_DATA frames |
| `REQ-QUIC-RFC9000-1269` | Set the MAX_DATA frame type value |
| `REQ-QUIC-RFC9000-1270` | Encode the Maximum Data field as a varint |
| `REQ-QUIC-RFC9000-1271` | Count STREAM data toward connection flow control |
| `REQ-QUIC-RFC9000-1272` | Keep total final stream sizes within the advertised limit |
| `REQ-QUIC-RFC9000-1274` | Allow MAX_STREAM_DATA on Recv streams |
| `REQ-QUIC-RFC9000-1277` | Encode MAX_STREAM_DATA fields in order |
| `REQ-QUIC-RFC9000-1278` | Set MAX_STREAM_DATA type to 0x11 |
| `REQ-QUIC-RFC9000-1279` | Identify the affected stream in MAX_STREAM_DATA |
| `REQ-QUIC-RFC9000-1280` | Define the stream data limit in bytes |
| `REQ-QUIC-RFC9000-1281` | Count the largest received offset toward the stream data limit |
| `REQ-QUIC-RFC9000-1284` | MAX_STREAMS frame cumulative limit |
| `REQ-QUIC-RFC9000-1285` | MAX_STREAMS type 0x12 applies to bidirectional streams |
| `REQ-QUIC-RFC9000-1286` | MAX_STREAMS type 0x13 applies to unidirectional streams |
| `REQ-QUIC-RFC9000-1287` | Maximum Streams cumulative lifetime count |
| `REQ-QUIC-RFC9000-1288` | MAX_STREAMS value limit |
| `REQ-QUIC-RFC9000-1289` | FRAME_ENCODING_ERROR on oversized MAX_STREAMS limit |
| `REQ-QUIC-RFC9000-1290` | Ignore non-increasing MAX_STREAMS frames |
| `REQ-QUIC-RFC9000-1294` | Send DATA_BLOCKED under connection flow control blocking |
| `REQ-QUIC-RFC9000-1295` | Include Maximum Data field |
| `REQ-QUIC-RFC9000-1296` | Set the DATA_BLOCKED frame type |
| `REQ-QUIC-RFC9000-1297` | Encode Maximum Data as a varint |
| `REQ-QUIC-RFC9000-1300` | Use type 0x15 for STREAM_DATA_BLOCKED |
| `REQ-QUIC-RFC9000-1301` | Encode STREAM_DATA_BLOCKED Stream ID as a variable-length integer |
| `REQ-QUIC-RFC9000-1302` | Encode STREAM_DATA_BLOCKED Maximum Stream Data as a variable-length integer |
| `REQ-QUIC-RFC9000-1303` | Send STREAMS_BLOCKED when stream creation is blocked |
| `REQ-QUIC-RFC9000-1304` | Use type 0x16 for bidirectional stream limit |
| `REQ-QUIC-RFC9000-1305` | Use type 0x17 for unidirectional stream limit |
| `REQ-QUIC-RFC9000-1306` | Include Maximum Streams as variable-length integer |
| `REQ-QUIC-RFC9000-1307` | Use STREAMS_BLOCKED frame type range 0x16..0x17 |
| `REQ-QUIC-RFC9000-1308` | Limit STREAMS_BLOCKED value |
| `REQ-QUIC-RFC9000-1309` | Reject oversized STREAMS_BLOCKED stream IDs |
| `REQ-QUIC-RFC9000-1310` | Encode NEW_CONNECTION_ID frame fields in order |
| `REQ-QUIC-RFC9000-1311` | Encode NEW_CONNECTION_ID sequence number as varint |
| `REQ-QUIC-RFC9000-1312` | Encode NEW_CONNECTION_ID retire-prior-to as varint |
| `REQ-QUIC-RFC9000-1313` | Encode NEW_CONNECTION_ID length as 8-bit integer |
| `REQ-QUIC-RFC9000-1314` | Reject invalid NEW_CONNECTION_ID lengths |
| `REQ-QUIC-RFC9000-1315` | Size NEW_CONNECTION_ID connection ID by Length |
| `REQ-QUIC-RFC9000-1316` | Encode NEW_CONNECTION_ID stateless reset token as 128 bits |
| `REQ-QUIC-RFC9000-1317` | Request additional connection IDs when retiring |
| `REQ-QUIC-RFC9000-1318` | Invalidate stateless reset tokens when retiring connection IDs |
| `REQ-QUIC-RFC9000-1319` | Use frame type 0x19 for RETIRE_CONNECTION_ID |
| `REQ-QUIC-RFC9000-1320` | Include a Sequence Number field in RETIRE_CONNECTION_ID frames |
| `REQ-QUIC-RFC9000-1321` | Sequence Number identifies the retired connection ID |
| `REQ-QUIC-RFC9000-132302` | Send updated ACKs quickly when packets are out of order |
| `REQ-QUIC-RFC9000-13231` | Fit ACK frames in one packet |
| `REQ-QUIC-RFC9000-13232` | Omit older ACK ranges when needed |
| `REQ-QUIC-RFC9000-1325` | Include acknowledged packet ranges in ACK frames |
| `REQ-QUIC-RFC9000-1326` | ACK frames in matching packet number spaces |
| `REQ-QUIC-RFC9000-1327` | Reject RETIRE_CONNECTION_ID sequence numbers above peer issuance |
| `REQ-QUIC-RFC9000-1329` | Prohibit RETIRE_CONNECTION_ID on zero-length peer CID |
| `REQ-QUIC-RFC9000-1331` | PATH_CHALLENGE Data field length |
| `REQ-QUIC-RFC9000-1332` | PATH_CHALLENGE frame type value |
| `REQ-QUIC-RFC9000-1333` | Send new connection IDs in NEW_CONNECTION_ID frames |
| `REQ-QUIC-RFC9000-1334` | Retransmit new connection IDs when lost |
| `REQ-QUIC-RFC9000-1335` | Preserve sequence number on retransmission |
| `REQ-QUIC-RFC9000-1336` | Send retired connection IDs in RETIRE_CONNECTION_ID frames |
| `REQ-QUIC-RFC9000-1337` | Retransmit retired connection IDs when lost |
| `REQ-QUIC-RFC9000-1338` | Retransmit NEW_TOKEN frames when lost |
| `REQ-QUIC-RFC9000-1339` | Detect reordered or duplicated NEW_TOKEN frames by direct comparison |
| `REQ-QUIC-RFC9000-1341` | Prioritize retransmission over new data |
| `REQ-QUIC-RFC9000-1342` | Allow retransmission of frames from lost packets |
| `REQ-QUIC-RFC9000-1343` | Handle payload size decreases during retransmission |
| `REQ-QUIC-RFC9000-1345` | PATH_CHALLENGE Data field contents |
| `REQ-QUIC-RFC9000-1346` | Respond to PATH_CHALLENGE with PATH_RESPONSE |
| `REQ-QUIC-RFC9000-1347` | PATH_RESPONSE frame type value |
| `REQ-QUIC-RFC9000-1348` | PATH_RESPONSE frame Data field |
| `REQ-QUIC-RFC9000-1349` | PATH_RESPONSE frame type |
| `REQ-QUIC-RFC9000-1350` | PATH_RESPONSE mismatch error handling |
| `REQ-QUIC-RFC9000-1351` | Signal application errors with type 0x1d CONNECTION_CLOSE |
| `REQ-QUIC-RFC9000-1352` | Implicitly close open streams on connection close |
| `REQ-QUIC-RFC9000-1353` | CONNECTION_CLOSE trailing field order |
| `REQ-QUIC-RFC9000-1354` | CONNECTION_CLOSE type range |
| `REQ-QUIC-RFC9000-1355` | Optional CONNECTION_CLOSE Frame Type field |
| `REQ-QUIC-RFC9000-1356` | Define CONNECTION_CLOSE error code field |
| `REQ-QUIC-RFC9000-1357` | Use application error code space for 0x1d |
| `REQ-QUIC-RFC9000-1359` | Define CONNECTION_CLOSE Frame Type field |
| `REQ-QUIC-RFC9000-1360` | Use zero for unknown frame types |
| `REQ-QUIC-RFC9000-1362` | Define reason phrase length encoding |
| `REQ-QUIC-RFC9000-1363` | Keep CONNECTION_CLOSE frames unsplit |
| `REQ-QUIC-RFC9000-1364` | Allow empty reason phrases |
| `REQ-QUIC-RFC9000-1365` | Encode the reason phrase as UTF-8 |
| `REQ-QUIC-RFC9000-1367` | Restrict application-specific CONNECTION_CLOSE packet types |
| `REQ-QUIC-RFC9000-1368` | Require HANDSHAKE_DONE to have no content |
| `REQ-QUIC-RFC9000-1369` | Set the HANDSHAKE_DONE frame type |
| `REQ-QUIC-RFC9000-1370` | Limit HANDSHAKE_DONE to server transmission |
| `REQ-QUIC-RFC9000-1374` | Understand frame syntax before processing packets |
| `REQ-QUIC-RFC9000-1375` | Do not send unknown frame types to peers |
| `REQ-QUIC-RFC9000-1382` | ACK-replacing extension frames are exempt |
| `REQ-QUIC-RFC9000-1384` | QUIC error codes are 62-bit unsigned integers |
| `REQ-QUIC-RFC9000-1385` | Use NO_ERROR for abrupt closes without error |
| `REQ-QUIC-RFC9000-1386` | Use INTERNAL_ERROR for unrecoverable internal failures |
| `REQ-QUIC-RFC9000-1387` | Use CONNECTION_REFUSED when refusing a new connection |
| `REQ-QUIC-RFC9000-1388` | Use FLOW_CONTROL_ERROR for advertised data limit violations |
| `REQ-QUIC-RFC9000-1389` | Use STREAM_LIMIT_ERROR for stream limit violations |
| `REQ-QUIC-RFC9000-1390` | Use STREAM_STATE_ERROR for frames invalid in the stream state |
| `REQ-QUIC-RFC9000-1391` | Use FINAL_SIZE_ERROR when a different final size is established |
| `REQ-QUIC-RFC9000-1392` | Use FINAL_SIZE_ERROR when stream data exceeds the final size |
| `REQ-QUIC-RFC9000-1393` | Use FINAL_SIZE_ERROR when the final size is lower than received stream data |
| `REQ-QUIC-RFC9000-1394` | Use FRAME_ENCODING_ERROR for badly formatted frames |
| `REQ-QUIC-RFC9000-1395` | Use TRANSPORT_PARAMETER_ERROR for badly formatted transport parameters |
| `REQ-QUIC-RFC9000-1396` | Use TRANSPORT_PARAMETER_ERROR for forbidden transport parameters |
| `REQ-QUIC-RFC9000-1397` | Use TRANSPORT_PARAMETER_ERROR for invalid transport parameter values |
| `REQ-QUIC-RFC9000-1398` | Use TRANSPORT_PARAMETER_ERROR for missing mandatory transport parameters |
| `REQ-QUIC-RFC9000-1399` | Use TRANSPORT_PARAMETER_ERROR for other transport parameter errors |
| `REQ-QUIC-RFC9000-1400` | Use CONNECTION_ID_LIMIT_ERROR when the peer exceeds active_connection_id_limit |
| `REQ-QUIC-RFC9000-1401` | Use PROTOCOL_VIOLATION for uncategorized protocol compliance errors |
| `REQ-QUIC-RFC9000-1402` | Use INVALID_TOKEN for an invalid client Initial token |
| `REQ-QUIC-RFC9000-1403` | Use APPLICATION_ERROR when the application closes the connection |
| `REQ-QUIC-RFC9000-1404` | Use CRYPTO_BUFFER_EXCEEDED when CRYPTO data exceeds buffer capacity |
| `REQ-QUIC-RFC9000-1405` | Use KEY_UPDATE_ERROR when key updates fail |
| `REQ-QUIC-RFC9000-1406` | Use AEAD_LIMIT_REACHED when AEAD limits are reached |
| `REQ-QUIC-RFC9000-1407` | Use NO_VIABLE_PATH when the network path cannot support QUIC |
| `REQ-QUIC-RFC9000-1408` | Reserve 256 values for handshake-specific crypto errors |
| `REQ-QUIC-RFC9000-1409` | Assign unique codes to actionable transport errors |
| `REQ-QUIC-RFC9000-1410` | Leave application error code management to application protocols |
| `REQ-QUIC-RFC9000-1411` | Use application error codes for CONNECTION_CLOSE type 0x1d |
| `REQ-QUIC-RFC9000-1412` | Use application error codes for RESET_STREAM |
| `REQ-QUIC-RFC9000-1413` | Use application error codes for STOP_SENDING |
| `REQ-QUIC-RFC9000-1414` | Anti-amplification 3x sending limit toward unvalidated address |
| `REQ-QUIC-RFC9000-1415` | Apply anti-amplification limit only on unvalidated addresses |
| `REQ-QUIC-RFC9000-1416` | Exclude anti-amplification limit for clients during connection setup and migration |
| `REQ-QUIC-RFC9000-1417` | Use Retry to validate the client address before expensive computation |
| `REQ-QUIC-RFC9000-1418` | Allow servers to issue new tokens after a successful handshake |
| `REQ-QUIC-RFC9000-1419` | Limit on-path handshake failure to packet dropping |
| `REQ-QUIC-RFC9000-1420` | Protect Handshake packets after valid Initial exchange |
| `REQ-QUIC-RFC9000-1423` | Use the quoted packet to associate ICMP messages |
| `REQ-QUIC-RFC9000-1424` | Match IP addresses and UDP ports in ICMP validation |
| `REQ-QUIC-RFC9000-1425` | Associate ICMP messages with an active QUIC session when possible |
| `REQ-QUIC-RFC9000-1427` | Do not increase PMTU based on ICMP messages |
| `REQ-QUIC-RFC9000-1429` | Encrypt Handshake and later packets with TLS-derived keys |
| `REQ-QUIC-RFC9000-1430` | Encrypt Initial packets with per-version keys |
| `REQ-QUIC-RFC9000-1431` | Fold parameter negotiation into the TLS transcript |
| `REQ-QUIC-RFC9000-1432` | Integrity-protect connection IDs in all packets |
| `REQ-QUIC-RFC9000-1433` | Keep connection IDs unencrypted |
| `REQ-QUIC-RFC9000-1434` | Fail incompatible-version connections |
| `REQ-QUIC-RFC9000-1435` | Apply authenticated encryption to protected packets |
| `REQ-QUIC-RFC9000-1436` | Limit protection for Initial and Retry packets |
| `REQ-QUIC-RFC9000-1437` | Ignore invalid packets after handshake completion |
| `REQ-QUIC-RFC9000-1438` | Restrict payload processing to handshake-complete endpoints |
| `REQ-QUIC-RFC9000-1439` | Use one migration path at a time |
| `REQ-QUIC-RFC9000-1440` | Establish peer willingness and ability for a path |
| `REQ-QUIC-RFC9000-1441` | Drop packets with modified authenticated portions |
| `REQ-QUIC-RFC9000-1442` | Keep stateless reset tokens secret until used |
| `REQ-QUIC-RFC9000-1443` | Discard packets on different paths during the handshake |
| `REQ-QUIC-RFC9000-1444` | Match connection IDs to the peer |
| `REQ-QUIC-RFC9000-1445` | Accept only packets with locally chosen DCIDs |
| `REQ-QUIC-RFC9000-1446` | Choose unpredictable Initial DCIDs |
| `REQ-QUIC-RFC9000-1447` | Protect handshake packets with derived keys |
| `REQ-QUIC-RFC9000-1448` | Permit other handshake interference recovery methods |
| `REQ-QUIC-RFC9000-1449` | Limit address validation token usage and lifetime |
| `REQ-QUIC-RFC9000-1450` | Skip packet numbers to detect optimistic ACK behavior |
| `REQ-QUIC-RFC9000-1451` | Close on optimistic ACK detection |
| `REQ-QUIC-RFC9000-1452` | Avoid deployment in unsafe ingress-filtering networks |
| `REQ-QUIC-RFC9000-1453` | Servers MUST NOT migrate in this version |
| `REQ-QUIC-RFC9000-1455` | Prevent non-QUIC packets to unwilling destinations |
| `REQ-QUIC-RFC9000-1456` | Choose unpredictable Destination Connection IDs |
| `REQ-QUIC-RFC9000-1457` | Choose Not To Use NEW_TOKEN |
| `REQ-QUIC-RFC9000-1458` | Send Empty Token After Address Change |
| `REQ-QUIC-RFC9000-1459` | Change Token Field In Retry |
| `REQ-QUIC-RFC9000-1460` | Control Destination Connection ID After Retry |
| `REQ-QUIC-RFC9000-1461` | Validate Server Address With Retry Exchange |
| `REQ-QUIC-RFC9000-1462` | Migrate To Preferred Address After Handshake |
| `REQ-QUIC-RFC9000-1463` | Specify Preferred Address |
| `REQ-QUIC-RFC9000-1464` | Do not send non-probing frames to a preferred address before validation |
| `REQ-QUIC-RFC9000-1465` | Keep the first byte of a Version Negotiation packet outside client control |
| `REQ-QUIC-RFC9000-1466` | Limit client control of Version Negotiation packets to 512 bytes from the fifth byte |
| `REQ-QUIC-RFC9000-1467` | Zero the next four bytes of a Version Negotiation packet |
| `REQ-QUIC-RFC9000-1471` | Use optional request-forgery countermeasures before address validation |
| `REQ-QUIC-RFC9000-1472` | Avoid sending datagrams to problematic ports or patterns before validation |
| `REQ-QUIC-RFC9000-1474` | Provide Slowloris mitigations |
| `REQ-QUIC-RFC9000-1475` | Align flow control windows with available memory |
| `REQ-QUIC-RFC9000-1477` | Open intervening streams for higher stream IDs |
| `REQ-QUIC-RFC9000-1478` | Limit active streams with transport parameters |
| `REQ-QUIC-RFC9000-1479` | Track processing cost relative to progress |
| `REQ-QUIC-RFC9000-1480` | Treat excessive non-productive packets as attacks |
| `REQ-QUIC-RFC9000-1481` | Endpoints may respond with a connection error or drop packets |
| `REQ-QUIC-RFC9000-1482` | Ignore the ECN field unless a QUIC packet is processed |
| `REQ-QUIC-RFC9000-1483` | Route packets to a stateful instance when sharing a static reset key |
| `REQ-QUIC-RFC9000-1484` | Require codepoint value and contact information for provisional registrations |
| `REQ-QUIC-RFC9000-1485` | Require Expert Review for provisional registrations |
| `REQ-QUIC-RFC9000-1486` | Include Date field in provisional registrations |
| `REQ-QUIC-RFC9000-1487` | Allow Date updates without expert review |
| `REQ-QUIC-RFC9000-1489` | Do not require Date when requesting registrations |
| `REQ-QUIC-RFC9000-1490` | Prefer randomly selected registry codepoints |
| `REQ-QUIC-RFC9000-1492` | Reserve first unassigned codepoint for Standards Action |
| `REQ-QUIC-RFC9000-1493` | Prefer short variable-length integer encodings for codepoints |
| `REQ-QUIC-RFC9000-1495` | Allocate selected unassigned codepoints when policy requirements are met |
| `REQ-QUIC-RFC9000-1496` | Do not reclaim recently updated entries |
| `REQ-QUIC-RFC9000-1497` | Limit reclamation to earliest recorded dates |
| `REQ-QUIC-RFC9000-1502` | Apply review and consultation to provisional-to-permanent changes |
| `REQ-QUIC-RFC9000-1503` | Confirm deployed usage for permanent registration changes |
| `REQ-QUIC-RFC9000-1504` | Allow additional constraints on permanent registrations |
| `REQ-QUIC-RFC9000-1505` | Allow different registration policies for codepoint ranges |
| `REQ-QUIC-RFC9000-1506` | Do not block provisional registrations |
| `REQ-QUIC-RFC9000-1508` | Assign permanent status to registrations in this document |
| `REQ-QUIC-RFC9000-1509` | List the change controller and contact for registrations in this document |
| `REQ-QUIC-RFC9000-1510` | Limit QUIC Versions registry to 32 bits |
| `REQ-QUIC-RFC9000-1511` | Apply the Section 22.1 registration policy |
| `REQ-QUIC-RFC9000-1512` | Use Specification Required for permanent QUIC Versions registrations |
| `REQ-QUIC-RFC9000-1513` | Assign 0x00000001 permanent status |
| `REQ-QUIC-RFC9000-1515` | Exclude 0x?a?a?a?a values from assigned listings |
| `REQ-QUIC-RFC9000-1516` | Reserve 0x?a?a?a?a values from assignment |
| `REQ-QUIC-RFC9000-1517` | Limit QUIC Transport Parameters registry to 62 bits |
| `REQ-QUIC-RFC9000-1518` | Assign 0x00 to original_destination_connection_id |
| `REQ-QUIC-RFC9000-1519` | Assign 0x01 to max_idle_timeout |
| `REQ-QUIC-RFC9000-1520` | Assign 0x02 to stateless_reset_token |
| `REQ-QUIC-RFC9000-1521` | Assign 0x03 to max_udp_payload_size |
| `REQ-QUIC-RFC9000-1522` | Assign 0x04 to initial_max_data |
| `REQ-QUIC-RFC9000-1523` | Assign 0x05 to initial_max_stream_data_bidi_local |
| `REQ-QUIC-RFC9000-1524` | Assign 0x06 to initial_max_stream_data_bidi_remote |
| `REQ-QUIC-RFC9000-1525` | Assign 0x07 to initial_max_stream_data_uni |
| `REQ-QUIC-RFC9000-1526` | Assign 0x08 to initial_max_streams_bidi |
| `REQ-QUIC-RFC9000-1527` | Assign 0x09 to initial_max_streams_uni |
| `REQ-QUIC-RFC9000-1528` | Assign 0x0a to ack_delay_exponent |
| `REQ-QUIC-RFC9000-1529` | Assign 0x0b to max_ack_delay |
| `REQ-QUIC-RFC9000-1530` | Assign 0x0c to disable_active_migration |
| `REQ-QUIC-RFC9000-1531` | Assign 0x0d to preferred_address |
| `REQ-QUIC-RFC9000-1532` | Assign 0x0e to active_connection_id_limit |
| `REQ-QUIC-RFC9000-1533` | Assign 0x0f to initial_source_connection_id |
| `REQ-QUIC-RFC9000-1534` | Assign 0x10 to retry_source_connection_id |
| `REQ-QUIC-RFC9000-1535` | Exclude 31*N+27 values from assigned listings |
| `REQ-QUIC-RFC9000-1536` | Reserve 31*N+27 values from assignment |
| `REQ-QUIC-RFC9000-1537` | Describe when a frame type can be sent |
| `REQ-QUIC-RFC9000-1538` | Allow Description to be a summary |
| `REQ-QUIC-RFC9000-1539` | ReadVarint accepts byte-sequence input |
| `REQ-QUIC-RFC9000-1540` | ReadVarint derives length from the first-byte prefix |
| `REQ-QUIC-RFC9000-1541` | ReadVarint clears prefix bits and reads remaining bytes |
| `REQ-QUIC-RFC9000-1542` | Compute num_unacked from the latest acknowledgment |
| `REQ-QUIC-RFC9000-1543` | Compute num_unacked with no prior acknowledgment |
| `REQ-QUIC-RFC9000-1544` | Require one extra bit beyond log2 of unacknowledged packets |
| `REQ-QUIC-RFC9000-1545` | Compute the minimum bit count |
| `REQ-QUIC-RFC9000-1546` | Round the bit count up to bytes |
| `REQ-QUIC-RFC9000-1547` | Compute packet number decode variables |
| `REQ-QUIC-RFC9000-1548` | Return the higher window candidate |
| `REQ-QUIC-RFC9000-1549` | Return the in-window candidate |
| `REQ-QUIC-RFC9000-1550` | Return the lower window candidate |
| `REQ-QUIC-RFC9000-1551` | Check ECN support on new paths |
| `REQ-QUIC-RFC9000-1552` | Periodically reassess unsupported ECN paths |
| `REQ-QUIC-RFC9000-1553` | Limit ECN state values |
| `REQ-QUIC-RFC9000-1554` | Send ECT-marked packets on testing or capable paths |
| `REQ-QUIC-RFC9000-1555` | Send unmarked packets on other paths |
| `REQ-QUIC-RFC9000-1556` | Mark a path testing when ECN validation starts |
| `REQ-QUIC-RFC9000-1557` | Remember ECN counts before testing |
| `REQ-QUIC-RFC9000-1558` | Transition testing paths to unknown |
| `REQ-QUIC-RFC9000-1559` | Transition unknown ECN state to capable after successful validation |
| `REQ-QUIC-RFC9000-1560` | Mark ECN state failed when validation fails |
| `REQ-QUIC-RFC9000-1561` | Allow marking ECN state failed for lost or CE-marked packets |
| `REQ-QUIC-RFC9000-1562` | Disable ECN when markings are modified incorrectly |
| `REQ-QUIC-RFC9000-1720` | Type-specific packet payload |
| `REQ-QUIC-RFC9000-1721` | Initial packet type value |
| `REQ-QUIC-RFC9000-1722` | 0-RTT packet type value |
| `REQ-QUIC-RFC9000-1723` | Handshake packet type value |
| `REQ-QUIC-RFC9000-1724` | Retry packet type value |
| `REQ-QUIC-RFC9000-1725` | Version-independent long-header fields |
| `REQ-QUIC-RFC9000-1726` | Version-specific first-byte fields |
| `REQ-QUIC-RFC9000-1727` | Version- and packet-type-specific interpretation |
| `REQ-QUIC-RFC9000-1728` | Reserved first-byte bits |
| `REQ-QUIC-RFC9000-1729` | Protect reserved bits with header protection |
| `REQ-QUIC-RFC9000-1730` | Zero the pre-protection value |
| `REQ-QUIC-RFC9000-1731` | Use a separate Handshake packet number space |
| `REQ-QUIC-RFC9000-1732` | Start server Handshake packet numbers at zero |
| `REQ-QUIC-RFC9000-1733` | Require CRYPTO frames in Handshake payloads |
| `REQ-QUIC-RFC9000-1734` | Allow PING, PADDING, or ACK frames in Handshake payloads |
| `REQ-QUIC-RFC9000-1824` | Count handshake, preferred_address, and NEW_CONNECTION_ID connection IDs |
| `REQ-QUIC-RFC9000-1825` | Default active_connection_id_limit to 2 when absent |
| `REQ-QUIC-RFC9000-1826` | Ignore peer active_connection_id_limit when using zero-length connection IDs |
| `REQ-QUIC-RFC9000-1827` | Bind initial_source_connection_id to first Initial packet |
| `REQ-QUIC-RFC9000-1828` | Bind retry_source_connection_id to Retry packet |
| `REQ-QUIC-RFC9000-1829` | Restrict retry_source_connection_id to servers |
| `REQ-QUIC-RFC9000-19150003` | Ignore duplicate NEW_CONNECTION_ID frames as connection errors |
| `REQ-QUIC-RFC9000-1918` | PATH_RESPONSE frame format |
| `REQ-QUIC-RFC9000-1919` | CONNECTION_CLOSE type 0x1c error scope |
| `REQ-QUIC-RFC9000-19310002` | Compute ACK range largest packet number |
| `REQ-QUIC-RFC9000-19310003` | Reject negative computed packet numbers |
| `REQ-QUIC-RFC9000-19320001` | Use ACK type 0x03 for ECN feedback |
| `REQ-QUIC-RFC9000-19320002` | Gate ECN counts on ACK type 0x03 |
| `REQ-QUIC-RFC9000-19320003` | Include all ECN count fields |
| `REQ-QUIC-RFC9000-19320004` | Define ECT0 Count field |
| `REQ-QUIC-RFC9000-19320005` | Define ECT1 Count field |
| `REQ-QUIC-RFC9000-19320006` | Define ECN-CE Count field |
| `REQ-QUIC-RFC9000-19320007` | Track ECN counts per packet number space |
| `REQ-QUIC-RFC9000-21110001` | Terminate after routing changes |
| `REQ-QUIC-RFC9000-21110002` | Prefer stateless reset over timeout |
| `REQ-QUIC-RFC9000-21130001` | Limit instance targeting |
| `RFC9000-S6-3-P2-R01` | Allow reserved versions in ignored version fields |
| `RFC9000-S6-3-P2-S2-R01` | Send reserved-version packets for discard testing |
| `REQ-QUIC-RFC9000-70001` | Transmit handshake data in CRYPTO frames |
| `REQ-QUIC-RFC9000-70002` | Identify QUIC version 0x00000001 |
| `REQ-QUIC-RFC9000-70003` | Use TLS for the QUIC handshake |
| `REQ-QUIC-RFC9000-70004` | Provide reliable ordered delivery of handshake data |
| `REQ-QUIC-RFC9000-7410001` | Include transport parameters in the handshake |
| `REQ-QUIC-RFC9000-7410002` | Peer transport parameters available after handshake |
| `REQ-QUIC-RFC9000-8131` | Allow any token in any connection attempt |
| `REQ-QUIC-RFC9000-8132` | Prefer the most recent unused token |
| `REQ-QUIC-RFC9000-8133` | Validate address validation tokens in Initial packets |
| `REQ-QUIC-RFC9000-8134` | Treat invalid tokens as unvalidated addresses |
