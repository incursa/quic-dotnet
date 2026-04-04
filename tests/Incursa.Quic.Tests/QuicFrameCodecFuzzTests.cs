namespace Incursa.Quic.Tests;

public sealed class QuicFrameCodecFuzzTests
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0006">Streams in QUIC MAY be canceled.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P4-0005">An application protocol MAY reset a stream if the stream is not already in a terminal state, resulting in a RESET_STREAM frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P4-0007">An application protocol MAY abort reading a stream and request closure, possibly resulting in a STOP_SENDING frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0008">QUIC MAY allow an arbitrary number of streams to operate concurrently.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0009">QUIC MAY allow an arbitrary amount of data to be sent on any stream, subject to flow control constraints and stream limits.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4-0004">Data sent in CRYPTO frames MUST NOT be flow controlled in the same way as stream data.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P1-0001">A PADDING frame (type=0x00) MUST have no semantic value.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P1-0004">PADDING frames are formatted as shown in Figure 23, which shows that PADDING frames MUST have no content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P1-0005">That is, a PADDING frame MUST consist of the single byte that identifies the frame as a PADDING frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P1-0006">The Type field MUST be encoded as a variable-length integer with value 0x00.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P2-0002">PING frames are formatted as shown in Figure 24, which shows that PING frames MUST have no content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P2-0003">The Type field MUST be encoded as a variable-length integer with value 0x01.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0001">When an ACK frame is sent, one or more ranges of acknowledged packets MUST be included.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0002">ACK frames SHOULD always acknowledge the most recently received packets.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0012">A receiver SHOULD include an ACK Range containing the largest received packet number in every ACK frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P5-0002">The endpoint MUST encode this acknowledgment delay in the ACK Delay field of an ACK frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0001">QUIC implementations MUST properly handle ACK frame types 0x02 and 0x03.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0002">The ACK frame MUST contain one or more ACK Ranges.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0003">If the frame type is 0x03, ACK frames also MUST contain the cumulative count of QUIC packets with associated ECN marks received on the connection up until this point.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0009">The Type field MUST be encoded as a variable-length integer with value 0x02..0x03.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0010">The Largest Acknowledged field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0011">The ACK Delay field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0012">The ACK Range Count field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0010">ACK frames MUST carry the most recent set of acknowledgments and the acknowledgment delay from the largest acknowledged packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0013">The First ACK Range field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0014">ACK frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0015">The Largest Acknowledged field MUST be variable-length integer representing the largest packet number the peer is acknowledging; this is usually the largest packet number that the peer has received prior to generating the ACK frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0016">Unlike the packet number in the QUIC long or short header, the value in an ACK frame MUST NOT be truncated.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0017">The ACK Delay field MUST be variable-length integer encoding the acknowledgment delay in microseconds; see Section 13.2.5.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0018">The ACK Range Count field MUST be variable-length integer specifying the number of ACK Range fields in the frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0019">The First ACK Range field MUST be variable-length integer indicating the number of contiguous packets preceding the Largest Acknowledged that are being acknowledged.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0020">MUST contain additional ranges of packets that are alternately not acknowledged (Gap) and acknowledged (ACK Range); see Section 19.3.1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3P1-0001">Each ACK Range MUST consist of alternating Gap and ACK Range Length values in descending packet number order.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3P1-0002">ACK Ranges MAY be repeated.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3P1-0003">The Gap field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3P1-0004">The ACK Range Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3P1-0005">The Gap field MUST be variable-length integer indicating the number of contiguous unacknowledged packets preceding the packet number one lower than the smallest in the preceding ACK Range.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3P1-0006">The ACK Range Length field MUST be variable-length integer indicating the number of contiguous acknowledged packets preceding the largest packet number, as determined by the preceding Gap.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3P1-0007">A value of 0 MUST indicate that only the largest packet number is acknowledged.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3P1-0008">Larger ACK Range values MUST indicate a larger range, with corresponding lower values for the smallest packet number in the range.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3P1-0009">Each Gap MUST indicate a range of packets that are not being acknowledged.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3P1-0010">If any computed packet number is negative, an endpoint MUST generate a connection error of type FRAME_ENCODING_ERROR.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3P2-0001">The ACK frame MUST use the least significant bit of the type value (that is, type 0x03) to indicate ECN feedback and report receipt of QUIC packets with associated ECN codepoints of ECT(0), ECT(1), or ECN-CE in the packet&apos;s IP header.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3P2-0002">The ECT0 Count field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3P2-0003">The ECT1 Count field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3P2-0004">The ECN-CE Count field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3P2-0005">The ECT0 Count field MUST be variable-length integer representing the total number of packets received with the ECT(0) codepoint in the packet number space of the ACK frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3P2-0006">The ECT1 Count field MUST be variable-length integer representing the total number of packets received with the ECT(1) codepoint in the packet number space of the ACK frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3P2-0007">The ECN-CE Count field MUST be variable-length integer representing the total number of packets received with the ECN-CE codepoint in the packet number space of the ACK frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0004">The Type field MUST be encoded as a variable-length integer with value 0x04.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0005">The Stream ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0006">The Application Protocol Error Code field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0007">The Final Size field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0008">RESET_STREAM frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0009">The Stream ID field MUST be variable-length integer encoding of the stream ID of the stream being terminated.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0010">A variable-length integer containing the application protocol error code (see Section 20.2) that MUST indicate why the stream is being closed.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0011">The Final Size field MUST be variable-length integer indicating the final size of the stream by the RESET_STREAM sender, in units of bytes; see Section 4.5.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0005">The Type field MUST be encoded as a variable-length integer with value 0x05.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0006">The Stream ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0007">The Application Protocol Error Code field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0008">STOP_SENDING frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0009">The Stream ID field MUST be variable-length integer carrying the stream ID of the stream being ignored.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0010">The Application Protocol Error Code field MUST be variable-length integer containing the application-specified reason the sender is ignoring the stream; see Section 20.2.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S20P2-0001">Application protocol error codes MUST be used for the RESET_STREAM frame (Section 19.4), the STOP_SENDING frame (Section 19.5), and the CONNECTION_CLOSE frame with a type of 0x1d (Section 19.19).</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0006">Subsequently, a receiver MUST send MAX_STREAM_DATA or MAX_DATA frames to advertise larger limits.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0007">A receiver MAY advertise a larger limit for a stream by sending a MAX_STREAM_DATA frame with the corresponding stream ID.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0008">A MAX_STREAM_DATA frame MUST indicate the maximum absolute byte offset of a stream.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0009">A receiver MAY advertise a larger limit for a connection by sending a MAX_DATA frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0004">The Type field MUST be encoded as a variable-length integer with value 0x06.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0005">The Offset field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0006">The Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0007">CRYPTO frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0008">The Offset field MUST be variable-length integer specifying the byte offset in the stream for the data in this CRYPTO frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0009">The Length field MUST be variable-length integer specifying the length of the Crypto Data field in this CRYPTO frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0010">The largest offset delivered on a stream -- the sum of the offset and data length -- MUST NOT exceed 262-1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0011">Receipt of a frame that exceeds this limit MUST be treated as a connection error of type FRAME_ENCODING_ERROR or CRYPTO_BUFFER_EXCEEDED.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0012">Unlike STREAM frames, which MUST include a stream ID indicating to which stream the data belongs, the CRYPTO frame carries data for a single stream per encryption level.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0013">The stream MUST NOT have an explicit end, so CRYPTO frames do not have a FIN bit.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P7-0001">The Type field MUST be encoded as a variable-length integer with value 0x07.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P7-0002">The Token Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P7-0003">NEW_TOKEN frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P7-0004">The Token Length field MUST be variable-length integer specifying the length of the token in bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P7-0005">An opaque blob that the client MAY use with a future Initial packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P7-0006">The token MUST NOT be empty.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P9-0002">The Type field MUST be encoded as a variable-length integer with value 0x10.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P9-0003">The Maximum Data field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P9-0004">MAX_DATA frames MUST contain the following field:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P9-0005">A variable-length integer indicating the maximum amount of data that MAY be sent on the entire connection, in units of bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P10-0005">The Type field MUST be encoded as a variable-length integer with value 0x11.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P10-0006">The Stream ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P10-0007">The Maximum Stream Data field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P10-0008">MAX_STREAM_DATA frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P10-0009">The Stream ID field MUST be stream ID of the affected stream, encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P10-0010">A variable-length integer indicating the maximum amount of data that MAY be sent on the identified stream, in units of bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0004">Subsequent limits MUST be advertised using MAX_STREAMS frames.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0005">Separate limits MUST apply to unidirectional and bidirectional streams.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P11-0001">The Type field MUST be encoded as a variable-length integer with value 0x12..0x13.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P11-0002">The Maximum Streams field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P11-0003">MAX_STREAMS frames MUST contain the following field:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P11-0004">A count of the cumulative number of streams of the corresponding type that MAY be opened over the lifetime of the connection.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P11-0005">This value MUST NOT exceed 260, as it is not possible to encode stream IDs larger than 262-1.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0005")]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0007")]
    [Requirement("REQ-QUIC-RFC9000-S2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S4-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P5-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0011")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0013")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0014")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0015")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0016")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0017")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0018")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0019")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0020")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0011")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0010")]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0011")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0013")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P9-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P9-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P9-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P9-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0010")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0004")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_FrameCodec_RoundTripsRepresentativeFrameShapesAndRejectsTruncation()
    {
        Random random = new(0x5150_2030);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            switch (random.Next(11))
            {
                case 0:
                    RoundTripPaddingFrame();
                    break;
                case 1:
                    RoundTripPingFrame();
                    break;
                case 2:
                    RoundTripAckFrame(random, includeEcnCounts: false);
                    break;
                case 3:
                    RoundTripAckFrame(random, includeEcnCounts: true);
                    break;
                case 4:
                    RoundTripResetStreamFrame(random);
                    break;
                case 5:
                    RoundTripStopSendingFrame(random);
                    break;
                case 6:
                    RoundTripCryptoFrame(random);
                    break;
                case 7:
                    RoundTripNewTokenFrame(random);
                    break;
                case 8:
                    RoundTripMaxDataFrame(random);
                    break;
                case 9:
                    RoundTripMaxStreamDataFrame(random);
                    break;
                default:
                    RoundTripMaxStreamsFrame(random);
                    break;
            }
        }
    }

    private static void RoundTripPaddingFrame()
    {
        byte[] packet = QuicFrameTestData.BuildPaddingFrame();

        Assert.True(QuicFrameCodec.TryParsePaddingFrame(packet, out int bytesConsumed));
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[8];
        Assert.True(QuicFrameCodec.TryFormatPaddingFrame(destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParsePaddingFrame([], out _));
    }

    private static void RoundTripPingFrame()
    {
        byte[] packet = QuicFrameTestData.BuildPingFrame();

        Assert.True(QuicFrameCodec.TryParsePingFrame(packet, out int bytesConsumed));
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[8];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParsePingFrame([], out _));
    }

    private static void RoundTripAckFrame(Random random, bool includeEcnCounts)
    {
        QuicAckFrame frame = BuildRandomAckFrame(random, includeEcnCounts);
        byte[] packet = QuicFrameTestData.BuildAckFrame(frame);

        Assert.True(QuicFrameCodec.TryParseAckFrame(packet, out QuicAckFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.FrameType, parsed.FrameType);
        Assert.Equal(frame.LargestAcknowledged, parsed.LargestAcknowledged);
        Assert.Equal(frame.AckDelay, parsed.AckDelay);
        Assert.Equal(frame.FirstAckRange, parsed.FirstAckRange);
        Assert.Equal(frame.AdditionalRanges.Length, parsed.AdditionalRanges.Length);

        for (int index = 0; index < frame.AdditionalRanges.Length; index++)
        {
            Assert.Equal(frame.AdditionalRanges[index].Gap, parsed.AdditionalRanges[index].Gap);
            Assert.Equal(frame.AdditionalRanges[index].AckRangeLength, parsed.AdditionalRanges[index].AckRangeLength);
            Assert.Equal(frame.AdditionalRanges[index].SmallestAcknowledged, parsed.AdditionalRanges[index].SmallestAcknowledged);
            Assert.Equal(frame.AdditionalRanges[index].LargestAcknowledged, parsed.AdditionalRanges[index].LargestAcknowledged);
        }

        Assert.Equal(frame.EcnCounts, parsed.EcnCounts);
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[128];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParseAckFrame(packet[..Math.Max(0, packet.Length - 1)], out _, out _));
    }

    private static QuicAckFrame BuildRandomAckFrame(Random random, bool includeEcnCounts)
    {
        ulong largestAcknowledged = (ulong)random.Next(1, 512);
        ulong firstAckRange = (ulong)random.Next(0, (int)Math.Min(largestAcknowledged, 8));
        ulong previousSmallestAcknowledged = largestAcknowledged - firstAckRange;
        int additionalRangeCount = previousSmallestAcknowledged > 1 ? random.Next(0, 4) : 0;

        List<QuicAckRange> additionalRanges = [];
        for (int index = 0; index < additionalRangeCount && previousSmallestAcknowledged > 1; index++)
        {
            ulong gap = (ulong)random.Next(0, (int)Math.Min(previousSmallestAcknowledged - 1, 4));
            ulong nextLargest = previousSmallestAcknowledged - gap - 2;
            ulong ackRangeLength = (ulong)random.Next(0, (int)Math.Min(nextLargest + 1, 4));
            QuicAckRange range = QuicFrameTestData.BuildAckRange(previousSmallestAcknowledged, gap, ackRangeLength);
            additionalRanges.Add(range);
            previousSmallestAcknowledged = range.SmallestAcknowledged;
        }

        QuicAckFrame frame = new()
        {
            FrameType = includeEcnCounts ? (byte)0x03 : (byte)0x02,
            LargestAcknowledged = largestAcknowledged,
            AckDelay = (ulong)random.Next(0, 256),
            FirstAckRange = firstAckRange,
            AdditionalRanges = additionalRanges.ToArray(),
        };

        if (includeEcnCounts)
        {
            frame.EcnCounts = new QuicEcnCounts(
                (ulong)random.Next(0, 32),
                (ulong)random.Next(0, 32),
                (ulong)random.Next(0, 32));
        }

        return frame;
    }

    private static void RoundTripResetStreamFrame(Random random)
    {
        QuicResetStreamFrame frame = new(
            (ulong)random.Next(0, 4096),
            (ulong)random.Next(0, 256),
            (ulong)random.Next(0, 4096));

        byte[] packet = QuicFrameTestData.BuildResetStreamFrame(frame);
        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(packet, out QuicResetStreamFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.ApplicationProtocolErrorCode, parsed.ApplicationProtocolErrorCode);
        Assert.Equal(frame.FinalSize, parsed.FinalSize);
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatResetStreamFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParseResetStreamFrame(packet[..Math.Max(0, packet.Length - 1)], out _, out _));
    }

    private static void RoundTripStopSendingFrame(Random random)
    {
        QuicStopSendingFrame frame = new(
            (ulong)random.Next(0, 4096),
            (ulong)random.Next(0, 256));

        byte[] packet = QuicFrameTestData.BuildStopSendingFrame(frame);
        Assert.True(QuicFrameCodec.TryParseStopSendingFrame(packet, out QuicStopSendingFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.ApplicationProtocolErrorCode, parsed.ApplicationProtocolErrorCode);
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatStopSendingFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParseStopSendingFrame(packet[..Math.Max(0, packet.Length - 1)], out _, out _));
    }

    private static void RoundTripCryptoFrame(Random random)
    {
        byte[] cryptoData = RandomBytes(random, random.Next(0, 16));
        ulong offset = (ulong)random.Next(0, 4096);
        QuicCryptoFrame frame = new(offset, cryptoData);
        byte[] packet = QuicFrameTestData.BuildCryptoFrame(frame);

        Assert.True(QuicFrameCodec.TryParseCryptoFrame(packet, out QuicCryptoFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.Offset, parsed.Offset);
        Assert.True(frame.CryptoData.SequenceEqual(parsed.CryptoData));
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatCryptoFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParseCryptoFrame(packet[..Math.Max(0, packet.Length - 1)], out _, out _));
    }

    private static void RoundTripNewTokenFrame(Random random)
    {
        byte[] token = RandomBytes(random, random.Next(1, 16));
        QuicNewTokenFrame frame = new(token);
        byte[] packet = QuicFrameTestData.BuildNewTokenFrame(frame);

        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(packet, out QuicNewTokenFrame parsed, out int bytesConsumed));
        Assert.True(token.AsSpan().SequenceEqual(parsed.Token));
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatNewTokenFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParseNewTokenFrame(packet[..Math.Max(0, packet.Length - 1)], out _, out _));
    }

    private static void RoundTripMaxDataFrame(Random random)
    {
        QuicMaxDataFrame frame = new((ulong)random.Next(0, 1 << 20));
        byte[] packet = QuicFrameTestData.BuildMaxDataFrame(frame);

        Assert.True(QuicFrameCodec.TryParseMaxDataFrame(packet, out QuicMaxDataFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.MaximumData, parsed.MaximumData);
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatMaxDataFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParseMaxDataFrame(packet[..Math.Max(0, packet.Length - 1)], out _, out _));
    }

    private static void RoundTripMaxStreamDataFrame(Random random)
    {
        QuicMaxStreamDataFrame frame = new(
            (ulong)random.Next(0, 4096),
            (ulong)random.Next(0, 1 << 20));

        byte[] packet = QuicFrameTestData.BuildMaxStreamDataFrame(frame);

        Assert.True(QuicFrameCodec.TryParseMaxStreamDataFrame(packet, out QuicMaxStreamDataFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.MaximumStreamData, parsed.MaximumStreamData);
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatMaxStreamDataFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParseMaxStreamDataFrame(packet[..Math.Max(0, packet.Length - 1)], out _, out _));
    }

    private static void RoundTripMaxStreamsFrame(Random random)
    {
        QuicMaxStreamsFrame frame = new(random.Next(2) == 0, (ulong)random.Next(0, 1 << 20));
        byte[] packet = QuicFrameTestData.BuildMaxStreamsFrame(frame);

        Assert.True(QuicFrameCodec.TryParseMaxStreamsFrame(packet, out QuicMaxStreamsFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.IsBidirectional, parsed.IsBidirectional);
        Assert.Equal(frame.MaximumStreams, parsed.MaximumStreams);
        Assert.Equal(packet.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatMaxStreamsFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.False(QuicFrameCodec.TryParseMaxStreamsFrame(packet[..Math.Max(0, packet.Length - 1)], out _, out _));
    }

    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }
}
