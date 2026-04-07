namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3-0002")]
public sealed class REQ_QUIC_RFC9000_S19P3_0002
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0001">QUIC implementations MUST properly handle ACK frame types 0x02 and 0x03.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0002">The ACK frame MUST contain one or more ACK Ranges.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0003">If the frame type is 0x03, ACK frames also MUST contain the cumulative count of QUIC packets with associated ECN marks received on the connection up until this point.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0010">The Largest Acknowledged field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0011">The ACK Delay field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0012">The ACK Range Count field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0013">The First ACK Range field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0014">ACK frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0015">The Largest Acknowledged field MUST be variable-length integer representing the largest packet number the peer is acknowledging; this is usually the largest packet number that the peer has received prior to generating the ACK frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0016">Unlike the packet number in the QUIC long or short header, the value in an ACK frame MUST NOT be truncated.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0017">The ACK Delay field MUST be variable-length integer encoding the acknowledgment delay in microseconds; see Section 13.2.5.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0018">The ACK Range Count field MUST be variable-length integer specifying the number of ACK Range fields in the frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0019">The First ACK Range field MUST be variable-length integer indicating the number of contiguous packets preceding the Largest Acknowledged that are being acknowledged.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0020">MUST contain additional ranges of packets that are alternately not acknowledged (Gap) and acknowledged (ACK Range); see Section 19.3.1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3P1-0001">Each ACK Range MUST consist of alternating Gap and ACK Range Length values in descending packet number order.</workbench-requirement>
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
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0011")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0013")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0014")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0015")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0016")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0017")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0018")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0019")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0020")]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0001")]
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
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseAckFrame_RejectsTruncatedAndInvalidRangeLayouts()
    {
        ulong largestAcknowledged = 0x10;
        QuicAckFrame validFrame = new()
        {
            FrameType = 0x02,
            LargestAcknowledged = largestAcknowledged,
            AckDelay = 0x01,
            FirstAckRange = 0x00,
            AdditionalRanges =
            [
                new QuicAckRange(0x00, 0x00, 0x0D, 0x0D),
            ],
        };

        byte[] encoded = QuicFrameTestData.BuildAckFrame(validFrame);
        Assert.False(QuicFrameCodec.TryParseAckFrame(encoded[..(encoded.Length - 1)], out _, out _));

        QuicAckFrame invalidFirstRange = new()
        {
            FrameType = 0x02,
            LargestAcknowledged = 0x03,
            AckDelay = 0x01,
            FirstAckRange = 0x04,
        };

        Assert.False(QuicFrameCodec.TryParseAckFrame(QuicFrameTestData.BuildAckFrame(invalidFirstRange), out _, out _));
    }
}
