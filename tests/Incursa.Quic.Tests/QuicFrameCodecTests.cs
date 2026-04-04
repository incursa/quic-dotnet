namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P4-0003">Permanent registrations in this registry MUST include the Frame Type Name field.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P4-0004">The Frame Type Name field MUST be a short mnemonic for the frame type.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P4-0006">Specifications for permanent registrations MUST describe the format and assigned semantics of any fields in the frame.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P4-0003")]
[Requirement("REQ-QUIC-RFC9000-S22P4-0004")]
[Requirement("REQ-QUIC-RFC9000-S22P4-0006")]
public sealed class QuicFrameCodecTests
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P1-0001">A PADDING frame (type=0x00) MUST have no semantic value.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P1-0004">PADDING frames are formatted as shown in Figure 23, which shows that PADDING frames MUST have no content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P1-0005">That is, a PADDING frame MUST consist of the single byte that identifies the frame as a PADDING frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P1-0006">The Type field MUST be encoded as a variable-length integer with value 0x00.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0008">QUIC packets MAY contain multiple frames of different types.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P1-0006")]
    [Requirement("REQ-QUIC-RFC9002-S3-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParsePaddingFrame_ParsesAndFormatsTheTypeOnlyFrame()
    {
        byte[] frameBytes = QuicFrameTestData.BuildPaddingFrame();

        Assert.True(QuicFrameCodec.TryParsePaddingFrame(frameBytes, out int bytesConsumed));
        Assert.Equal(frameBytes.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[8];
        Assert.True(QuicFrameCodec.TryFormatPaddingFrame(destination, out int bytesWritten));
        Assert.Equal(frameBytes.Length, bytesWritten);
        Assert.True(frameBytes.AsSpan().SequenceEqual(destination[..bytesWritten]));

        byte[] packetWithFollowingFrame = [0x00, 0x01];
        Assert.True(QuicFrameCodec.TryParsePaddingFrame(packetWithFollowingFrame, out int consumedBeforePing));
        Assert.Equal(1, consumedBeforePing);
        Assert.True(QuicFrameCodec.TryParsePingFrame(packetWithFollowingFrame[consumedBeforePing..], out int pingConsumed));
        Assert.Equal(1, pingConsumed);
    }

    [Theory]
    [InlineData(0x00UL, false)]
    [InlineData(0x01UL, true)]
    [InlineData(0x02UL, false)]
    [InlineData(0x03UL, false)]
    [InlineData(0x06UL, true)]
        [InlineData(0x07UL, true)]
        [InlineData(0x10UL, true)]
        [InlineData(0x1AUL, true)]
        [InlineData(0x1EUL, true)]
        [InlineData(0x1CUL, false)]
        [InlineData(0x1DUL, false)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P1P1-0001">An endpoint MAY send a PING or another ack-eliciting frame to test the connection for liveness if the peer could time out soon.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S2-0002">Frames other than ACK, PADDING, and CONNECTION_CLOSE MUST be treated as ack-eliciting.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0017">PADDING frames MUST NOT directly cause an acknowledgment to be sent.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S10P1P1-0001")]
    [Requirement("REQ-QUIC-RFC9002-S2-0002")]
    [Requirement("REQ-QUIC-RFC9002-S3-0017")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void IsAckElicitingFrameType_ClassifiesKnownFrameTypes(ulong frameType, bool expectedAckEliciting)
    {
        Assert.Equal(expectedAckEliciting, QuicFrameCodec.IsAckElicitingFrameType(frameType));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P1-0001">A PADDING frame (type=0x00) MUST have no semantic value.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P1-0004">PADDING frames are formatted as shown in Figure 23, which shows that PADDING frames MUST have no content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P1-0005">That is, a PADDING frame MUST consist of the single byte that identifies the frame as a PADDING frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P1-0006">The Type field MUST be encoded as a variable-length integer with value 0x00.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P2-0002">PING frames are formatted as shown in Figure 24, which shows that PING frames MUST have no content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P2-0003">The Type field MUST be encoded as a variable-length integer with value 0x01.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P2-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParsePaddingAndPingFrame_RejectsEmptyAndMismatchedTypes()
    {
        Assert.False(QuicFrameCodec.TryParsePaddingFrame([], out _));
        Assert.False(QuicFrameCodec.TryParsePaddingFrame([0x01], out _));
        Assert.False(QuicFrameCodec.TryParsePingFrame([], out _));
        Assert.False(QuicFrameCodec.TryParsePingFrame([0x00], out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P1P1-0001">An endpoint MAY send a PING or another ack-eliciting frame to test the connection for liveness if the peer could time out soon.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P2-0002">PING frames are formatted as shown in Figure 24, which shows that PING frames MUST have no content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P2-0003">The Type field MUST be encoded as a variable-length integer with value 0x01.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S10P1P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P2-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParsePingFrame_ParsesAndFormatsTheTypeOnlyFrame()
    {
        byte[] frameBytes = QuicFrameTestData.BuildPingFrame();

        Assert.True(QuicFrameCodec.TryParsePingFrame(frameBytes, out int bytesConsumed));
        Assert.Equal(frameBytes.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[8];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(destination, out int bytesWritten));
        Assert.Equal(frameBytes.Length, bytesWritten);
        Assert.True(frameBytes.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P4P1-0004">On receiving an IP packet with an ECT(0), ECT(1), or ECN-CE codepoint, an ECN-enabled endpoint MUST access the ECN field and increase the corresponding ECT(0), ECT(1), or ECN-CE count.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P4P1-0005">These ECN counts MUST be included in subsequent ACK frames.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0001">QUIC implementations MUST properly handle ACK frame types 0x02 and 0x03.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0002">The ACK frame MUST contain one or more ACK Ranges.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0003">If the frame type is 0x03, ACK frames also MUST contain the cumulative count of QUIC packets with associated ECN marks received on the connection up until this point.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P3-0009">The Type field MUST be encoded as a variable-length integer with value 0x02..0x03.</workbench-requirement>
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
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0010">ACK frames MUST carry the most recent set of acknowledgments and the acknowledgment delay from the largest acknowledged packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0001">When an ACK frame is sent, one or more ranges of acknowledged packets MUST be included.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0002">ACK frames SHOULD always acknowledge the most recently received packets.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0012">A receiver SHOULD include an ACK Range containing the largest received packet number in every ACK frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P5-0002">The endpoint MUST encode this acknowledgment delay in the ACK Delay field of an ACK frame.</workbench-requirement>
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
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0009")]
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
    [Requirement("REQ-QUIC-RFC9000-S13P3-0010")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P5-0002")]
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
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseAckFrame_RoundTripsRangesAndEcnCounts()
    {
        ulong largestAcknowledged = 0x1234;
        ulong firstAckRange = 0x04;
        ulong firstSmallest = largestAcknowledged - firstAckRange;
        QuicAckRange firstAdditionalRange = QuicFrameTestData.BuildAckRange(firstSmallest, 0x01, 0x02);
        QuicAckRange secondAdditionalRange = QuicFrameTestData.BuildAckRange(firstAdditionalRange.SmallestAcknowledged, 0x00, 0x00);

        QuicAckFrame frame = new()
        {
            FrameType = 0x03,
            LargestAcknowledged = largestAcknowledged,
            AckDelay = 0x25,
            FirstAckRange = firstAckRange,
            AdditionalRanges =
            [
                firstAdditionalRange,
                secondAdditionalRange,
            ],
            EcnCounts = new QuicEcnCounts(0x11, 0x12, 0x13),
        };

        byte[] encoded = QuicFrameTestData.BuildAckFrame(frame);

        Assert.True(QuicFrameCodec.TryParseAckFrame(encoded, out QuicAckFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.FrameType, parsed.FrameType);
        Assert.Equal(frame.LargestAcknowledged, parsed.LargestAcknowledged);
        Assert.Equal(frame.AckDelay, parsed.AckDelay);
        Assert.Equal(frame.FirstAckRange, parsed.FirstAckRange);
        Assert.Equal(frame.AdditionalRanges.Length, parsed.AdditionalRanges.Length);
        Assert.Equal(frame.AdditionalRanges[0].Gap, parsed.AdditionalRanges[0].Gap);
        Assert.Equal(frame.AdditionalRanges[0].AckRangeLength, parsed.AdditionalRanges[0].AckRangeLength);
        Assert.Equal(frame.AdditionalRanges[0].SmallestAcknowledged, parsed.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(frame.AdditionalRanges[0].LargestAcknowledged, parsed.AdditionalRanges[0].LargestAcknowledged);
        Assert.Equal(frame.AdditionalRanges[1].Gap, parsed.AdditionalRanges[1].Gap);
        Assert.Equal(frame.AdditionalRanges[1].AckRangeLength, parsed.AdditionalRanges[1].AckRangeLength);
        Assert.Equal(frame.AdditionalRanges[1].SmallestAcknowledged, parsed.AdditionalRanges[1].SmallestAcknowledged);
        Assert.Equal(frame.AdditionalRanges[1].LargestAcknowledged, parsed.AdditionalRanges[1].LargestAcknowledged);
        Assert.Equal(frame.EcnCounts!.Value.Ect0Count, parsed.EcnCounts!.Value.Ect0Count);
        Assert.Equal(frame.EcnCounts!.Value.Ect1Count, parsed.EcnCounts!.Value.Ect1Count);
        Assert.Equal(frame.EcnCounts!.Value.EcnCeCount, parsed.EcnCounts!.Value.EcnCeCount);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

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

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0006">Streams in QUIC MAY be canceled.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P4-0005">An application protocol MAY reset a stream if the stream is not already in a terminal state, resulting in a RESET_STREAM frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P5-0003">The Final Size field of a RESET_STREAM frame MUST carry the final size value.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0004">The Type field MUST be encoded as a variable-length integer with value 0x04.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0005">The Stream ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0006">The Application Protocol Error Code field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0007">The Final Size field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0008">RESET_STREAM frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0009">The Stream ID field MUST be variable-length integer encoding of the stream ID of the stream being terminated.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0010">A variable-length integer containing the application protocol error code (see Section 20.2) that MUST indicate why the stream is being closed.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0011">The Final Size field MUST be variable-length integer indicating the final size of the stream by the RESET_STREAM sender, in units of bytes; see Section 4.5.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0005")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseResetStreamFrame_ParsesAndFormatsAllFields()
    {
        QuicResetStreamFrame frame = new(0x1234, 0x55, 0x200);
        byte[] encoded = QuicFrameTestData.BuildResetStreamFrame(frame);

        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(encoded, out QuicResetStreamFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.ApplicationProtocolErrorCode, parsed.ApplicationProtocolErrorCode);
        Assert.Equal(frame.FinalSize, parsed.FinalSize);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatResetStreamFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0006">Streams in QUIC MAY be canceled.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0004">The Type field MUST be encoded as a variable-length integer with value 0x04.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0005">The Stream ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0006">The Application Protocol Error Code field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0007">The Final Size field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0008">RESET_STREAM frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0009">The Stream ID field MUST be variable-length integer encoding of the stream ID of the stream being terminated.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0010">A variable-length integer containing the application protocol error code (see Section 20.2) that MUST indicate why the stream is being closed.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0011">The Final Size field MUST be variable-length integer indicating the final size of the stream by the RESET_STREAM sender, in units of bytes; see Section 4.5.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0011")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseResetStreamFrame_RejectsTruncatedInputs()
    {
        byte[] encoded = QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(0x1234, 0x55, 0x200));

        Assert.False(QuicFrameCodec.TryParseResetStreamFrame(encoded[..(encoded.Length - 1)], out _, out _));
        Assert.False(QuicFrameCodec.TryParseResetStreamFrame([], out _, out _));
        Assert.False(QuicFrameCodec.TryParseResetStreamFrame([0x05], out _, out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0006">Streams in QUIC MAY be canceled.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P4-0007">An application protocol MAY abort reading a stream and request closure, possibly resulting in a STOP_SENDING frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0005">The Type field MUST be encoded as a variable-length integer with value 0x05.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0006">The Stream ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0007">The Application Protocol Error Code field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0008">STOP_SENDING frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0009">The Stream ID field MUST be variable-length integer carrying the stream ID of the stream being ignored.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0010">The Application Protocol Error Code field MUST be variable-length integer containing the application-specified reason the sender is ignoring the stream; see Section 20.2.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStopSendingFrame_ParsesAndFormatsAllFields()
    {
        QuicStopSendingFrame frame = new(0x44, 0x66);
        byte[] encoded = QuicFrameTestData.BuildStopSendingFrame(frame);

        Assert.True(QuicFrameCodec.TryParseStopSendingFrame(encoded, out QuicStopSendingFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.ApplicationProtocolErrorCode, parsed.ApplicationProtocolErrorCode);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatStopSendingFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0006">Streams in QUIC MAY be canceled.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0005">The Type field MUST be encoded as a variable-length integer with value 0x05.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0006">The Stream ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0007">The Application Protocol Error Code field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0008">STOP_SENDING frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0009">The Stream ID field MUST be variable-length integer carrying the stream ID of the stream being ignored.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0010">The Application Protocol Error Code field MUST be variable-length integer containing the application-specified reason the sender is ignoring the stream; see Section 20.2.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStopSendingFrame_RejectsTruncatedInputs()
    {
        byte[] encoded = QuicFrameTestData.BuildStopSendingFrame(new QuicStopSendingFrame(0x44, 0x66));

        Assert.False(QuicFrameCodec.TryParseStopSendingFrame(encoded[..(encoded.Length - 1)], out _, out _));
        Assert.False(QuicFrameCodec.TryParseStopSendingFrame([], out _, out _));
        Assert.False(QuicFrameCodec.TryParseStopSendingFrame([0x04], out _, out _));
    }
}
