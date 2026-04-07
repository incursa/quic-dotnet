namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P1-0001")]
public sealed class REQ_QUIC_RFC9000_S19P1_0001
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

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P1-0001">A PADDING frame (type=0x00) MUST have no semantic value.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P1-0004">PADDING frames are formatted as shown in Figure 23, which shows that PADDING frames MUST have no content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P1-0005">That is, a PADDING frame MUST consist of the single byte that identifies the frame as a PADDING frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P1-0006">The Type field MUST be encoded as a variable-length integer with value 0x00.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P1-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParsePaddingFrame_RejectsEmptyAndNonPaddingTypes()
    {
        Assert.False(QuicFrameCodec.TryParsePaddingFrame([], out _));
        Assert.False(QuicFrameCodec.TryParsePaddingFrame([0x01], out _));
    }
}
