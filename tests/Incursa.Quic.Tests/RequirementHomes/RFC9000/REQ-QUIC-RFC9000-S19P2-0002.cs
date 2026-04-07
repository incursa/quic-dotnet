namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P2-0002")]
public sealed class REQ_QUIC_RFC9000_S19P2_0002
{
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
    public void TryParsePingFrame_RejectsEmptyAndNonPingTypes()
    {
        Assert.False(QuicFrameCodec.TryParsePingFrame([], out _));
        Assert.False(QuicFrameCodec.TryParsePingFrame([0x00], out _));
    }
}
