namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0005">Frames MUST fit within a single QUIC packet rather than span multiple packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P4-0005")]
public sealed class REQ_QUIC_RFC9000_S12P4_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseConnectionCloseFrame_ConsumesTheCompleteFramePayload()
    {
        byte[] packetPayload = QuicFrameTestData.BuildConnectionCloseFrame(
            new QuicConnectionCloseFrame(QuicTransportErrorCode.ProtocolViolation, triggeringFrameType: 0x02, reasonPhrase: [0x6F, 0x6B]));

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(packetPayload, out QuicConnectionCloseFrame parsedFrame, out int bytesConsumed));
        Assert.False(parsedFrame.IsApplicationError);
        Assert.Equal(packetPayload.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseMaxDataFrame_RejectsFramesThatAreTruncatedAtThePacketBoundary()
    {
        byte[] packetPayload = QuicFrameTestData.BuildMaxDataFrame(new QuicMaxDataFrame(0x1234));

        Assert.False(QuicFrameCodec.TryParseMaxDataFrame(packetPayload[..^1], out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParsePingFrame_ConsumesTheEntireShortestFrameWithoutSpanningPastThePacket()
    {
        byte[] packetPayload = QuicFrameTestData.BuildPingFrame();

        Assert.True(QuicFrameCodec.TryParsePingFrame(packetPayload, out int bytesConsumed));
        Assert.Equal(1, bytesConsumed);
    }
}
