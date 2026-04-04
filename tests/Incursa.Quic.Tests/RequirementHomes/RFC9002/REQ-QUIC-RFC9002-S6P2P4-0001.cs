namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P4-0001">When a PTO timer expires, a sender MUST send at least one ack-eliciting packet in the packet number space as a probe.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P4-0001")]
public sealed class REQ_QUIC_RFC9002_S6P2P4_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatPingFrame_ProducesTheMinimumAckElicitingProbe()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(state.CongestionWindowBytes);

        Span<byte> pingFrame = stackalloc byte[1];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(pingFrame, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        Assert.True(QuicFrameCodec.IsAckElicitingFrameType(0x01));

        Assert.True(state.CanSend(1, isProbePacket: true));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatPingFrame_RejectsAZeroLengthDestination()
    {
        Assert.False(QuicFrameCodec.TryFormatPingFrame(stackalloc byte[0], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParsePingFrame_ConsumesTheSingleByteAtThePacketBoundary()
    {
        Assert.True(QuicFrameCodec.TryParsePingFrame([0x01], out int bytesConsumed));
        Assert.Equal(1, bytesConsumed);
    }
}
