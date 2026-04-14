namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP9-0004">When PTO fires, the sender MUST send one or two ack-eliciting packets in the selected packet number space.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP9-0004")]
public sealed class REQ_QUIC_RFC9002_SAP9_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanSend_AllowsAnAckElicitingProbePacketWhenTheCongestionWindowIsFull()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(state.CongestionWindowBytes);

        Span<byte> probeFrame = stackalloc byte[1];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(probeFrame, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        Assert.True(QuicFrameCodec.IsAckElicitingFrameType(probeFrame[0]));

        Assert.True(state.CanSend(1, isProbePacket: true));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CanSend_RejectsNonProbePacketsWhenTheCongestionWindowIsFull()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(state.CongestionWindowBytes);

        Assert.False(state.CanSend(1, isProbePacket: false));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void CanSend_AllowsTwoFullSizedProbeDatagramsWhenTheCongestionWindowIsFull()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(state.CongestionWindowBytes);
        ulong fullSizedDatagramBytes = state.MaxDatagramSizeBytes;

        Assert.True(state.CanSend(fullSizedDatagramBytes, isProbePacket: true));
        state.RegisterPacketSent(fullSizedDatagramBytes, isProbePacket: true);

        Assert.True(state.CanSend(fullSizedDatagramBytes, isProbePacket: true));
        state.RegisterPacketSent(fullSizedDatagramBytes, isProbePacket: true);

        Assert.Equal(
            state.CongestionWindowBytes + (2 * fullSizedDatagramBytes),
            state.BytesInFlightBytes);
    }
}
