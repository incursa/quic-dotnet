namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P2P4-0001")]
public sealed class REQ_QUIC_RFC9002_S6P2P4_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TrySendProbePacket_AllowsAnAckElicitingPingWhenTheWindowIsFull()
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
    public void TrySendProbePacket_RejectsNonProbePacketsWhenTheWindowIsFull()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(state.CongestionWindowBytes);

        Assert.False(state.CanSend(1, isAckOnlyPacket: false, isProbePacket: false));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TrySendProbePacket_CountsProbeBytesAtTheWindowBoundary()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(state.CongestionWindowBytes);

        state.RegisterPacketSent(1, isProbePacket: true);

        Assert.Equal(state.CongestionWindowBytes + 1UL, state.BytesInFlightBytes);
    }
}
