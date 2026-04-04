namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P4-0002">An endpoint MAY send up to two full-sized datagrams containing ack-eliciting packets to avoid an expensive consecutive PTO expiration due to a single lost datagram or to transmit data from multiple packet number spaces.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P4-0002")]
public sealed class REQ_QUIC_RFC9002_S6P2P4_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProbePackets_CanUseTwoFullSizedDatagramsAfterTheCongestionWindowIsFilled()
    {
        QuicCongestionControlState state = new();
        ulong fullSizedDatagramBytes = state.MaxDatagramSizeBytes;

        state.RegisterPacketSent(state.CongestionWindowBytes);

        Span<byte> probeFrame = stackalloc byte[1];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(probeFrame, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        Assert.True(QuicFrameCodec.IsAckElicitingFrameType(probeFrame[0]));

        Assert.True(state.CanSend(fullSizedDatagramBytes, isProbePacket: true));
        state.RegisterPacketSent(fullSizedDatagramBytes, isProbePacket: true);

        Assert.True(state.CanSend(fullSizedDatagramBytes, isProbePacket: true));
        state.RegisterPacketSent(fullSizedDatagramBytes, isProbePacket: true);

        Assert.Equal(
            state.CongestionWindowBytes + (2 * fullSizedDatagramBytes),
            state.BytesInFlightBytes);
    }
}
