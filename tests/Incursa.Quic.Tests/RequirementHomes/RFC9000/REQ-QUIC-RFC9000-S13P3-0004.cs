namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0004">New frames and packets MUST be used to carry information that is determined to have been lost.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0004")]
public sealed class REQ_QUIC_RFC9000_S13P3_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task LostStreamDataRepairUsesANewFrameInANewPacket()
    {
        QuicS13StreamDataSend send = await QuicS13RetransmissionTestSupport.SendSingleStreamDataPacketAsync();
        using QuicConnectionRuntime runtime = send.Runtime;

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            send.PacketKey.PacketNumberSpace,
            send.PacketKey.PacketNumber,
            handshakeConfirmed: true));

        QuicS13StreamDataRetransmission retransmission =
            QuicS13RetransmissionTestSupport.FlushSingleApplicationRetransmission(runtime);

        Assert.NotEqual(send.PacketKey.PacketNumber, retransmission.PacketKey.PacketNumber);
        Assert.False(retransmission.Packet.PacketBytes.Span.SequenceEqual(send.Packet.PacketBytes.Span));
        Assert.Equal(send.StreamFrame.StreamId, retransmission.StreamFrame.StreamId);
        Assert.Equal(send.StreamFrame.Offset, retransmission.StreamFrame.Offset);
        Assert.True(retransmission.StreamFrame.StreamData.SequenceEqual(send.Payload));
    }
}
