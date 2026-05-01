namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0002">The same rule MUST apply to the frames that are contained within lost packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0002")]
public sealed class REQ_QUIC_RFC9000_S13P3_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task LostStreamFrameInformationIsCarriedByAFrameInANewPacket()
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
        Assert.Equal(send.StreamFrame.StreamId, retransmission.StreamFrame.StreamId);
        Assert.Equal(send.StreamFrame.Offset, retransmission.StreamFrame.Offset);
        Assert.True(retransmission.StreamFrame.StreamData.SequenceEqual(send.Payload));
    }
}
