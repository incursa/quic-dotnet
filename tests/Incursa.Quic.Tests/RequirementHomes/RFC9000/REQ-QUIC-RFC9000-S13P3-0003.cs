namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0003">Instead, the information that might be carried in frames MUST be sent again in new frames as needed.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0003")]
public sealed class REQ_QUIC_RFC9000_S13P3_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task LostStreamDataInformationIsSentAgainInARetransmissionFrame()
    {
        QuicS13StreamDataSend send = await QuicS13RetransmissionTestSupport.SendSingleStreamDataPacketAsync();
        using QuicConnectionRuntime runtime = send.Runtime;

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            send.PacketKey.PacketNumberSpace,
            send.PacketKey.PacketNumber,
            handshakeConfirmed: true));

        QuicS13StreamDataRetransmission retransmission =
            QuicS13RetransmissionTestSupport.FlushSingleApplicationRetransmission(runtime);

        Assert.Equal(send.StreamFrame.StreamId, retransmission.StreamFrame.StreamId);
        Assert.Equal(send.StreamFrame.Offset, retransmission.StreamFrame.Offset);
        Assert.Equal(send.StreamFrame.StreamDataLength, retransmission.StreamFrame.StreamDataLength);
        Assert.True(retransmission.StreamFrame.StreamData.SequenceEqual(send.StreamFrame.StreamData));
    }
}
