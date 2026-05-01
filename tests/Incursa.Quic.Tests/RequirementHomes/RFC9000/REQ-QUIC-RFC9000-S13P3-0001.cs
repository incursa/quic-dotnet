namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0001">QUIC packets that are determined to be lost MUST NOT be retransmitted whole.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0001")]
public sealed class REQ_QUIC_RFC9000_S13P3_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task LostStreamDataRetransmissionUsesANewProtectedPacket()
    {
        QuicS13StreamDataSend send = await QuicS13RetransmissionTestSupport.SendSingleStreamDataPacketAsync();
        using QuicConnectionRuntime runtime = send.Runtime;

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            send.PacketKey.PacketNumberSpace,
            send.PacketKey.PacketNumber,
            handshakeConfirmed: true));
        Assert.DoesNotContain(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumberSpace == send.PacketKey.PacketNumberSpace
                && entry.Key.PacketNumber == send.PacketKey.PacketNumber);

        QuicS13StreamDataRetransmission retransmission =
            QuicS13RetransmissionTestSupport.FlushSingleApplicationRetransmission(runtime);

        Assert.NotEqual(send.PacketKey.PacketNumber, retransmission.PacketKey.PacketNumber);
        Assert.False(retransmission.SendEffect.Datagram.Span.SequenceEqual(send.SendEffect.Datagram.Span));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UntrackedPacketLossDoesNotQueueAWholePacketRetransmission()
    {
        QuicConnectionSendRuntime runtime = new();

        Assert.False(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            handshakeConfirmed: true));

        Assert.Equal(0, runtime.PendingRetransmissionCount);
        Assert.False(runtime.TryDequeueRetransmission(out _));
    }
}
