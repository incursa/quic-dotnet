namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0005">In general, information MUST be sent again when a packet containing that information is determined to be lost and cease being sent when a packet containing that information is acknowledged.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0005")]
public sealed class REQ_QUIC_RFC9000_S13P3_0005
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task LostStreamDataIsSentAgainAndStopsAfterRetransmissionIsAcknowledged()
    {
        QuicS13StreamDataSend send = await QuicS13RetransmissionTestSupport.SendSingleStreamDataPacketAsync();
        using QuicConnectionRuntime runtime = send.Runtime;

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            send.PacketKey.PacketNumberSpace,
            send.PacketKey.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        QuicS13StreamDataRetransmission retransmission =
            QuicS13RetransmissionTestSupport.FlushSingleApplicationRetransmission(runtime);

        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.True(retransmission.StreamFrame.StreamData.SequenceEqual(send.Payload));

        Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
            retransmission.PacketKey.PacketNumberSpace,
            retransmission.PacketKey.PacketNumber,
            handshakeConfirmed: true));

        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.DoesNotContain(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumberSpace == retransmission.PacketKey.PacketNumberSpace
                && entry.Key.PacketNumber == retransmission.PacketKey.PacketNumber);
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task AcknowledgingAnUnrelatedPacketDoesNotStopQueuedLostInformation()
    {
        QuicS13StreamDataSend send = await QuicS13RetransmissionTestSupport.SendSingleStreamDataPacketAsync();
        using QuicConnectionRuntime runtime = send.Runtime;

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            send.PacketKey.PacketNumberSpace,
            send.PacketKey.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        Assert.False(runtime.SendRuntime.TryAcknowledgePacket(
            send.PacketKey.PacketNumberSpace,
            send.PacketKey.PacketNumber + 1,
            handshakeConfirmed: true));

        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.True(runtime.SendRuntime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.Equal(send.PacketKey.PacketNumber, retransmission.PacketNumber);
        Assert.True(retransmission.PlaintextPayload.Span.SequenceEqual(send.Packet.PlaintextPayload.Span));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0005")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task AcknowledgingTheOriginalLostPacketRemovesTheQueuedRetransmission()
    {
        QuicS13StreamDataSend send = await QuicS13RetransmissionTestSupport.SendSingleStreamDataPacketAsync();
        using QuicConnectionRuntime runtime = send.Runtime;

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            send.PacketKey.PacketNumberSpace,
            send.PacketKey.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
            send.PacketKey.PacketNumberSpace,
            send.PacketKey.PacketNumber,
            handshakeConfirmed: true));

        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
    }
}
