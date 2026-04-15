namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0029">New connection IDs MUST be sent in NEW_CONNECTION_ID frames and retransmitted if the packet containing them is lost.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0029")]
public sealed class REQ_QUIC_RFC9000_S13P3_0029
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0029")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LossOfANewConnectionIdPacketQueuesRetransmissionUntilAcknowledged()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] packet = BuildNewConnectionIdPacket();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: (ulong)packet.Length,
            SentAtMicros: 100,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: packet));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            7,
            handshakeConfirmed: true));

        Assert.Equal(1, runtime.PendingRetransmissionCount);
        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.Equal(7UL, retransmission.PacketNumber);
        Assert.True(packet.AsSpan().SequenceEqual(retransmission.PacketBytes.Span));
        Assert.False(runtime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0029")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AcknowledgingAnUnrelatedPacketDoesNotClearQueuedNewConnectionIdRepair()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] packet = BuildNewConnectionIdPacket();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: (ulong)packet.Length,
            SentAtMicros: 100,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: packet));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            7,
            handshakeConfirmed: true));

        Assert.False(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            8,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.PendingRetransmissionCount);

        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.True(packet.AsSpan().SequenceEqual(retransmission.PacketBytes.Span));
        Assert.False(runtime.TryDequeueRetransmission(out _));
    }

    private static byte[] BuildNewConnectionIdPacket()
    {
        byte[] connectionId =
        [
            0x10, 0x11, 0x12, 0x13,
        ];

        byte[] statelessResetToken =
        [
            0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B,
            0x2C, 0x2D, 0x2E, 0x2F,
        ];

        QuicNewConnectionIdFrame frame = new(0x06, 0x04, connectionId, statelessResetToken);
        byte[] encoded = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

        Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded, out QuicNewConnectionIdFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(frame.SequenceNumber, parsed.SequenceNumber);
        Assert.Equal(frame.RetirePriorTo, parsed.RetirePriorTo);
        Assert.True(connectionId.AsSpan().SequenceEqual(parsed.ConnectionId));
        Assert.True(statelessResetToken.AsSpan().SequenceEqual(parsed.StatelessResetToken));

        return encoded;
    }
}
