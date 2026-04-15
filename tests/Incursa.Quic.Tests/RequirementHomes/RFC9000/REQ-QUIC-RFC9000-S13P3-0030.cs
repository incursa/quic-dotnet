namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0030">Retired connection IDs MUST be sent in RETIRE_CONNECTION_ID frames and retransmitted if the packet containing them is lost.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0030")]
public sealed class REQ_QUIC_RFC9000_S13P3_0030
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0030")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LossOfARetireConnectionIdPacketQueuesRetransmissionUntilAcknowledged()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] packet = BuildRetireConnectionIdPacket();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 11,
            PayloadBytes: (ulong)packet.Length,
            SentAtMicros: 200,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: packet));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            11,
            handshakeConfirmed: true));

        Assert.Equal(1, runtime.PendingRetransmissionCount);
        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.Equal(11UL, retransmission.PacketNumber);
        Assert.True(packet.AsSpan().SequenceEqual(retransmission.PacketBytes.Span));
        Assert.False(runtime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0030")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AcknowledgingAnUnrelatedPacketDoesNotClearQueuedRetireConnectionIdRepair()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] packet = BuildRetireConnectionIdPacket();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 11,
            PayloadBytes: (ulong)packet.Length,
            SentAtMicros: 200,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: packet));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            11,
            handshakeConfirmed: true));

        Assert.False(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            12,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.PendingRetransmissionCount);

        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.True(packet.AsSpan().SequenceEqual(retransmission.PacketBytes.Span));
        Assert.False(runtime.TryDequeueRetransmission(out _));
    }

    private static byte[] BuildRetireConnectionIdPacket()
    {
        QuicRetireConnectionIdFrame frame = new(0x1234_5678);
        byte[] encoded = QuicFrameTestData.BuildRetireConnectionIdFrame(frame);

        Assert.True(QuicFrameCodec.TryParseRetireConnectionIdFrame(encoded, out QuicRetireConnectionIdFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(frame.SequenceNumber, parsed.SequenceNumber);

        return encoded;
    }
}
