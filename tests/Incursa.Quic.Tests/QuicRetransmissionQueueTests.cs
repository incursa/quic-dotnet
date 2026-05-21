namespace Incursa.Quic.Tests;

public sealed class QuicRetransmissionQueueTests
{
    [Fact]
    public void TryDequeueRetransmission_ReturnsPlansInFirstInFirstOutOrder()
    {
        QuicRetransmissionQueue queue = new();
        queue.QueueRetransmission(CreatePlan(QuicPacketNumberSpace.Initial, 1, sentAtMicros: 100));
        queue.QueueRetransmission(CreatePlan(QuicPacketNumberSpace.Handshake, 2, sentAtMicros: 200));
        queue.QueueRetransmission(CreatePlan(QuicPacketNumberSpace.ApplicationData, 3, sentAtMicros: 300));

        Assert.True(queue.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan first));
        Assert.Equal(QuicPacketNumberSpace.Initial, first.PacketNumberSpace);
        Assert.Equal(1UL, first.PacketNumber);

        Assert.True(queue.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan second));
        Assert.Equal(QuicPacketNumberSpace.Handshake, second.PacketNumberSpace);
        Assert.Equal(2UL, second.PacketNumber);

        Assert.True(queue.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan third));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, third.PacketNumberSpace);
        Assert.Equal(3UL, third.PacketNumber);

        Assert.False(queue.TryDequeueRetransmission(out _));
    }

    [Fact]
    public void TryDiscardPacketNumberSpace_RemovesOnlyMatchingSpace()
    {
        QuicRetransmissionQueue queue = new();
        queue.QueueRetransmission(CreatePlan(QuicPacketNumberSpace.Initial, 1));
        queue.QueueRetransmission(CreatePlan(QuicPacketNumberSpace.Handshake, 2));
        queue.QueueRetransmission(CreatePlan(QuicPacketNumberSpace.ApplicationData, 3));

        Assert.True(queue.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));
        Assert.False(queue.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));

        Assert.True(queue.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan first));
        Assert.Equal(QuicPacketNumberSpace.Handshake, first.PacketNumberSpace);
        Assert.Equal(2UL, first.PacketNumber);

        Assert.True(queue.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan second));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, second.PacketNumberSpace);
        Assert.Equal(3UL, second.PacketNumber);

        Assert.False(queue.TryDequeueRetransmission(out _));
    }

    [Fact]
    public void TryDiscardPacketProtectionLevel_RemovesOnlyMatchingProtectionLevel()
    {
        QuicRetransmissionQueue queue = new();
        queue.QueueRetransmission(CreatePlan(
            QuicPacketNumberSpace.ApplicationData,
            1,
            packetProtectionLevel: QuicTlsEncryptionLevel.ZeroRtt));
        queue.QueueRetransmission(CreatePlan(
            QuicPacketNumberSpace.ApplicationData,
            2,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: 0));
        queue.QueueRetransmission(CreatePlan(
            QuicPacketNumberSpace.ApplicationData,
            3,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: 1));

        Assert.True(queue.TryDiscardPacketProtectionLevel(QuicTlsEncryptionLevel.ZeroRtt));
        Assert.False(queue.TryDiscardPacketProtectionLevel(QuicTlsEncryptionLevel.ZeroRtt));

        Assert.True(queue.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan first));
        Assert.Equal(2UL, first.PacketNumber);

        Assert.True(queue.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan second));
        Assert.Equal(3UL, second.PacketNumber);

        Assert.False(queue.TryDequeueRetransmission(out _));
    }

    [Fact]
    public void TryDiscardOneRttKeyPhase_RemovesOnlyMatchingPhase()
    {
        QuicRetransmissionQueue queue = new();
        queue.QueueRetransmission(CreatePlan(
            QuicPacketNumberSpace.ApplicationData,
            1,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: 0));
        queue.QueueRetransmission(CreatePlan(
            QuicPacketNumberSpace.ApplicationData,
            2,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: 1));
        queue.QueueRetransmission(CreatePlan(
            QuicPacketNumberSpace.ApplicationData,
            3,
            packetProtectionLevel: QuicTlsEncryptionLevel.ZeroRtt));

        Assert.True(queue.TryDiscardOneRttKeyPhase(1));
        Assert.False(queue.TryDiscardOneRttKeyPhase(1));

        Assert.True(queue.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan first));
        Assert.Equal(1UL, first.PacketNumber);

        Assert.True(queue.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan second));
        Assert.Equal(3UL, second.PacketNumber);

        Assert.False(queue.TryDequeueRetransmission(out _));
    }

    [Fact]
    public void TryDiscardPendingRetransmissionsOlderThan_RemovesOnlyOlderPlans()
    {
        QuicRetransmissionQueue queue = new();
        queue.QueueRetransmission(CreatePlan(QuicPacketNumberSpace.ApplicationData, 1, sentAtMicros: 100));
        queue.QueueRetransmission(CreatePlan(QuicPacketNumberSpace.ApplicationData, 2, sentAtMicros: 200));
        queue.QueueRetransmission(CreatePlan(QuicPacketNumberSpace.ApplicationData, 3, sentAtMicros: 300));

        Assert.True(queue.TryDiscardPendingRetransmissionsOlderThan(200));
        Assert.False(queue.TryDiscardPendingRetransmissionsOlderThan(200));

        Assert.True(queue.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan first));
        Assert.Equal(2UL, first.PacketNumber);
        Assert.Equal(200UL, first.SentAtMicros);

        Assert.True(queue.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan second));
        Assert.Equal(3UL, second.PacketNumber);
        Assert.Equal(300UL, second.SentAtMicros);

        Assert.False(queue.TryDequeueRetransmission(out _));
    }

    [Fact]
    public void TrySuppressRetransmissionForStream_RemovesOnlySingleStreamPlans()
    {
        ulong targetStreamId = 7;
        QuicRetransmissionQueue queue = new();
        queue.QueueRetransmission(CreatePlan(
            QuicPacketNumberSpace.ApplicationData,
            1,
            streamIds: [targetStreamId]));
        queue.QueueRetransmission(CreatePlan(
            QuicPacketNumberSpace.ApplicationData,
            2,
            streamIds: [targetStreamId, 8]));
        queue.QueueRetransmission(CreatePlan(
            QuicPacketNumberSpace.ApplicationData,
            3,
            streamIds: [8]));

        Assert.True(queue.TrySuppressRetransmissionForStream(targetStreamId));
        Assert.False(queue.TrySuppressRetransmissionForStream(targetStreamId));

        Assert.True(queue.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan first));
        Assert.Equal(2UL, first.PacketNumber);

        Assert.True(queue.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan second));
        Assert.Equal(3UL, second.PacketNumber);

        Assert.False(queue.TryDequeueRetransmission(out _));
    }

    [Fact]
    public void TrySuppressStopSendingRetransmissionForStream_RemovesMatchingPayloadAndPreservesRetainedOrder()
    {
        ulong targetStreamId = 7;
        byte[] targetPayload =
        [
            ..QuicFrameTestData.BuildPaddingFrame(),
            ..QuicFrameTestData.BuildStopSendingFrame(new QuicStopSendingFrame(targetStreamId, 0x11)),
        ];

        QuicRetransmissionQueue queue = new();
        queue.QueueRetransmission(CreatePlan(QuicPacketNumberSpace.ApplicationData, 1, plaintextPayload: targetPayload));
        queue.QueueRetransmission(CreatePlan(
            QuicPacketNumberSpace.ApplicationData,
            2,
            plaintextPayload: QuicFrameTestData.BuildStopSendingFrame(new QuicStopSendingFrame(8, 0x22))));
        queue.QueueRetransmission(CreatePlan(
            QuicPacketNumberSpace.ApplicationData,
            3,
            plaintextPayload: QuicStreamTestData.BuildStreamFrame(0x0A, 9, [0xAA])));

        Assert.True(queue.TrySuppressStopSendingRetransmissionForStream(targetStreamId));
        Assert.False(queue.TrySuppressStopSendingRetransmissionForStream(targetStreamId));

        Assert.True(queue.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan first));
        Assert.Equal(2UL, first.PacketNumber);

        Assert.True(queue.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan second));
        Assert.Equal(3UL, second.PacketNumber);

        Assert.False(queue.TryDequeueRetransmission(out _));
    }

    [Fact]
    public void TrySuppressResetStreamRetransmissionForStream_RemovesMatchingPayloadAndPreservesRetainedOrder()
    {
        ulong targetStreamId = 7;
        byte[] targetPayload =
        [
            ..QuicFrameTestData.BuildPaddingFrame(),
            ..QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(targetStreamId, 0x11, 0x00)),
        ];

        QuicRetransmissionQueue queue = new();
        queue.QueueRetransmission(CreatePlan(QuicPacketNumberSpace.ApplicationData, 1, plaintextPayload: targetPayload));
        queue.QueueRetransmission(CreatePlan(
            QuicPacketNumberSpace.ApplicationData,
            2,
            plaintextPayload: QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(8, 0x22, 0x00))));
        queue.QueueRetransmission(CreatePlan(
            QuicPacketNumberSpace.ApplicationData,
            3,
            plaintextPayload: QuicStreamTestData.BuildStreamFrame(0x0A, 9, [0xAA])));

        Assert.True(queue.TrySuppressResetStreamRetransmissionForStream(targetStreamId));
        Assert.False(queue.TrySuppressResetStreamRetransmissionForStream(targetStreamId));

        Assert.True(queue.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan first));
        Assert.Equal(2UL, first.PacketNumber);

        Assert.True(queue.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan second));
        Assert.Equal(3UL, second.PacketNumber);

        Assert.False(queue.TryDequeueRetransmission(out _));
    }

    [Fact]
    public void CaptureBuildableApplicationRetransmissions_CollectsOnlyBuildableApplicationState()
    {
        QuicRetransmissionQueue queue = new();
        queue.QueueRetransmission(CreatePlan(
            QuicPacketNumberSpace.ApplicationData,
            5,
            packetBytes: [0x55, 0x66],
            plaintextPayload: [0x11, 0x22],
            streamIds: [7],
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: 1));

        Dictionary<QuicConnectionSentPacketKey, QuicConnectionSentPacket> sentPackets = [];
        sentPackets[new QuicConnectionSentPacketKey(QuicPacketNumberSpace.Initial, 1)] = new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Initial,
            1,
            1_200,
            100,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: new byte[] { 0xA1 },
            PlaintextPayload: new byte[] { 0x01 });
        sentPackets[new QuicConnectionSentPacketKey(QuicPacketNumberSpace.ApplicationData, 2)] = new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            2,
            900,
            200,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: new byte[] { 0xA2 },
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            StreamIds: new ulong[] { 7 },
            PlaintextPayload: new byte[] { 0x02, 0x03 },
            OneRttKeyPhase: 1);
        sentPackets[new QuicConnectionSentPacketKey(QuicPacketNumberSpace.ApplicationData, 3)] = new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            3,
            900,
            300,
            AckEliciting: true,
            Retransmittable: false,
            PacketBytes: new byte[] { 0xA3 },
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            StreamIds: new ulong[] { 8 },
            PlaintextPayload: new byte[] { 0x04 },
            OneRttKeyPhase: 2);
        sentPackets[new QuicConnectionSentPacketKey(QuicPacketNumberSpace.ApplicationData, 4)] = new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            4,
            900,
            400,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: new byte[] { 0xA4 },
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            StreamIds: new ulong[] { 9 },
            PlaintextPayload: new byte[0],
            OneRttKeyPhase: 3);

        List<QuicConnectionRetransmissionPlan>? retainedRetransmissions = null;
        queue.CaptureBuildableApplicationRetransmissions(sentPackets.Values, ref retainedRetransmissions);

        Assert.NotNull(retainedRetransmissions);
        List<QuicConnectionRetransmissionPlan> retained = retainedRetransmissions!;
        Assert.Equal(2, retained.Count);

        QuicConnectionRetransmissionPlan capturedSent = Assert.Single(retained, plan => plan.PacketNumber == 2);
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, capturedSent.PacketNumberSpace);
        Assert.True(capturedSent.PacketBytes.IsEmpty);
        Assert.Equal(new byte[] { 0x02, 0x03 }, capturedSent.PlaintextPayload.ToArray());

        QuicConnectionRetransmissionPlan capturedQueued = Assert.Single(retained, plan => plan.PacketNumber == 5);
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, capturedQueued.PacketNumberSpace);
        Assert.True(capturedQueued.PacketBytes.IsEmpty);
        Assert.Equal(new byte[] { 0x11, 0x22 }, capturedQueued.PlaintextPayload.ToArray());
    }

    private static QuicConnectionRetransmissionPlan CreatePlan(
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        ulong sentAtMicros = 0,
        byte[]? packetBytes = null,
        byte[]? plaintextPayload = null,
        ulong[]? streamIds = null,
        QuicTlsEncryptionLevel? packetProtectionLevel = null,
        ulong? oneRttKeyPhase = null)
    {
        return new QuicConnectionRetransmissionPlan(
            packetNumberSpace,
            packetNumber,
            PayloadBytes: (ulong)(plaintextPayload?.Length ?? packetBytes?.Length ?? 0),
            SentAtMicros: sentAtMicros,
            ProbePacket: false,
            CryptoMetadata: null,
            PacketBytes: packetBytes is null ? default : packetBytes,
            PacketProtectionLevel: packetProtectionLevel,
            StreamIds: streamIds,
            PlaintextPayload: plaintextPayload is null ? default : plaintextPayload,
            OneRttKeyPhase: oneRttKeyPhase);
    }
}
