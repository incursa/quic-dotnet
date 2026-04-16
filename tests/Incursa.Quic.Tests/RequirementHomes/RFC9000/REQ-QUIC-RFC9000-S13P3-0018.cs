namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0018">Like MAX_DATA, an updated value MUST be sent when the packet containing the most recent MAX_STREAM_DATA frame for a stream is lost or when the limit is updated.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0018")]
public sealed class REQ_QUIC_RFC9000_S13P3_0018
{
    private static readonly byte[] PacketConnectionId = [0x0A, 0x0B, 0x0C];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0018")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReadStreamData_UpdatesTheCurrentStreamDataOffsetWhenAdditionalBytesAreRead()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame firstFrame));
        Assert.True(state.TryReceiveStreamFrame(firstFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[3];
        Assert.True(state.TryReadStreamData(
            1,
            destination[..2],
            out int bytesWritten,
            out bool completed,
            out _,
            out QuicMaxStreamDataFrame firstMaxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(2, bytesWritten);
        Assert.False(completed);
        Assert.Equal(1UL, firstMaxStreamDataFrame.StreamId);
        Assert.Equal(10UL, firstMaxStreamDataFrame.MaximumStreamData);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x33, 0x44, 0x55], offset: 2),
            out QuicStreamFrame secondFrame));
        Assert.True(state.TryReceiveStreamFrame(secondFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReadStreamData(
            1,
            destination,
            out bytesWritten,
            out completed,
            out _,
            out QuicMaxStreamDataFrame secondMaxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(3, bytesWritten);
        Assert.False(completed);
        Assert.Equal(1UL, secondMaxStreamDataFrame.StreamId);
        Assert.Equal(13UL, secondMaxStreamDataFrame.MaximumStreamData);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(13UL, snapshot.ReceiveLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0018")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ReadAsync_EmitsTheCurrentMaxStreamDataAndMaxDataUpdatesAfterBytesAreConsumed()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        AcknowledgeTrackedPackets(runtime);

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        AcknowledgeTrackedPackets(runtime);
        outboundEffects.Clear();

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, (ulong)stream.Id, [0x11, 0x22], offset: 0),
            out QuicStreamFrame streamFrame));
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryReceiveStreamFrame(streamFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        byte[] readBuffer = new byte[2];
        int bytesRead = await stream.ReadAsync(readBuffer, 0, readBuffer.Length);

        Assert.Equal(2, bytesRead);
        Assert.True(readBuffer.AsSpan().SequenceEqual(new byte[] { 0x11, 0x22 }));
        Assert.Equal(2, outboundEffects.Count);

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        bool sawMaxData = false;
        bool sawMaxStreamData = false;

        foreach (QuicConnectionEffect effect in outboundEffects)
        {
            QuicConnectionSendDatagramEffect sendEffect = Assert.IsType<QuicConnectionSendDatagramEffect>(effect);
            Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
                sendEffect.Datagram.Span,
                runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength));

            ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
            if (QuicFrameCodec.TryParseMaxDataFrame(payload, out QuicMaxDataFrame maxDataFrame, out int maxDataBytesConsumed))
            {
                sawMaxData = true;
                Assert.True(maxDataBytesConsumed > 0);
                Assert.Equal(66UL, maxDataFrame.MaximumData);
                continue;
            }

            if (QuicFrameCodec.TryParseMaxStreamDataFrame(payload, out QuicMaxStreamDataFrame maxStreamDataFrame, out int maxStreamDataBytesConsumed))
            {
                sawMaxStreamData = true;
                Assert.True(maxStreamDataBytesConsumed > 0);
                Assert.Equal((ulong)stream.Id, maxStreamDataFrame.StreamId);
                Assert.Equal(10UL, maxStreamDataFrame.MaximumStreamData);
                continue;
            }

            Assert.Fail("Unexpected flow-control datagram.");
        }

        Assert.True(sawMaxData);
        Assert.True(sawMaxStreamData);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0018")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterLoss_QueuesTheMostRecentMaxStreamDataPacketForRepairUntilAcknowledged()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] packet = QuicFrameTestData.BuildMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 10));
        Assert.True(QuicFrameCodec.TryParseMaxStreamDataFrame(packet, out QuicMaxStreamDataFrame frame, out int bytesConsumed));
        Assert.Equal(packet.Length, bytesConsumed);
        Assert.Equal(1UL, frame.StreamId);
        Assert.Equal(10UL, frame.MaximumStreamData);

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
    [Requirement("REQ-QUIC-RFC9000-S13P3-0018")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryAcknowledgePacket_DoesNotRetainTheMostRecentMaxStreamDataFrameForRepair()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] packet = QuicFrameTestData.BuildMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 10));
        Assert.True(QuicFrameCodec.TryParseMaxStreamDataFrame(packet, out QuicMaxStreamDataFrame frame, out int bytesConsumed));
        Assert.Equal(packet.Length, bytesConsumed);
        Assert.Equal(1UL, frame.StreamId);
        Assert.Equal(10UL, frame.MaximumStreamData);

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 12,
            PayloadBytes: (ulong)packet.Length,
            SentAtMicros: 250,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: packet));

        Assert.True(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            12,
            handshakeConfirmed: true));
        Assert.Equal(0, runtime.PendingRetransmissionCount);
        Assert.False(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            12,
            handshakeConfirmed: true));
        Assert.False(runtime.TryDequeueRetransmission(out _));
    }

    private static void AcknowledgeTrackedPackets(QuicConnectionRuntime runtime)
    {
        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> sentPacket in runtime.SendRuntime.SentPackets.ToArray())
        {
            Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
                sentPacket.Key.PacketNumberSpace,
                sentPacket.Key.PacketNumber,
                handshakeConfirmed: true));
        }
    }
}
